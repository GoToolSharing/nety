package jobs

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/bus"
	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
	"github.com/vaadata/nety/internal/store"
)

// ---------------------------------------------------------------------------
// fake engines
// ---------------------------------------------------------------------------

type fakeDiscoverer struct {
	mu      sync.Mutex
	calls   int
	perUnit int           // live hosts reported per work unit
	delay   time.Duration // simulated work per unit
}

func (f *fakeDiscoverer) Discover(ctx context.Context, opts engine.DiscoveryOptions, out func(engine.DiscoveredHost)) error {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	n := 0
	for _, p := range opts.Targets {
		addr := p.Addr()
		for range max(1, p.Addr().BitLen()-p.Bits()) {
			if n >= f.perUnit {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			out(engine.DiscoveredHost{IP: addr, Methods: []string{"icmp-echo"}, TTL: 64})
			n++
			addr = addr.Next()
		}
	}
	return nil
}

func (f *fakeDiscoverer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakePortScanner struct {
	openPorts []uint16
	calls     atomic.Int64
}

func (f *fakePortScanner) Scan(ctx context.Context, opts engine.PortScanOptions, out func(engine.PortResult)) error {
	f.calls.Add(1)
	for _, ip := range opts.Hosts {
		for _, p := range f.openPorts {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, want := range opts.TCPPorts {
				if want == p {
					out(engine.PortResult{
						IP: ip, Port: p, Proto: model.TCP,
						State: model.PortOpen, Reason: "syn-ack", TTL: 64,
					})
				}
			}
		}
	}
	return nil
}

type fakeFingerprinter struct {
	calls atomic.Int64
	delay time.Duration
}

func (f *fakeFingerprinter) Fingerprint(ctx context.Context, ip netip.Addr, port uint16, proto model.Protocol, opts engine.FingerprintOptions) (model.Service, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return model.Service{}, ctx.Err()
		}
	}
	return model.Service{
		State: model.PortOpen, Name: "http", Product: "nginx", Version: "1.24.0",
		Confidence: 90, Method: "probe-match",
	}, nil
}

type fakeChecker struct{}

func (fakeChecker) Run(ctx context.Context, host model.Host, services []model.Service, opts engine.CheckOptions) ([]model.Finding, error) {
	if len(services) == 0 {
		return nil, nil
	}
	return []model.Finding{{
		IP: host.IP, Port: services[0].Port, Protocol: services[0].Protocol,
		CheckID: "demo-check", Title: "Demo", Severity: model.SevLow,
	}}, nil
}

func (fakeChecker) Catalog() []engine.CheckInfo {
	return []engine.CheckInfo{{ID: "demo-check", Title: "Demo", Severity: model.SevLow}}
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type harness struct {
	st     *store.Store
	bus    *bus.Bus
	runner *Runner
	sub    *bus.Subscription
	mis    model.Mission
	net    model.Network
}

func newHarness(t *testing.T, eng Engines) *harness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "jobs.db"), nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	b := bus.New()
	t.Cleanup(b.Close)

	r := New(st, b, eng, Options{
		MaxConcurrentScans: 2,
		DiscoveryChunk:     64,
		PortChunk:          64,
		Workers:            4,
	}, nil)
	t.Cleanup(r.Close)

	ctx := context.Background()
	mis, err := st.CreateMission(ctx, model.Mission{Name: "test"})
	if err != nil {
		t.Fatalf("mission: %v", err)
	}
	net, err := st.CreateNetwork(ctx, model.Network{
		MissionID: mis.ID, Name: "VLAN10", VLANID: 10,
		Interface: "eth0", LocalIP: "10.0.0.2", Prefixes: []string{"10.0.0.0/24"},
	})
	if err != nil {
		t.Fatalf("network: %v", err)
	}
	return &harness{st: st, bus: b, runner: r, sub: b.Subscribe(mis.ID, 4096), mis: mis, net: net}
}

func (h *harness) newScan(t *testing.T, opts model.ScanOptions) model.Scan {
	t.Helper()
	sc, err := h.st.CreateScan(context.Background(), model.Scan{
		MissionID: h.mis.ID, NetworkID: h.net.ID, Kind: model.ScanDiscovery, Options: opts,
	})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	return sc
}

// waitStatus polls until the scan reaches one of the wanted states.
func (h *harness) waitStatus(t *testing.T, scanID int64, timeout time.Duration, want ...model.ScanStatus) model.Scan {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sc, err := h.st.Scan(context.Background(), scanID)
		if err != nil {
			t.Fatalf("load scan: %v", err)
		}
		for _, w := range want {
			if sc.Status == w {
				return sc
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	sc, _ := h.st.Scan(context.Background(), scanID)
	t.Fatalf("timed out waiting for %v, scan is %q (phase %q, err %q)", want, sc.Status, sc.Phase, sc.Error)
	return model.Scan{}
}

func defaultOptions() model.ScanOptions {
	return model.ScanOptions{
		Targets:          []string{"10.0.0.0/28"},
		TCPPorts:         "80,443",
		HostDiscovery:    true,
		ServiceDetection: true,
		Checks:           true,
	}
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// TestScanStreamsResultsLive is requirement R1: results must be stored and
// published while the scan runs, not at the end.
func TestScanStreamsResultsLive(t *testing.T) {
	fp := &fakeFingerprinter{}
	h := newHarness(t, Engines{
		Discoverer:    &fakeDiscoverer{perUnit: 4},
		PortScanner:   &fakePortScanner{openPorts: []uint16{80}},
		Fingerprinter: fp,
		Checker:       fakeChecker{},
	})
	sc := h.newScan(t, defaultOptions())

	if err := h.runner.Start(context.Background(), sc.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	done := h.waitStatus(t, sc.ID, 15*time.Second, model.ScanCompleted, model.ScanFailed)
	if done.Status != model.ScanCompleted {
		t.Fatalf("scan failed: %s", done.Error)
	}

	// Results are in the store.
	hosts, _ := h.st.ListHosts(context.Background(), h.mis.ID, h.net.ID)
	if len(hosts) == 0 {
		t.Fatal("no host was recorded")
	}
	services, _ := h.st.ListServices(context.Background(), store.ServiceFilter{MissionID: h.mis.ID})
	if len(services) == 0 {
		t.Fatal("no service was recorded")
	}
	for _, sv := range services {
		if sv.Product != "nginx" {
			t.Fatalf("service was not fingerprinted: %+v", sv)
		}
	}
	findings, _ := h.st.ListFindings(context.Background(), h.mis.ID, 0)
	if len(findings) == 0 {
		t.Fatal("no finding was recorded")
	}

	// And they were published live, before the completion event.
	var sawHost, sawService, sawProgress bool
	var hostBeforeComplete bool
	completed := false
	h.sub.Close()
	for ev := range h.sub.C() {
		switch ev.Type {
		case model.EvtHost:
			sawHost = true
			if !completed {
				hostBeforeComplete = true
			}
		case model.EvtService:
			sawService = true
		case model.EvtScanProgress:
			sawProgress = true
		case model.EvtScanStatus:
			if s, ok := ev.Data.(model.Scan); ok && s.Status == model.ScanCompleted {
				completed = true
			}
		}
	}
	if !sawHost || !sawService || !sawProgress {
		t.Fatalf("missing live events: host=%v service=%v progress=%v", sawHost, sawService, sawProgress)
	}
	if !hostBeforeComplete {
		t.Fatal("host events must be published before the scan completes")
	}
	if fp.calls.Load() == 0 {
		t.Fatal("fingerprinter was never called")
	}
}

// TestPauseAndResume is requirement R2: pausing returns in-flight work to the
// queue, and resuming continues without losing or repeating work.
func TestPauseAndResume(t *testing.T) {
	disc := &fakeDiscoverer{perUnit: 2, delay: 40 * time.Millisecond}
	h := newHarness(t, Engines{
		Discoverer:  disc,
		PortScanner: &fakePortScanner{openPorts: []uint16{80}},
	})
	opts := defaultOptions()
	opts.Targets = []string{"10.0.0.0/24"} // several discovery units
	opts.ServiceDetection = false
	opts.Checks = false
	sc := h.newScan(t, opts)

	ctx := context.Background()
	if err := h.runner.Start(ctx, sc.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Let a couple of units run, then pause.
	time.Sleep(120 * time.Millisecond)
	if err := h.runner.Pause(sc.ID); err != nil {
		t.Fatalf("pause: %v", err)
	}
	paused := h.waitStatus(t, sc.ID, 10*time.Second, model.ScanPaused, model.ScanCompleted)
	if paused.Status == model.ScanCompleted {
		t.Skip("scan finished before the pause could take effect")
	}
	if !paused.Resumable {
		t.Fatal("a paused scan with pending work must be resumable")
	}

	pendingAtPause, err := h.st.PendingWorkCount(ctx, sc.ID)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if pendingAtPause == 0 {
		t.Fatal("expected work left in the queue after pausing")
	}
	callsAtPause := disc.count()

	// Nothing must be left leased: a crash now would lose nothing.
	phases, _ := h.st.PhaseProgress(ctx, sc.ID)
	for _, p := range phases {
		if p.Active != 0 {
			t.Fatalf("phase %s still has %d leased units after a pause", p.Phase, p.Active)
		}
	}

	// Resume: the scan picks up exactly where it stopped.
	if err := h.runner.Start(ctx, sc.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	done := h.waitStatus(t, sc.ID, 30*time.Second, model.ScanCompleted, model.ScanFailed)
	if done.Status != model.ScanCompleted {
		t.Fatalf("scan failed after resume: %s", done.Error)
	}
	if left, _ := h.st.PendingWorkCount(ctx, sc.ID); left != 0 {
		t.Fatalf("%d work units left after completion", left)
	}

	// The discoverer ran once per unit in total: no unit was executed twice.
	totalUnits := int64(0)
	phases, _ = h.st.PhaseProgress(ctx, sc.ID)
	for _, p := range phases {
		if p.Phase == model.PhaseDiscovery {
			totalUnits = p.Total
		}
	}
	if int64(disc.count()) != totalUnits {
		t.Fatalf("discovery ran %d times for %d units (work was repeated or skipped)", disc.count(), totalUnits)
	}
	if disc.count() <= callsAtPause {
		t.Fatal("resuming did not execute the remaining units")
	}
}

// TestStopKeepsResults checks that stopping cancels the scan but preserves
// everything already collected.
func TestStopKeepsResults(t *testing.T) {
	h := newHarness(t, Engines{
		Discoverer:  &fakeDiscoverer{perUnit: 2, delay: 30 * time.Millisecond},
		PortScanner: &fakePortScanner{openPorts: []uint16{80}},
	})
	opts := defaultOptions()
	opts.Targets = []string{"10.0.0.0/24"}
	opts.ServiceDetection = false
	opts.Checks = false
	sc := h.newScan(t, opts)

	ctx := context.Background()
	if err := h.runner.Start(ctx, sc.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	time.Sleep(120 * time.Millisecond)
	if err := h.runner.Stop(sc.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	final := h.waitStatus(t, sc.ID, 10*time.Second, model.ScanCancelled, model.ScanCompleted)
	if final.Status == model.ScanCompleted {
		t.Skip("scan finished before the stop could take effect")
	}
	hosts, _ := h.st.ListHosts(ctx, h.mis.ID, h.net.ID)
	if len(hosts) == 0 {
		t.Fatal("results collected before the stop must be kept")
	}
}

// TestRecoverAfterCrash simulates a process that died mid-scan: leased units
// go back to the queue and the scan becomes resumable.
func TestRecoverAfterCrash(t *testing.T) {
	h := newHarness(t, Engines{Discoverer: &fakeDiscoverer{perUnit: 1}})
	ctx := context.Background()
	sc := h.newScan(t, defaultOptions())

	// Hand-roll the state a crash would leave behind.
	if err := h.runner.plan(ctx, sc); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := h.st.SetScanStatus(ctx, sc.ID, model.ScanRunning, ""); err != nil {
		t.Fatalf("status: %v", err)
	}
	claimed, err := h.st.ClaimWork(ctx, sc.ID, model.PhaseDiscovery, 2)
	if err != nil || len(claimed) == 0 {
		t.Fatalf("claim: %d %v", len(claimed), err)
	}

	if err := h.runner.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	recovered, err := h.st.Scan(ctx, sc.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if recovered.Status != model.ScanPaused {
		t.Fatalf("expected the interrupted scan to be paused, got %q", recovered.Status)
	}
	if !recovered.Resumable {
		t.Fatal("an interrupted scan must be resumable")
	}
	for _, p := range recovered.Phases {
		if p.Active != 0 {
			t.Fatalf("phase %s still has leased units after recovery", p.Phase)
		}
	}
	if err := h.runner.Start(ctx, sc.ID); err != nil {
		t.Fatalf("resume after recovery: %v", err)
	}
	done := h.waitStatus(t, sc.ID, 15*time.Second, model.ScanCompleted, model.ScanFailed)
	if done.Status != model.ScanCompleted {
		t.Fatalf("resumed scan failed: %s", done.Error)
	}
}

// TestConcurrentScanLimit checks the runner refuses more than it is allowed.
func TestConcurrentScanLimit(t *testing.T) {
	h := newHarness(t, Engines{Discoverer: &fakeDiscoverer{perUnit: 1, delay: 300 * time.Millisecond}})
	h.runner.sem = make(chan struct{}, 1)

	ctx := context.Background()
	opts := defaultOptions()
	opts.Targets = []string{"10.0.0.0/24"}
	a := h.newScan(t, opts)
	b := h.newScan(t, opts)

	if err := h.runner.Start(ctx, a.ID); err != nil {
		t.Fatalf("start a: %v", err)
	}
	if err := h.runner.Start(ctx, b.ID); err != ErrBusy {
		t.Fatalf("expected ErrBusy for the second scan, got %v", err)
	}
	_ = h.runner.Stop(a.ID)
}

// TestPlanIsIdempotent makes sure resuming does not duplicate work units.
func TestPlanIsIdempotent(t *testing.T) {
	h := newHarness(t, Engines{Discoverer: &fakeDiscoverer{perUnit: 1}})
	ctx := context.Background()
	sc := h.newScan(t, defaultOptions())

	if err := h.runner.plan(ctx, sc); err != nil {
		t.Fatalf("plan: %v", err)
	}
	before, _ := h.st.PendingWorkCount(ctx, sc.ID)
	if before == 0 {
		t.Fatal("planning produced no work")
	}
	if err := h.runner.plan(ctx, sc); err != nil {
		t.Fatalf("replan: %v", err)
	}
	after, _ := h.st.PendingWorkCount(ctx, sc.ID)
	if after != before {
		t.Fatalf("replanning changed the queue: %d -> %d", before, after)
	}
}

func TestScanWithoutHostDiscoveryScansEveryTarget(t *testing.T) {
	ps := &fakePortScanner{openPorts: []uint16{80}}
	h := newHarness(t, Engines{PortScanner: ps})
	opts := defaultOptions()
	opts.HostDiscovery = false
	opts.ServiceDetection = false
	opts.Checks = false
	opts.Targets = []string{"10.0.0.0/29"}
	sc := h.newScan(t, opts)

	if err := h.runner.Start(context.Background(), sc.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	done := h.waitStatus(t, sc.ID, 15*time.Second, model.ScanCompleted, model.ScanFailed)
	if done.Status != model.ScanCompleted {
		t.Fatalf("scan failed: %s", done.Error)
	}
	// The /29 holds 8 addresses; our own (10.0.0.2) is always excluded.
	hosts, _ := h.st.ListHosts(context.Background(), h.mis.ID, h.net.ID)
	if len(hosts) != 7 {
		t.Fatalf("expected the 7 scannable addresses of the /29 to be recorded, got %d", len(hosts))
	}
	for _, hh := range hosts {
		if hh.IP == "10.0.0.2" {
			t.Fatal("the operator's own address must never be scanned")
		}
	}
}

func TestLocalAddressIsNeverScanned(t *testing.T) {
	h := newHarness(t, Engines{})
	ctx := context.Background()
	sc := h.newScan(t, model.ScanOptions{Targets: []string{"10.0.0.0/29"}, TCPPorts: "80"})

	net, _ := h.st.Network(ctx, h.net.ID) // LocalIP is 10.0.0.2
	targets, excludes, err := h.runner.resolveTargets(ctx, sc, net)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	f := NewExcludeFilter(excludes)
	var seen []string
	IterateAddresses(targets, f, func(a netip.Addr) bool {
		seen = append(seen, a.String())
		return true
	})
	for _, s := range seen {
		if s == "10.0.0.2" {
			t.Fatal("the operator's own address must be excluded from the scope")
		}
	}
	if len(seen) != 7 {
		t.Fatalf("expected 7 addresses, got %d: %v", len(seen), seen)
	}
}

// TestResumeDoesNotRegenerateWork guards requirement R2 from its subtler side:
// resuming walks every phase again, including the ones that already completed
// before the pause, and must not append a second set of work units for the
// phases they feed.
func TestResumeDoesNotRegenerateWork(t *testing.T) {
	fp := &fakeFingerprinter{delay: 30 * time.Millisecond}
	h := newHarness(t, Engines{
		Discoverer:    &fakeDiscoverer{perUnit: 4},
		PortScanner:   &fakePortScanner{openPorts: []uint16{80, 443}},
		Fingerprinter: fp,
	})
	ctx := context.Background()
	opts := defaultOptions()
	opts.Targets = []string{"10.0.0.0/27"}
	opts.Checks = false
	opts.Concurrency = 1
	sc := h.newScan(t, opts)

	if err := h.runner.Start(ctx, sc.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Wait until the fingerprint phase is under way, then pause: discovery and
	// the port phases are complete, so a resume will walk over them again.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		cur, err := h.st.Scan(ctx, sc.ID)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if cur.Status != model.ScanRunning && cur.Status != model.ScanQueued {
			t.Skipf("scan reached %q before the fingerprint phase could be paused", cur.Status)
		}
		if model.WorkPhase(cur.Phase) == model.PhaseFingerprint && fp.calls.Load() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := h.runner.Pause(sc.ID); err != nil {
		t.Fatalf("pause: %v", err)
	}
	paused := h.waitStatus(t, sc.ID, 15*time.Second, model.ScanPaused, model.ScanCompleted)
	if paused.Status == model.ScanCompleted {
		t.Skip("scan finished before the pause took effect")
	}

	unitsPerPhase := func() map[model.WorkPhase]int64 {
		t.Helper()
		phases, err := h.st.PhaseProgress(ctx, sc.ID)
		if err != nil {
			t.Fatalf("phases: %v", err)
		}
		out := map[model.WorkPhase]int64{}
		for _, p := range phases {
			out[p.Phase] = p.Total
		}
		return out
	}
	before := unitsPerPhase()
	if before[model.PhaseFingerprint] == 0 {
		t.Fatalf("the fingerprint phase should have units by now: %+v", before)
	}

	if err := h.runner.Start(ctx, sc.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	done := h.waitStatus(t, sc.ID, 30*time.Second, model.ScanCompleted, model.ScanFailed)
	if done.Status != model.ScanCompleted {
		t.Fatalf("resumed scan failed: %s", done.Error)
	}

	after := unitsPerPhase()
	for phase, n := range before {
		if after[phase] != n {
			t.Fatalf("phase %s went from %d to %d work units across the resume: work was regenerated",
				phase, n, after[phase])
		}
	}
	// Every service was fingerprinted exactly once across both runs.
	if got := fp.calls.Load(); got != before[model.PhaseFingerprint] {
		t.Fatalf("fingerprinted %d times for %d services: work was repeated or skipped",
			got, before[model.PhaseFingerprint])
	}
}
