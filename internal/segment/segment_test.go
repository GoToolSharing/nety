package segment

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
)

// newTester returns a Tester wired to a fake applier and, unless the test
// replaces it, a prober that answers instantly.
func newTester(t *testing.T) (*Tester, *fakeApplier) {
	t.Helper()
	tester := New(nil, nil, nil).(*Tester)
	fa := newFakeApplier()
	tester.sys = fa
	tester.probe = func(context.Context, probeSpec) probeResult {
		return probeResult{Status: model.ReachFiltered, Detail: "stub"}
	}
	return tester, fa
}

// collector gathers streamed results.
type collector struct {
	mu      sync.Mutex
	results []model.ReachResult
}

func (c *collector) add(r model.ReachResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = append(c.results, r)
}

func (c *collector) all() []model.ReachResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]model.ReachResult(nil), c.results...)
}

func (c *collector) byTechnique(tech string) []model.ReachResult {
	var out []model.ReachResult
	for _, r := range c.all() {
		if r.Technique == tech {
			out = append(out, r)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Direct path against real loopback listeners
// ---------------------------------------------------------------------------

func TestDirectAgainstLoopbackListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)

	tester := New(nil, nil, nil).(*Tester)
	tester.sys = newFakeApplier()

	var c collector
	target := engine.ReachTarget{
		TargetNetworkID: 2, TargetHostID: 1, TargetServiceID: 9,
		IP:    netip.MustParseAddr("127.0.0.1"),
		Port:  uint16(addr.Port),
		Proto: model.TCP,
	}
	opts := engine.SegmentOptions{
		Techniques: []string{model.TechDirect},
		Timeout:    2 * time.Second,
	}
	if err := tester.Test(context.Background(), opts, []engine.ReachTarget{target}, c.add); err != nil {
		t.Fatalf("Test: %v", err)
	}
	got := c.all()
	if len(got) != 1 {
		t.Fatalf("results = %d, want 1", len(got))
	}
	if got[0].Status != model.ReachOpen {
		t.Errorf("status = %q (%s), want reachable", got[0].Status, got[0].Detail)
	}
	if got[0].Technique != model.TechDirect || got[0].Port != addr.Port {
		t.Errorf("result = %+v", got[0])
	}
	if got[0].TargetServiceID != 9 || got[0].TargetHostID != 1 || got[0].TargetNetworkID != 2 {
		t.Errorf("target identifiers not carried through: %+v", got[0])
	}
	if got[0].TestedAt.IsZero() {
		t.Error("TestedAt not stamped")
	}
}

// A closed port on loopback must be reported as "closed", not "filtered": the
// difference is exactly what a segmentation report hinges on.
func TestDirectAgainstClosedLoopbackPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // nothing listens on this port any more

	tester := New(nil, nil, nil).(*Tester)
	tester.sys = newFakeApplier()

	var c collector
	target := engine.ReachTarget{
		TargetHostID: 1, TargetServiceID: 9,
		IP: netip.MustParseAddr("127.0.0.1"), Port: uint16(port), Proto: model.TCP,
	}
	opts := engine.SegmentOptions{Techniques: []string{model.TechDirect}, Timeout: 2 * time.Second}
	if err := tester.Test(context.Background(), opts, []engine.ReachTarget{target}, c.add); err != nil {
		t.Fatalf("Test: %v", err)
	}
	got := c.all()
	if len(got) != 1 {
		t.Fatalf("results = %d", len(got))
	}
	if got[0].Status != model.ReachClosed {
		t.Errorf("status = %q (%s), want closed", got[0].Status, got[0].Detail)
	}
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

func TestTestStreamsResultsImmediately(t *testing.T) {
	tester, _ := newTester(t)
	release := make(chan struct{})
	tester.probe = func(ctx context.Context, s probeSpec) probeResult {
		if s.IP.String() == "10.20.0.11" {
			<-release // the second target stays blocked
		}
		return probeResult{Status: model.ReachOpen}
	}

	first := make(chan model.ReachResult, 4)
	done := make(chan error, 1)
	go func() {
		done <- tester.Test(context.Background(), engine.SegmentOptions{
			Techniques:  []string{model.TechDirect},
			Concurrency: 2,
		}, []engine.ReachTarget{
			svc("10.20.0.10", 80, model.TCP, 1, 11),
			svc("10.20.0.11", 80, model.TCP, 2, 12),
		}, func(r model.ReachResult) { first <- r })
	}()

	select {
	case r := <-first:
		if r.IP != "10.20.0.10" {
			t.Errorf("first streamed result = %s, want the unblocked target", r.IP)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no result was streamed while another target was still in flight")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Test: %v", err)
	}
}

func TestTestReportsProgress(t *testing.T) {
	tester, _ := newTester(t)
	var mu sync.Mutex
	var lastDone, lastTotal int64
	calls := 0

	targets := []engine.ReachTarget{
		svc("10.20.0.10", 80, model.TCP, 1, 11),
		svc("10.20.0.11", 80, model.TCP, 2, 12),
		svc("10.20.0.12", 80, model.TCP, 3, 13),
	}
	opts := engine.SegmentOptions{
		Techniques: []string{model.TechDirect, model.TechICMP},
		Progress: func(done, total int64) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			lastDone, lastTotal = done, total
		},
	}
	var c collector
	if err := tester.Test(context.Background(), opts, targets, c.add); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if lastTotal != 6 {
		t.Errorf("total = %d, want 6 (3 targets x 2 techniques)", lastTotal)
	}
	if lastDone != lastTotal {
		t.Errorf("done = %d, want %d at the end", lastDone, lastTotal)
	}
	if calls < 2 {
		t.Errorf("progress reported %d times; it must be continuous", calls)
	}
}

func TestTestHonoursConcurrency(t *testing.T) {
	tester, _ := newTester(t)
	var mu sync.Mutex
	inFlight, peak := 0, 0
	tester.probe = func(ctx context.Context, s probeSpec) probeResult {
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		return probeResult{Status: model.ReachOpen}
	}

	var targets []engine.ReachTarget
	for i := range 20 {
		targets = append(targets, svc("10.20.0."+itoa(10+i), 80, model.TCP, int64(i), int64(100+i)))
	}
	var c collector
	err := tester.Test(context.Background(), engine.SegmentOptions{
		Techniques:  []string{model.TechDirect},
		Concurrency: 3,
	}, targets, c.add)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if peak > 3 {
		t.Errorf("peak concurrency = %d, want at most 3", peak)
	}
	if len(c.all()) != 20 {
		t.Errorf("results = %d, want 20", len(c.all()))
	}
}

func TestTestHonoursRate(t *testing.T) {
	tester, _ := newTester(t)
	tester.probe = func(context.Context, probeSpec) probeResult {
		return probeResult{Status: model.ReachOpen}
	}
	var targets []engine.ReachTarget
	for i := range 10 {
		targets = append(targets, svc("10.20.0."+itoa(10+i), 80, model.TCP, int64(i), int64(100+i)))
	}
	var c collector
	start := time.Now()
	err := tester.Test(context.Background(), engine.SegmentOptions{
		Techniques:  []string{model.TechDirect},
		Concurrency: 8,
		Rate:        100, // 10ms apart
	}, targets, c.add)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("10 probes at 100/s took %v; the rate limit was not applied", elapsed)
	}
}

func TestTestStopsOnCancellation(t *testing.T) {
	tester, _ := newTester(t)
	ctx, cancel := context.WithCancel(context.Background())
	var seen int
	var mu sync.Mutex
	tester.probe = func(context.Context, probeSpec) probeResult {
		mu.Lock()
		seen++
		if seen == 2 {
			cancel()
		}
		mu.Unlock()
		return probeResult{Status: model.ReachOpen}
	}

	var targets []engine.ReachTarget
	for i := range 50 {
		targets = append(targets, svc("10.20.0."+itoa(10+i), 80, model.TCP, int64(i), int64(100+i)))
	}
	var c collector
	err := tester.Test(ctx, engine.SegmentOptions{
		Techniques:  []string{model.TechDirect},
		Concurrency: 1,
	}, targets, c.add)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(c.all()) >= 50 {
		t.Errorf("%d results produced; cancellation should have cut the run short", len(c.all()))
	}
}

func TestTestRejectsEmptyTechniqueSet(t *testing.T) {
	tester, _ := newTester(t)
	err := tester.Test(context.Background(), engine.SegmentOptions{
		Techniques: []string{"nope"},
	}, []engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, nil)
	if err == nil || !strings.Contains(err.Error(), "no technique") {
		t.Fatalf("err = %v, want a 'no technique enabled' error", err)
	}
}

func TestTestWithNoTargetsIsANoOp(t *testing.T) {
	tester, _ := newTester(t)
	if err := tester.Test(context.Background(), engine.SegmentOptions{}, nil, nil); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestTestToleratesANilCallback(t *testing.T) {
	tester, _ := newTester(t)
	err := tester.Test(context.Background(), engine.SegmentOptions{
		Techniques: []string{model.TechDirect},
	}, []engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
}

// A panic inside a probe must not take the process down: it becomes an error
// result and the rest of the scan carries on.
func TestTestRecoversFromAProbePanic(t *testing.T) {
	tester, fa := newTester(t)
	tester.probe = func(_ context.Context, s probeSpec) probeResult {
		if s.IP.String() == "10.20.0.10" {
			panic("probe exploded")
		}
		return probeResult{Status: model.ReachOpen}
	}
	var c collector
	err := tester.Test(context.Background(), engine.SegmentOptions{
		Techniques:  []string{model.TechDirect},
		Concurrency: 1,
	}, []engine.ReachTarget{
		svc("10.20.0.10", 80, model.TCP, 1, 11),
		svc("10.20.0.11", 80, model.TCP, 2, 12),
	}, c.add)
	if err != nil {
		t.Fatalf("err = %v, want the panic contained", err)
	}
	got := c.all()
	if len(got) != 2 {
		t.Fatalf("results = %d, want both targets reported", len(got))
	}
	var sawPanic, sawOK bool
	for _, r := range got {
		if r.Status == model.ReachError && strings.Contains(r.Detail, "panicked") {
			sawPanic = true
		}
		if r.Status == model.ReachOpen {
			sawOK = true
		}
	}
	if !sawPanic {
		t.Error("the panicking probe did not produce an error result")
	}
	if !sawOK {
		t.Error("the scan stopped after the panic instead of carrying on")
	}
	fa.assertClean(t)
}

func TestTestRecoversFromAPanicInTheExclusivePhase(t *testing.T) {
	tester, fa := newTester(t)
	fa.onDHCP = func() { panic("netlink exploded") }

	opts := engine.SegmentOptions{
		Interface:     "eth0",
		AllowL2Active: true,
		Techniques:    []string{model.TechDot1QSubif},
	}
	var c collector
	err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add)

	if err == nil || !strings.Contains(err.Error(), "panic") {
		t.Fatalf("err = %v, want the panic surfaced as an error", err)
	}
	fa.assertClean(t)
}

func TestResultForZeroesTheServiceOnICMP(t *testing.T) {
	j := job{
		target: svc("10.20.0.10", 443, model.TCP, 1, 11),
		tech:   model.TechICMP,
		ip:     netip.MustParseAddr("10.20.0.10"),
	}
	r := resultFor(j, probeResult{Status: model.ReachOpen, RTT: 1500 * time.Microsecond})
	if r.Port != 0 || r.Protocol != "" || r.TargetServiceID != 0 {
		t.Errorf("icmp result still names a service: %+v", r)
	}
	if r.RTTMs != 1.5 {
		t.Errorf("RTTMs = %v, want 1.5", r.RTTMs)
	}
}

func TestDefaultStaticFallback(t *testing.T) {
	addr, gw, ok := DefaultStaticFallback(20, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")})
	if !ok {
		t.Fatal("no fallback produced for a /24")
	}
	if addr.String() != "10.20.0.250/24" {
		t.Errorf("addr = %s, want a high address in the range", addr)
	}
	if gw.String() != "10.20.0.1" {
		t.Errorf("gateway = %s", gw)
	}

	// Refuse to guess rather than squat an address on an unknown network.
	if _, _, ok := DefaultStaticFallback(20, nil); ok {
		t.Error("a fallback was invented although the target prefixes are unknown")
	}
	if _, _, ok := DefaultStaticFallback(20, []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}); ok {
		t.Error("IPv6 prefixes are not supported by the static fallback")
	}
}

func TestNormalizeOptions(t *testing.T) {
	got := normalizeOptions(engine.SegmentOptions{Local: engine.NetContext{Interface: "ens3"}})
	if got.Timeout != defaultTimeout {
		t.Errorf("timeout = %v", got.Timeout)
	}
	if got.Concurrency != defaultConcurrency {
		t.Errorf("concurrency = %d", got.Concurrency)
	}
	if got.Interface != "ens3" {
		t.Errorf("interface = %q, want the one from the detected context", got.Interface)
	}
}

// TestWirelessDropsSwitchPortTechniques covers the Wi-Fi case: an operator
// associates to the client's wireless network instead of plugging a cable in.
// Everything that rides on IP must behave identically; only the switch-port
// techniques, which have no meaning on an access point association, drop out —
// and they must drop out cleanly rather than failing against the driver.
func TestWirelessDropsSwitchPortTechniques(t *testing.T) {
	for _, wireless := range []bool{false, true} {
		tester, fa := newTester(t)
		fa.wireless = wireless

		var got []model.ReachResult
		opts := engine.SegmentOptions{
			Interface:     "wlan0",
			AllowL2Active: true,
			Techniques: []string{
				model.TechDirect, model.TechDot1QSubif,
				model.TechDTPTrunk, model.TechDoubleTag,
			},
			Timeout:     50 * time.Millisecond,
			Concurrency: 1,
		}
		targets := []engine.ReachTarget{{
			TargetNetworkID: 2,
			IP:              netip.MustParseAddr("10.20.0.5"),
			Port:            445,
			Proto:           model.TCP,
			TargetVLANID:    20,
			TargetPrefixes:  []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")},
		}}
		if err := tester.Test(context.Background(), opts, targets, func(r model.ReachResult) {
			got = append(got, r)
		}); err != nil {
			t.Fatalf("wireless=%v: %v", wireless, err)
		}

		usedL2, direct := false, false
		for _, r := range got {
			switch r.Technique {
			case model.TechDot1QSubif, model.TechDTPTrunk, model.TechDoubleTag:
				usedL2 = true
			case model.TechDirect:
				direct = true
			}
		}
		if wireless && usedL2 {
			t.Fatalf("switch-port techniques must not be attempted over Wi-Fi, got %+v", got)
		}
		if !wireless && !usedL2 {
			t.Fatalf("switch-port techniques should still run on a wired port, got %+v", got)
		}
		// Wi-Fi is not a second-class attachment above layer 2.
		if !direct {
			t.Fatalf("the direct technique must run regardless of link type (wireless=%v): %+v", wireless, got)
		}
		// And nothing must have been attempted on the wireless interface.
		if wireless {
			for _, c := range fa.callLog() {
				if strings.HasPrefix(c, "AddVLAN") || strings.HasPrefix(c, "RequestTrunk") {
					t.Fatalf("no switch-port call may be made over Wi-Fi, got %q", c)
				}
			}
		}
	}
}
