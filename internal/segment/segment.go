// Package segment answers the question a VLAN segmentation audit exists to answer:
// plugged into network S, which of the services inventoried on networks T != S can
// actually be reached, and how.
//
// For every (target, technique) pair it emits one model.ReachResult as soon as the
// verdict is known, so the operator watches the reachability matrix fill up live.
// Techniques range from "just connect" to "create a tagged sub-interface for the target
// VLAN"; the ones that touch the client's switch are opt-in
// (SegmentOptions.AllowL2Active) and every system change is undone before Test returns -
// on success, on error, on cancellation and on panic.
package segment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/netif"
)

var errUnsupported = engine.ErrUnsupported

const (
	defaultTimeout     = 3 * time.Second
	defaultConcurrency = 32
	// dhcpTimeout bounds the DHCP exchange on a freshly created sub-interface; a VLAN
	// with no DHCP server must not stall the scan.
	dhcpTimeout = 6 * time.Second
	// dtpSettle is how long to wait after asking for a trunk before assuming the switch
	// has converged.
	dtpSettle = 5 * time.Second
	// maxIPv6PerTarget bounds how many of a target's IPv6 addresses are tried.
	maxIPv6PerTarget = 2
)

// StaticFallbackFunc supplies an address to configure on a tagged sub-interface when the
// target VLAN has no DHCP server (or does not answer). It returns the address to assign
// and the next hop to route through.
type StaticFallbackFunc func(vlanID int, prefixes []netip.Prefix) (addr netip.Prefix, gateway netip.Addr, ok bool)

// Tester implements engine.SegmentTester.
type Tester struct {
	log *slog.Logger
	ps  engine.PortScanner
	ni  engine.NetInspector

	sys            sysApplier
	probe          prober
	staticFallback StaticFallbackFunc
}

var _ engine.SegmentTester = (*Tester)(nil)

// New returns a SegmentTester. ps is used as a fallback for the fixed source-port
// techniques when the process may not bind a privileged local port; ni supplies the local
// L2/L3 context. Either may be nil, which only disables the features that need them.
func New(log *slog.Logger, ps engine.PortScanner, ni engine.NetInspector) engine.SegmentTester {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	t := &Tester{
		log:            log,
		ps:             ps,
		ni:             ni,
		sys:            netifApplier{},
		staticFallback: DefaultStaticFallback,
	}
	t.probe = t.netProbe
	return t
}

// SetStaticFallback replaces the address picker used by the dot1q-subif and dtp-trunk
// techniques when the target VLAN has no DHCP server. Wiring code can type-assert the
// engine.SegmentTester to *Tester to call it.
func (t *Tester) SetStaticFallback(f StaticFallbackFunc) {
	if f != nil {
		t.staticFallback = f
	}
}

// DefaultStaticFallback picks a high address inside the target network, far from the DHCP
// pool and from the infrastructure addresses at the bottom of the range, and assumes the
// first address of the prefix is the router. It deliberately refuses to guess when the
// target prefixes are unknown: silently squatting an address on a client VLAN is worse
// than skipping a test.
func DefaultStaticFallback(vlanID int, prefixes []netip.Prefix) (netip.Prefix, netip.Addr, bool) {
	for _, p := range prefixes {
		if !p.IsValid() || !p.Addr().Is4() || p.Bits() > 30 {
			continue
		}
		addr, ok := netif.HostFromEnd(p, 5)
		if !ok {
			continue
		}
		gw, ok := netif.HostInPrefix(p, 1)
		if !ok {
			continue
		}
		return netip.PrefixFrom(addr, p.Bits()), gw, true
	}
	return netip.Prefix{}, netip.Addr{}, false
}

// --------------------------------------------------------------------------- Test
// ---------------------------------------------------------------------------

// Test tries to reach every target with every enabled technique and streams one
// model.ReachResult per (target, technique[, vlan]) through out as soon as it is known.
func (t *Tester) Test(ctx context.Context, opts engine.SegmentOptions, targets []engine.ReachTarget, out func(model.ReachResult)) (err error) {
	log := t.logger(opts)
	cl := newCleanup()

	// Deferred in this order so the cleanup runs *while* a panic is unwinding and the
	// recover still turns it into an error.
	defer func() {
		if r := recover(); r != nil {
			log.Error("segment: panic during reachability testing", "panic", r)
			err = fmt.Errorf("segment: panic during reachability testing: %v", r)
		}
	}()
	defer func() {
		if cerr := cl.restore(log); cerr != nil {
			log.Error("segment: some system changes could not be reverted", "err", cerr)
			if err == nil {
				err = fmt.Errorf("segment: cleanup failed: %w", cerr)
			}
		}
	}()

	if out == nil {
		out = func(model.ReachResult) {}
	}
	opts = normalizeOptions(opts)

	techs, dropped := selectTechniques(opts.Techniques, opts.AllowL2Active)
	for _, id := range dropped {
		if isL2Active(id) {
			log.Warn("segment: technique skipped, it needs AllowL2Active", "technique", id)
		} else {
			log.Warn("segment: unknown technique ignored", "technique", id)
		}
	}

	// Wi-Fi behaves exactly like a cable for everything that rides on IP, but the
	// switch-port techniques have no meaning on an access point association: an AP does
	// not forward 802.1Q-tagged frames to a station and does not speak DTP. Drop them
	// with an explicit reason rather than letting each one fail against the driver.
	if t.sys.IsWireless(opts.Interface) {
		kept := techs[:0]
		for _, id := range techs {
			if isL2Active(id) {
				log.Warn("segment: technique skipped, the interface is wireless",
					"technique", id, "interface", opts.Interface)
				continue
			}
			kept = append(kept, id)
		}
		techs = kept
	}
	if len(techs) == 0 {
		return errors.New("segment: no technique enabled")
	}
	if len(targets) == 0 {
		return nil
	}

	plan := buildPlan(opts, targets, techs)
	em := &emitter{
		out:      out,
		progress: opts.Progress,
		total:    int64(plan.count()),
		limiter:  newLimiter(opts.Rate),
	}
	em.report()

	log.Info("segment: starting reachability tests",
		"targets", len(targets), "techniques", techs,
		"tests", em.total, "concurrency", opts.Concurrency, "l2_active", opts.AllowL2Active)

	if err := t.runParallel(ctx, opts, plan.parallel, em); err != nil {
		return err
	}
	// Techniques that change system state run one group at a time so two of them can
	// never fight over the routing table or the same sub-interface.
	for _, g := range plan.exclusive {
		if ctx.Err() != nil {
			break
		}
		t.runExclusive(ctx, opts, g, cl, em, log)
	}
	if ctx.Err() != nil {
		log.Info("segment: cancelled", "completed", em.doneCount(), "total", em.total)
		return ctx.Err()
	}
	log.Info("segment: reachability tests finished", "results", em.doneCount())
	return nil
}

func (t *Tester) logger(opts engine.SegmentOptions) *slog.Logger {
	if opts.Log != nil {
		return opts.Log
	}
	return t.log
}

func normalizeOptions(o engine.SegmentOptions) engine.SegmentOptions {
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.Concurrency <= 0 {
		o.Concurrency = defaultConcurrency
	}
	if o.Interface == "" {
		o.Interface = o.Local.Interface
	}
	return o
}

// --------------------------------------------------------------------------- Parallel
// phase ---------------------------------------------------------------------------

func (t *Tester) runParallel(ctx context.Context, opts engine.SegmentOptions, jobs []job, em *emitter) error {
	if len(jobs) == 0 {
		return nil
	}
	workers := opts.Concurrency
	if workers > len(jobs) {
		workers = len(jobs)
	}
	ch := make(chan job)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for j := range ch {
				if ctx.Err() != nil {
					return
				}
				if err := em.wait(ctx); err != nil {
					return
				}
				em.emit(t.runJob(ctx, opts, j))
			}
		}()
	}
feed:
	for _, j := range jobs {
		select {
		case <-ctx.Done():
			break feed
		case ch <- j:
		}
	}
	close(ch)
	wg.Wait()
	return nil
}

// runProbe calls the prober, turning a panic into an error result instead of taking the
// whole server down: a single malformed target must never kill a scan that has been
// running for an hour.
func (t *Tester) runProbe(ctx context.Context, spec probeSpec) (pr probeResult) {
	defer func() {
		if r := recover(); r != nil {
			t.log.Error("segment: probe panicked", "technique", spec.Technique, "ip", spec.IP, "panic", r)
			pr = errResult(fmt.Sprintf("probe panicked: %v", r))
		}
	}()
	return t.probe(ctx, spec)
}

// runJob executes one stateless job.
func (t *Tester) runJob(ctx context.Context, opts engine.SegmentOptions, j job) model.ReachResult {
	spec := probeSpec{
		Technique: j.tech,
		IP:        j.ip,
		Port:      j.target.Port,
		Proto:     j.target.Proto,
		Service:   j.target.ServiceName,
		SrcPort:   j.srcPort,
		SrcAddr:   j.srcAddr,
		Iface:     j.iface,
		VLANID:    j.vlanID,
		Timeout:   opts.Timeout,
	}
	if j.tech == model.TechICMP {
		spec.Port, spec.Proto = 0, ""
	}
	pr := t.runProbe(ctx, spec)
	if pr.Status == model.ReachFiltered && j.srcPort != 0 && t.ps != nil {
		// A bound privileged source port may have been refused locally; the injected
		// scanner can still try it with a raw SYN.
		if alt, ok := t.portScanFallback(ctx, opts, j); ok {
			pr = alt
		}
	}
	return resultFor(j, pr)
}

// portScanFallback re-runs a fixed-source-port test through the injected PortScanner. The
// scanner only reports open ports, so this can confirm reachability but never
// distinguishes closed from filtered: the detail says so.
func (t *Tester) portScanFallback(ctx context.Context, opts engine.SegmentOptions, j job) (probeResult, bool) {
	if t.ps == nil || j.target.Port == 0 {
		return probeResult{}, false
	}
	sopts := engine.PortScanOptions{
		Interface:  opts.Interface,
		Hosts:      []netip.Addr{j.ip},
		Mode:       engine.ModeAuto,
		Rate:       opts.Rate,
		Timeout:    opts.Timeout,
		SourcePort: j.srcPort,
	}
	if j.target.Proto == model.UDP {
		sopts.UDPPorts = []uint16{j.target.Port}
	} else {
		sopts.TCPPorts = []uint16{j.target.Port}
	}
	var open atomic.Bool
	sctx, cancel := context.WithTimeout(ctx, opts.Timeout+time.Second)
	defer cancel()
	if err := t.ps.Scan(sctx, sopts, func(engine.PortResult) { open.Store(true) }); err != nil {
		return probeResult{}, false
	}
	if !open.Load() {
		return probeResult{}, false
	}
	return probeResult{
		Status: model.ReachOpen,
		Detail: fmt.Sprintf("reachable with source port %d (confirmed by the raw scanner; the local socket could not bind that port)", j.srcPort),
	}, true
}

// --------------------------------------------------------------------------- Results
// ---------------------------------------------------------------------------

func resultFor(j job, pr probeResult) model.ReachResult {
	r := model.ReachResult{
		TargetNetworkID: j.target.TargetNetworkID,
		TargetHostID:    j.target.TargetHostID,
		TargetServiceID: j.target.TargetServiceID,
		IP:              j.ip.String(),
		Port:            int(j.target.Port),
		Protocol:        j.target.Proto,
		Technique:       j.tech,
		VLANID:          j.vlanID,
		Status:          pr.Status,
		Detail:          pr.Detail,
		TestedAt:        time.Now().UTC(),
	}
	if pr.RTT > 0 {
		r.RTTMs = float64(pr.RTT.Microseconds()) / 1000
	}
	if j.tech == model.TechICMP {
		// Host-level technique: it says nothing about a specific service.
		r.Port = 0
		r.Protocol = ""
		r.TargetServiceID = 0
	}
	return r
}

// errorResults emits the same failure for every job of a group, so a target is never
// silently missing from the matrix.
func (t *Tester) errorResults(jobs []job, status model.ReachStatus, detail string, em *emitter) {
	for _, j := range jobs {
		em.emit(resultFor(j, probeResult{Status: status, Detail: detail}))
	}
}

// --------------------------------------------------------------------------- Emitter:
// streaming, progress and rate limiting
// ---------------------------------------------------------------------------

type emitter struct {
	out      func(model.ReachResult)
	progress engine.Progress
	total    int64
	done     atomic.Int64
	limiter  *limiter
	mu       sync.Mutex
}

func (e *emitter) emit(r model.ReachResult) {
	// The engine contract allows concurrent callbacks, but serialising here costs nothing
	// at these volumes and keeps the live UI ordering sane.
	e.mu.Lock()
	e.out(r)
	e.mu.Unlock()
	e.done.Add(1)
	e.report()
}

func (e *emitter) doneCount() int64 { return e.done.Load() }

func (e *emitter) report() {
	if e.progress != nil {
		e.progress(e.done.Load(), e.total)
	}
}

func (e *emitter) wait(ctx context.Context) error {
	if e.limiter == nil {
		return ctx.Err()
	}
	return e.limiter.wait(ctx)
}

// limiter is a simple pacing limiter: probes per second across all workers.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(rate int) *limiter {
	if rate <= 0 {
		return nil
	}
	return &limiter{interval: time.Second / time.Duration(rate)}
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	d := time.Until(at)
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
