// Package jobs runs scans.
//
// It implements the two non-negotiable requirements of docs/ARCHITECTURE.md:
//
//	R1 live results   — every host, port, service, finding and reachability
//	                    result is written to the store and published on the bus
//	                    the instant the engine reports it, never at the end.
//	R2 pause/resume   — a scan is a queue of persisted work units. Pausing
//	                    stops claiming new units and returns the in-flight ones
//	                    to the queue; resuming continues exactly where it
//	                    stopped, even after a crash or a reboot.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vaadata/nety/internal/bus"
	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
	"github.com/vaadata/nety/internal/store"
)

// Engines holds the scanning implementations. A nil engine makes the phases
// that need it no-ops (logged), so the platform runs with a partial toolset.
type Engines struct {
	Discoverer    engine.Discoverer
	PortScanner   engine.PortScanner
	Fingerprinter engine.Fingerprinter
	Identity      engine.IdentityCollector
	Correlator    engine.Correlator
	Checker       engine.Checker
	NetInspector  engine.NetInspector
	Segment       engine.SegmentTester
}

// Options tunes the runner.
type Options struct {
	MaxConcurrentScans int
	DefaultRate        int
	MaxRate            int
	DefaultTimeout     time.Duration
	Workers            int

	// Work-unit sizing. Smaller units resume more precisely but add overhead.
	DiscoveryChunk int // addresses per discovery unit
	PortChunk      int // host×port probes per port-scan unit
	SegmentChunk   int // targets per segmentation unit
}

func (o *Options) normalize() {
	if o.MaxConcurrentScans < 1 {
		o.MaxConcurrentScans = 2
	}
	if o.DefaultRate < 1 {
		o.DefaultRate = 5000
	}
	if o.MaxRate < o.DefaultRate {
		o.MaxRate = o.DefaultRate
	}
	if o.DefaultTimeout <= 0 {
		o.DefaultTimeout = 3 * time.Second
	}
	if o.Workers < 1 {
		o.Workers = 64
	}
	if o.DiscoveryChunk < 1 {
		o.DiscoveryChunk = 1024
	}
	if o.PortChunk < 1 {
		o.PortChunk = 8192
	}
	if o.SegmentChunk < 1 {
		o.SegmentChunk = 64
	}
}

// errPaused unwinds a run when the operator pauses it.
var errPaused = errors.New("scan paused")

// ErrBusy is returned when the concurrent-scan limit is reached.
var ErrBusy = errors.New("jobs: too many scans already running")

// ErrNotRunning is returned by Pause/Stop for a scan that is not active.
var ErrNotRunning = errors.New("jobs: scan is not running")

// Runner executes scans.
type Runner struct {
	st   *store.Store
	bus  *bus.Bus
	eng  Engines
	opts Options
	log  *slog.Logger

	mu     sync.Mutex
	active map[int64]*control
	sem    chan struct{}
	wg     sync.WaitGroup

	// segMu serialises the segmentation phase process-wide. The segmentation
	// engine creates sub-interfaces, addresses and routes on the one machine
	// we are running on, and tracks them for cleanup per call; two concurrent
	// callers would tear down each other's state, leaking interfaces and —
	// worse — turning a reachable service into a "filtered" cell in the
	// matrix handed to the client.
	segMu sync.Mutex

	closed atomic.Bool
}

type control struct {
	cancel  context.CancelFunc
	pause   atomic.Bool
	stopped atomic.Bool
	done    chan struct{}
}

// New builds a runner.
func New(st *store.Store, b *bus.Bus, eng Engines, opts Options, log *slog.Logger) *Runner {
	opts.normalize()
	if log == nil {
		log = slog.Default()
	}
	return &Runner{
		st:     st,
		bus:    b,
		eng:    eng,
		opts:   opts,
		log:    log,
		active: make(map[int64]*control),
		sem:    make(chan struct{}, opts.MaxConcurrentScans),
	}
}

// Recover is called at startup. Scans that were running when the process died
// are moved back to paused and their leased work units returned to the queue,
// so the operator can resume them without losing anything.
func (r *Runner) Recover(ctx context.Context) error {
	scans, err := r.st.ScansByStatus(ctx, model.ScanRunning)
	if err != nil {
		return err
	}
	for _, sc := range scans {
		released, err := r.st.ReleaseRunningWork(ctx, sc.ID)
		if err != nil {
			return err
		}
		if err := r.st.SetScanStatus(ctx, sc.ID, model.ScanPaused,
			"interrupted by a restart — resume to continue"); err != nil {
			return err
		}
		r.log.Warn("recovered an interrupted scan",
			"scan", sc.ID, "mission", sc.MissionID, "requeued_units", released)
		r.logScan(ctx, sc, "warn",
			fmt.Sprintf("scan interrupted by a server restart; %d work units returned to the queue, resume to continue", released))
	}
	return nil
}

// Start begins (or continues) a scan in the background.
func (r *Runner) Start(ctx context.Context, scanID int64) error {
	if r.closed.Load() {
		return errors.New("jobs: runner is shutting down")
	}
	sc, err := r.st.Scan(ctx, scanID)
	if err != nil {
		return err
	}
	switch sc.Status {
	case model.ScanRunning:
		return errors.New("jobs: scan is already running")
	case model.ScanCompleted:
		// Completed is not a dead end: "retry failed units" puts work back in
		// the queue, and that work has to be runnable.
		pending, err := r.st.PendingWorkCount(ctx, sc.ID)
		if err != nil {
			return err
		}
		if pending == 0 {
			return errors.New("jobs: scan is already completed")
		}
	}

	r.mu.Lock()
	if _, busy := r.active[scanID]; busy {
		r.mu.Unlock()
		return errors.New("jobs: scan is already running")
	}
	select {
	case r.sem <- struct{}{}:
	default:
		r.mu.Unlock()
		return ErrBusy
	}
	ctl := &control{done: make(chan struct{})}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	ctl.cancel = cancel
	r.active[scanID] = ctl
	r.mu.Unlock()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer close(ctl.done)
		defer func() {
			r.mu.Lock()
			delete(r.active, scanID)
			r.mu.Unlock()
			<-r.sem
			cancel()
		}()
		// A panic anywhere in a scan must never take the server down with it:
		// the operator would lose the web interface and, worse, the deferred
		// network cleanup would never run. Mark the scan failed and carry on.
		defer func() {
			if p := recover(); p != nil {
				r.log.Error("scan panicked", "scan", scanID, "panic", p,
					"stack", string(debug.Stack()))
				bg, cancelBG := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancelBG()
				_, _ = r.st.ReleaseRunningWork(bg, scanID)
				_ = r.st.SetScanStatus(bg, scanID, model.ScanFailed,
					fmt.Sprintf("internal error: %v", p))
				if sc, err := r.st.Scan(bg, scanID); err == nil {
					r.bus.PublishData(model.EvtScanStatus, sc.MissionID, sc.ID, sc)
				}
			}
		}()
		r.run(runCtx, ctl, scanID)
	}()
	return nil
}

// Pause asks a running scan to stop claiming work. In-flight units finish and
// everything else returns to the queue.
func (r *Runner) Pause(scanID int64) error {
	r.mu.Lock()
	ctl := r.active[scanID]
	r.mu.Unlock()
	if ctl == nil {
		return ErrNotRunning
	}
	ctl.pause.Store(true)
	return nil
}

// Stop cancels a scan. Results already collected are kept.
func (r *Runner) Stop(scanID int64) error {
	r.mu.Lock()
	ctl := r.active[scanID]
	r.mu.Unlock()
	if ctl == nil {
		return ErrNotRunning
	}
	ctl.stopped.Store(true)
	ctl.cancel()
	return nil
}

// IsRunning reports whether the runner currently owns this scan.
func (r *Runner) IsRunning(scanID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.active[scanID]
	return ok
}

// Running lists the active scan ids.
func (r *Runner) Running() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int64, 0, len(r.active))
	for id := range r.active {
		out = append(out, id)
	}
	return out
}

// Close cancels every scan and waits for them to unwind.
func (r *Runner) Close() {
	r.closed.Store(true)
	r.mu.Lock()
	for _, ctl := range r.active {
		ctl.pause.Store(true)
		ctl.cancel()
	}
	r.mu.Unlock()
	r.wg.Wait()
}

// ---------------------------------------------------------------------------
// the run loop
// ---------------------------------------------------------------------------

func (r *Runner) run(ctx context.Context, ctl *control, scanID int64) {
	sc, err := r.st.Scan(ctx, scanID)
	if err != nil {
		r.log.Error("cannot load scan", "scan", scanID, "error", err)
		return
	}

	st := newRunState(sc)
	if err := r.st.SetScanStatus(ctx, scanID, model.ScanRunning, ""); err != nil {
		r.log.Error("cannot mark scan running", "scan", scanID, "error", err)
		return
	}
	r.publishScan(ctx, scanID)
	r.logScan(ctx, sc, "info", "scan started")

	runErr := r.execute(ctx, ctl, sc, st)

	// The epilogue must run even when ctx was cancelled by Stop or Close:
	// otherwise the scan would stay stuck in "running" and its work units
	// would stay leased, which is exactly what R2 forbids.
	epi, cancelEpi := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancelEpi()
	ctx = epi

	// Flush the final counters before deciding the outcome.
	r.flushProgress(ctx, sc, st, true)

	switch {
	case ctl.pause.Load() && !ctl.stopped.Load():
		released, _ := r.st.ReleaseRunningWork(ctx, scanID)
		_ = r.st.SetScanStatus(ctx, scanID, model.ScanPaused, "")
		r.logScan(ctx, sc, "info",
			fmt.Sprintf("scan paused; %d work units returned to the queue, resume to continue", released))
	case ctl.stopped.Load() || errors.Is(runErr, context.Canceled):
		released, _ := r.st.ReleaseRunningWork(ctx, scanID)
		_ = r.st.SetScanStatus(ctx, scanID, model.ScanCancelled, "")
		r.logScan(ctx, sc, "warn",
			fmt.Sprintf("scan stopped by the operator; %d work units left in the queue, collected results are kept", released))
	case runErr != nil:
		_, _ = r.st.ReleaseRunningWork(ctx, scanID)
		_ = r.st.SetScanStatus(ctx, scanID, model.ScanFailed, runErr.Error())
		r.log.Error("scan failed", "scan", scanID, "error", runErr)
		r.logScan(ctx, sc, "error", "scan failed: "+runErr.Error())
	default:
		_ = r.st.SetScanStatus(ctx, scanID, model.ScanCompleted, "")
		r.logScan(ctx, sc, "info", "scan completed")
	}
	_ = r.st.TouchMission(ctx, sc.MissionID)
	r.publishScan(ctx, scanID)
}

// execute plans the scan if needed and walks its phases in order.
func (r *Runner) execute(ctx context.Context, ctl *control, sc model.Scan, st *runState) error {
	if err := r.plan(ctx, sc); err != nil {
		return fmt.Errorf("planning: %w", err)
	}
	for _, phase := range phasesFor(sc.Kind) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if ctl.pause.Load() {
			return errPaused
		}
		if err := r.runPhase(ctx, ctl, sc, st, phase); err != nil {
			if errors.Is(err, errPaused) || errors.Is(err, context.Canceled) {
				return err
			}
			return fmt.Errorf("phase %s: %w", phase, err)
		}
		// A phase feeds the next one: generate its units now that the results
		// of this phase are all in the store.
		if err := r.generate(ctx, sc, phase); err != nil {
			return fmt.Errorf("generating work after %s: %w", phase, err)
		}
	}
	return nil
}

// runPhase drains the pending work units of one phase.
func (r *Runner) runPhase(ctx context.Context, ctl *control, sc model.Scan, st *runState, phase model.WorkPhase) error {
	workers := r.phaseWorkers(phase, sc)
	st.setPhase(phase)

	// The segmentation phase reconfigures this machine's interfaces and
	// routes, so only one may run at a time across the whole process.
	if phase == model.PhaseSegment {
		if pending, err := r.st.PendingWorkCount(ctx, sc.ID); err == nil && pending > 0 {
			r.logScan(ctx, sc, "debug", "waiting for exclusive access to the network configuration")
		}
		r.segMu.Lock()
		defer r.segMu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		if ctl.pause.Load() {
			return errPaused
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if ctl.pause.Load() {
			return errPaused
		}
		units, err := r.st.ClaimWork(ctx, sc.ID, phase, workers)
		if err != nil {
			return err
		}
		if len(units) == 0 {
			return nil
		}

		var wg sync.WaitGroup
		sem := make(chan struct{}, workers)
		for _, u := range units {
			wg.Add(1)
			sem <- struct{}{}
			go func(u model.WorkUnit) {
				defer wg.Done()
				defer func() { <-sem }()
				defer func() {
					if p := recover(); p != nil {
						r.log.Error("work unit panicked",
							"scan", sc.ID, "phase", u.Phase, "seq", u.Seq, "panic", p)
						_ = r.st.FailWork(ctx, u.ID, fmt.Sprintf("panic: %v", p), false)
					}
				}()

				err := r.exec(ctx, sc, st, u)
				switch {
				case err == nil:
					if cerr := r.st.CompleteWork(ctx, u.ID); cerr != nil {
						r.log.Warn("cannot mark work done", "unit", u.ID, "error", cerr)
					}
				case errors.Is(err, context.Canceled):
					// Paused or stopped: hand the unit back untouched.
					_ = r.st.FailWork(ctx, u.ID, "", true)
				default:
					requeue := u.Attempts < 3
					r.log.Warn("work unit failed",
						"scan", sc.ID, "phase", u.Phase, "seq", u.Seq,
						"attempt", u.Attempts, "requeue", requeue, "error", err)
					_ = r.st.FailWork(ctx, u.ID, err.Error(), requeue)
					if !requeue {
						r.logScan(ctx, sc, "error",
							fmt.Sprintf("%s unit %d failed after %d attempts: %v", u.Phase, u.Seq, u.Attempts, err))
					}
				}
				r.flushProgress(ctx, sc, st, false)
			}(u)
		}
		wg.Wait()
		r.flushProgress(ctx, sc, st, true)
	}
}

// phaseWorkers picks the parallelism of a phase.
func (r *Runner) phaseWorkers(phase model.WorkPhase, sc model.Scan) int {
	switch phase {
	case model.PhaseL2:
		return 1
	case model.PhaseDiscovery, model.PhasePortsTCP, model.PhasePortsUDP:
		// The packet engines are internally parallel and rate limited; running
		// several units at once would multiply the real packet rate.
		return 1
	case model.PhaseSegment:
		// One unit at a time: see Runner.segMu.
		return 1
	default:
		n := sc.Options.Concurrency
		if n <= 0 {
			n = r.opts.Workers
		}
		return min(max(n, 1), 256)
	}
}

// exec dispatches one work unit to its phase implementation.
func (r *Runner) exec(ctx context.Context, sc model.Scan, st *runState, u model.WorkUnit) error {
	switch u.Phase {
	case model.PhaseL2:
		return r.execL2(ctx, sc, st, u)
	case model.PhaseDiscovery:
		return r.execDiscovery(ctx, sc, st, u)
	case model.PhasePortsTCP, model.PhasePortsUDP:
		return r.execPorts(ctx, sc, st, u)
	case model.PhaseFingerprint:
		return r.execFingerprint(ctx, sc, st, u)
	case model.PhaseIdentity:
		return r.execIdentity(ctx, sc, st, u)
	case model.PhaseChecks:
		return r.execChecks(ctx, sc, st, u)
	case model.PhaseSegment:
		return r.execSegment(ctx, sc, st, u)
	default:
		return fmt.Errorf("unknown phase %q", u.Phase)
	}
}

// ---------------------------------------------------------------------------
// progress and events
// ---------------------------------------------------------------------------

// runState tracks the live counters of a scan.
type runState struct {
	mu        sync.Mutex
	stats     model.ScanStats
	phase     model.WorkPhase
	lastFlush time.Time

	hostIDs map[string]int64 // ip -> host id, per network, filled as we go
}

func newRunState(sc model.Scan) *runState {
	return &runState{stats: sc.Stats, hostIDs: make(map[string]int64)}
}

func (s *runState) setPhase(p model.WorkPhase) {
	s.mu.Lock()
	s.phase = p
	s.mu.Unlock()
}

func (s *runState) add(fn func(*model.ScanStats)) {
	s.mu.Lock()
	fn(&s.stats)
	s.mu.Unlock()
}

func (s *runState) snapshot() (model.ScanStats, model.WorkPhase) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats, s.phase
}

func (s *runState) rememberHost(key string, id int64) {
	s.mu.Lock()
	s.hostIDs[key] = id
	s.mu.Unlock()
}

func (s *runState) lookupHost(key string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.hostIDs[key]
	return id, ok
}

// flushProgress persists and publishes the live counters, throttled to a few
// updates per second unless force is set.
func (r *Runner) flushProgress(ctx context.Context, sc model.Scan, st *runState, force bool) {
	st.mu.Lock()
	if !force && time.Since(st.lastFlush) < 250*time.Millisecond {
		st.mu.Unlock()
		return
	}
	st.lastFlush = time.Now()
	stats := st.stats
	phase := st.phase
	st.mu.Unlock()

	phases, err := r.st.PhaseProgress(ctx, sc.ID)
	if err != nil {
		return
	}
	progress := overallProgress(phases)
	if err := r.st.UpdateScanProgress(ctx, sc.ID, string(phase), progress, stats); err != nil {
		return
	}
	r.bus.PublishData(model.EvtScanProgress, sc.MissionID, sc.ID, map[string]any{
		"scan_id":  sc.ID,
		"phase":    phase,
		"progress": progress,
		"stats":    stats,
		"phases":   phases,
	})
}

// overallProgress weighs each phase equally in units, which is close enough
// for a progress bar and never goes backwards.
func overallProgress(phases []model.PhaseProgress) float64 {
	var total, done int64
	for _, p := range phases {
		total += p.Total
		done += p.Done + p.Failed
	}
	if total == 0 {
		return 0
	}
	return float64(done) / float64(total)
}

func (r *Runner) publishScan(ctx context.Context, scanID int64) {
	sc, err := r.st.Scan(ctx, scanID)
	if err != nil {
		return
	}
	r.bus.PublishData(model.EvtScanStatus, sc.MissionID, sc.ID, sc)
}

// logScan stores and broadcasts one line of the scan's live log.
func (r *Runner) logScan(ctx context.Context, sc model.Scan, level, msg string) {
	if err := r.st.AppendScanLog(ctx, sc.ID, level, msg); err != nil {
		r.log.Warn("cannot store scan log", "scan", sc.ID, "error", err)
	}
	r.bus.PublishData(model.EvtScanLog, sc.MissionID, sc.ID, model.LogLine{Level: level, Message: msg})
}
