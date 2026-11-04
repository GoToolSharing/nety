// Package portscan implements the port scanning engine: a stateless,
// masscan-style raw SYN scanner (Linux), a portable TCP connect() scanner and
// a UDP scanner sending protocol-specific payloads. Only open ports are
// reported.
package portscan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/rawnet"
)

// Defaults applied when the corresponding option is zero.
const (
	DefaultSYNRate        = 5000 // packets per second
	DefaultConnectRate    = 2000 // connection attempts per second
	DefaultUDPRate        = 1000 // datagrams per second
	DefaultSYNWait        = 2 * time.Second
	DefaultConnectTimeout = 1500 * time.Millisecond
	DefaultUDPWait        = 2 * time.Second
	DefaultSYNRetries     = 1
	DefaultConnectRetries = 0
	DefaultUDPRetries     = 1
	// MaxConnectWorkers bounds concurrent connect() attempts (file
	// descriptors).
	MaxConnectWorkers = 512
)

// Scanner implements engine.PortScanner.
type Scanner struct {
	log *slog.Logger
}

// New returns the port scanning engine.
func New(log *slog.Logger) engine.PortScanner {
	if log == nil {
		log = slog.Default()
	}
	return &Scanner{log: log.With("engine", "portscan")}
}

var _ engine.PortScanner = (*Scanner)(nil)

// Scan scans opts.Hosts on opts.TCPPorts and opts.UDPPorts and reports open
// ports through out (possibly concurrently).
//
// Options semantics:
//   - Mode: auto (SYN when raw sockets are available, else connect), syn,
//     connect. Forcing syn without privileges returns
//     engine.ErrNeedPrivileges (engine.ErrUnsupported off Linux).
//   - Rate: packets (SYN, UDP) or connection attempts (connect) per second.
//   - Retries: 0 = per-mode default (SYN 1, connect 0, UDP 1); < 0 = none.
//   - Timeout: SYN/UDP = how long to wait for late replies after the last
//     probe; connect = per-attempt dial timeout.
//   - SourcePort: fixed source port (segmentation bypass); 0 = random.
//
// UDP is scanned with ordinary (unprivileged) UDP sockets in every mode: only
// responses are reported, which the kernel delivers just as well as a raw
// socket would, and no privileges are needed.
func (s *Scanner) Scan(ctx context.Context, opts engine.PortScanOptions, out func(engine.PortResult)) error {
	if out == nil {
		return errors.New("portscan: nil output callback")
	}
	hosts := uniqueHosts(opts.Hosts)
	if len(hosts) == 0 || (len(opts.TCPPorts) == 0 && len(opts.UDPPorts) == 0) {
		if opts.Progress != nil {
			opts.Progress(0, 0)
		}
		return nil
	}
	tcpPorts := uniquePorts(opts.TCPPorts)
	udpPorts := uniquePorts(opts.UDPPorts)

	mode := opts.Mode
	if mode == "" {
		mode = engine.ModeAuto
	}
	if len(tcpPorts) > 0 {
		switch mode {
		case engine.ModeAuto:
			if rawnet.CanRaw() && synSupported {
				mode = engine.ModeSYN
			} else {
				mode = engine.ModeConnect
			}
		case engine.ModeSYN:
			if !synSupported {
				return fmt.Errorf("portscan: syn mode: %w", engine.ErrUnsupported)
			}
			if !rawnet.CanRaw() {
				return fmt.Errorf("portscan: syn mode: %w", engine.ErrNeedPrivileges)
			}
		case engine.ModeConnect:
		default:
			return fmt.Errorf("portscan: unknown mode %q", opts.Mode)
		}
	}

	tcpRetries := retries(opts.Retries, DefaultSYNRetries)
	if mode == engine.ModeConnect {
		tcpRetries = retries(opts.Retries, DefaultConnectRetries)
	}
	udpRetries := retries(opts.Retries, DefaultUDPRetries)

	tcpUnits := int64(len(hosts)) * int64(len(tcpPorts)) * int64(tcpRetries+1)
	udpUnits := int64(0)
	for _, p := range udpPorts {
		udpUnits += int64(len(UDPPayloads(p)))
	}
	udpUnits *= int64(len(hosts)) * int64(udpRetries+1)
	prog := newProgress(opts.Progress, tcpUnits+udpUnits)
	defer prog.stop()

	log := s.log.With("hosts", len(hosts), "tcp_ports", len(tcpPorts), "udp_ports", len(udpPorts), "mode", string(mode))
	log.Info("port scan started")
	start := time.Now()

	emit := safeEmit(out)
	var firstErr error
	if len(tcpPorts) > 0 {
		job := &job{
			hosts: hosts, ports: tcpPorts, opts: opts, retries: tcpRetries,
			prog: prog, emit: emit, log: log,
		}
		var err error
		if mode == engine.ModeSYN {
			err = s.synScan(ctx, job)
		} else {
			err = s.connectScan(ctx, job)
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			firstErr = err
			log.Error("tcp scan failed", "err", err)
		}
		prog.skipTo(tcpUnits)
	}
	if len(udpPorts) > 0 && ctx.Err() == nil {
		job := &job{
			hosts: hosts, ports: udpPorts, opts: opts, retries: udpRetries,
			prog: prog, emit: emit, log: log,
		}
		if err := s.udpScan(ctx, job); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if firstErr == nil {
				firstErr = err
			}
			log.Error("udp scan failed", "err", err)
		}
	}
	prog.finish()
	if err := ctx.Err(); err != nil {
		return err
	}
	log.Info("port scan finished", "duration", time.Since(start).Round(time.Millisecond), "open", emit.count())
	return firstErr
}

// job is one protocol pass over hosts x ports.
type job struct {
	hosts   []netip.Addr
	ports   []uint16
	opts    engine.PortScanOptions
	retries int
	prog    *progress
	emit    *emitter
	log     *slog.Logger
}

func (j *job) size() uint64 { return uint64(len(j.hosts)) * uint64(len(j.ports)) }

// split maps a linear index to (host, port) indices.
func (j *job) split(idx uint64) (int, int) {
	p := uint64(len(j.ports))
	return int(idx / p), int(idx % p)
}

func retries(v, def int) int {
	switch {
	case v < 0:
		return 0
	case v == 0:
		return def
	case v > 10:
		return 10
	}
	return v
}

func uniqueHosts(in []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(in))
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		if !a.IsValid() {
			continue
		}
		a = a.Unmap()
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

func uniquePorts(in []uint16) []uint16 {
	var seen [65536]bool
	out := make([]uint16, 0, len(in))
	for _, p := range in {
		if p == 0 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// hostIndex maps addresses back to their index in a job.
type hostIndex map[netip.Addr]int32

func newHostIndex(hosts []netip.Addr) hostIndex {
	m := make(hostIndex, len(hosts))
	for i, h := range hosts {
		m[h] = int32(i)
	}
	return m
}

func (m hostIndex) get(a netip.Addr) (int, bool) {
	i, ok := m[a.Unmap()]
	return int(i), ok
}

// portIndex maps a port number to its index (-1 = not scanned).
type portIndex [65536]int32

func newPortIndex(ports []uint16) *portIndex {
	var pi portIndex
	for i := range pi {
		pi[i] = -1
	}
	for i, p := range ports {
		pi[p] = int32(i)
	}
	return &pi
}

// doneSet records which (host, port) indices already got a definitive
// answer, to skip them on retry rounds and report each open port once. It
// is a lock-free bitset for spaces up to 2^28 entries (32 MiB) and a map
// beyond (answers are sparse in huge spaces).
type doneSet interface {
	// testAndSet marks idx and reports whether it was already marked.
	testAndSet(idx uint64) bool
	has(idx uint64) bool
}

const bitsetMax = 1 << 28

func newDoneSet(n uint64) doneSet {
	if n <= bitsetMax {
		return &bitDone{w: make([]atomic.Uint64, (n+63)/64)}
	}
	return &mapDone{m: map[uint64]struct{}{}}
}

type bitDone struct{ w []atomic.Uint64 }

func (b *bitDone) testAndSet(idx uint64) bool {
	mask := uint64(1) << (idx % 64)
	old := b.w[idx/64].Or(mask)
	return old&mask != 0
}

func (b *bitDone) has(idx uint64) bool { return b.w[idx/64].Load()&(uint64(1)<<(idx%64)) != 0 }

type mapDone struct {
	mu sync.Mutex
	m  map[uint64]struct{}
}

func (d *mapDone) testAndSet(idx uint64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.m[idx]; ok {
		return true
	}
	d.m[idx] = struct{}{}
	return false
}

func (d *mapDone) has(idx uint64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.m[idx]
	return ok
}

// emitter serialises nothing (the callback may be called concurrently per
// the engine contract) but shields the scan from a panicking callback and
// counts results.
type emitter struct {
	out func(engine.PortResult)
	n   atomic.Int64
}

func safeEmit(out func(engine.PortResult)) *emitter { return &emitter{out: out} }

func (e *emitter) emit(r engine.PortResult) {
	e.n.Add(1)
	e.out(r)
}

func (e *emitter) count() int64 { return e.n.Load() }

// progress aggregates work units and reports them at most every 250ms.
type progress struct {
	fn    engine.Progress
	total int64
	done  atomic.Int64
	quit  chan struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

func newProgress(fn engine.Progress, total int64) *progress {
	p := &progress{fn: fn, total: total, quit: make(chan struct{})}
	if fn == nil {
		return p
	}
	fn(0, total)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		last := int64(-1)
		for {
			select {
			case <-p.quit:
				return
			case <-t.C:
				if d := p.done.Load(); d != last {
					last = d
					fn(min(d, total), total)
				}
			}
		}
	}()
	return p
}

func (p *progress) add(n int64) { p.done.Add(n) }

// skipTo raises the done counter to at least v (units skipped because their
// host was unreachable or the phase ended early).
func (p *progress) skipTo(v int64) {
	for {
		cur := p.done.Load()
		if cur >= v || p.done.CompareAndSwap(cur, v) {
			return
		}
	}
}

func (p *progress) stop() {
	p.once.Do(func() { close(p.quit) })
	p.wg.Wait()
}

func (p *progress) finish() {
	p.stop()
	if p.fn != nil {
		p.fn(p.total, p.total)
	}
}
