// Package discovery implements host discovery: ARP/NDP sweeps on directly connected
// segments, ICMP echo/timestamp, TCP SYN and ACK pings and UDP probes with real protocol
// payloads (raw sockets, Linux), with an unprivileged fallback (TCP connect ping, ICMP
// over "udp" ping sockets, UDP sockets) used without privileges and on non-Linux systems.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/rawnet"
)

// Method names accepted in engine.DiscoveryOptions.Methods.
const (
	MethodARP           = "arp"
	MethodICMPEcho      = "icmp-echo"
	MethodICMPTimestamp = "icmp-timestamp"
	MethodTCPSyn        = "tcp-syn"
	MethodTCPAck        = "tcp-ack"
	MethodUDP           = "udp"
)

// Additional method labels reported in DiscoveredHost.Methods.
const (
	labelNDP        = "ndp"         // IPv6 neighbour discovery (on-link)
	labelTCPConnect = "tcp-connect" // unprivileged fallback, "tcp-connect:port"
)

// Defaults (engine.DiscoveryOptions documents the port lists).
var (
	DefaultTCPPorts = []uint16{21, 22, 23, 25, 53, 80, 88, 135, 139, 389, 443, 445, 3389, 5985, 8080, 8443}
	DefaultUDPPorts = []uint16{53, 123, 137, 161, 500}
	DefaultACKPorts = []uint16{80, 443}
	DefaultMethods  = []string{MethodARP, MethodICMPEcho, MethodICMPTimestamp, MethodTCPSyn, MethodTCPAck, MethodUDP}
)

const (
	DefaultRate    = 5000
	DefaultRetries = 1
	DefaultTimeout = 2 * time.Second
	// coalesceWindow is how long answers for a host are merged after the first one before
	// the host is emitted.
	coalesceWindow = 500 * time.Millisecond
)

// Discoverer implements engine.Discoverer.
type Discoverer struct {
	log *slog.Logger
}

// New returns the host discovery engine.
func New(log *slog.Logger) engine.Discoverer {
	if log == nil {
		log = slog.Default()
	}
	return &Discoverer{log: log.With("engine", "discovery")}
}

var _ engine.Discoverer = (*Discoverer)(nil)

// config is the normalised option set.
type config struct {
	space    *rawnet.AddrSpace
	methods  map[string]bool
	tcpPorts []uint16
	ackPorts []uint16
	udpPorts []uint16
	rate     int
	retries  int
	wait     time.Duration
	iface    string
	progress engine.Progress
}

func (c *config) has(m string) bool { return c.methods[m] }

func normalize(opts engine.DiscoveryOptions) (*config, error) {
	space, err := rawnet.NewAddrSpace(opts.Targets, opts.Excludes)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	c := &config{space: space, iface: opts.Interface, progress: opts.Progress, methods: map[string]bool{}}
	methods := opts.Methods
	if len(methods) == 0 {
		methods = DefaultMethods
	}
	for _, m := range methods {
		m = strings.ToLower(strings.TrimSpace(m))
		switch m {
		case MethodARP, MethodICMPEcho, MethodICMPTimestamp, MethodTCPSyn, MethodTCPAck, MethodUDP:
			c.methods[m] = true
		case "icmp":
			c.methods[MethodICMPEcho] = true
		case "tcp", "tcp-connect":
			c.methods[MethodTCPSyn] = true
		case "ndp":
			c.methods[MethodARP] = true
		case "":
		default:
			return nil, fmt.Errorf("discovery: unknown method %q", m)
		}
	}
	c.tcpPorts = cleanPorts(opts.TCPPorts, DefaultTCPPorts)
	c.ackPorts = cleanPorts(opts.TCPPorts, DefaultACKPorts)
	c.udpPorts = cleanPorts(opts.UDPPorts, DefaultUDPPorts)
	c.rate = opts.Rate
	if c.rate <= 0 {
		c.rate = DefaultRate
	}
	switch {
	case opts.Retries < 0:
		c.retries = 0
	case opts.Retries == 0:
		c.retries = DefaultRetries
	default:
		c.retries = min(opts.Retries, 10)
	}
	c.wait = opts.Timeout
	if c.wait <= 0 {
		c.wait = DefaultTimeout
	}
	return c, nil
}

func cleanPorts(in, def []uint16) []uint16 {
	if len(in) == 0 {
		return slices.Clone(def)
	}
	out := make([]uint16, 0, len(in))
	for _, p := range in {
		if p != 0 && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// Discover finds live hosts among opts.Targets (minus opts.Excludes).
//
// Each host is emitted once: the first answer opens a short merge window (500ms) during
// which further answering methods, the MAC (ARP/NDP) and TTL are accumulated; later
// answers for an already emitted host are only logged. Methods is therefore best effort
// (complete for answers arriving close together, which is the common case since all
// probes for a host are sent back-to-back).
//
// With raw socket privileges on Linux the raw engine is used (ARP/NDP for on-link
// targets, ICMP echo/timestamp, TCP SYN/ACK, UDP payloads). Otherwise the unprivileged
// engine runs: ICMP echo over ping sockets when the system allows it, TCP connect ping on
// TCPPorts (an accepted or refused connection proves the host is up) and UDP probes.
//
// Retries: 0 = default (1), < 0 = none. Timeout is the late-reply wait after the last
// probe. Rate is in packets (or connection attempts) per second.
func (d *Discoverer) Discover(ctx context.Context, opts engine.DiscoveryOptions, out func(engine.DiscoveredHost)) error {
	if out == nil {
		return errors.New("discovery: nil output callback")
	}
	cfg, err := normalize(opts)
	if err != nil {
		return err
	}
	total := cfg.space.Len()
	if total == 0 || len(cfg.methods) == 0 {
		if cfg.progress != nil {
			cfg.progress(0, 0)
		}
		return nil
	}
	log := d.log.With("targets", total)
	col := newCollector(out, d.macLookup())
	start := time.Now()
	raw := rawnet.CanRaw() && rawSupported
	log.Info("host discovery started", "raw", raw, "methods", keys(cfg.methods), "rate", cfg.rate)

	if raw {
		err = d.discoverRaw(ctx, cfg, col, log)
		if err != nil && ctx.Err() == nil && (errors.Is(err, engine.ErrNeedPrivileges) || errors.Is(err, engine.ErrUnsupported)) {
			log.Warn("raw discovery unavailable, falling back to unprivileged probes", "err", err)
			raw = false
		}
	}
	if !raw {
		err = d.discoverUnprivileged(ctx, cfg, col, log)
	}
	col.close()
	if cfg.progress != nil && ctx.Err() == nil {
		cfg.progress(int64(total), int64(total))
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	log.Info("host discovery finished", "up", col.count(), "duration", time.Since(start).Round(time.Millisecond))
	return err
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// collector merges answers per IP and emits each host once.
type collector struct {
	out    func(engine.DiscoveredHost)
	macFn  func(netip.Addr) net.HardwareAddr
	window time.Duration

	mu     sync.Mutex
	hosts  map[netip.Addr]*hostState
	closed bool
	wg     sync.WaitGroup
	n      int
}

type hostState struct {
	h       engine.DiscoveredHost
	emitted bool
	timer   *time.Timer
}

func newCollector(out func(engine.DiscoveredHost), macFn func(netip.Addr) net.HardwareAddr) *collector {
	return &collector{out: out, macFn: macFn, window: coalesceWindow, hosts: map[netip.Addr]*hostState{}}
}

// up reports whether ip already answered.
func (c *collector) up(ip netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.hosts[ip.Unmap()]
	return ok
}

// add records an answer. mac, ttl and rtt are optional (zero values).
func (c *collector) add(ip netip.Addr, method string, mac net.HardwareAddr, ttl uint8, rtt time.Duration) {
	ip = ip.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	st, ok := c.hosts[ip]
	if !ok {
		st = &hostState{h: engine.DiscoveredHost{IP: ip}}
		c.hosts[ip] = st
		st.timer = time.AfterFunc(c.window, func() { c.fire(ip) })
	}
	if st.emitted {
		return
	}
	if method != "" && !slices.Contains(st.h.Methods, method) {
		st.h.Methods = append(st.h.Methods, method)
	}
	if len(mac) == 6 && st.h.MAC == nil {
		st.h.MAC = append(net.HardwareAddr(nil), mac...)
	}
	if ttl != 0 && st.h.TTL == 0 {
		st.h.TTL = ttl
	}
	if rtt > 0 && (st.h.RTT == 0 || rtt < st.h.RTT) {
		st.h.RTT = rtt
	}
}

func (c *collector) fire(ip netip.Addr) {
	c.mu.Lock()
	st := c.hosts[ip]
	if st == nil || st.emitted || c.closed {
		c.mu.Unlock()
		return
	}
	st.emitted = true
	h := c.finalize(st)
	c.wg.Add(1)
	c.mu.Unlock()
	defer c.wg.Done()
	c.out(h)
}

// finalize copies the host for emission (caller holds mu).
func (c *collector) finalize(st *hostState) engine.DiscoveredHost {
	c.n++
	h := st.h
	h.Methods = slices.Clone(h.Methods)
	if h.MAC == nil && c.macFn != nil {
		h.MAC = c.macFn(h.IP)
	}
	return h
}

// close emits every pending host and waits for in-flight callbacks; no callback runs
// after close returns.
func (c *collector) close() {
	c.mu.Lock()
	c.closed = true
	var pending []engine.DiscoveredHost
	for _, st := range c.hosts {
		if st.timer != nil {
			st.timer.Stop()
		}
		if !st.emitted {
			st.emitted = true
			pending = append(pending, c.finalize(st))
		}
	}
	c.mu.Unlock()
	for _, h := range pending {
		c.out(h)
	}
	c.wg.Wait()
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hosts)
}

// progressCounter reports host-visit progress at most every 250ms.
type progressCounter struct {
	fn    engine.Progress
	total int64
	mu    sync.Mutex
	done  int64
	last  time.Time
}

func newProgressCounter(fn engine.Progress, total int64) *progressCounter {
	p := &progressCounter{fn: fn, total: total}
	if fn != nil {
		fn(0, total)
	}
	return p
}

func (p *progressCounter) add(n int64) {
	if p == nil || p.fn == nil {
		return
	}
	p.mu.Lock()
	p.done += n
	d := min(p.done, p.total)
	now := time.Now()
	report := now.Sub(p.last) >= 250*time.Millisecond
	if report {
		p.last = now
	}
	p.mu.Unlock()
	if report {
		p.fn(d, p.total)
	}
}
