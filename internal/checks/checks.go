// Package checks implements NETY's light, safe and non-destructive
// misconfiguration / vulnerability checks. Every check is registered in a
// static catalog (see register) and run concurrently per host.
//
// Rules for checks:
//   - Never modify state on the target (read-only protocol operations only).
//   - Bound every I/O with Target.Timeout and honour ctx.
//   - Parse hostile input defensively: never panic (a recover guard exists as
//     a last resort but must not be relied upon).
//   - Intrusive checks (login attempts) only run when
//     CheckOptions.AllowDefaultCreds is true, and try very few credentials.
package checks

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

// DefaultTimeout is the per-I/O timeout when CheckOptions.Timeout is zero.
const DefaultTimeout = 5 * time.Second

// MaxConcurrentPerHost bounds checks running in parallel against one host.
const MaxConcurrentPerHost = 6

// Check is one registered check.
type Check struct {
	Info engine.CheckInfo
	// Description/Remediation/References used to fill findings.
	Remediation string
	References  []string
	// HostLevel checks run once per host (Applies receives every service and
	// Run gets Target.Service zero-valued); otherwise once per applicable
	// service.
	HostLevel bool
	// Applies reports whether the check is relevant for svc (service level)
	// or for the host's services (host level, svc is the zero value).
	Applies func(t *Target) bool
	// Run executes the check. It returns findings (use t.Finding to build them).
	Run func(ctx context.Context, t *Target) []model.Finding
	// Budget is the max wall time for one execution (0 = 8 x Timeout, min 15s).
	Budget time.Duration
}

// Target is the context handed to a check run.
type Target struct {
	Host     model.Host
	IP       string
	Service  model.Service   // zero for host level checks
	Services []model.Service // every open service of the host
	Opts     engine.CheckOptions
	Timeout  time.Duration // per I/O
	Log      *slog.Logger
	check    *Check
}

// Addr returns ip:port for the service.
func (t *Target) Addr() string { return net.JoinHostPort(t.IP, strconv.Itoa(t.Service.Port)) }

// AddrPort returns ip:port for an arbitrary port.
func (t *Target) AddrPort(port int) string { return net.JoinHostPort(t.IP, strconv.Itoa(port)) }

// HasPort reports whether the host has an open service on port/proto.
func (t *Target) HasPort(port int, proto model.Protocol) bool {
	return findService(t.Services, port, proto) != nil
}

// ServiceOn returns the open service on port/proto or nil.
func (t *Target) ServiceOn(port int, proto model.Protocol) *model.Service {
	return findService(t.Services, port, proto)
}

func findService(svcs []model.Service, port int, proto model.Protocol) *model.Service {
	for i := range svcs {
		s := &svcs[i]
		if s.Port == port && s.Protocol == proto && isOpen(s.State) {
			return s
		}
	}
	return nil
}

func isOpen(s model.PortState) bool {
	return s == "" || s == model.PortOpen || s == model.PortOpenFiltered
}

// Finding builds a finding for this check on the current service (or on
// port/proto for host level checks, pass 0/"" for host-wide findings).
func (t *Target) Finding(evidence string) model.Finding {
	f := model.Finding{
		IP:          t.IP,
		Port:        t.Service.Port,
		Protocol:    t.Service.Protocol,
		CheckID:     t.check.Info.ID,
		Title:       t.check.Info.Title,
		Severity:    t.check.Info.Severity,
		Description: t.check.Info.Description,
		Evidence:    truncate(evidence, 4000),
		Remediation: t.check.Remediation,
		References:  append([]string(nil), t.check.References...),
	}
	return f
}

// FindingOn builds a finding attached to a specific port/proto.
func (t *Target) FindingOn(port int, proto model.Protocol, evidence string) model.Finding {
	f := t.Finding(evidence)
	f.Port, f.Protocol = port, proto
	return f
}

// Dial opens a TCP connection to the service with the per-I/O timeout and
// an initial deadline.
func (t *Target) Dial(ctx context.Context) (net.Conn, error) { return t.DialPort(ctx, t.Service.Port) }

// DialPort opens a TCP connection to port. The connection is closed when ctx
// is cancelled.
func (t *Target) DialPort(ctx context.Context, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: t.Timeout}
	c, err := d.DialContext(ctx, "tcp", t.AddrPort(port))
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(t.Timeout))
	return &ctxConn{Conn: c, stop: context.AfterFunc(ctx, func() { _ = c.Close() })}, nil
}

type ctxConn struct {
	net.Conn
	stop func() bool
}

func (c *ctxConn) Close() error { c.stop(); return c.Conn.Close() }

// DialUDP opens a connected UDP socket to port.
func (t *Target) DialUDP(ctx context.Context, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: t.Timeout}
	c, err := d.DialContext(ctx, "udp", t.AddrPort(port))
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(t.Timeout))
	return &ctxConn{Conn: c, stop: context.AfterFunc(ctx, func() { _ = c.Close() })}, nil
}

var (
	regMu    sync.Mutex
	registry []*Check
)

// register adds a check to the catalog (called from init functions).
func register(c *Check) {
	regMu.Lock()
	defer regMu.Unlock()
	for _, x := range registry {
		if x.Info.ID == c.Info.ID {
			panic("checks: duplicate check id " + c.Info.ID)
		}
	}
	registry = append(registry, c)
	sort.Slice(registry, func(i, j int) bool { return registry[i].Info.ID < registry[j].Info.ID })
}

func allChecks() []*Check {
	regMu.Lock()
	defer regMu.Unlock()
	return append([]*Check(nil), registry...)
}

type checker struct {
	log *slog.Logger
}

// New returns the engine.Checker implementation.
func New(log *slog.Logger) engine.Checker {
	if log == nil {
		log = slog.Default()
	}
	return &checker{log: log.With("component", "checks")}
}

// Catalog lists every registered check sorted by ID.
func (c *checker) Catalog() []engine.CheckInfo {
	cs := allChecks()
	out := make([]engine.CheckInfo, 0, len(cs))
	for _, x := range cs {
		info := x.Info
		info.Services = append([]string(nil), info.Services...)
		out = append(out, info)
	}
	return out
}

type job struct {
	check *Check
	t     *Target
}

// Run executes every applicable check against host.
func (c *checker) Run(ctx context.Context, host model.Host, services []model.Service, opts engine.CheckOptions) ([]model.Finding, error) {
	ip := host.IP
	if a, err := netip.ParseAddr(ip); err == nil {
		ip = a.Unmap().String()
	} else if ip == "" && len(services) > 0 {
		ip = services[0].IP
	}
	if ip == "" {
		return nil, fmt.Errorf("checks: host without IP")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	var open []model.Service
	for _, s := range services {
		if isOpen(s.State) {
			open = append(open, s)
		}
	}
	log := c.log.With("ip", ip)
	var jobs []job
	for _, ch := range allChecks() {
		if ch.Info.Intrusive && !opts.AllowDefaultCreds {
			continue
		}
		base := Target{Host: host, IP: ip, Services: open, Opts: opts, Timeout: timeout, check: ch}
		if ch.HostLevel {
			t := base
			t.Log = log.With("check", ch.Info.ID)
			if ch.Applies == nil || safeApplies(ch, &t) {
				jobs = append(jobs, job{ch, &t})
			}
			continue
		}
		for _, s := range open {
			t := base
			t.Service = s
			t.Log = log.With("check", ch.Info.ID, "port", s.Port, "proto", s.Protocol)
			if ch.Applies != nil && safeApplies(ch, &t) {
				jobs = append(jobs, job{ch, &t})
			}
		}
	}
	var (
		mu       sync.Mutex
		findings []model.Finding
		wg       sync.WaitGroup
		sem      = make(chan struct{}, MaxConcurrentPerHost)
	)
	for _, j := range jobs {
		select {
		case <-ctx.Done():
			wg.Wait()
			return sortFindings(dedupe(findings)), ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			fs := runOne(ctx, j)
			if len(fs) > 0 {
				mu.Lock()
				findings = append(findings, fs...)
				mu.Unlock()
			}
		}(j)
	}
	wg.Wait()
	return sortFindings(dedupe(findings)), nil
}

func safeApplies(ch *Check, t *Target) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	return ch.Applies(t)
}

func runOne(ctx context.Context, j job) (out []model.Finding) {
	budget := j.check.Budget
	if budget <= 0 {
		budget = 8 * j.t.Timeout
		if budget < 15*time.Second {
			budget = 15 * time.Second
		}
	}
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			j.t.Log.Error("check panicked", "panic", r, "stack", string(debug.Stack()))
			out = nil
		}
	}()
	start := time.Now()
	out = j.check.Run(cctx, j.t)
	j.t.Log.Debug("check done", "findings", len(out), "elapsed", time.Since(start))
	now := time.Now().UTC()
	for i := range out {
		if out[i].IP == "" {
			out[i].IP = j.t.IP
		}
		if out[i].FirstSeen.IsZero() {
			out[i].FirstSeen = now
		}
		if out[i].LastSeen.IsZero() {
			out[i].LastSeen = now
		}
	}
	return out
}

func dedupe(fs []model.Finding) []model.Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		k := f.CheckID + "|" + strconv.Itoa(f.Port) + "|" + string(f.Protocol) + "|" + f.Title
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

func sortFindings(fs []model.Finding) []model.Finding {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Port != fs[j].Port {
			return fs[i].Port < fs[j].Port
		}
		if fs[i].Protocol != fs[j].Protocol {
			return fs[i].Protocol < fs[j].Protocol
		}
		return fs[i].CheckID < fs[j].CheckID
	})
	return fs
}

// ---------------------------------------------------------------------------
// Small helpers shared by checks
// ---------------------------------------------------------------------------

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// printable returns a printable, single-line, truncated version of b.
func printable(b []byte, n int) string {
	var sb strings.Builder
	for _, c := range b {
		if sb.Len() >= n {
			sb.WriteString("…")
			break
		}
		switch {
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	return sb.String()
}

// svcIs reports whether the service matches one of the names or ports.
func svcIs(s model.Service, proto model.Protocol, names []string, ports ...int) bool {
	if s.Protocol != proto {
		return false
	}
	n := strings.ToLower(s.Name)
	for _, x := range names {
		if n == x {
			return true
		}
	}
	for _, p := range ports {
		if s.Port == p && (n == "" || n == "unknown" || strings.HasSuffix(n, "?") || n == "tcpwrapped") {
			return true
		}
	}
	return false
}

// isTLS reports whether the service is wrapped in TLS.
func isTLS(s model.Service) bool {
	return s.Tunnel == "ssl" || s.TLS != nil
}
