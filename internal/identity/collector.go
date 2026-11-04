// Package identity collects identity evidence about a host and correlates
// observations into long-lived assets.
//
// A pentester scans VLAN A on Monday and VLAN B on Tuesday; DHCP reshuffles
// addresses in between. Identity evidence is what survives an IP change:
// an SMB server GUID, an SNMP engine ID, an SSH host key, a NetBIOS name
// table. The collector gathers it from the services that were actually found
// open plus a handful of cheap UDP queries; the correlator (see correlator.go)
// turns observations into assets.
//
// Every probe here is strictly read-only: it negotiates, reads what the
// protocol volunteers before authentication, and hangs up. Nothing is written
// on the target and no credential is ever guessed.
package identity

import (
	"context"
	"log/slog"
	"net/netip"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
)

const (
	// DefaultIOTimeout bounds a single network read/write. Probes that need
	// several round trips get a multiple of it.
	DefaultIOTimeout = 4 * time.Second
	// CollectBudget caps the whole Collect call whatever the caller's ctx.
	CollectBudget = 60 * time.Second
	// MaxConcurrentProbes bounds probes running in parallel against one host.
	MaxConcurrentProbes = 6
)

// Well-known UDP ports queried unconditionally: one datagram each.
const (
	portNBNS  = 137
	portMDNS  = 5353
	portLLMNR = 5355
	portSNMP  = 161
)

type collector struct {
	log *slog.Logger
	// ioTimeout bounds one network operation.
	ioTimeout time.Duration
}

// NewCollector returns the identity evidence collector.
func NewCollector(log *slog.Logger) engine.IdentityCollector {
	if log == nil {
		log = slog.Default()
	}
	return &collector{
		log:       log.With("component", "identity"),
		ioTimeout: DefaultIOTimeout,
	}
}

// ---------------------------------------------------------------------------
// Evidence sink
// ---------------------------------------------------------------------------

// evidenceSink accumulates evidence from concurrently running probes.
type evidenceSink struct {
	mu    sync.Mutex
	items []model.IdentityEvidence
}

// add records one piece of evidence. Empty values and non-positive
// confidences are dropped, so probes can call it unconditionally.
func (s *evidenceSink) add(kind model.EvidenceKind, value, source string, conf int, attrs map[string]string) {
	value = strings.TrimSpace(value)
	if value == "" || conf <= 0 {
		return
	}
	if len(value) > 512 {
		value = value[:512]
	}
	e := model.IdentityEvidence{Kind: kind, Value: value, Source: source, Confidence: conf}
	if len(attrs) > 0 {
		clean := make(map[string]string, len(attrs))
		for k, v := range attrs {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if len(v) > 512 {
				v = v[:512]
			}
			clean[k] = v
		}
		if len(clean) > 0 {
			e.Attributes = clean
		}
	}
	s.mu.Lock()
	s.items = append(s.items, e)
	s.mu.Unlock()
}

// evidence returns the deduplicated, deterministically ordered evidence.
// Identical (kind, value, source) triples are merged, keeping the highest
// confidence and the union of the attributes.
func (s *evidenceSink) evidence() []model.IdentityEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) == 0 {
		return nil
	}
	type key struct {
		kind          model.EvidenceKind
		value, source string
	}
	idx := make(map[key]int, len(s.items))
	out := make([]model.IdentityEvidence, 0, len(s.items))
	for _, e := range s.items {
		k := key{e.Kind, strings.ToLower(e.Value), e.Source}
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, e)
			continue
		}
		if e.Confidence > out[i].Confidence {
			out[i].Confidence = e.Confidence
		}
		for ak, av := range e.Attributes {
			if out[i].Attributes == nil {
				out[i].Attributes = map[string]string{}
			}
			if _, exists := out[i].Attributes[ak]; !exists {
				out[i].Attributes[ak] = av
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// ---------------------------------------------------------------------------
// Collect
// ---------------------------------------------------------------------------

// namedProbe is one identity source scheduled by Collect.
type namedProbe struct {
	name string
	run  func(ctx context.Context, sink *evidenceSink) error
}

// Collect gathers identity evidence for host. Probes run concurrently with a
// bound; each has its own timeout and honours ctx. Errors from individual
// probes are logged and skipped: a host that refuses SMB still yields its
// SSH host key.
func (c *collector) Collect(ctx context.Context, host model.Host, services []model.Service, dns []netip.Addr) ([]model.IdentityEvidence, error) {
	addr, ok := hostAddr(host, services)
	if !ok {
		return nil, nil
	}
	ip := addr.String()
	log := c.log.With("ip", ip)

	ctx, cancel := context.WithTimeout(ctx, CollectBudget)
	defer cancel()

	open := openServices(services)
	sink := &evidenceSink{}

	// Evidence derivable from data the fingerprinter already collected costs
	// nothing: SSH host keys, TLS certificates, favicon hashes, MAC/OUI.
	c.fromServiceData(sink, host, open)

	probes := c.plan(addr, open, dns)

	sem := make(chan struct{}, MaxConcurrentProbes)
	var wg sync.WaitGroup
	for _, p := range probes {
		select {
		case <-ctx.Done():
			wg.Wait()
			return sink.evidence(), ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(p namedProbe) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					log.Error("identity probe panicked", "probe", p.name,
						"panic", r, "stack", string(debug.Stack()))
				}
			}()
			start := time.Now()
			if err := p.run(ctx, sink); err != nil {
				log.Debug("identity probe failed", "probe", p.name, "err", err,
					"elapsed", time.Since(start))
				return
			}
			log.Debug("identity probe done", "probe", p.name, "elapsed", time.Since(start))
		}(p)
	}
	wg.Wait()
	return sink.evidence(), nil
}

// plan decides which network probes to run, using only services found open
// plus the cheap UDP queries.
func (c *collector) plan(addr netip.Addr, open []model.Service, dns []netip.Addr) []namedProbe {
	ip := addr.String()
	var out []namedProbe
	add := func(name string, fn func(context.Context, *evidenceSink) error) {
		out = append(out, namedProbe{name: name, run: fn})
	}

	// SMB: direct TCP first, NetBIOS session service as a fallback.
	if port, ok := smbPort(open); ok {
		add("smb", func(ctx context.Context, s *evidenceSink) error {
			return c.probeSMB(ctx, s, ip, port)
		})
	}

	for _, svc := range open {
		if svc.Protocol != model.TCP {
			continue
		}
		svc := svc
		name := svcName(svc)
		switch {
		case svc.Port == 3389 || name == "ms-wbt-server" || name == "rdp":
			add("rdp", func(ctx context.Context, s *evidenceSink) error {
				return c.probeRDP(ctx, s, ip, svc.Port)
			})
		case svc.Port == 1433 || name == "ms-sql-s" || name == "mssql":
			add("mssql", func(ctx context.Context, s *evidenceSink) error {
				return c.probeMSSQL(ctx, s, ip, svc.Port)
			})
		}
		if p, ok := mailProtoOf(svc); ok {
			add(p.String(), func(ctx context.Context, s *evidenceSink) error {
				return c.probeMail(ctx, s, ip, svc, p)
			})
		}
		if plan := httpNTLMPlan(svc); len(plan) > 0 {
			add("http-ntlm", func(ctx context.Context, s *evidenceSink) error {
				return c.probeHTTPNTLM(ctx, s, ip, svc, plan)
			})
		}
	}

	// Cheap UDP queries, always attempted: one datagram each, and they are the
	// only identity source for hosts with every TCP port filtered.
	add("nbstat", func(ctx context.Context, s *evidenceSink) error {
		return c.probeNBSTAT(ctx, s, ip, portNBNS)
	})
	add("mdns", func(ctx context.Context, s *evidenceSink) error {
		return c.probeMDNS(ctx, s, addr, portMDNS)
	})
	add("llmnr", func(ctx context.Context, s *evidenceSink) error {
		return c.probeLLMNR(ctx, s, addr, portLLMNR)
	})
	add("snmp", func(ctx context.Context, s *evidenceSink) error {
		return c.probeSNMP(ctx, s, ip, portSNMP)
	})
	add("rdns", func(ctx context.Context, s *evidenceSink) error {
		return c.probeReverseDNS(ctx, s, addr, dns)
	})
	return out
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

// withTimeout bounds ctx by d, never extending an earlier deadline.
func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = DefaultIOTimeout
	}
	return context.WithTimeout(ctx, d)
}

// hostAddr resolves the address to probe.
func hostAddr(host model.Host, services []model.Service) (netip.Addr, bool) {
	raw := strings.TrimSpace(host.IP)
	if raw == "" {
		for _, s := range services {
			if strings.TrimSpace(s.IP) != "" {
				raw = strings.TrimSpace(s.IP)
				break
			}
		}
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// openServices keeps the services that are actually reachable.
func openServices(services []model.Service) []model.Service {
	out := make([]model.Service, 0, len(services))
	for _, s := range services {
		switch s.State {
		case "", model.PortOpen, model.PortOpenFiltered:
			out = append(out, s)
		}
	}
	return out
}

// svcName returns the lowercase service name.
func svcName(s model.Service) string {
	return strings.ToLower(strings.TrimSpace(s.Name))
}

// isTLSService reports whether the service speaks TLS from the first byte,
// either because the fingerprinter said so or because it sits on an implicit
// TLS port.
func isTLSService(s model.Service, implicitTLSPorts ...int) bool {
	if s.Tunnel == "ssl" || s.TLS != nil {
		return true
	}
	for _, p := range implicitTLSPorts {
		if s.Port == p {
			return true
		}
	}
	return strings.HasSuffix(svcName(s), "s") && svcName(s) != "wsman"
}

// smbPort picks the SMB transport to use: 445 when open, else 139.
func smbPort(open []model.Service) (int, bool) {
	has := func(p int) bool {
		for _, s := range open {
			if s.Protocol == model.TCP && s.Port == p {
				return true
			}
		}
		return false
	}
	switch {
	case has(445):
		return 445, true
	case has(139):
		return 139, true
	}
	return 0, false
}

// mailProtoOf classifies a service as SMTP/IMAP/POP3 when it is one.
func mailProtoOf(s model.Service) (mailProto, bool) {
	n := svcName(s)
	switch {
	case n == "smtp" || n == "smtps" || n == "submission" || s.Port == 25 || s.Port == 465 || s.Port == 587:
		return mailSMTP, true
	case n == "imap" || n == "imaps" || s.Port == 143 || s.Port == 993:
		return mailIMAP, true
	case n == "pop3" || n == "pop3s" || s.Port == 110 || s.Port == 995:
		return mailPOP3, true
	}
	return 0, false
}
