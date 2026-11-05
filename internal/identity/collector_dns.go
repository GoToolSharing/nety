package identity

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/GoToolSharing/nety/internal/model"
)

// reverseName returns the in-addr.arpa / ip6.arpa name of addr.
func reverseName(addr netip.Addr) string {
	r, err := dns.ReverseAddr(addr.String())
	if err != nil {
		return ""
	}
	return r
}

// ptrNames extracts PTR targets from a DNS message (answers + additionals).
func ptrNames(m *dns.Msg) []string {
	if m == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, rrs := range [][]dns.RR{m.Answer, m.Extra} {
		for _, rr := range rrs {
			p, ok := rr.(*dns.PTR)
			if !ok {
				continue
			}
			n := strings.ToLower(strings.TrimRight(p.Ptr, "."))
			if n == "" || seen[n] || !validHostname(n) {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// validHostname accepts reasonable DNS names only (hostile responders).
func validHostname(n string) bool {
	if len(n) == 0 || len(n) > 253 {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// genericPTR reports whether a PTR name merely embeds the IP address (e.g.
// "10-0-0-5.dhcp.corp", "host-10.0.0.5.isp.net").
func genericPTR(name string, addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	n := strings.ToLower(name)
	octs := []string{strconv.Itoa(int(b[0])), strconv.Itoa(int(b[1])), strconv.Itoa(int(b[2])), strconv.Itoa(int(b[3]))}
	for _, sep := range []string{"-", ".", "_", ""} {
		fwd := strings.Join(octs, sep)
		rev := octs[3] + sep + octs[2] + sep + octs[1] + sep + octs[0]
		if len(fwd) >= 7 && (strings.Contains(n, fwd) || strings.Contains(n, rev)) {
			return true
		}
	}
	return false
}

func shortLabel(n string) string {
	if i := strings.IndexByte(n, '.'); i > 0 {
		return n[:i]
	}
	return n
}

// probeMDNS sends a unicast ("legacy") mDNS reverse PTR query to the host.
func (c *collector) probeMDNS(ctx context.Context, sink *evidenceSink, addr netip.Addr, port int) error {
	rn := reverseName(addr)
	if rn == "" {
		return errors.New("mdns: no reverse name")
	}
	m := new(dns.Msg)
	m.SetQuestion(rn, dns.TypePTR)
	m.RecursionDesired = false
	resp, err := c.dnsExchange(ctx, m, net.JoinHostPort(addr.String(), strconv.Itoa(port)), "udp")
	if err != nil {
		return err
	}
	names := ptrNames(resp)
	if len(names) == 0 {
		return errors.New("mdns: no PTR answer")
	}
	src := "mdns/" + strconv.Itoa(port)
	for _, n := range names {
		sink.add(model.EvMDNSName, n, src, 75, nil)
		sink.add(model.EvHostname, shortLabel(n), src, 65, nil)
	}
	return nil
}

// probeLLMNR sends a unicast LLMNR reverse PTR query to the host.
func (c *collector) probeLLMNR(ctx context.Context, sink *evidenceSink, addr netip.Addr, port int) error {
	rn := reverseName(addr)
	if rn == "" {
		return errors.New("llmnr: no reverse name")
	}
	m := new(dns.Msg)
	m.SetQuestion(rn, dns.TypePTR)
	m.RecursionDesired = false
	resp, err := c.dnsExchange(ctx, m, net.JoinHostPort(addr.String(), strconv.Itoa(port)), "udp")
	if err != nil {
		return err
	}
	names := ptrNames(resp)
	if len(names) == 0 {
		return errors.New("llmnr: no PTR answer")
	}
	for _, n := range names {
		if strings.Contains(n, ".") {
			sink.add(model.EvFQDN, n, "llmnr", 60, nil)
		}
		sink.add(model.EvHostname, shortLabel(n), "llmnr", 65, nil)
	}
	return nil
}

func (c *collector) dnsExchange(ctx context.Context, m *dns.Msg, server, network string) (*dns.Msg, error) {
	cl := &dns.Client{Net: network, Timeout: c.ioTimeout, UDPSize: 4096}
	resp, _, err := cl.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, err
	}
	if resp.Id != m.Id {
		return nil, errors.New("dns: id mismatch")
	}
	return resp, nil
}

// probeReverseDNS resolves the PTR of addr via the given DNS servers (or the system
// resolver when none).
func (c *collector) probeReverseDNS(ctx context.Context, sink *evidenceSink, addr netip.Addr, servers []netip.Addr) error {
	var names []string
	var lastErr error = errors.New("rdns: no answer")
	valid := 0
	for _, s := range servers {
		if !s.IsValid() {
			continue
		}
		valid++
		if valid > 2 {
			break
		}
		rn := reverseName(addr)
		if rn == "" {
			return errors.New("rdns: no reverse name")
		}
		m := new(dns.Msg)
		m.SetQuestion(rn, dns.TypePTR)
		m.RecursionDesired = true
		server := net.JoinHostPort(s.Unmap().String(), "53")
		resp, err := c.dnsExchange(ctx, m, server, "udp")
		if err == nil && resp.Truncated {
			resp, err = c.dnsExchange(ctx, m, server, "tcp")
		}
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = errors.New("rdns: " + dns.RcodeToString[resp.Rcode])
			if resp.Rcode == dns.RcodeNameError {
				break
			}
			continue
		}
		names = ptrNames(resp)
		break
	}
	if valid == 0 {
		rctx, cancel := withTimeout(ctx, c.ioTimeout)
		defer cancel()
		res, err := net.DefaultResolver.LookupAddr(rctx, addr.String())
		if err != nil {
			return err
		}
		for _, n := range res {
			n = strings.ToLower(strings.TrimRight(n, "."))
			if validHostname(n) {
				names = append(names, n)
			}
		}
	}
	if len(names) == 0 {
		return lastErr
	}
	if len(names) > 8 {
		names = names[:8]
	}
	for _, n := range names {
		generic := genericPTR(n, addr)
		attrs := map[string]string{"source": "rdns"}
		if generic {
			attrs["generic"] = "true"
			sink.add(model.EvReverseDNS, n, "rdns", 15, attrs)
			continue
		}
		sink.add(model.EvReverseDNS, n, "rdns", 50, attrs)
		if strings.Contains(n, ".") {
			sink.add(model.EvFQDN, n, "rdns", 40, attrs)
		}
	}
	return nil
}
