package checks

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("dns-zone-transfer", "DNS zone transfer (AXFR) allowed to an unauthorised client", model.SevHigh,
			[]string{"domain", "dns"},
			"The DNS server hands a complete zone to any client that asks for it. A zone transfer is the fastest inventory an attacker can get on an internal network: every host name, every service record, the domain controllers (_ldap._tcp, _kerberos._tcp), the naming of test and backup systems, and often internal addressing that was never meant to be reachable. It turns a blind foothold into a full target list in one request."),
		Remediation: "Restrict transfers to the secondary servers that need them: 'allow-transfer { <secondaries>; };' on BIND, 'notify/provide-xfr' on NSD/Knot, or on Windows DNS set the zone's transfer policy to 'Only to servers listed on the Name Servers tab'. Where possible authenticate the transfer with a TSIG key.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/200.html",
			"https://attack.mitre.org/techniques/T1590/002/",
		},
		Applies: dnsApplies,
		Run:     runDNSZoneTransfer,
	})
}

func dnsApplies(t *Target) bool {
	// AXFR is a TCP transfer, so only the TCP side of a resolver is relevant.
	return svcIs(t.Service, model.TCP, []string{"domain", "dns", "dns-tcp"}, 53)
}

// dnsMaxZoneRecords bounds how much of a zone is read. The finding only needs the zone
// name and a count, so there is no reason to pull a large zone into memory; the transfer
// is abandoned once the cap is reached.
const dnsMaxZoneRecords = 20000

// dnsZoneCandidates returns the zones worth asking for, most specific first. Nothing here
// is guessed: every candidate comes from what the scan already learned about the host,
// plus the reverse zone of its own subnet, which an internal resolver is nearly always
// authoritative for.
func dnsZoneCandidates(t *Target) []string {
	var out []string
	seen := map[string]bool{}
	add := func(z string) {
		z = strings.ToLower(strings.Trim(strings.TrimSpace(z), "."))
		if z == "" || strings.Count(z, ".") > 8 || !dnsPlausibleZone(z) || seen[z] {
			return
		}
		seen[z] = true
		out = append(out, dns.Fqdn(z))
	}
	add(t.Host.Domain)
	for _, h := range append([]string{t.Host.Hostname}, t.Host.Hostnames...) {
		if i := strings.Index(strings.Trim(h, "."), "."); i > 0 {
			add(h[i+1:])
		}
	}
	// The /24 reverse zone of the server itself. On an internal network the resolver that
	// answers on this address is almost always the one holding the matching in-addr.arpa
	// zone.
	if a, err := netip.ParseAddr(t.IP); err == nil && a.Unmap().Is4() {
		b := a.Unmap().As4()
		add(fmt.Sprintf("%d.%d.%d.in-addr.arpa", b[2], b[1], b[0]))
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

// dnsPlausibleZone rejects anything that is not a usable domain name, since the
// candidates come from fingerprint data that a host controls.
func dnsPlausibleZone(z string) bool {
	if len(z) == 0 || len(z) > 253 || !strings.Contains(z, ".") {
		return false
	}
	for _, l := range strings.Split(z, ".") {
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

func runDNSZoneTransfer(ctx context.Context, t *Target) []model.Finding {
	var out []model.Finding
	for _, zone := range dnsZoneCandidates(t) {
		if ctx.Err() != nil {
			break
		}
		res, err := dnsTryAXFR(ctx, t, zone)
		if err != nil {
			t.Log.Debug("axfr refused", "zone", zone, "err", err)
			continue
		}
		out = append(out, t.Finding(res))
		// One proven transfer is enough evidence; asking for every remaining candidate
		// only adds load and noise in the server's logs.
		break
	}
	return out
}

// dnsTryAXFR requests one zone and summarises what came back. It reads the zone only to
// count it: no record data beyond the SOA is kept, so a client report never carries
// someone else's internal inventory.
func dnsTryAXFR(ctx context.Context, t *Target, zone string) (string, error) {
	m := new(dns.Msg)
	m.SetAxfr(zone)
	tr := &dns.Transfer{
		DialTimeout:  t.Timeout,
		ReadTimeout:  t.Timeout,
		WriteTimeout: t.Timeout,
	}
	ch, err := tr.In(m, t.Addr())
	if err != nil {
		return "", err
	}
	var (
		total   int
		byType  = map[string]int{}
		soa     string
		xferErr error
		capped  bool
	)
	for env := range ch {
		if env.Error != nil {
			xferErr = env.Error
			// Keep draining: abandoning the channel would leak the reader goroutine
			// inside the dns package.
			continue
		}
		for _, rr := range env.RR {
			total++
			if total > dnsMaxZoneRecords {
				capped = true
				continue
			}
			byType[dns.TypeToString[rr.Header().Rrtype]]++
			if s, ok := rr.(*dns.SOA); ok && soa == "" {
				soa = fmt.Sprintf("%s (primary %s, serial %d)", partASanitize(strings.TrimSuffix(s.Hdr.Name, ".")), partASanitize(strings.TrimSuffix(s.Ns, ".")), s.Serial)
			}
		}
	}
	// A refused transfer either errors or sends nothing but a bare SOA.
	if total < 2 {
		if xferErr != nil {
			return "", xferErr
		}
		return "", fmt.Errorf("dns: zone %s not transferred (%d records)", zone, total)
	}
	types := make([]string, 0, len(byType))
	for k, v := range byType {
		types = append(types, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(types)

	var ev strings.Builder
	fmt.Fprintf(&ev, "AXFR of zone %q accepted from this client (no TSIG, no address restriction).\n", strings.TrimSuffix(zone, "."))
	fmt.Fprintf(&ev, "Records transferred: %d", total)
	if capped {
		fmt.Fprintf(&ev, " (transfer abandoned after %d; the zone is larger)", dnsMaxZoneRecords)
	}
	fmt.Fprintf(&ev, "\nRecord types: %s\n", strings.Join(limitStrings(types, 15), ", "))
	if soa != "" {
		fmt.Fprintf(&ev, "SOA: %s\n", soa)
	}
	if xferErr != nil {
		fmt.Fprintf(&ev, "Transfer ended with: %v\n", xferErr)
	}
	ev.WriteString("The zone content itself was counted, not recorded.")
	return ev.String(), nil
}
