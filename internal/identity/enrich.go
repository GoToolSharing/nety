package identity

import (
	"sort"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

// derived holds host-level facts computed from identity evidence and services. Empty
// fields mean "no information".
type derived struct {
	FQDN      string
	Hostname  string
	Hostnames []string
	Domain    string
	OS        string
	Vendor    string
}

// sortedEvidence returns the evidence of the given kind with a non-empty value, best
// first: highest confidence, then value, then source. The order is fully deterministic.
func sortedEvidence(ev []model.IdentityEvidence, kind model.EvidenceKind) []model.IdentityEvidence {
	var out []model.IdentityEvidence
	for _, e := range ev {
		if e.Kind == kind && strings.TrimSpace(e.Value) != "" {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func bestValue(ev []model.IdentityEvidence, kind model.EvidenceKind) string {
	s := sortedEvidence(ev, kind)
	if len(s) == 0 {
		return ""
	}
	return cleanName(s[0].Value)
}

// cleanName trims spaces and trailing dots from a DNS-ish name.
func cleanName(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), ".")
}

// shortName returns the first label of a DNS name.
func shortName(s string) string {
	s = cleanName(s)
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[:i]
	}
	return s
}

// domainOf returns everything after the first label of a DNS name.
func domainOf(fqdn string) string {
	fqdn = cleanName(fqdn)
	if i := strings.IndexByte(fqdn, '.'); i > 0 && i < len(fqdn)-1 {
		return fqdn[i+1:]
	}
	return ""
}

func isIPLiteral(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9') && r != '.' && r != ':' && !(r >= 'a' && r <= 'f') && !(r >= 'A' && r <= 'F') {
			return false
		}
	}
	return strings.Count(s, ".") == 3 || strings.Contains(s, ":")
}

// deriveFields computes host facts from evidence and services.
func deriveFields(services []model.Service, ev []model.IdentityEvidence) derived {
	var d derived

	// FQDN: explicit DNS computer name first, then reverse DNS / mDNS names that look
	// fully qualified (but never ".local" / ".in-addr.arpa").
	d.FQDN = strings.ToLower(bestValue(ev, model.EvFQDN))
	if d.FQDN != "" && !strings.Contains(d.FQDN, ".") {
		d.FQDN = ""
	}

	// Hostname.
	switch {
	case d.FQDN != "":
		d.Hostname = strings.ToLower(shortName(d.FQDN))
	default:
		for _, k := range []model.EvidenceKind{model.EvHostname, model.EvNetBIOSName, model.EvMDNSName, model.EvSNMPSysName, model.EvReverseDNS} {
			v := bestValue(ev, k)
			if v == "" || isIPLiteral(v) {
				continue
			}
			if k == model.EvMDNSName || k == model.EvReverseDNS || k == model.EvSNMPSysName {
				v = shortName(v)
			}
			if v != "" {
				d.Hostname = v
				break
			}
		}
	}

	// Hostnames: every distinct name seen.
	seen := map[string]bool{}
	add := func(v string) {
		v = cleanName(v)
		if v == "" || isIPLiteral(v) {
			return
		}
		k := strings.ToLower(v)
		if seen[k] {
			return
		}
		seen[k] = true
		d.Hostnames = append(d.Hostnames, v)
	}
	for _, k := range []model.EvidenceKind{model.EvFQDN, model.EvReverseDNS, model.EvMDNSName, model.EvHostname, model.EvNetBIOSName, model.EvSNMPSysName} {
		for _, e := range sortedEvidence(ev, k) {
			add(e.Value)
		}
	}
	sortNames(d.Hostnames)

	// Domain: DNS domain (contains a dot) > domain of the FQDN > NetBIOS domain.
	for _, e := range sortedEvidence(ev, model.EvDomain) {
		if v := strings.ToLower(cleanName(e.Value)); strings.Contains(v, ".") {
			d.Domain = v
			break
		}
	}
	if d.Domain == "" {
		d.Domain = strings.ToLower(domainOf(d.FQDN))
	}
	if d.Domain == "" {
		if v := bestValue(ev, model.EvDomain); v != "" {
			d.Domain = v
		}
	}
	if d.Domain == "" {
		d.Domain = bestValue(ev, model.EvNetBIOSDomain)
	}

	d.OS = deriveOS(services, ev)

	if v := sortedEvidence(ev, model.EvVendor); len(v) > 0 {
		d.Vendor = strings.TrimSpace(v[0].Value)
	}
	return d
}

func sortNames(s []string) {
	sort.SliceStable(s, func(i, j int) bool {
		a, b := strings.ToLower(s[i]), strings.ToLower(s[j])
		if a != b {
			return a < b
		}
		return s[i] < s[j]
	})
}

// deriveOS picks the best OS description available.
func deriveOS(services []model.Service, ev []model.IdentityEvidence) string {
	osv := sortedEvidence(ev, model.EvOSVersion)
	// 1. Mapped name provided by the collector (NTLM / SMB).
	for _, e := range osv {
		if n := strings.TrimSpace(e.Attributes["os_name"]); n != "" {
			return n
		}
	}
	// 2. SMB1 NativeOS string.
	for _, e := range osv {
		if e.Attributes["source"] == "smb1" || strings.HasPrefix(e.Source, "smb1") {
			return strings.TrimSpace(e.Value)
		}
	}
	// 3. SNMP sysDescr.
	for _, e := range append(sortedEvidence(ev, model.EvSNMPSysName), osv...) {
		if sd := strings.TrimSpace(e.Attributes["sysdescr"]); sd != "" {
			return shortSysDescr(sd)
		}
	}
	for _, e := range osv {
		if e.Attributes["source"] == "snmp" {
			return shortSysDescr(e.Value)
		}
	}
	// 4. Bare NTLM version number.
	for _, e := range osv {
		v := strings.TrimSpace(e.Value)
		if e.Attributes["source"] == "ntlm" || strings.Contains(e.Source, "ntlm") || looksLikeNTVersion(v) {
			if looksLikeNTVersion(v) {
				return "Windows (" + v + ")"
			}
			return v
		}
	}
	// 5. Most common service OSType.
	counts := map[string]int{}
	for _, s := range services {
		if t := strings.TrimSpace(s.OSType); t != "" {
			counts[t]++
		}
	}
	best, bestN := "", 0
	for t, n := range counts {
		if n > bestN || (n == bestN && t < best) {
			best, bestN = t, n
		}
	}
	if best != "" {
		return best
	}
	// 6. SSH banner distribution hint.
	var banners []string
	for _, s := range services {
		if s.SSH != nil && s.SSH.Banner != "" {
			banners = append(banners, s.SSH.Banner)
		} else if strings.HasPrefix(s.Banner, "SSH-") {
			banners = append(banners, s.Banner)
		}
	}
	sort.Strings(banners)
	for _, b := range banners {
		if os := sshDistro(b); os != "" {
			return os
		}
	}
	// 7. Any remaining os-version value.
	if len(osv) > 0 {
		return strings.TrimSpace(osv[0].Value)
	}
	return ""
}

func looksLikeNTVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 5 {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// shortSysDescr keeps the first meaningful line of an SNMP sysDescr.
func shortSysDescr(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 100 {
		s = strings.TrimSpace(s[:100])
	}
	return s
}

var sshDistros = []struct{ needle, os string }{
	{"ubuntu", "Linux (Ubuntu)"},
	{"raspbian", "Linux (Raspbian)"},
	{"debian", "Linux (Debian)"},
	{"deb", "Linux (Debian)"},
	{"freebsd", "FreeBSD"},
	{"openbsd", "OpenBSD"},
	{"netbsd", "NetBSD"},
	{"dropbear", "Linux (embedded)"},
	{"for_windows", "Windows"},
	{"cisco", "Cisco"},
	{"rosssh", "MikroTik RouterOS"},
}

// sshDistro maps an SSH identification string to an OS hint.
func sshDistro(banner string) string {
	b := strings.ToLower(banner)
	// Only consider the software/comments part after "SSH-2.0-".
	if i := strings.Index(b, "ssh-"); i >= 0 {
		b = b[i:]
	}
	for _, d := range sshDistros {
		if d.needle == "deb" {
			// "OpenSSH_7.4p1 Debian-10+deb9u7" handled by "debian"; plain "+deb10u2"
			// suffix also indicates Debian.
			if strings.Contains(b, "+deb") {
				return d.os
			}
			continue
		}
		if strings.Contains(b, d.needle) {
			return d.os
		}
	}
	return ""
}

// Enrich derives Host-level fields from evidence and services. Values derived from
// evidence override existing ones; when nothing is derived, existing values are kept.
func (correlator) Enrich(host model.Host, services []model.Service, ev []model.IdentityEvidence) model.Host {
	d := deriveFields(services, ev)
	if d.Hostname != "" {
		host.Hostname = d.Hostname
	}
	if d.Domain != "" {
		host.Domain = d.Domain
	}
	if d.OS != "" {
		host.OS = d.OS
	}
	if host.Vendor == "" && d.Vendor != "" {
		host.Vendor = d.Vendor
	}
	names := append([]string(nil), host.Hostnames...)
	names = append(names, d.Hostnames...)
	if host.Hostname != "" {
		names = append(names, host.Hostname)
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = cleanName(n)
		if n == "" || isIPLiteral(n) || seen[strings.ToLower(n)] {
			continue
		}
		seen[strings.ToLower(n)] = true
		out = append(out, n)
	}
	sortNames(out)
	host.Hostnames = out
	return host
}
