package netif

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Lease is a DHCP lease, however it was obtained (parsed from a lease file or
// negotiated by the built-in client).
type Lease struct {
	Interface  string
	Address    netip.Addr
	Prefix     netip.Prefix
	Router     netip.Addr
	Server     netip.Addr // option 54, dhcp-server-identifier
	DNS        []netip.Addr
	DomainName string
	Search     []string
	Renew      time.Time
	Rebind     time.Time
	Expire     time.Time
	Source     string // file the lease was read from, or "dhcp-client"
}

// Valid reports whether the lease carries a usable address.
func (l Lease) Valid() bool { return l.Address.IsValid() && !l.Address.IsUnspecified() }

// CIDR returns the lease address with its prefix length, defaulting to /24
// when the server did not send a subnet mask.
func (l Lease) CIDR() netip.Prefix {
	if l.Prefix.IsValid() && l.Prefix.Bits() > 0 {
		return netip.PrefixFrom(l.Address, l.Prefix.Bits())
	}
	if l.Address.Is4() {
		return netip.PrefixFrom(l.Address, 24)
	}
	return netip.PrefixFrom(l.Address, 64)
}

// ---------------------------------------------------------------------------
// Lease file discovery
// ---------------------------------------------------------------------------

// LeaseGlobs are the well-known lease file locations, most specific first.
// "%s" is replaced by the interface name, "%d" by its ifindex.
var LeaseGlobs = []string{
	"/run/systemd/netif/leases/%d",                // systemd-networkd (key=value)
	"/var/lib/NetworkManager/*-%s-*.lease",        // NetworkManager internal DHCP (key=value)
	"/var/lib/NetworkManager/dhclient-*-%s.lease", // NetworkManager + dhclient (ISC)
	"/var/lib/dhcp/dhclient.%s.leases",            // Debian/Ubuntu ISC dhclient
	"/var/lib/dhcp/dhclient.leases",               //
	"/var/lib/dhclient/dhclient-%s.leases",        // RHEL ISC dhclient
	"/var/lib/dhclient/dhclient.leases",           //
	"/var/lib/dhcpcd/%s.lease",                    // dhcpcd (raw DHCP packet)
	"/var/lib/dhcpcd5/dhcpcd-%s.lease",            //
	"/var/db/dhcpcd-%s.lease",                     //
	"/var/lib/dhcpcd/dhcpcd-%s.lease",             //
	"/run/systemd/netif/leases/%s",                // defensive
	"/var/lib/udhcpc/udhcpc.%s.leases",            // busybox udhcpc (key=value via script)
	"/run/NetworkManager/dhclient-*-%s.lease",     //
	"/var/lib/dhcp/dhclient-*-%s.lease",           //
}

// FindLease looks for a DHCP lease for iface under root ("/" in production,
// a temporary directory in tests) and returns the freshest usable one.
//
// NETY does not send DHCP traffic during passive detection: Detect reports a
// DHCP server only when a lease file says so. The active client
// (DHCPAcquire) is used solely on the temporary sub-interfaces created by the
// opt-in L2 segmentation techniques.
func FindLease(root, iface string, ifIndex int) (Lease, bool) {
	var best Lease
	found := false
	for _, pattern := range LeaseGlobs {
		p := pattern
		p = strings.ReplaceAll(p, "%d", strconv.Itoa(ifIndex))
		p = strings.ReplaceAll(p, "%s", iface)
		matches, err := filepath.Glob(joinRoot(root, p))
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, m := range matches {
			l, ok := parseLeaseFile(m, iface)
			if !ok {
				continue
			}
			l.Source = m
			if !found || leaseNewer(l, best) {
				best, found = l, true
			}
		}
	}
	return best, found
}

func leaseNewer(a, b Lease) bool {
	if !a.Expire.IsZero() || !b.Expire.IsZero() {
		return a.Expire.After(b.Expire)
	}
	return false
}

// parseLeaseFile sniffs the format of one lease file and parses it.
func parseLeaseFile(path, iface string) (Lease, bool) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return Lease{}, false
	}
	// dhcpcd stores the raw DHCP ACK packet.
	if m, err := ParseDHCPMessage(data); err == nil {
		l := m.Lease(iface, fileModTime(path))
		return l, l.Valid()
	}
	s := string(data)
	if strings.Contains(s, "lease {") || strings.Contains(s, "lease6 {") {
		leases := ParseISCLeases(strings.NewReader(s))
		best, ok := pickISCLease(leases, iface)
		return best, ok
	}
	l := ParseKVLease(strings.NewReader(s))
	l.Interface = iface
	return l, l.Valid()
}

func fileModTime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Now()
}

func pickISCLease(leases []Lease, iface string) (Lease, bool) {
	var best Lease
	found := false
	for _, l := range leases {
		if !l.Valid() {
			continue
		}
		if iface != "" && l.Interface != "" && l.Interface != iface {
			continue
		}
		// The file is append-only: the last matching entry wins.
		best, found = l, true
	}
	if found && best.Interface == "" {
		best.Interface = iface
	}
	return best, found
}

// ---------------------------------------------------------------------------
// key=value leases (systemd-networkd, NetworkManager internal DHCP, udhcpc)
// ---------------------------------------------------------------------------

// ParseKVLease parses the "KEY=value" lease format written by
// systemd-networkd (/run/systemd/netif/leases/<ifindex>) and by
// NetworkManager's internal DHCP client.
func ParseKVLease(r io.Reader) Lease {
	var l Lease
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	var maskBits = -1
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToUpper(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "ADDRESS", "IP_ADDRESS", "FIXED_ADDRESS":
			if a, err := netip.ParseAddr(v); err == nil {
				l.Address = a.Unmap()
			}
		case "NETMASK", "SUBNET_MASK":
			maskBits = maskToBits(v)
		case "PREFIXLEN":
			if n, err := strconv.Atoi(v); err == nil {
				maskBits = n
			}
		case "ROUTER", "ROUTERS", "GATEWAY":
			for _, f := range splitList(v) {
				if a, err := netip.ParseAddr(f); err == nil {
					l.Router = a.Unmap()
					break
				}
			}
		case "SERVER_ADDRESS", "SERVER_IDENTIFIER", "DHCP_SERVER_IDENTIFIER", "SERVERID", "SIADDR":
			if a, err := netip.ParseAddr(v); err == nil {
				l.Server = a.Unmap()
			}
		case "DNS", "DOMAIN_NAME_SERVERS", "DNS_SERVERS":
			for _, f := range splitList(v) {
				if a, err := netip.ParseAddr(f); err == nil {
					l.DNS = appendUniqueAddr(l.DNS, a.Unmap())
				}
			}
		case "DOMAINNAME", "DOMAIN_NAME", "DOMAIN":
			l.DomainName = v
			l.Search = appendUniqueString(l.Search, v)
		case "DOMAIN_SEARCH_LIST", "SEARCH":
			for _, f := range splitList(v) {
				l.Search = appendUniqueString(l.Search, f)
			}
		case "INTERFACE":
			l.Interface = v
		case "LIFETIME", "LEASETIME", "LEASE_TIME":
			if n, err := strconv.Atoi(v); err == nil {
				l.Expire = time.Now().Add(time.Duration(n) * time.Second)
			}
		case "T1":
			if ts, ok := parseEpoch(v); ok {
				l.Renew = ts
			}
		case "T2":
			if ts, ok := parseEpoch(v); ok {
				l.Rebind = ts
			}
		case "EXPIRY", "EXPIRES":
			if ts, ok := parseEpoch(v); ok {
				l.Expire = ts
			}
		}
	}
	if l.Address.IsValid() && maskBits >= 0 {
		l.Prefix = netip.PrefixFrom(l.Address, maskBits)
	}
	return l
}

func parseEpoch(v string) (time.Time, bool) {
	n, err := strconv.ParseInt(strings.Fields(v)[0], 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

func splitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == ';'
	})
}

func maskToBits(v string) int {
	ip := net.ParseIP(v)
	if ip == nil {
		return -1
	}
	if v4 := ip.To4(); v4 != nil {
		ones, _ := net.IPv4Mask(v4[0], v4[1], v4[2], v4[3]).Size()
		if ones == 0 && v4.String() != "0.0.0.0" {
			return -1
		}
		return ones
	}
	ones, _ := net.IPMask(ip.To16()).Size()
	return ones
}

// ---------------------------------------------------------------------------
// ISC dhclient leases
// ---------------------------------------------------------------------------

// ParseISCLeases parses /var/lib/dhcp/dhclient*.leases. Entries are returned
// in file order; the last one for an interface is the current lease.
func ParseISCLeases(r io.Reader) []Lease {
	var out []Lease
	var cur *Lease
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "lease ") || line == "lease{" || strings.HasPrefix(line, "lease{") {
			cur = &Lease{}
			continue
		}
		if line == "}" {
			if cur != nil {
				out = append(out, *cur)
				cur = nil
			}
			continue
		}
		if cur == nil {
			continue
		}
		line = strings.TrimSuffix(line, ";")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		kw := fields[0]
		if kw == "option" && len(fields) >= 3 {
			applyISCOption(cur, fields[1], strings.Join(fields[2:], " "))
			continue
		}
		switch kw {
		case "interface":
			if len(fields) >= 2 {
				cur.Interface = strings.Trim(fields[1], `"`)
			}
		case "fixed-address":
			if len(fields) >= 2 {
				if a, err := netip.ParseAddr(strings.Trim(fields[1], `"`)); err == nil {
					cur.Address = a.Unmap()
				}
			}
		case "renew", "rebind", "expire":
			if len(fields) < 2 {
				continue
			}
			if ts, ok := parseISCTime(fields[1:]); ok {
				switch kw {
				case "renew":
					cur.Renew = ts
				case "rebind":
					cur.Rebind = ts
				case "expire":
					cur.Expire = ts
				}
			}
		}
	}
	// Apply pending masks.
	for i := range out {
		if out[i].Prefix.IsValid() && out[i].Address.IsValid() {
			out[i].Prefix = netip.PrefixFrom(out[i].Address, out[i].Prefix.Bits())
		}
	}
	return out
}

func applyISCOption(l *Lease, name, value string) {
	value = strings.TrimSpace(strings.Trim(value, `"`))
	switch name {
	case "subnet-mask":
		if bits := maskToBits(value); bits >= 0 {
			l.Prefix = netip.PrefixFrom(netip.IPv4Unspecified(), bits)
		}
	case "routers":
		for _, f := range splitList(value) {
			if a, err := netip.ParseAddr(f); err == nil {
				l.Router = a.Unmap()
				break
			}
		}
	case "dhcp-server-identifier":
		if a, err := netip.ParseAddr(value); err == nil {
			l.Server = a.Unmap()
		}
	case "domain-name-servers":
		for _, f := range splitList(value) {
			if a, err := netip.ParseAddr(f); err == nil {
				l.DNS = appendUniqueAddr(l.DNS, a.Unmap())
			}
		}
	case "domain-name":
		l.DomainName = strings.Trim(value, `"`)
		l.Search = appendUniqueString(l.Search, l.DomainName)
	case "domain-search":
		for _, f := range splitList(value) {
			l.Search = appendUniqueString(l.Search, strings.Trim(f, `"`))
		}
	}
}

// parseISCTime parses `<weekday> YYYY/MM/DD HH:MM:SS` (UTC) and the `epoch
// <seconds>;` form emitted by newer dhclient versions.
func parseISCTime(fields []string) (time.Time, bool) {
	if len(fields) >= 2 && fields[0] == "epoch" {
		if n, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			return time.Unix(n, 0).UTC(), true
		}
	}
	if len(fields) >= 3 {
		t, err := time.Parse("2006/01/02 15:04:05", fields[1]+" "+fields[2])
		if err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
