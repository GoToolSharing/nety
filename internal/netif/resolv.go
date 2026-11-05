package netif

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

// ResolvConf is the useful part of a resolv.conf(5) file.
type ResolvConf struct {
	Nameservers []netip.Addr
	Search      []string
	Domain      string
	// Stub is true when the only nameserver is a local stub resolver (127.0.0.53 for
	// systemd-resolved, 127.0.0.1 for dnsmasq-style setups), meaning the real upstream
	// servers must be looked up elsewhere.
	Stub bool
}

// SystemdStubResolver is the loopback address systemd-resolved listens on in
// /etc/resolv.conf when the stub listener is enabled.
var SystemdStubResolver = netip.MustParseAddr("127.0.0.53")

// ResolvConfPaths are the files Detect reads, most authoritative first.
// /run/systemd/resolve/resolv.conf holds the real upstream servers when /etc/resolv.conf
// only points at the 127.0.0.53 stub.
var ResolvConfPaths = []string{
	"/run/systemd/resolve/resolv.conf",
	"/etc/resolv.conf",
	"/run/systemd/resolve/stub-resolv.conf",
	"/run/resolvconf/resolv.conf",
	"/etc/resolvconf/run/resolv.conf",
}

// ParseResolvConf parses one resolv.conf stream. Unknown directives, comments (# and ;)
// and malformed addresses are ignored: this must never fail on a vendor-mangled file.
func ParseResolvConf(r io.Reader) ResolvConf {
	var rc ResolvConf
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "nameserver":
			if a, ok := parseResolvAddr(fields[1]); ok {
				rc.Nameservers = appendUniqueAddr(rc.Nameservers, a)
			}
		case "search":
			for _, d := range fields[1:] {
				rc.Search = appendUniqueString(rc.Search, strings.TrimSuffix(d, "."))
			}
		case "domain":
			if rc.Domain == "" {
				rc.Domain = strings.TrimSuffix(fields[1], ".")
			}
		}
	}
	if rc.Domain != "" {
		rc.Search = appendUniqueString(rc.Search, rc.Domain)
	}
	rc.Stub = isStubOnly(rc.Nameservers)
	return rc
}

func isStubOnly(ns []netip.Addr) bool {
	if len(ns) == 0 {
		return false
	}
	for _, a := range ns {
		if !a.IsLoopback() {
			return false
		}
	}
	return true
}

// parseResolvAddr accepts "8.8.8.8", "fe80::1%eth0" and bracketed forms.
func parseResolvAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// LoadResolvConf reads every readable file in paths under root and merges them. Loopback
// stub resolvers are dropped as soon as a real upstream server is known, so the caller
// reports the servers the segment actually uses. root is normally "/"; tests pass a
// temporary directory.
func LoadResolvConf(root string, paths []string) ResolvConf {
	var merged ResolvConf
	sawStub := false
	for _, p := range paths {
		f, err := os.Open(joinRoot(root, p))
		if err != nil {
			continue
		}
		rc := ParseResolvConf(f)
		_ = f.Close()
		for _, a := range rc.Nameservers {
			if a.IsLoopback() {
				sawStub = true
				continue
			}
			merged.Nameservers = appendUniqueAddr(merged.Nameservers, a)
		}
		for _, d := range rc.Search {
			merged.Search = appendUniqueString(merged.Search, d)
		}
		if merged.Domain == "" {
			merged.Domain = rc.Domain
		}
	}
	if len(merged.Nameservers) == 0 && sawStub {
		// Only a stub resolver is configured and its upstreams are not readable: report
		// the stub rather than nothing.
		merged.Nameservers = []netip.Addr{SystemdStubResolver}
		merged.Stub = true
	}
	return merged
}

func joinRoot(root, p string) string {
	if root == "" || root == "/" {
		return p
	}
	return strings.TrimSuffix(root, "/") + p
}

func appendUniqueAddr(dst []netip.Addr, a netip.Addr) []netip.Addr {
	if !a.IsValid() {
		return dst
	}
	for _, x := range dst {
		if x == a {
			return dst
		}
	}
	return append(dst, a)
}

func appendUniqueString(dst []string, s string) []string {
	if s == "" {
		return dst
	}
	for _, x := range dst {
		if x == s {
			return dst
		}
	}
	return append(dst, s)
}
