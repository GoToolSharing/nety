package netif

import "net/netip"

// MaxScannablePrefixBits is the smallest prefix length NETY will offer as a scan scope
// for IPv6. A /112 is 65536 addresses, the same order as an IPv4 /16; anything shorter
// cannot be enumerated in a human lifetime and is an addressing artefact rather than a
// segment.
const MaxScannablePrefixBits = 112

// scannablePrefix reports whether a locally configured prefix is something an operator
// could sensibly scan.
//
// This exists because auto-detect hands the network's prefixes straight to the scan
// planner. A link-local fe80::/64 in that list means a planner asked to enumerate 18
// quintillion addresses, which is not a slow scan but a dead process.
func scannablePrefix(p netip.Prefix) bool {
	a := p.Addr()
	switch {
	case a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsMulticast():
		return false
	case a.IsUnspecified():
		return false
	}
	if a.Is4() || a.Is4In6() {
		return true
	}
	return p.Bits() >= MaxScannablePrefixBits
}
