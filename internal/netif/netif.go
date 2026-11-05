// Package netif inspects the local network attachment of the operator's machine and
// manipulates it when a segmentation technique needs to.
//
// It has three jobs:
//
//   - implement engine.NetInspector: enumerate interfaces, detect the
//     addressing/routing/DNS/DHCP context of the attached segment, and
//     passively sniff the switch-port control plane (CDP/LLDP/DTP/STP/802.1Q);
//   - expose plain helpers that internal/segment uses to temporarily change
//     the system (802.1Q sub-interfaces, addresses, routes, DHCP);
//   - track every change so RestoreAll undoes all of it, including on
//     cancellation or panic.
//
// Everything that talks to the kernel lives in a //go:build linux file; the //go:build
// !linux stubs return engine.ErrUnsupported so the tree still compiles (and the pure
// parsing/decoding logic is still testable) on darwin.
package netif

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"

	"github.com/GoToolSharing/nety/internal/engine"
)

// errUnsupported is engine.ErrUnsupported, returned by the !linux stubs.
var errUnsupported = engine.ErrUnsupported

// errNeedPrivileges is engine.ErrNeedPrivileges, returned when a netlink or AF_PACKET
// operation fails with EPERM/EACCES.
var errNeedPrivileges = engine.ErrNeedPrivileges

// Inspector implements engine.NetInspector. Use New.
type Inspector struct {
	log *slog.Logger
}

// New returns a NetInspector. A nil logger is replaced by a discarding one.
func New(log *slog.Logger) engine.NetInspector {
	return &Inspector{log: orDiscard(log)}
}

var _ engine.NetInspector = (*Inspector)(nil)

func orDiscard(log *slog.Logger) *slog.Logger {
	if log != nil {
		return log
	}
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// --------------------------------------------------------------------------- VLAN naming
// helpers ---------------------------------------------------------------------------

// VLANName is the conventional name of the 802.1Q sub-interface carrying vlanID on parent
// ("eth0" + 20 -> "eth0.20"). Linux limits interface names to IFNAMSIZ-1 = 15 bytes, so a
// long parent name is truncated to make room.
func VLANName(parent string, vlanID int) string {
	suffix := "." + strconv.Itoa(vlanID)
	const maxLen = 15
	if len(parent)+len(suffix) > maxLen {
		keep := maxLen - len(suffix)
		if keep < 1 {
			keep = 1
		}
		parent = parent[:keep]
	}
	return parent + suffix
}

// ParseVLANName splits an "eth0.20" style sub-interface name. ok is false when name does
// not look like an 802.1Q sub-interface.
func ParseVLANName(name string) (parent string, vlanID int, ok bool) {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 {
		return "", 0, false
	}
	id, err := strconv.Atoi(name[i+1:])
	if err != nil || !ValidVLANID(id) {
		return "", 0, false
	}
	return name[:i], id, true
}

// ValidVLANID reports whether id is a usable 802.1Q VLAN identifier. 0 (priority tagging)
// and 4095 (reserved) are rejected.
func ValidVLANID(id int) bool { return id >= 1 && id <= 4094 }

// --------------------------------------------------------------------------- Prefix
// helpers ---------------------------------------------------------------------------

// PrefixesContain reports whether any prefix contains ip.
func PrefixesContain(prefixes []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range prefixes {
		if p.IsValid() && p.Contains(ip) {
			return true
		}
	}
	return false
}

// HostInPrefix returns the n-th host address of p counting from the network address (n ==
// 1 is the usual router address). For IPv4 it refuses the network and broadcast addresses
// of prefixes shorter than /31.
func HostInPrefix(p netip.Prefix, n int) (netip.Addr, bool) {
	if !p.IsValid() || n < 0 {
		return netip.Addr{}, false
	}
	base := p.Masked().Addr()
	addr := base
	for i := 0; i < n; i++ {
		addr = addr.Next()
		if !addr.IsValid() || !p.Contains(addr) {
			return netip.Addr{}, false
		}
	}
	if addr.Is4() && p.Bits() < 31 {
		if addr == base || addr == broadcastOf(p) {
			return netip.Addr{}, false
		}
	}
	return addr, true
}

// HostFromEnd returns the n-th host address counting backwards from the end of p (n == 0
// is the last address, which for IPv4 is the broadcast address and is therefore rejected
// for prefixes shorter than /31).
func HostFromEnd(p netip.Prefix, n int) (netip.Addr, bool) {
	if !p.IsValid() || n < 0 {
		return netip.Addr{}, false
	}
	addr := lastOf(p)
	for i := 0; i < n; i++ {
		addr = addr.Prev()
		if !addr.IsValid() || !p.Contains(addr) {
			return netip.Addr{}, false
		}
	}
	if addr.Is4() && p.Bits() < 31 {
		if addr == broadcastOf(p) || addr == p.Masked().Addr() {
			return netip.Addr{}, false
		}
	}
	return addr, true
}

func lastOf(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		lo := i * 8
		switch {
		case lo >= bits:
			b[i] = 0xff
		case lo+8 > bits:
			b[i] |= byte(0xff >> (bits - lo))
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func broadcastOf(p netip.Prefix) netip.Addr { return lastOf(p) }

// FormatPrefixes renders prefixes for log lines and result details.
func FormatPrefixes(prefixes []netip.Prefix) string {
	parts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

func errUnsupportedf(format string, args ...any) error {
	return fmt.Errorf("netif: %s: %w", fmt.Sprintf(format, args...), errUnsupported)
}
