//go:build !linux

package netif

import (
	"net/netip"
)

// Stubs so the whole tree compiles (and its pure logic stays testable) on
// darwin. Everything that needs netlink / AF_PACKET returns
// engine.ErrUnsupported.

// AddVLAN is Linux-only.
func AddVLAN(parent string, vlanID int) (string, error) {
	return "", errUnsupportedf("create 802.1Q sub-interface %s", VLANName(parent, vlanID))
}

// DeleteVLAN is Linux-only.
func DeleteVLAN(name string) error { return errUnsupportedf("delete sub-interface %s", name) }

// SetLinkUp is Linux-only.
func SetLinkUp(iface string) error { return errUnsupportedf("bring up %s", iface) }

// AddAddr is Linux-only.
func AddAddr(iface string, p netip.Prefix) error {
	return errUnsupportedf("add address %s to %s", p, iface)
}

// DelAddr is Linux-only.
func DelAddr(iface string, p netip.Prefix) error {
	return errUnsupportedf("remove address %s from %s", p, iface)
}

// AddRoute is Linux-only.
func AddRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	return errUnsupportedf("add route %s via %s", dst, via)
}

// DelRoute is Linux-only.
func DelRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	return errUnsupportedf("remove route %s via %s", dst, via)
}

// HasRoute is Linux-only and always reports false.
func HasRoute(ip netip.Addr) bool { return false }

// NetyRouteMetric mirrors the Linux constant so callers compile everywhere.
const NetyRouteMetric = 2048
