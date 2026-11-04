//go:build linux

package netif

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Netlink-backed system mutations used by the segmentation techniques. Every
// one of them registers an undo action with the tracker (see track.go), so
// netif.RestoreAll() puts the machine back exactly as it was.

// AddVLAN creates an 802.1Q sub-interface carrying vlanID on parent and brings
// it up. It returns the sub-interface name. If the sub-interface already
// exists it is reused and NOT registered for deletion (NETY never removes an
// interface it did not create).
func AddVLAN(parent string, vlanID int) (string, error) {
	if !ValidVLANID(vlanID) {
		return "", fmt.Errorf("netif: invalid VLAN id %d", vlanID)
	}
	pl, err := netlink.LinkByName(parent)
	if err != nil {
		return "", fmt.Errorf("netif: parent %q: %w", parent, err)
	}
	name := VLANName(parent, vlanID)
	if existing, err := netlink.LinkByName(name); err == nil {
		if v, ok := existing.(*netlink.Vlan); ok && v.VlanId == vlanID {
			if err := netlink.LinkSetUp(existing); err != nil {
				return "", fmt.Errorf("netif: link up %q: %w", name, err)
			}
			return name, nil
		}
		return "", fmt.Errorf("netif: %q already exists and is not VLAN %d", name, vlanID)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	attrs.ParentIndex = pl.Attrs().Index
	link := &netlink.Vlan{
		LinkAttrs:    attrs,
		VlanId:       vlanID,
		VlanProtocol: netlink.VLAN_PROTOCOL_8021Q,
	}
	if err := netlink.LinkAdd(link); err != nil {
		return "", fmt.Errorf("netif: create %q on %q: %w", name, parent, mapPermErr(err))
	}
	trackKeyed("vlan|"+name, "delete vlan interface "+name, func() error { return DeleteVLAN(name) })

	if err := netlink.LinkSetUp(link); err != nil {
		return name, fmt.Errorf("netif: link up %q: %w", name, err)
	}
	return name, nil
}

// DeleteVLAN removes a sub-interface created by AddVLAN. Deleting a link also
// drops its addresses and routes, so the tracker entries for those become
// no-ops.
func DeleteVLAN(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil
		}
		return fmt.Errorf("netif: lookup %q: %w", name, err)
	}
	if _, ok := l.(*netlink.Vlan); !ok {
		return fmt.Errorf("netif: refusing to delete %q: not an 802.1Q sub-interface", name)
	}
	if err := netlink.LinkDel(l); err != nil {
		return fmt.Errorf("netif: delete %q: %w", name, mapPermErr(err))
	}
	forgetKeyed("vlan|" + name)
	return nil
}

// SetLinkUp brings iface up. It restores the previous administrative state on
// cleanup when NETY was the one that brought it up.
func SetLinkUp(iface string) error {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("netif: lookup %q: %w", iface, err)
	}
	wasUp := l.Attrs().Flags&net.FlagUp != 0
	if wasUp {
		return nil
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("netif: link up %q: %w", iface, mapPermErr(err))
	}
	trackChange("bring down interface "+iface, func() error {
		cur, err := netlink.LinkByName(iface)
		if err != nil {
			return nil // already gone
		}
		return netlink.LinkSetDown(cur)
	})
	return nil
}

// AddAddr assigns p to iface and registers its removal.
func AddAddr(iface string, p netip.Prefix) error {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("netif: lookup %q: %w", iface, err)
	}
	addr, err := netlinkAddr(p)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(l, addr); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return fmt.Errorf("netif: add %s to %q: %w", p, iface, mapPermErr(err))
	}
	trackKeyed(addrKey(iface, p), fmt.Sprintf("remove address %s from %s", p, iface), func() error {
		return DelAddr(iface, p)
	})
	return nil
}

// DelAddr removes p from iface. A missing address or interface is not an error.
func DelAddr(iface string, p netip.Prefix) error {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return nil
	}
	addr, err := netlinkAddr(p)
	if err != nil {
		return err
	}
	if err := netlink.AddrDel(l, addr); err != nil {
		if errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ENODEV) {
			return nil
		}
		return fmt.Errorf("netif: del %s from %q: %w", p, iface, mapPermErr(err))
	}
	forgetKeyed(addrKey(iface, p))
	return nil
}

func netlinkAddr(p netip.Prefix) (*netlink.Addr, error) {
	if !p.IsValid() {
		return nil, errors.New("netif: invalid prefix")
	}
	ipnet := &net.IPNet{
		IP:   p.Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
	return &netlink.Addr{IPNet: ipnet}, nil
}

// AddRoute installs a route to dst via the next hop `via` on iface and
// registers its removal. `via` may be invalid for an on-link (dev) route;
// iface may be empty when `via` alone determines the egress interface.
//
// The route is added with a high metric and the RTPROT_STATIC protocol so it
// is easy to recognise in `ip route` output during an engagement.
func AddRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	r, err := buildRoute(dst, via, iface)
	if err != nil {
		return err
	}
	if err := netlink.RouteAdd(r); err != nil {
		if errors.Is(err, unix.EEXIST) {
			// The route already exists: nothing to add, nothing to undo.
			return nil
		}
		return fmt.Errorf("netif: add route %s via %s dev %s: %w", dst, via, iface, mapPermErr(err))
	}
	trackKeyed(routeKey(dst, via, iface), fmt.Sprintf("remove route %s via %s dev %s", dst, via, iface), func() error {
		return DelRoute(dst, via, iface)
	})
	return nil
}

// DelRoute removes a route previously added by AddRoute. A missing route is
// not an error.
func DelRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	r, err := buildRoute(dst, via, iface)
	if err != nil {
		return err
	}
	if err := netlink.RouteDel(r); err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
			return nil
		}
		return fmt.Errorf("netif: del route %s via %s dev %s: %w", dst, via, iface, mapPermErr(err))
	}
	forgetKeyed(routeKey(dst, via, iface))
	return nil
}

// NetyRouteMetric is the metric NETY installs its temporary routes with: high
// enough to never win over a legitimate route to the same prefix.
const NetyRouteMetric = 2048

func buildRoute(dst netip.Prefix, via netip.Addr, iface string) (*netlink.Route, error) {
	if !dst.IsValid() {
		return nil, errors.New("netif: invalid destination prefix")
	}
	r := &netlink.Route{
		Dst: &net.IPNet{
			IP:   dst.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(dst.Bits(), dst.Addr().BitLen()),
		},
		Priority: NetyRouteMetric,
		Protocol: unix.RTPROT_STATIC,
		Scope:    netlink.SCOPE_UNIVERSE,
	}
	if dst.Addr().Is4() {
		r.Family = unix.AF_INET
	} else {
		r.Family = unix.AF_INET6
	}
	if via.IsValid() && !via.IsUnspecified() {
		r.Gw = via.Unmap().AsSlice()
	} else {
		r.Scope = netlink.SCOPE_LINK
	}
	if iface != "" {
		l, err := netlink.LinkByName(iface)
		if err != nil {
			return nil, fmt.Errorf("netif: lookup %q: %w", iface, err)
		}
		r.LinkIndex = l.Attrs().Index
	}
	if r.LinkIndex == 0 && !via.IsValid() {
		return nil, errors.New("netif: route needs a next hop or an interface")
	}
	return r, nil
}

// HasRoute reports whether the main routing table already covers ip.
func HasRoute(ip netip.Addr) bool {
	routes, err := netlink.RouteGet(ip.Unmap().AsSlice())
	if err != nil || len(routes) == 0 {
		return false
	}
	return true
}

// mapPermErr turns EPERM/EACCES into engine.ErrNeedPrivileges so the UI can
// tell the operator to grant CAP_NET_ADMIN instead of showing a raw errno.
func mapPermErr(err error) error {
	if errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return fmt.Errorf("%w (%v)", errNeedPrivileges, err)
	}
	return err
}

func routeKey(dst netip.Prefix, via netip.Addr, iface string) string {
	return "route|" + dst.String() + "|" + via.String() + "|" + iface
}

func addrKey(iface string, p netip.Prefix) string {
	return "addr|" + iface + "|" + p.String()
}
