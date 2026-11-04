//go:build linux

package netif

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/vaadata/nety/internal/engine"
)

// Interfaces enumerates local interfaces via netlink.
func (n *Inspector) Interfaces() ([]engine.InterfaceInfo, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("netif: list links: %w", err)
	}
	byIndex := make(map[int]string, len(links))
	for _, l := range links {
		byIndex[l.Attrs().Index] = l.Attrs().Name
	}
	out := make([]engine.InterfaceInfo, 0, len(links))
	for _, l := range links {
		a := l.Attrs()
		info := engine.InterfaceInfo{
			Name: a.Name,
			Up:   a.Flags&net.FlagUp != 0 && a.OperState != netlink.OperDown,
			MTU:  a.MTU,
		}
		if len(a.HardwareAddr) > 0 {
			info.MAC = a.HardwareAddr.String()
		}
		if v, ok := l.(*netlink.Vlan); ok {
			info.IsVLAN = true
			info.VLANID = v.VlanId
			info.Parent = byIndex[a.ParentIndex]
		}
		addrs, err := netlink.AddrList(l, unix.AF_UNSPEC)
		if err != nil {
			n.log.Debug("netif: address list failed", "iface", a.Name, "err", err)
		}
		for _, ad := range addrs {
			if p, ok := toPrefix(ad.IPNet); ok {
				info.Addresses = append(info.Addresses, p)
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func toPrefix(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones), true
}

// Detect reports what the machine sees on the segment attached to iface.
// An empty iface means "the interface holding the default route".
//
// Detect is passive apart from one detail: when the default gateway is not in
// the neighbour cache, it sends a single UDP datagram to the gateway's discard
// port to make the kernel ARP for it, then re-reads the cache. No scanning and
// no DHCP traffic is generated; the DHCP server is reported only when a lease
// file names it.
func (n *Inspector) Detect(ctx context.Context, iface string) (engine.NetContext, error) {
	var nc engine.NetContext

	link, defGW, err := n.resolveInterface(iface)
	if err != nil {
		return nc, err
	}
	attrs := link.Attrs()
	nc.Interface = attrs.Name
	nc.LocalMAC = attrs.HardwareAddr

	addrs, err := netlink.AddrList(link, unix.AF_UNSPEC)
	if err != nil {
		return nc, fmt.Errorf("netif: address list %q: %w", nc.Interface, err)
	}
	for _, ad := range addrs {
		p, ok := toPrefix(ad.IPNet)
		if !ok {
			continue
		}
		a := p.Addr()
		switch {
		case a.Is4():
			if !nc.LocalIP.IsValid() && !a.IsLoopback() {
				nc.LocalIP = a
			}
		default:
			nc.LocalIPv6 = append(nc.LocalIPv6, a)
		}
		nc.Prefixes = append(nc.Prefixes, p.Masked())
	}
	nc.Prefixes = dedupPrefixes(nc.Prefixes)
	sortIPv6(nc.LocalIPv6)

	nc.Gateway = defGW
	if !nc.Gateway.IsValid() {
		nc.Gateway = gatewayOn(attrs.Index)
	}
	if nc.Gateway.IsValid() {
		nc.GatewayMAC = n.resolveNeighbour(ctx, attrs.Index, nc.Gateway)
	}

	rc := LoadResolvConf("/", ResolvConfPaths)
	nc.DNSServers = rc.Nameservers
	nc.DomainSearch = rc.Search

	if lease, ok := FindLease("/", nc.Interface, attrs.Index); ok {
		if lease.Server.IsValid() {
			nc.DHCPServer = lease.Server
		}
		for _, d := range lease.DNS {
			nc.DNSServers = appendUniqueAddr(nc.DNSServers, d)
		}
		for _, s := range lease.Search {
			nc.DomainSearch = appendUniqueString(nc.DomainSearch, s)
		}
		n.log.Debug("netif: dhcp lease found", "iface", nc.Interface, "server", lease.Server, "file", lease.Source)
	}
	return nc, nil
}

func (n *Inspector) resolveInterface(iface string) (netlink.Link, netip.Addr, error) {
	if iface != "" {
		l, err := netlink.LinkByName(iface)
		if err != nil {
			return nil, netip.Addr{}, fmt.Errorf("netif: interface %q: %w", iface, err)
		}
		return l, defaultGatewayOn(l.Attrs().Index), nil
	}
	idx, gw, ok := defaultRoute()
	if !ok {
		return nil, netip.Addr{}, errors.New("netif: no default route; pass an explicit interface")
	}
	l, err := netlink.LinkByIndex(idx)
	if err != nil {
		return nil, netip.Addr{}, fmt.Errorf("netif: default route interface %d: %w", idx, err)
	}
	return l, gw, nil
}

// defaultRoute returns the ifindex and next hop of the IPv4 default route,
// falling back to IPv6.
func defaultRoute() (int, netip.Addr, bool) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteList(nil, family)
		if err != nil {
			continue
		}
		best := -1
		var bestGW netip.Addr
		bestPrio := 1 << 30
		for _, r := range routes {
			if r.Dst != nil && !isDefaultDst(r.Dst) {
				continue
			}
			if r.LinkIndex == 0 || r.Priority > bestPrio {
				continue
			}
			bestPrio = r.Priority
			best = r.LinkIndex
			bestGW, _ = netip.AddrFromSlice(r.Gw)
			bestGW = bestGW.Unmap()
		}
		if best > 0 {
			return best, bestGW, true
		}
	}
	return 0, netip.Addr{}, false
}

func isDefaultDst(d *net.IPNet) bool {
	ones, _ := d.Mask.Size()
	return ones == 0
}

func defaultGatewayOn(ifIndex int) netip.Addr {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteList(nil, family)
		if err != nil {
			continue
		}
		for _, r := range routes {
			if r.LinkIndex != ifIndex || r.Gw == nil {
				continue
			}
			if r.Dst != nil && !isDefaultDst(r.Dst) {
				continue
			}
			if a, ok := netip.AddrFromSlice(r.Gw); ok {
				return a.Unmap()
			}
		}
	}
	return netip.Addr{}
}

// gatewayOn returns any next hop reachable through ifIndex, used when the
// interface has no default route of its own.
func gatewayOn(ifIndex int) netip.Addr {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteList(nil, family)
		if err != nil {
			continue
		}
		for _, r := range routes {
			if r.LinkIndex != ifIndex || r.Gw == nil {
				continue
			}
			if a, ok := netip.AddrFromSlice(r.Gw); ok {
				return a.Unmap()
			}
		}
	}
	return netip.Addr{}
}

// resolveNeighbour reads the gateway's MAC from the kernel neighbour table,
// nudging the kernel into ARPing/NDing for it if the entry is missing.
func (n *Inspector) resolveNeighbour(ctx context.Context, ifIndex int, ip netip.Addr) net.HardwareAddr {
	family := unix.AF_INET
	if !ip.Is4() {
		family = unix.AF_INET6
	}
	for attempt := 0; attempt < 4; attempt++ {
		if mac, ok := lookupNeighbour(ifIndex, family, ip); ok {
			return mac
		}
		if attempt == 0 {
			nudgeNeighbour(ip)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(150 * time.Millisecond):
		}
	}
	n.log.Debug("netif: gateway MAC not resolved", "gateway", ip)
	return nil
}

func lookupNeighbour(ifIndex, family int, ip netip.Addr) (net.HardwareAddr, bool) {
	neighs, err := netlink.NeighList(ifIndex, family)
	if err != nil {
		return nil, false
	}
	for _, nb := range neighs {
		a, ok := netip.AddrFromSlice(nb.IP)
		if !ok || a.Unmap() != ip {
			continue
		}
		if len(nb.HardwareAddr) == 0 || nb.State&(unix.NUD_FAILED|unix.NUD_INCOMPLETE) != 0 {
			continue
		}
		return nb.HardwareAddr, true
	}
	return nil, false
}

// nudgeNeighbour sends one datagram to the discard port so the kernel resolves
// the next hop. Nothing is received and the payload is empty.
func nudgeNeighbour(ip netip.Addr) {
	c, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), "9"), 300*time.Millisecond)
	if err != nil {
		return
	}
	_, _ = c.Write(nil)
	_ = c.Close()
}

func dedupPrefixes(in []netip.Prefix) []netip.Prefix {
	out := in[:0]
	seen := make(map[netip.Prefix]struct{}, len(in))
	for _, p := range in {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// sortIPv6 puts global unicast addresses before link-local ones so callers can
// take the first element as "the" address.
func sortIPv6(a []netip.Addr) {
	sort.SliceStable(a, func(i, j int) bool {
		return rankV6(a[i]) < rankV6(a[j])
	})
}

func rankV6(a netip.Addr) int {
	switch {
	case a.IsGlobalUnicast() && !a.IsPrivate():
		return 0
	case a.IsGlobalUnicast():
		return 1
	case a.IsLinkLocalUnicast():
		return 2
	}
	return 3
}
