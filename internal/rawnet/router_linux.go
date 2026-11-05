//go:build linux

package rawnet

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Router resolves Paths for scanners. The main routing table is loaded once over netlink
// and matched in-process (longest prefix, then metric) so that lookups for millions of
// destinations cost no syscall; the source address of each route is learnt once with an
// RTM_GETROUTE for the first destination using it. Destinations not covered by the main
// table (policy routing) fall back to RTM_GETROUTE.
//
// When an interface is forced, only routes through it are considered and destinations
// inside its connected prefixes are treated as on-link.
type Router struct {
	forced *net.Interface
	routes []fibEntry // immutable after NewRouter

	mu    sync.Mutex
	cache map[int]Path // route index -> path template
	addrs map[int][]netip.Prefix
}

type fibEntry struct {
	dst      netip.Prefix
	gw       netip.Addr
	src      netip.Addr
	link     int
	priority int
}

// NewRouter loads the routing table. iface may be "" (use the system's choice) or an
// interface name to force egress.
func NewRouter(iface string) (*Router, error) {
	r := &Router{cache: map[int]Path{}, addrs: map[int][]netip.Prefix{}}
	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("rawnet: interface %q: %w", iface, err)
		}
		r.forced = ifi
	}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rs, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, fmt.Errorf("rawnet: list routes: %w", err)
		}
		for _, rt := range rs {
			if rt.Type != unix.RTN_UNICAST && rt.Type != 0 {
				continue // blackhole / unreachable / prohibit ...
			}
			e := fibEntry{link: rt.LinkIndex, priority: rt.Priority}
			gw := rt.Gw
			if len(rt.MultiPath) > 0 {
				e.link = rt.MultiPath[0].LinkIndex
				gw = rt.MultiPath[0].Gw
			}
			if a, ok := netip.AddrFromSlice(gw); ok && !a.IsUnspecified() {
				e.gw = a.Unmap()
			}
			if a, ok := netip.AddrFromSlice(rt.Src); ok {
				e.src = a.Unmap()
			}
			if rt.Dst == nil {
				if fam == netlink.FAMILY_V4 {
					e.dst = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
				} else {
					e.dst = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
				}
			} else {
				a, ok := netip.AddrFromSlice(rt.Dst.IP)
				if !ok {
					continue
				}
				ones, _ := rt.Dst.Mask.Size()
				e.dst = netip.PrefixFrom(a.Unmap(), ones).Masked()
			}
			if r.forced != nil && e.link != r.forced.Index {
				continue
			}
			r.routes = append(r.routes, e)
		}
	}
	// Longest prefix first, then lowest metric: the first match wins.
	slices.SortStableFunc(r.routes, func(a, b fibEntry) int {
		if a.dst.Bits() != b.dst.Bits() {
			return b.dst.Bits() - a.dst.Bits()
		}
		return a.priority - b.priority
	})
	return r, nil
}

// Interface returns the forced interface, or nil.
func (r *Router) Interface() *net.Interface { return r.forced }

// Lookup returns the path to dst.
func (r *Router) Lookup(dst netip.Addr) (Path, error) {
	dst = dst.Unmap()
	if !dst.IsValid() {
		return Path{}, errors.New("rawnet: invalid destination")
	}
	for i, e := range r.routes {
		if e.dst.Addr().Is4() != dst.Is4() || !e.dst.Contains(dst) {
			continue
		}
		r.mu.Lock()
		p, ok := r.cache[i]
		r.mu.Unlock()
		if ok {
			return p, nil
		}
		p, err := r.buildPath(e, dst)
		if err != nil {
			return Path{}, err
		}
		r.mu.Lock()
		r.cache[i] = p
		r.mu.Unlock()
		return p, nil
	}
	if r.forced != nil {
		// No route via the forced interface: accept destinations inside its connected
		// prefixes, otherwise it is unreachable through it.
		for _, pf := range r.ifacePrefixes(r.forced.Index) {
			if pf.Contains(dst) {
				return Path{Ifi: r.forced, Src: pf.Addr()}, nil
			}
		}
		return Path{}, fmt.Errorf("rawnet: no route to %s via %s", dst, r.forced.Name)
	}
	return r.kernelPath(dst)
}

func (r *Router) buildPath(e fibEntry, dst netip.Addr) (Path, error) {
	ifi, err := net.InterfaceByIndex(e.link)
	if err != nil {
		return Path{}, fmt.Errorf("rawnet: route interface %d: %w", e.link, err)
	}
	p := Path{Ifi: ifi, Gateway: e.gw, Src: e.src}
	if !p.Src.IsValid() {
		// Ask the kernel which source it would pick for this destination.
		if kp, err := r.kernelPath(dst); err == nil && kp.Ifi.Index == ifi.Index {
			p.Src = kp.Src
		}
	}
	if !p.Src.IsValid() {
		p.Src = r.pickSource(ifi.Index, dst, e.gw)
	}
	if !p.Src.IsValid() {
		return Path{}, fmt.Errorf("rawnet: no source address on %s for %s", ifi.Name, dst)
	}
	return p, nil
}

func (r *Router) kernelPath(dst netip.Addr) (Path, error) {
	rs, err := netlink.RouteGet(dst.AsSlice())
	if err != nil {
		return Path{}, fmt.Errorf("rawnet: route to %s: %w", dst, err)
	}
	if len(rs) == 0 {
		return Path{}, fmt.Errorf("rawnet: no route to %s", dst)
	}
	rt := rs[0]
	ifi, err := net.InterfaceByIndex(rt.LinkIndex)
	if err != nil {
		return Path{}, fmt.Errorf("rawnet: route interface %d: %w", rt.LinkIndex, err)
	}
	p := Path{Ifi: ifi}
	if a, ok := netip.AddrFromSlice(rt.Gw); ok && !a.IsUnspecified() {
		p.Gateway = a.Unmap()
	}
	if a, ok := netip.AddrFromSlice(rt.Src); ok {
		p.Src = a.Unmap()
	} else {
		p.Src = r.pickSource(ifi.Index, dst, p.Gateway)
	}
	if !p.Src.IsValid() {
		return Path{}, fmt.Errorf("rawnet: no source address on %s for %s", ifi.Name, dst)
	}
	return p, nil
}

// pickSource chooses an address of the interface in dst's family, preferring one whose
// prefix contains dst or the gateway, and global over link-local.
func (r *Router) pickSource(link int, dst, gw netip.Addr) netip.Addr {
	var best netip.Addr
	for _, pf := range r.ifacePrefixes(link) {
		a := pf.Addr()
		if a.Is4() != dst.Is4() {
			continue
		}
		if pf.Contains(dst) || (gw.IsValid() && pf.Contains(gw)) {
			return a
		}
		if !best.IsValid() || (best.IsLinkLocalUnicast() && !a.IsLinkLocalUnicast()) {
			best = a
		}
	}
	return best
}

func (r *Router) ifacePrefixes(link int) []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ps, ok := r.addrs[link]; ok {
		return ps
	}
	var ps []netip.Prefix
	if l, err := netlink.LinkByIndex(link); err == nil {
		if as, err := netlink.AddrList(l, netlink.FAMILY_ALL); err == nil {
			for _, a := range as {
				ip, ok := netip.AddrFromSlice(a.IP)
				if !ok {
					continue
				}
				ones, _ := a.Mask.Size()
				ps = append(ps, netip.PrefixFrom(ip.Unmap(), ones))
			}
		}
	}
	r.addrs[link] = ps
	return ps
}

// InterfacePrefixes returns the addresses (with prefix length) configured on ifi.
func (r *Router) InterfacePrefixes(ifi *net.Interface) []netip.Prefix {
	return slices.Clone(r.ifacePrefixes(ifi.Index))
}
