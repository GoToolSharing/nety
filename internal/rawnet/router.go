package rawnet

import (
	"net"
	"net/netip"
)

// Path is how a destination is reached: egress interface, source address
// and next hop (gateway, or the destination itself when on-link).
type Path struct {
	Ifi     *net.Interface
	Src     netip.Addr
	Gateway netip.Addr // invalid when the destination is on-link
}

// OnLink reports whether the destination is directly connected.
func (p Path) OnLink() bool { return !p.Gateway.IsValid() }

// NextHop returns the L2 neighbour to address frames to for dst.
func (p Path) NextHop(dst netip.Addr) netip.Addr {
	if p.Gateway.IsValid() {
		return p.Gateway
	}
	return dst.Unmap()
}
