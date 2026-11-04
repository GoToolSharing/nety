package rawnet

import (
	"iter"
	"net"
	"net/netip"
	"time"
)

// SweepOptions configures an active neighbour (ARP / NDP) sweep.
type SweepOptions struct {
	Ifi     *net.Interface
	Src     netip.Addr           // source address (IPv4 for ARP, or IPv6)
	SrcV6   netip.Addr           // optional IPv6 source when Targets mixes families
	Targets iter.Seq[netip.Addr] // re-iterated on each retry round
	Limiter *Limiter             // nil = unlimited
	Retries int                  // extra rounds for unanswered targets
	Wait    time.Duration        // late-reply wait after each round (default 1s)
	// Filter, when set, accepts replies only from IPs it approves.
	Filter func(ip netip.Addr) bool
	// Skip, when set, suppresses requests to IPs already known.
	Skip func(ip netip.Addr) bool
	// Sent is called after each request is sent (progress accounting).
	Sent func(ip netip.Addr)
	// OnReply is called once per newly answering IP.
	OnReply func(ip netip.Addr, mac net.HardwareAddr, rtt time.Duration)
}

func zeroMAC(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}
