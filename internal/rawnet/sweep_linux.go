//go:build linux

package rawnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

// Neighbors resolves IP -> MAC on directly connected segments for the
// scanners. It caches answers, seeds itself from the kernel neighbour table
// (netlink), and actively resolves with ARP (IPv4) or ICMPv6 Neighbor
// Solicitation (IPv6) over its own packet socket. Safe for concurrent use.
type Neighbors struct {
	log *slog.Logger

	mu     sync.RWMutex
	cache  map[netip.Addr]net.HardwareAddr
	seeded map[int]bool
}

// NewNeighbors returns an empty resolver.
func NewNeighbors(log *slog.Logger) *Neighbors {
	if log == nil {
		log = slog.Default()
	}
	return &Neighbors{log: log, cache: map[netip.Addr]net.HardwareAddr{}, seeded: map[int]bool{}}
}

// Lookup returns a cached MAC (including seeded kernel neighbour entries).
func (n *Neighbors) Lookup(ip netip.Addr) (net.HardwareAddr, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	m, ok := n.cache[ip.Unmap()]
	return m, ok
}

// Set records a MAC for ip.
func (n *Neighbors) Set(ip netip.Addr, mac net.HardwareAddr) {
	if len(mac) != 6 || zeroMAC(mac) {
		return
	}
	n.mu.Lock()
	n.cache[ip.Unmap()] = append(net.HardwareAddr(nil), mac...)
	n.mu.Unlock()
}

// Seed loads the kernel neighbour table of ifi into the cache (once per
// interface).
func (n *Neighbors) Seed(ifi *net.Interface) {
	n.mu.Lock()
	if n.seeded[ifi.Index] {
		n.mu.Unlock()
		return
	}
	n.seeded[ifi.Index] = true
	n.mu.Unlock()
	const valid = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE | netlink.NUD_PERMANENT
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		ns, err := netlink.NeighList(ifi.Index, fam)
		if err != nil {
			n.log.Debug("rawnet: neighbour list", "iface", ifi.Name, "err", err)
			continue
		}
		for _, e := range ns {
			if e.State&valid == 0 {
				continue
			}
			if ip, ok := netip.AddrFromSlice(e.IP); ok {
				n.Set(ip, e.HardwareAddr)
			}
		}
	}
}

// Resolve returns the MAC of one on-link neighbour, probing actively when it
// is not cached.
func (n *Neighbors) Resolve(ctx context.Context, ifi *net.Interface, src, ip netip.Addr, timeout time.Duration) (net.HardwareAddr, error) {
	ip = ip.Unmap()
	n.Seed(ifi)
	if m, ok := n.Lookup(ip); ok {
		return m, nil
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	err := n.Sweep(ctx, SweepOptions{
		Ifi: ifi, Src: src, Retries: 2, Wait: timeout / 3,
		Targets: func(yield func(netip.Addr) bool) { yield(ip) },
	})
	if err != nil {
		return nil, err
	}
	if m, ok := n.Lookup(ip); ok {
		return m, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("rawnet: no neighbour answer for %s on %s", ip, ifi.Name)
}

// Sweep sends ARP requests (IPv4 targets) / neighbour solicitations (IPv6
// targets) to every target, retrying unanswered ones, and caches answers.
// OnReply is called once per answering IP from a single goroutine. A
// cancelled ctx stops the sweep and returns nil (callers check ctx).
func (n *Neighbors) Sweep(ctx context.Context, opts SweepOptions) error {
	if opts.Ifi == nil || opts.Targets == nil {
		return errors.New("rawnet: sweep needs an interface and targets")
	}
	if len(opts.Ifi.HardwareAddr) != 6 {
		return fmt.Errorf("rawnet: interface %s has no Ethernet address", opts.Ifi.Name)
	}
	src4, src6 := opts.Src.Unmap(), opts.SrcV6.Unmap()
	if src4.Is6() {
		src4, src6 = netip.Addr{}, src4
	}
	if opts.Wait <= 0 {
		opts.Wait = time.Second
	}
	spec := FilterSpec{ARP: src4.IsValid(), LocalIPv4: src4, DropOutgoing: true}
	if src6.IsValid() {
		spec.IPv6Protos = []uint8{ProtoICMPv6}
	}
	if !spec.ARP && len(spec.IPv6Protos) == 0 {
		return errors.New("rawnet: sweep needs a source address")
	}
	h, err := OpenHandle(opts.Ifi, spec)
	if err != nil {
		return err
	}
	defer h.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		smu   sync.Mutex
		sent  = map[netip.Addr]time.Time{} // first send time; bounded by on-link targets
		found = map[netip.Addr]bool{}
	)
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		buf := make([]byte, 4096)
		var p Packet
		for ctx.Err() == nil {
			nr, err := h.Read(buf, time.Now().Add(100*time.Millisecond))
			if err != nil {
				if ctx.Err() == nil {
					n.log.Debug("rawnet: sweep read", "err", err)
				}
				return
			}
			if nr == 0 || !ParseFrame(buf[:nr], &p) {
				continue
			}
			var ip netip.Addr
			var mac net.HardwareAddr
			switch {
			case p.IsARP && p.ARPOp == 2:
				ip, mac = p.ARPSenderIP, p.ARPSenderMAC
			case p.IsIP && p.Proto == ProtoICMPv6 && p.ICMPType == 136:
				var ok bool
				if ip, mac, ok = NeighborAdvertisement(&p); !ok {
					continue
				}
			default:
				continue
			}
			if zeroMAC(mac) || (opts.Filter != nil && !opts.Filter(ip)) {
				continue
			}
			smu.Lock()
			t0, asked := sent[ip]
			dup := found[ip]
			if asked {
				found[ip] = true
			}
			smu.Unlock()
			if !asked || dup {
				continue // unsolicited / gratuitous, or already reported
			}
			n.Set(ip, mac)
			if opts.OnReply != nil {
				opts.OnReply(ip, append(net.HardwareAddr(nil), mac...), time.Since(t0))
			}
		}
	}()

	fb := NewFrameBuilder()
	srcMAC := opts.Ifi.HardwareAddr
	batch := 1
	if opts.Limiter != nil {
		batch = opts.Limiter.Batch()
	}
	budget := 0
	var sendErr error
rounds:
	for round := 0; round <= opts.Retries; round++ {
		for ip := range opts.Targets {
			ip = ip.Unmap()
			smu.Lock()
			done := found[ip]
			smu.Unlock()
			if done || (opts.Skip != nil && opts.Skip(ip)) {
				continue
			}
			var frame []byte
			switch {
			case ip.Is4() && src4.IsValid():
				frame, err = fb.ARPRequest(srcMAC, src4, ip)
			case ip.Is6() && src6.IsValid():
				frame, err = fb.NeighborSolicitation(srcMAC, src6, ip)
			default:
				continue
			}
			if err != nil {
				n.log.Debug("rawnet: build neighbour request", "ip", ip, "err", err)
				continue
			}
			if opts.Limiter != nil {
				if budget == 0 {
					if err := opts.Limiter.Wait(ctx, batch); err != nil {
						sendErr = err
						break rounds
					}
					budget = batch
				}
				budget--
			}
			smu.Lock()
			if _, ok := sent[ip]; !ok {
				sent[ip] = time.Now()
			}
			smu.Unlock()
			if err := h.Write(frame); err != nil {
				sendErr = fmt.Errorf("rawnet: send neighbour request: %w", err)
				break rounds
			}
			if opts.Sent != nil {
				opts.Sent(ip)
			}
		}
		if err := sleepCtx(ctx, opts.Wait); err != nil {
			sendErr = err
			break
		}
	}
	cancel()
	<-recvDone
	if sendErr != nil && !errors.Is(sendErr, context.Canceled) && !errors.Is(sendErr, context.DeadlineExceeded) {
		return sendErr
	}
	return nil
}
