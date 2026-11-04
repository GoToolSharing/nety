//go:build linux

package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/GoToolSharing/nety/internal/portscan"
	"github.com/GoToolSharing/nety/internal/rawnet"
)

const rawSupported = true

// Probe source ports (outside Linux's default ephemeral range so they never
// collide with kernel sockets).
const (
	rawPortBase = 61000
	rawPortSpan = 4096
)

// rawEgress is one interface used by the raw engine.
type rawEgress struct {
	ifi  *net.Interface
	h    *rawnet.Handle
	src4 netip.Addr
	src6 netip.Addr
}

// rawDisc holds the state shared by the raw sender and receivers.
type rawDisc struct {
	cfg    *config
	col    *collector
	log    *slog.Logger
	cookie rawnet.Cookie
	start  time.Time
	router *rawnet.Router
	neigh  *rawnet.Neighbors

	mu      sync.Mutex
	egs     map[int]*rawEgress
	gwMAC   map[netip.Addr]net.HardwareAddr
	gwFail  map[netip.Addr]bool
	udpPort map[uint16]bool
	synPort map[uint16]bool
	ackPort map[uint16]bool
}

func (r *rawDisc) sport(dst netip.Addr, dport uint16, tag uint8) uint16 {
	return rawPortBase + r.cookie.Sum16(dst, dport, uint16(tag), rawnet.TagSrcPort)%rawPortSpan
}

func (r *rawDisc) tsNow() uint32 { return uint32(time.Since(r.start) / time.Microsecond) }

// discoverRaw runs the privileged engine:
//
//  1. on-link targets are swept with ARP (IPv4) / NDP (IPv6); answering
//     hosts are up ("arp"/"ndp") when the arp method is enabled, and in any
//     case their MAC is learnt (on-link hosts that do not answer ARP cannot
//     receive IP probes either and are considered down);
//  2. every other target (and on-link hosts when arp is disabled) gets a
//     burst of IP probes - ICMP echo + timestamp, TCP SYN on TCPPorts, TCP
//     ACK, UDP payloads - sent through the gateway's MAC. Hosts are visited
//     in a keyed random permutation and probes are rate limited.
//
// Replies are validated statelessly with keyed cookies (TCP sequence / ACK
// numbers, ICMP identifier, UDP source port).
func (d *Discoverer) discoverRaw(ctx context.Context, cfg *config, col *collector, log *slog.Logger) error {
	router, err := rawnet.NewRouter(cfg.iface)
	if err != nil {
		return err
	}
	r := &rawDisc{
		cfg: cfg, col: col, log: log, cookie: rawnet.NewCookie(), start: time.Now(),
		router: router, neigh: rawnet.NewNeighbors(log),
		egs: map[int]*rawEgress{}, gwMAC: map[netip.Addr]net.HardwareAddr{}, gwFail: map[netip.Addr]bool{},
		udpPort: set(cfg.udpPorts), synPort: set(cfg.tcpPorts), ackPort: set(cfg.ackPorts),
	}
	defer func() {
		for _, e := range r.egs {
			if e.h != nil {
				_ = e.h.Close()
			}
		}
	}()

	n := cfg.space.Len()
	limiter := rawnet.NewLimiter(cfg.rate, 0)
	seed := rand.Uint64()
	perm := rawnet.NewPermutation(n, seed)

	// Pass 0: classify targets per egress interface (in-process LPM; no I/O
	// per address).
	onLink := map[int]int{}
	var routed, noRoute uint64
	for i := uint64(0); i < n; i++ {
		if i&0xffff == 0 && ctx.Err() != nil {
			return nil
		}
		ip := cfg.space.At(i)
		p, err := router.Lookup(ip)
		if err != nil {
			noRoute++
			continue
		}
		if _, err := r.egress(p); err != nil {
			return err
		}
		if p.OnLink() {
			onLink[p.Ifi.Index]++
		} else {
			routed++
		}
	}
	if noRoute > 0 {
		log.Warn("targets without route skipped", "count", noRoute)
	}
	sweepUnits := uint64(0)
	for _, c := range onLink {
		sweepUnits += uint64(c)
	}
	ipUnits := routed
	if !cfg.has(MethodARP) {
		ipUnits += sweepUnits
	}
	prog := newProgressCounter(cfg.progress, int64(sweepUnits+ipUnits*uint64(cfg.retries+1)))

	// Phase 1: neighbour sweep of on-link targets.
	for idx, count := range onLink {
		e := r.egs[idx]
		if count == 0 || e == nil {
			continue
		}
		r.neigh.Seed(e.ifi)
		ifIndex := idx
		err := r.neigh.Sweep(ctx, rawnet.SweepOptions{
			Ifi: e.ifi, Src: e.src4, SrcV6: e.src6, Limiter: limiter,
			Retries: cfg.retries, Wait: min(cfg.wait, time.Second),
			Targets: func(yield func(netip.Addr) bool) {
				for i := uint64(0); i < n; i++ {
					ip := cfg.space.At(perm.At(i))
					p, err := router.Lookup(ip)
					if err != nil || !p.OnLink() || p.Ifi.Index != ifIndex {
						continue
					}
					if !yield(ip) {
						return
					}
				}
			},
			Filter: cfg.space.Contains,
			OnReply: func(ip netip.Addr, mac net.HardwareAddr, rtt time.Duration) {
				if cfg.has(MethodARP) {
					label := MethodARP
					if ip.Is6() {
						label = labelNDP
					}
					col.add(ip, label, mac, 0, rtt)
				}
			},
		})
		prog.add(int64(count))
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("discovery: neighbour sweep on %s: %w", e.ifi.Name, err)
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if ipUnits == 0 || !r.hasIPMethods() {
		return nil
	}

	// Phase 2: IP probes.
	for _, e := range r.egs {
		spec := rawnet.FilterSpec{DropOutgoing: true}
		if e.src4.IsValid() {
			spec.LocalIPv4 = e.src4
			spec.IPv4Protos = []uint8{rawnet.ProtoICMP, rawnet.ProtoTCP, rawnet.ProtoUDP}
		}
		if e.src6.IsValid() {
			spec.LocalIPv6 = e.src6
			spec.IPv6Protos = []uint8{rawnet.ProtoICMPv6, rawnet.ProtoTCP, rawnet.ProtoUDP}
		}
		h, err := rawnet.OpenHandle(e.ifi, spec)
		if err != nil {
			return err
		}
		e.h = h
	}
	rctx, rcancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, e := range r.egs {
		wg.Add(1)
		go func(e *rawEgress) {
			defer wg.Done()
			r.receive(rctx, e)
		}(e)
	}

	fb := rawnet.NewFrameBuilder()
	batch, budget := limiter.Batch(), 0
	var sendErr error
	visits := int64(0)
send:
	for round := 0; round <= cfg.retries; round++ {
		rp := rawnet.NewPermutation(n, seed^uint64(round+1)*0x9e3779b97f4a7c15)
		for i := uint64(0); i < n; i++ {
			ip := cfg.space.At(rp.At(i))
			p, err := router.Lookup(ip)
			if err != nil || (p.OnLink() && cfg.has(MethodARP)) {
				continue // on-link hosts were decided by the sweep
			}
			visits++
			if visits&255 == 0 {
				prog.add(256)
			}
			if col.up(ip) {
				continue
			}
			l2, src, ok := r.l2For(ctx, p, ip)
			if !ok {
				continue
			}
			e := r.egs[p.Ifi.Index]
			frames := r.buildProbes(fb, l2, src, ip, round)
			for _, f := range frames {
				if budget == 0 {
					if err := limiter.Wait(ctx, batch); err != nil {
						sendErr = err
						break send
					}
					budget = batch
				}
				budget--
				if err := e.h.Write(f); err != nil {
					if errors.Is(err, net.ErrClosed) {
						sendErr = err
						break send
					}
					r.log.Debug("discovery: send", "dst", ip, "err", err)
				}
			}
		}
		if round < cfg.retries {
			if err := rawnet.SleepCtx(ctx, min(cfg.wait/2, time.Second)); err != nil {
				sendErr = err
				break
			}
		}
	}
	if sendErr == nil {
		_ = rawnet.SleepCtx(ctx, cfg.wait)
	}
	rcancel()
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if sendErr != nil {
		return sendErr
	}
	return nil
}

func set(ps []uint16) map[uint16]bool {
	m := make(map[uint16]bool, len(ps))
	for _, p := range ps {
		m[p] = true
	}
	return m
}

func (r *rawDisc) hasIPMethods() bool {
	c := r.cfg
	return c.has(MethodICMPEcho) || c.has(MethodICMPTimestamp) || c.has(MethodTCPSyn) || c.has(MethodTCPAck) || c.has(MethodUDP)
}

// egress registers the interface/source of a path.
func (r *rawDisc) egress(p rawnet.Path) (*rawEgress, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.egs[p.Ifi.Index]
	if !ok {
		if len(p.Ifi.HardwareAddr) != 6 {
			return nil, fmt.Errorf("discovery: interface %s has no Ethernet address: %w", p.Ifi.Name, rawnet.ErrUnsupported)
		}
		e = &rawEgress{ifi: p.Ifi}
		r.egs[p.Ifi.Index] = e
	}
	if p.Src.Is4() && !e.src4.IsValid() {
		e.src4 = p.Src
	}
	if p.Src.Is6() && !e.src6.IsValid() {
		e.src6 = p.Src
	}
	return e, nil
}

// l2For returns the Ethernet addressing and source address for dst.
func (r *rawDisc) l2For(ctx context.Context, p rawnet.Path, dst netip.Addr) (rawnet.L2, netip.Addr, bool) {
	e := r.egs[p.Ifi.Index]
	if e == nil {
		return rawnet.L2{}, netip.Addr{}, false
	}
	src := e.src4
	if dst.Is6() {
		src = e.src6
	}
	if !src.IsValid() {
		return rawnet.L2{}, netip.Addr{}, false
	}
	if p.OnLink() {
		m, ok := r.neigh.Lookup(dst)
		if !ok {
			return rawnet.L2{}, netip.Addr{}, false
		}
		return rawnet.L2{SrcMAC: e.ifi.HardwareAddr, DstMAC: m}, src, true
	}
	gw := p.Gateway
	r.mu.Lock()
	m, ok := r.gwMAC[gw]
	failed := r.gwFail[gw]
	r.mu.Unlock()
	if failed {
		return rawnet.L2{}, netip.Addr{}, false
	}
	if !ok {
		var err error
		m, err = r.neigh.Resolve(ctx, e.ifi, src, gw, 3*time.Second)
		r.mu.Lock()
		if err != nil {
			if ctx.Err() == nil {
				r.gwFail[gw] = true
				r.log.Warn("discovery: cannot resolve gateway MAC", "gateway", gw, "err", err)
			}
			r.mu.Unlock()
			return rawnet.L2{}, netip.Addr{}, false
		}
		r.gwMAC[gw] = m
		r.mu.Unlock()
	}
	return rawnet.L2{SrcMAC: e.ifi.HardwareAddr, DstMAC: m}, src, true
}

// buildProbes returns the frames of one host burst. Frames are copied
// because FrameBuilder reuses its buffer.
func (r *rawDisc) buildProbes(fb *rawnet.FrameBuilder, l2 rawnet.L2, src, dst netip.Addr, round int) [][]byte {
	var out [][]byte
	keep := func(f []byte, err error) {
		if err != nil {
			r.log.Debug("discovery: build probe", "dst", dst, "err", err)
			return
		}
		out = append(out, append([]byte(nil), f...))
	}
	c := r.cfg
	if c.has(MethodICMPEcho) {
		var pl [16]byte
		binary.BigEndian.PutUint64(pl[:8], uint64(time.Since(r.start)))
		copy(pl[8:], "nety-png")
		keep(fb.ICMPEcho(l2, src, dst, 64, r.cookie.Sum16(dst, 0, 0, rawnet.TagICMPEcho), uint16(round+1), pl[:]))
	}
	if c.has(MethodICMPTimestamp) && dst.Is4() {
		keep(fb.ICMPTimestamp(l2, src, dst, 64, r.cookie.Sum16(dst, 0, 0, rawnet.TagICMPTimestamp), uint16(round+1), msSinceMidnightUTC()))
	}
	if c.has(MethodTCPSyn) {
		for _, port := range c.tcpPorts {
			sp := r.sport(dst, port, rawnet.TagTCPSyn)
			keep(fb.TCP(l2, src, dst, 64, rawnet.TCPParams{
				SrcPort: sp, DstPort: port, Flags: rawnet.TCPSyn,
				Seq: r.cookie.Sum32(dst, port, sp, rawnet.TagTCPSyn), SynOptions: true, TSval: r.tsNow(),
			}))
		}
	}
	if c.has(MethodTCPAck) {
		for _, port := range c.ackPorts {
			sp := r.sport(dst, port, rawnet.TagTCPAck)
			keep(fb.TCP(l2, src, dst, 64, rawnet.TCPParams{
				SrcPort: sp, DstPort: port, Flags: rawnet.TCPAck,
				Seq: r.cookie.Sum32(dst, port, sp, rawnet.TagTCPSyn^0x40), Ack: r.cookie.Sum32(dst, port, sp, rawnet.TagTCPAck),
			}))
		}
	}
	if c.has(MethodUDP) {
		for _, port := range c.udpPorts {
			sp := r.sport(dst, port, rawnet.TagUDP)
			for _, pl := range portscan.UDPPayloads(port) {
				keep(fb.UDP(l2, src, dst, 64, sp, port, pl))
			}
		}
	}
	return out
}

func msSinceMidnightUTC() uint32 {
	now := time.Now().UTC()
	y, m, d := now.Date()
	return uint32(now.Sub(time.Date(y, m, d, 0, 0, 0, 0, time.UTC)) / time.Millisecond)
}

// receive validates replies and feeds the collector.
func (r *rawDisc) receive(ctx context.Context, e *rawEgress) {
	buf := make([]byte, 65536)
	var p rawnet.Packet
	for ctx.Err() == nil {
		nr, err := e.h.Read(buf, time.Now().Add(100*time.Millisecond))
		if err != nil {
			if ctx.Err() == nil {
				r.log.Error("discovery: read", "iface", e.ifi.Name, "err", err)
			}
			return
		}
		if nr == 0 || !rawnet.ParseFrame(buf[:nr], &p) || !p.IsIP || p.Fragment {
			continue
		}
		if method, rtt, ok := r.classify(&p); ok {
			r.col.add(p.Src, method, nil, p.TTL, rtt)
		}
	}
}

// classify validates a reply and names the method it answers.
func (r *rawDisc) classify(p *rawnet.Packet) (string, time.Duration, bool) {
	src := p.Src.Unmap()
	if !r.cfg.space.Contains(src) {
		return "", 0, false
	}
	switch p.Proto {
	case rawnet.ProtoICMP, rawnet.ProtoICMPv6:
		switch {
		case (p.Proto == rawnet.ProtoICMP && p.ICMPType == rawnet.ICMPv4EchoReply) ||
			(p.Proto == rawnet.ProtoICMPv6 && p.ICMPType == rawnet.ICMPv6EchoReply):
			if p.ICMPID != r.cookie.Sum16(src, 0, 0, rawnet.TagICMPEcho) {
				return "", 0, false
			}
			var rtt time.Duration
			if len(p.Payload) >= 8 {
				if d := time.Since(r.start) - time.Duration(binary.BigEndian.Uint64(p.Payload[:8])); d > 0 && d < time.Minute {
					rtt = d
				}
			}
			return MethodICMPEcho, rtt, true
		case p.Proto == rawnet.ProtoICMP && p.ICMPType == rawnet.ICMPv4TimestampReply:
			if p.ICMPID != r.cookie.Sum16(src, 0, 0, rawnet.TagICMPTimestamp) {
				return "", 0, false
			}
			return MethodICMPTimestamp, 0, true
		case p.HasInner && p.InnerProto == rawnet.ProtoUDP && p.InnerDst.Unmap() == src &&
			((p.Proto == rawnet.ProtoICMP && p.ICMPType == rawnet.ICMPv4Unreachable) ||
				(p.Proto == rawnet.ProtoICMPv6 && p.ICMPType == rawnet.ICMPv6Unreachable)):
			// Port unreachable generated by the target itself: it is up.
			if r.udpPort[p.InnerDstPort] && p.InnerSrcPort == r.sport(src, p.InnerDstPort, rawnet.TagUDP) {
				return MethodUDP + ":" + strconv.Itoa(int(p.InnerDstPort)), 0, true
			}
		}
	case rawnet.ProtoTCP:
		port := p.SrcPort
		if r.synPort[port] && p.DstPort == r.sport(src, port, rawnet.TagTCPSyn) &&
			p.Flags&rawnet.TCPAck != 0 && p.Ack-1 == r.cookie.Sum32(src, port, p.DstPort, rawnet.TagTCPSyn) {
			var rtt time.Duration
			if p.HasTS && p.TSecr != 0 {
				if d := r.tsNow() - p.TSecr; d < uint32(time.Minute/time.Microsecond) {
					rtt = time.Duration(d) * time.Microsecond
				}
			}
			return MethodTCPSyn + ":" + strconv.Itoa(int(port)), rtt, true
		}
		if r.ackPort[port] && p.DstPort == r.sport(src, port, rawnet.TagTCPAck) && p.Flags&rawnet.TCPRst != 0 &&
			p.Seq == r.cookie.Sum32(src, port, p.DstPort, rawnet.TagTCPAck) {
			return MethodTCPAck + ":" + strconv.Itoa(int(port)), 0, true
		}
	case rawnet.ProtoUDP:
		port := p.SrcPort
		if r.udpPort[port] && p.DstPort == r.sport(src, port, rawnet.TagUDP) {
			return MethodUDP + ":" + strconv.Itoa(int(port)), 0, true
		}
	}
	return "", 0, false
}

// macLookup returns a resolver of MAC addresses from the kernel neighbour
// table, used to enrich hosts found by the unprivileged engine (netlink
// dumps need no privilege). The table is re-read at most once a second.
func (d *Discoverer) macLookup() func(netip.Addr) net.HardwareAddr {
	var (
		mu     sync.Mutex
		table  map[netip.Addr]net.HardwareAddr
		loaded time.Time
	)
	return func(ip netip.Addr) net.HardwareAddr {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(loaded) > time.Second {
			loaded = time.Now()
			table = map[netip.Addr]net.HardwareAddr{}
			const valid = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE | netlink.NUD_PERMANENT
			for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				ns, err := netlink.NeighList(0, fam)
				if err != nil {
					continue
				}
				for _, n := range ns {
					a, ok := netip.AddrFromSlice(n.IP)
					if ok && n.State&valid != 0 && len(n.HardwareAddr) == 6 {
						table[a.Unmap()] = n.HardwareAddr
					}
				}
			}
		}
		if m, ok := table[ip.Unmap()]; ok {
			return append(net.HardwareAddr(nil), m...)
		}
		return nil
	}
}
