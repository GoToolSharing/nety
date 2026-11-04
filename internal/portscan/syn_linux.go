//go:build linux

package portscan

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
	"github.com/vaadata/nety/internal/rawnet"
)

const synSupported = true

// Ephemeral source port window for SYN probes when no SourcePort is forced.
// It sits above Linux's default ip_local_port_range (32768-60999) so probes
// never collide with the kernel's own connections.
const (
	synPortBase = 61000
	synPortSpan = 4096
)

// egress is one interface used by the SYN scan.
type egress struct {
	ifi  *net.Interface
	h    *rawnet.Handle
	srcs []netip.Addr // source addresses used on this interface
}

// srcIndex returns the index of a in e.srcs, adding it if needed.
func (e *egress) srcIndex(a netip.Addr) int {
	for i, s := range e.srcs {
		if s == a {
			return i
		}
	}
	e.srcs = append(e.srcs, a)
	return len(e.srcs) - 1
}

// synHost is the per-host send plan (compact: a /16 costs ~2 MiB).
type synHost struct {
	mac [6]byte
	eg  uint8
	src uint8 // index into egress.srcs
	ok  bool
}

// synScan is a stateless masscan-style SYN scan:
//
//   - the (host x port) space is walked in a keyed random permutation with
//     O(1) memory; each retry round uses a new permutation and skips probes
//     that already got an answer;
//   - the SYN sequence number is a SipHash cookie of (dst, dport, sport), so
//     SYN-ACKs are validated without per-probe state (ack-1 must equal the
//     cookie); with a fixed SourcePort the cookie alone authenticates replies;
//   - the TCP timestamp option carries the send time, echoed back in TSecr,
//     giving an RTT without state;
//   - each SYN-ACK is answered with a RST so no half-open connection lingers.
//
// The Linux kernel, which has no socket for our probe source ports, also
// answers SYN-ACKs with a RST: this is harmless (masscan users add a
// firewall rule to silence it; we do not touch the firewall).
func (s *Scanner) synScan(ctx context.Context, j *job) error {
	wait := j.opts.Timeout
	if wait <= 0 {
		wait = DefaultSYNWait
	}
	rate := j.opts.Rate
	if rate <= 0 {
		rate = DefaultSYNRate
	}
	limiter := rawnet.NewLimiter(rate, 0)

	router, err := rawnet.NewRouter(j.opts.Interface)
	if err != nil {
		return err
	}
	neigh := rawnet.NewNeighbors(j.log)

	plan, egs, err := s.planSYN(ctx, j, router, neigh, limiter)
	defer func() {
		for _, e := range egs {
			if e.h != nil {
				_ = e.h.Close()
			}
		}
	}()
	if err != nil {
		return err
	}
	if len(egs) == 0 {
		j.log.Warn("syn scan: no reachable host")
		return nil
	}

	n := j.size()
	nPorts := uint64(len(j.ports))
	hidx := newHostIndex(j.hosts)
	pidx := newPortIndex(j.ports)
	done := newDoneSet(n)
	cookie := rawnet.NewCookie()
	start := time.Now()
	fixedSport := j.opts.SourcePort

	sport := func(dst netip.Addr, dport uint16) uint16 {
		if fixedSport != 0 {
			return fixedSport
		}
		return synPortBase + cookie.Sum16(dst, dport, 0, rawnet.TagSrcPort)%synPortSpan
	}
	tsNow := func() uint32 { return uint32(time.Since(start) / time.Microsecond) }

	// Receivers: one per egress interface.
	rctx, rcancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var replies, rsts atomic.Int64
	for _, e := range egs {
		wg.Add(1)
		go func(e *egress) {
			defer wg.Done()
			fb := rawnet.NewFrameBuilder()
			buf := make([]byte, 65536)
			var p rawnet.Packet
			for rctx.Err() == nil {
				nr, err := e.h.Read(buf, time.Now().Add(100*time.Millisecond))
				if err != nil {
					if rctx.Err() == nil {
						j.log.Error("syn scan: read", "iface", e.ifi.Name, "err", err)
					}
					return
				}
				if nr == 0 || !rawnet.ParseFrame(buf[:nr], &p) || !p.IsIP || p.Proto != rawnet.ProtoTCP {
					continue
				}
				h, ok := hidx.get(p.Src)
				if !ok {
					continue
				}
				pi := pidx[p.SrcPort]
				if pi < 0 || p.DstPort != sport(p.Src, p.SrcPort) {
					continue
				}
				expect := cookie.Sum32(p.Src, p.SrcPort, p.DstPort, rawnet.TagTCPSyn)
				idx := uint64(h)*nPorts + uint64(pi)
				switch {
				case p.Flags&(rawnet.TCPSyn|rawnet.TCPAck) == rawnet.TCPSyn|rawnet.TCPAck:
					if p.Ack-1 != expect {
						continue
					}
					replies.Add(1)
					// Tear down the half-open connection ourselves.
					if hp := plan[h]; hp.ok {
						if f, err := fb.TCP(rawnet.L2{SrcMAC: e.ifi.HardwareAddr, DstMAC: hp.mac[:]}, p.Dst, p.Src, 64,
							rawnet.TCPParams{SrcPort: p.DstPort, DstPort: p.SrcPort, Seq: p.Ack, Flags: rawnet.TCPRst}); err == nil {
							_ = e.h.Write(f)
						}
					}
					if done.testAndSet(idx) {
						continue
					}
					var rtt time.Duration
					if p.HasTS && p.TSecr != 0 {
						if d := tsNow() - p.TSecr; d < uint32(60*time.Second/time.Microsecond) {
							rtt = time.Duration(d) * time.Microsecond
						}
					}
					j.emit.emit(engine.PortResult{
						IP: j.hosts[h], Port: p.SrcPort, Proto: model.TCP, State: model.PortOpen,
						Reason: "syn-ack", TTL: p.TTL, RTT: rtt,
					})
				case p.Flags&rawnet.TCPRst != 0:
					// RST to a SYN acknowledges seq+1.
					if p.Flags&rawnet.TCPAck != 0 && p.Ack-1 != expect {
						continue
					}
					rsts.Add(1)
					done.testAndSet(idx) // closed: no retry needed
				}
			}
		}(e)
	}
	stopRecv := func() {
		rcancel()
		wg.Wait()
	}

	// Sender.
	fb := rawnet.NewFrameBuilder()
	seed := rand.Uint64()
	batch := limiter.Batch()
	budget := 0
	var sendErr error
	var sent, skipped int64
	var unreachable int64
	for i := range plan {
		if !plan[i].ok {
			unreachable++
		}
	}
	if unreachable > 0 {
		j.log.Info("syn scan: hosts without layer-2 path skipped", "count", unreachable)
	}
send:
	for round := 0; round <= j.retries; round++ {
		perm := rawnet.NewPermutation(n, seed+uint64(round)*0x9e3779b97f4a7c15)
		for i := uint64(0); i < n; i++ {
			idx := perm.At(i)
			hi, pi := j.split(idx)
			hp := plan[hi]
			if !hp.ok || done.has(idx) {
				skipped++
				if skipped&1023 == 0 {
					j.prog.add(1024)
				}
				continue
			}
			if budget == 0 {
				if err := limiter.Wait(ctx, batch); err != nil {
					sendErr = err
					break send
				}
				budget = batch
			}
			budget--
			e := egs[hp.eg]
			dst, dport := j.hosts[hi], j.ports[pi]
			src := e.srcs[hp.src]
			sp := sport(dst, dport)
			f, err := fb.TCP(rawnet.L2{SrcMAC: e.ifi.HardwareAddr, DstMAC: hp.mac[:]}, src, dst, 64, rawnet.TCPParams{
				SrcPort: sp, DstPort: dport, Flags: rawnet.TCPSyn,
				Seq:        cookie.Sum32(dst, dport, sp, rawnet.TagTCPSyn),
				Window:     64240,
				SynOptions: true, TSval: tsNow(),
			})
			if err != nil {
				j.log.Debug("syn scan: build", "dst", dst, "err", err)
				continue
			}
			if err := e.h.Write(f); err != nil {
				if errors.Is(err, net.ErrClosed) {
					sendErr = err
					break send
				}
				j.log.Debug("syn scan: send", "dst", dst, "err", err)
			}
			sent++
			if sent&255 == 0 {
				j.prog.add(256)
			}
		}
		if round < j.retries {
			// Let in-flight answers land before deciding what to retry.
			if err := rawnet.SleepCtx(ctx, min(wait/2, 500*time.Millisecond)); err != nil {
				sendErr = err
				break
			}
		}
	}
	j.prog.add(sent&255 + skipped&1023)
	if sendErr == nil {
		_ = rawnet.SleepCtx(ctx, wait)
	}
	stopRecv()
	var drops uint32
	for _, e := range egs {
		drops += e.h.Drops()
	}
	j.log.Debug("syn scan done", "sent", sent, "synack", replies.Load(), "rst", rsts.Load(), "kernel_drops", drops)
	if drops > 0 {
		j.log.Warn("syn scan: kernel dropped replies, consider a lower rate", "drops", drops)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if sendErr != nil {
		return sendErr
	}
	return nil
}

// planSYN resolves, for every host, the egress interface and the next-hop
// MAC. On-link hosts are resolved with a rate-limited ARP/NDP sweep (hosts
// that do not answer cannot receive our SYNs and are skipped); routed hosts
// use their gateway's MAC.
func (s *Scanner) planSYN(ctx context.Context, j *job, router *rawnet.Router, neigh *rawnet.Neighbors, lim *rawnet.Limiter) ([]synHost, []*egress, error) {
	plan := make([]synHost, len(j.hosts))
	var egs []*egress
	egByIfi := map[int]int{}
	type sweepSet struct {
		ifi        *net.Interface
		src4, src6 netip.Addr
		hosts      []int
	}
	sweeps := map[int]*sweepSet{}
	gwMAC := map[netip.Addr]net.HardwareAddr{}
	gwFail := map[netip.Addr]bool{}
	var routeErrs int

	for i, h := range j.hosts {
		if ctx.Err() != nil {
			return plan, egs, ctx.Err()
		}
		path, err := router.Lookup(h)
		if err != nil {
			routeErrs++
			if routeErrs <= 5 {
				j.log.Warn("syn scan: no route", "host", h, "err", err)
			}
			continue
		}
		if len(path.Ifi.HardwareAddr) != 6 {
			routeErrs++
			if routeErrs <= 5 {
				j.log.Warn("syn scan: egress interface has no Ethernet address (use connect mode)", "host", h, "iface", path.Ifi.Name)
			}
			continue
		}
		ei, ok := egByIfi[path.Ifi.Index]
		if !ok {
			ei = len(egs)
			if ei > 255 {
				continue
			}
			egByIfi[path.Ifi.Index] = ei
			egs = append(egs, &egress{ifi: path.Ifi})
			neigh.Seed(path.Ifi)
		}
		e := egs[ei]
		si := e.srcIndex(path.Src)
		if si > 255 {
			continue
		}
		plan[i].eg = uint8(ei)
		plan[i].src = uint8(si)

		if path.OnLink() {
			if m, ok := neigh.Lookup(h); ok {
				copy(plan[i].mac[:], m)
				plan[i].ok = true
				continue
			}
			ss := sweeps[path.Ifi.Index]
			if ss == nil {
				ss = &sweepSet{ifi: path.Ifi}
				sweeps[path.Ifi.Index] = ss
			}
			if h.Is4() {
				ss.src4 = path.Src
			} else {
				ss.src6 = path.Src
			}
			ss.hosts = append(ss.hosts, i)
			continue
		}
		gw := path.Gateway
		if m, ok := gwMAC[gw]; ok {
			copy(plan[i].mac[:], m)
			plan[i].ok = true
			continue
		}
		if gwFail[gw] {
			continue
		}
		m, err := neigh.Resolve(ctx, path.Ifi, path.Src, gw, 3*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return plan, egs, ctx.Err()
			}
			gwFail[gw] = true
			j.log.Warn("syn scan: cannot resolve gateway MAC", "gateway", gw, "err", err)
			continue
		}
		gwMAC[gw] = m
		copy(plan[i].mac[:], m)
		plan[i].ok = true
	}
	if routeErrs > 5 {
		j.log.Warn("syn scan: hosts without route", "count", routeErrs)
	}

	for _, ss := range sweeps {
		members := ss.hosts
		j.log.Debug("syn scan: resolving on-link hosts", "iface", ss.ifi.Name, "count", len(members))
		err := neigh.Sweep(ctx, rawnet.SweepOptions{
			Ifi: ss.ifi, Src: ss.src4, SrcV6: ss.src6, Limiter: lim, Retries: 1, Wait: time.Second,
			Targets: func(yield func(netip.Addr) bool) {
				for _, hi := range members {
					if !yield(j.hosts[hi]) {
						return
					}
				}
			},
		})
		if err != nil {
			return plan, egs, fmt.Errorf("portscan: neighbour sweep on %s: %w", ss.ifi.Name, err)
		}
		for _, hi := range members {
			if m, ok := neigh.Lookup(j.hosts[hi]); ok {
				copy(plan[hi].mac[:], m)
				plan[hi].ok = true
			}
		}
	}
	if ctx.Err() != nil {
		return plan, egs, ctx.Err()
	}

	// Open one filtered packet socket per egress interface.
	for _, e := range egs {
		spec := rawnet.FilterSpec{DropOutgoing: true}
		var v4, v6 []netip.Addr
		for _, a := range e.srcs {
			if a.Is4() {
				v4 = append(v4, a)
			} else {
				v6 = append(v6, a)
			}
		}
		if len(v4) > 0 {
			spec.IPv4Protos = []uint8{rawnet.ProtoTCP}
			if len(v4) == 1 {
				spec.LocalIPv4 = v4[0]
			}
		}
		if len(v6) > 0 {
			spec.IPv6Protos = []uint8{rawnet.ProtoTCP}
			if len(v6) == 1 {
				spec.LocalIPv6 = v6[0]
			}
		}
		h, err := rawnet.OpenHandle(e.ifi, spec)
		if err != nil {
			// Close the ones already open; caller closes egs with nil-safe loop.
			for _, o := range egs {
				if o.h != nil {
					_ = o.h.Close()
					o.h = nil
				}
			}
			return plan, nil, err
		}
		e.h = h
	}
	return plan, egs, nil
}
