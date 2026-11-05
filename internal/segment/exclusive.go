package segment

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

// Techniques that change the operator's machine or the client's switch. They run one
// group at a time, and every change is pushed onto the cleanup stack the instant it
// succeeds, so an abort between two steps still unwinds what has been done so far.

func (t *Tester) runExclusive(ctx context.Context, opts engine.SegmentOptions, g exclusiveGroup, cl *cleanup, em *emitter, log *slog.Logger) {
	depth := cl.depth()
	defer func() {
		if err := cl.unwindTo(depth, log); err != nil {
			log.Error("segment: could not revert a technique's changes", "technique", g.tech, "err", err)
		}
	}()

	switch g.tech {
	case model.TechGatewayRoute, model.TechAltGateway:
		t.runRouteGroup(ctx, opts, g, cl, em, log)
	case model.TechDot1QSubif, model.TechDTPTrunk:
		t.runVLANGroup(ctx, opts, g, cl, em, log)
	case model.TechDoubleTag:
		t.runDoubleTagGroup(ctx, opts, g, em, log)
	default:
		t.errorResults(g.jobs, model.ReachError, "unsupported technique "+g.tech, em)
	}
}

// ---------------------------------------------------------------------------
// gateway-route / alt-gateway
// ---------------------------------------------------------------------------

// runRouteGroup installs one route to the target prefix through a candidate next hop,
// tests every target behind it, then removes the route. It answers "would the router
// forward this if the client only knew the way?", which is a different question from "is
// there a path configured today".
func (t *Tester) runRouteGroup(ctx context.Context, opts engine.SegmentOptions, g exclusiveGroup, cl *cleanup, em *emitter, log *slog.Logger) {
	if !g.via.IsValid() {
		t.errorResults(g.jobs, model.ReachError, "no next hop to route through", em)
		return
	}
	if !g.prefix.IsValid() {
		t.errorResults(g.jobs, model.ReachError, "target prefix unknown", em)
		return
	}

	note := ""
	preexisting := t.sys.HasRoute(g.jobs[0].ip)
	if preexisting {
		note = "a route to the target already existed, so none was installed: "
		log.Debug("segment: route already present, testing through it",
			"prefix", g.prefix, "technique", g.tech)
	} else {
		if err := t.sys.AddRoute(g.prefix, g.via, opts.Interface); err != nil {
			t.errorResults(g.jobs, model.ReachError,
				fmt.Sprintf("could not install a route to %s via %s: %v", g.prefix, g.via, err), em)
			return
		}
		cl.push(fmt.Sprintf("remove route %s via %s", g.prefix, g.via), func() error {
			return t.sys.UndoRoute(g.prefix, g.via, opts.Interface)
		})
		note = fmt.Sprintf("route %s via %s installed for the test: ", g.prefix, g.via)
		log.Info("segment: temporary route installed", "prefix", g.prefix, "via", g.via, "technique", g.tech)
	}

	t.probeJobs(ctx, opts, g.jobs, em, func(j job) job { return j }, note)
}

// --------------------------------------------------------------------------- dot1q-subif
// / dtp-trunk ---------------------------------------------------------------------------

// runVLANGroup creates a tagged sub-interface for one VLAN, gives it an address, routes
// the target prefix through it and tests from inside that VLAN. For dtp-trunk it first
// asks the switch port to become a trunk.
func (t *Tester) runVLANGroup(ctx context.Context, opts engine.SegmentOptions, g exclusiveGroup, cl *cleanup, em *emitter, log *slog.Logger) {
	parent := opts.Interface
	if parent == "" {
		t.errorResults(g.jobs, model.ReachError, "no interface to build the sub-interface on", em)
		return
	}
	if g.vlanID < 1 || g.vlanID > 4094 {
		t.errorResults(g.jobs, model.ReachError, "target VLAN id unknown; set it on the network or pass VLANIDs", em)
		return
	}

	note := ""
	if g.tech == model.TechDTPTrunk {
		domain := vtpDomain(opts.L2)
		if err := t.sys.RequestTrunk(ctx, parent, domain, dtpSettle); err != nil {
			t.errorResults(g.jobs, model.ReachError, "DTP trunk negotiation failed: "+err.Error(), em)
			return
		}
		cl.push("advertise DTP access mode on "+parent, func() error {
			return t.sys.ReleaseTrunk(parent, domain)
		})
		note = "after requesting an 802.1Q trunk over DTP (the switch may need up to 90s to drop it again): "
		log.Warn("segment: DTP trunk requested", "iface", parent, "vlan", g.vlanID,
			"note", "the port stays trunking until the switch's DTP timer expires")
	}

	name, err := t.sys.AddVLAN(parent, g.vlanID)
	if err != nil {
		t.errorResults(g.jobs, model.ReachError,
			fmt.Sprintf("could not create a sub-interface for VLAN %d on %s: %v", g.vlanID, parent, err), em)
		return
	}
	cl.push("delete sub-interface "+name, func() error { return t.sys.UndoVLAN(name) })
	log.Info("segment: sub-interface created", "iface", name, "vlan", g.vlanID)

	addr, gw, how, err := t.addressSubif(ctx, name, g, opts)
	if err != nil {
		t.errorResults(g.jobs, model.ReachError,
			fmt.Sprintf("VLAN %d sub-interface %s has no usable address: %v", g.vlanID, name, err), em)
		return
	}
	// Pushed after the sub-interface was created, so it runs before the interface is
	// deleted: a DHCPRELEASE needs the interface to leave on.
	cl.push("release the DHCP lease on "+name, func() error { return t.sys.ReleaseDHCP(name) })
	cl.push(fmt.Sprintf("remove address %s from %s", addr, name), func() error {
		return t.sys.UndoAddr(name, addr)
	})
	note += fmt.Sprintf("tested from %s on VLAN %d (%s): ", addr.Addr(), g.vlanID, how)

	// Route the target prefix out of the sub-interface so the probes do not follow the
	// main routing table back out of the untagged interface.
	if g.prefix.IsValid() && !addr.Contains(g.jobs[0].ip) {
		if err := t.sys.AddRoute(g.prefix, gw, name); err != nil {
			log.Warn("segment: could not route the target prefix through the sub-interface",
				"prefix", g.prefix, "iface", name, "err", err)
		} else {
			cl.push(fmt.Sprintf("remove route %s dev %s", g.prefix, name), func() error {
				return t.sys.UndoRoute(g.prefix, gw, name)
			})
		}
	}

	src := addr.Addr()
	t.probeJobs(ctx, opts, g.jobs, em, func(j job) job {
		j.srcAddr = src
		j.iface = name
		return j
	}, note)
}

// addressSubif gives the sub-interface an address: DHCP first, because a lease proves the
// VLAN has a live DHCP server and gives us the right gateway, then the caller-supplied
// static fallback.
func (t *Tester) addressSubif(ctx context.Context, name string, g exclusiveGroup, opts engine.SegmentOptions) (netip.Prefix, netip.Addr, string, error) {
	prefix, gw, err := t.sys.DHCP(ctx, name, dhcpTimeout)
	if err == nil && prefix.IsValid() {
		return prefix, gw, "address obtained by DHCP", nil
	}
	dhcpErr := err

	prefixes := g.jobs[0].target.TargetPrefixes
	if t.staticFallback != nil {
		if p, sgw, ok := t.staticFallback(g.vlanID, prefixes); ok {
			if aerr := t.sys.AddAddr(name, p); aerr == nil {
				return p, sgw, "static address (no DHCP answer)", nil
			} else {
				return netip.Prefix{}, netip.Addr{}, "", fmt.Errorf("DHCP failed (%v) and the static fallback could not be applied: %w", dhcpErr, aerr)
			}
		}
	}
	return netip.Prefix{}, netip.Addr{}, "", fmt.Errorf("no DHCP answer (%v) and no static fallback for VLAN %d", dhcpErr, g.vlanID)
}

// vtpDomain is the VTP domain to put in the DTP advertisement. model.L2Info does not
// carry it, and an empty (NULL) domain is what switches in the default domain expect,
// which covers the overwhelming majority of access ports; a switch in a named domain
// simply ignores the request.
func vtpDomain(l2 model.L2Info) string { return "" }

// --------------------------------------------------------------------------- double-tag
// ---------------------------------------------------------------------------

// runDoubleTagGroup emits a double-tagged frame per target. The technique is inherently
// one-way, so the normal verdict is "sent"; a reply can still come back along the
// ordinary routed path, and when it does we upgrade the verdict to "reachable", which is
// the strongest possible evidence of a VLAN hop.
func (t *Tester) runDoubleTagGroup(ctx context.Context, opts engine.SegmentOptions, g exclusiveGroup, em *emitter, log *slog.Logger) {
	native := opts.L2.NativeVLAN
	if native == 0 {
		t.errorResults(g.jobs, model.ReachError,
			"the native VLAN of the switch port is unknown (no CDP/LLDP seen); double tagging cannot build the outer tag", em)
		return
	}
	if native == g.vlanID {
		t.errorResults(g.jobs, model.ReachError,
			fmt.Sprintf("the target VLAN %d is the port's native VLAN; double tagging has nothing to escape", g.vlanID), em)
		return
	}
	srcMAC, err := t.sys.InterfaceMAC(opts.Interface)
	if err != nil {
		t.errorResults(g.jobs, model.ReachError, "cannot read the local MAC address: "+err.Error(), em)
		return
	}
	dstMAC := opts.Local.GatewayMAC
	if len(dstMAC) != 6 {
		// Without the gateway's MAC the frame still reaches the switch, which is all
		// double tagging needs; broadcast guarantees it is forwarded.
		dstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	src := opts.Local.LocalIP
	if !src.IsValid() || !src.Is4() {
		t.errorResults(g.jobs, model.ReachError, "no local IPv4 address to use as the inner source", em)
		return
	}

	for _, j := range g.jobs {
		if ctx.Err() != nil {
			return
		}
		if err := em.wait(ctx); err != nil {
			return
		}
		em.emit(resultFor(j, t.doubleTagOne(ctx, opts, j, srcMAC, dstMAC, src, native, g.vlanID, log)))
	}
}

func (t *Tester) doubleTagOne(ctx context.Context, opts engine.SegmentOptions, j job, srcMAC, dstMAC net.HardwareAddr, src netip.Addr, native, vlan int, log *slog.Logger) probeResult {
	magic := make([]byte, 16)
	_, _ = rand.Read(magic)
	id := binary.BigEndian.Uint16(magic[0:2])
	seq := binary.BigEndian.Uint16(magic[2:4])

	frame, err := doubleTagFrame(srcMAC, dstMAC, native, vlan, src, j.ip, id, seq, magic)
	if err != nil {
		return errResult(err.Error())
	}

	// Listen for a reply on the ordinary path before transmitting. The frame itself
	// cannot carry one back: the outer tag is consumed by the trunk.
	reply := make(chan string, 1)
	stop := t.watchEchoReply(ctx, magic, opts.Timeout, reply)
	defer stop()

	if err := t.sys.SendFrames(opts.Interface, frame); err != nil {
		return errResult("could not transmit the double-tagged frame: " + err.Error())
	}
	log.Info("segment: double-tagged frame sent", "target", j.ip, "outer_vlan", native, "inner_vlan", vlan)

	select {
	case peer := <-reply:
		return probeResult{
			Status: model.ReachOpen,
			Detail: fmt.Sprintf("double-tagged frame (outer VLAN %d, inner VLAN %d) was delivered and %s answered on the normal path: the VLAN hop works in both directions",
				native, vlan, peer),
		}
	case <-ctx.Done():
	case <-time.After(opts.Timeout):
	}

	detail := fmt.Sprintf(
		"double-tagged frame sent (outer VLAN %d = the port's native VLAN, inner VLAN %d); 802.1Q double tagging is one-way, so delivery cannot be confirmed from here. "+
			"No reply reached %s, which means either the frame was not injected into VLAN %d or VLAN %d has no route back to this network. "+
			"To confirm, watch for the ICMP echo on a host inside VLAN %d, or re-run with a source address that VLAN %d can route to.",
		native, vlan, src, vlan, vlan, vlan, vlan)
	return probeResult{Status: model.ReachSent, Detail: detail}
}

// watchEchoReply listens for an ICMP echo reply carrying magic and reports the peer that
// sent it. The returned function stops the listener.
func (t *Tester) watchEchoReply(ctx context.Context, magic []byte, timeout time.Duration, out chan<- string) func() {
	var conn *icmp.PacketConn
	for _, network := range []string{"udp4", "ip4:icmp"} {
		c, err := icmp.ListenPacket(network, "0.0.0.0")
		if err == nil {
			conn = c
			break
		}
	}
	if conn == nil {
		return func() {}
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			m, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), buf[:n])
			if err != nil {
				continue
			}
			echo, ok := m.Body.(*icmp.Echo)
			if !ok || len(echo.Data) < len(magic) || string(echo.Data[:len(magic)]) != string(magic) {
				continue
			}
			select {
			case out <- peerString(peer):
			default:
			}
			return
		}
	}()
	return func() {
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}

// --------------------------------------------------------------------------- Shared
// probing loop for the exclusive techniques
// ---------------------------------------------------------------------------

// probeJobs runs the jobs of one exclusive group sequentially (the system state they
// share must not change underneath them) and prefixes every Detail with note, so a reader
// of the report knows what was set up for the test.
func (t *Tester) probeJobs(ctx context.Context, opts engine.SegmentOptions, jobs []job, em *emitter, prepare func(job) job, note string) {
	for _, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		if err := em.wait(ctx); err != nil {
			return
		}
		j = prepare(j)
		spec := probeSpec{
			Technique: j.tech,
			IP:        j.ip,
			Port:      j.target.Port,
			Proto:     j.target.Proto,
			Service:   j.target.ServiceName,
			SrcAddr:   j.srcAddr,
			Iface:     j.iface,
			VLANID:    j.vlanID,
			Timeout:   opts.Timeout,
		}
		pr := t.runProbe(ctx, spec)
		pr.Detail = note + pr.Detail
		em.emit(resultFor(j, pr))
	}
}
