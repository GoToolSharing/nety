package segment

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/GoToolSharing/nety/internal/model"
)

// probeSpec is one network probe: what to reach, and from where.
type probeSpec struct {
	Technique string
	IP        netip.Addr
	Port      uint16
	Proto     model.Protocol
	Service   string // service name, used to pick a meaningful UDP payload
	SrcPort   uint16 // 0 = ephemeral
	SrcAddr   netip.Addr
	Iface     string // bind the socket to this interface when set
	VLANID    int
	Timeout   time.Duration
}

// probeResult is the verdict of one probe.
type probeResult struct {
	Status model.ReachStatus
	Detail string
	RTT    time.Duration
}

func errResult(detail string) probeResult {
	return probeResult{Status: model.ReachError, Detail: detail}
}

// prober runs one probe. The Tester holds one so tests can substitute a fake
// and exercise the orchestration without touching the network.
type prober func(ctx context.Context, s probeSpec) probeResult

// netProbe is the production prober.
func (t *Tester) netProbe(ctx context.Context, s probeSpec) probeResult {
	if s.Timeout <= 0 {
		s.Timeout = defaultTimeout
	}
	switch s.Technique {
	case model.TechICMP:
		return icmpEcho(ctx, s)
	case model.TechFragment:
		return t.fragmentProbe(ctx, s)
	}
	if s.Port == 0 {
		// Host-level target: the only thing we can try is an echo.
		return icmpEcho(ctx, s)
	}
	if s.Proto == model.UDP {
		return udpProbe(ctx, s)
	}
	return tcpProbe(ctx, s)
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

func tcpProbe(ctx context.Context, s probeSpec) probeResult {
	laddr, err := localTCPAddr(s)
	if err != nil {
		return errResult(err.Error())
	}
	d := net.Dialer{
		Timeout:   s.Timeout,
		LocalAddr: laddr,
		Control:   dialControl(s.Iface, s.SrcPort != 0),
	}
	network := "tcp4"
	if !s.IP.Is4() {
		network = "tcp6"
	}
	dctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	start := time.Now()
	conn, err := d.DialContext(dctx, network, addrPort(s.IP, s.Port))
	rtt := time.Since(start)
	if err == nil {
		_ = conn.Close()
		return probeResult{Status: model.ReachOpen, Detail: "TCP handshake completed", RTT: rtt}
	}
	// A deadline we set ourselves looks like a timeout to the caller, which is
	// exactly the verdict we want, but a cancelled parent context is not.
	if ctx.Err() != nil {
		return probeResult{Status: model.ReachError, Detail: "cancelled", RTT: rtt}
	}
	st, detail := classify(err)
	return probeResult{Status: st, Detail: detail, RTT: rtt}
}

func localTCPAddr(s probeSpec) (*net.TCPAddr, error) {
	if s.SrcPort == 0 && !s.SrcAddr.IsValid() {
		return nil, nil
	}
	a := &net.TCPAddr{Port: int(s.SrcPort)}
	if s.SrcAddr.IsValid() {
		a.IP = net.IP(s.SrcAddr.AsSlice())
	}
	return a, nil
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

func udpProbe(ctx context.Context, s probeSpec) probeResult {
	var laddr *net.UDPAddr
	if s.SrcPort != 0 || s.SrcAddr.IsValid() {
		laddr = &net.UDPAddr{Port: int(s.SrcPort)}
		if s.SrcAddr.IsValid() {
			laddr.IP = net.IP(s.SrcAddr.AsSlice())
		}
	}
	d := net.Dialer{
		Timeout:   s.Timeout,
		LocalAddr: laddr,
		Control:   dialControl(s.Iface, s.SrcPort != 0),
	}
	network := "udp4"
	if !s.IP.Is4() {
		network = "udp6"
	}
	dctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	conn, err := d.DialContext(dctx, network, addrPort(s.IP, s.Port))
	if err != nil {
		st, detail := classify(err)
		return probeResult{Status: st, Detail: detail}
	}
	defer conn.Close()

	payload := udpPayload(s.Port, s.Service)
	deadline := time.Now().Add(s.Timeout)
	_ = conn.SetDeadline(deadline)

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		st, detail := classifyUDP(err, false)
		return probeResult{Status: st, Detail: detail, RTT: time.Since(start)}
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	rtt := time.Since(start)
	if err == nil && n > 0 {
		return probeResult{
			Status: model.ReachOpen,
			Detail: fmt.Sprintf("UDP service answered with %d bytes", n),
			RTT:    rtt,
		}
	}
	if ctx.Err() != nil {
		return probeResult{Status: model.ReachError, Detail: "cancelled", RTT: rtt}
	}
	st, detail := classifyUDP(err, false)
	return probeResult{Status: st, Detail: detail, RTT: rtt}
}

// ---------------------------------------------------------------------------
// ICMP
// ---------------------------------------------------------------------------

// icmpEcho pings s.IP. It first tries an unprivileged datagram ICMP socket
// (net.ipv4.ping_group_range) and falls back to a raw socket, which needs
// CAP_NET_RAW.
func icmpEcho(ctx context.Context, s probeSpec) probeResult {
	v6 := !s.IP.Is4()
	nets := []string{"udp4", "ip4:icmp"}
	listen := "0.0.0.0"
	if v6 {
		nets = []string{"udp6", "ip6:ipv6-icmp"}
		listen = "::"
	}
	if s.SrcAddr.IsValid() {
		listen = s.SrcAddr.String()
	}

	var conn *icmp.PacketConn
	var lastErr error
	for _, network := range nets {
		c, err := icmp.ListenPacket(network, listen)
		if err == nil {
			conn = c
			break
		}
		lastErr = err
	}
	if conn == nil {
		return errResult("cannot open an ICMP socket: " + lastErr.Error() +
			" (needs CAP_NET_RAW or a permissive net.ipv4.ping_group_range)")
	}
	defer conn.Close()

	magic := make([]byte, 16)
	_, _ = rand.Read(magic)
	id := int(magic[0])<<8 | int(magic[1])
	seq := int(magic[2])<<8 | int(magic[3])

	typ := icmp.Type(ipv4.ICMPTypeEcho)
	if v6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	msg := icmp.Message{
		Type: typ,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: magic},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return errResult("icmp marshal: " + err.Error())
	}

	var dst net.Addr = &net.UDPAddr{IP: net.IP(s.IP.AsSlice())}
	if conn.IPv4PacketConn() == nil && conn.IPv6PacketConn() == nil {
		dst = &net.IPAddr{IP: net.IP(s.IP.AsSlice())}
	}
	// icmp.PacketConn built from "ip4:icmp" wants an *net.IPAddr.
	if isRawICMP(conn) {
		dst = &net.IPAddr{IP: net.IP(s.IP.AsSlice())}
	}

	deadline := time.Now().Add(s.Timeout)
	_ = conn.SetDeadline(deadline)

	start := time.Now()
	if _, err := conn.WriteTo(wire, dst); err != nil {
		st, detail := classify(err)
		return probeResult{Status: st, Detail: detail}
	}

	proto := ipv4.ICMPTypeEcho.Protocol()
	if v6 {
		proto = ipv6.ICMPTypeEchoRequest.Protocol()
	}
	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		rtt := time.Since(start)
		if err != nil {
			if ctx.Err() != nil {
				return probeResult{Status: model.ReachError, Detail: "cancelled", RTT: rtt}
			}
			st, detail := classify(err)
			if st == model.ReachFiltered {
				detail = "no ICMP echo reply (dropped or host silent)"
			}
			return probeResult{Status: st, Detail: detail, RTT: rtt}
		}
		m, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		switch body := m.Body.(type) {
		case *icmp.Echo:
			// The reply must come from the host we are testing. On a raw ICMP
			// socket every reply on the machine is delivered to every socket,
			// so without this a concurrent probe's reply could be credited to
			// this target and put a false "reachable" in the client's matrix.
			if !peerIs(peer, s.IP) {
				continue
			}
			if !matchesEcho(m, body, magic, seq, v6) {
				continue
			}
			return probeResult{
				Status: model.ReachOpen,
				Detail: "ICMP echo reply from " + peerString(peer),
				RTT:    rtt,
			}
		case *icmp.DstUnreach:
			if !quotesTarget(body.Data, s.IP) {
				continue
			}
			return probeResult{
				Status: model.ReachUnreachable,
				Detail: unreachableDetail(m, peer),
				RTT:    rtt,
			}
		case *icmp.TimeExceeded:
			if !quotesTarget(body.Data, s.IP) {
				continue
			}
			return probeResult{
				Status: model.ReachUnreachable,
				Detail: "ICMP time exceeded from " + peerString(peer) + " (routing loop or TTL too small)",
				RTT:    rtt,
			}
		}
	}
}

// peerIs reports whether an ICMP reply came from the address under test.
func peerIs(peer net.Addr, want netip.Addr) bool {
	var got netip.Addr
	switch a := peer.(type) {
	case *net.IPAddr:
		got, _ = netip.AddrFromSlice(a.IP)
	case *net.UDPAddr:
		got, _ = netip.AddrFromSlice(a.IP)
	default:
		parsed, err := netip.ParseAddr(peerString(peer))
		if err != nil {
			return false
		}
		got = parsed
	}
	if !got.IsValid() {
		return false
	}
	return got.Unmap() == want.Unmap()
}

// matchesEcho decides whether an echo reply answers the probe we sent. The
// caller has already checked that it comes from the right host.
func matchesEcho(m *icmp.Message, body *icmp.Echo, magic []byte, seq int, v6 bool) bool {
	// A datagram ICMP socket has its own ID rewritten by the kernel, so the
	// 16 random payload bytes are the reliable discriminator.
	if len(body.Data) >= len(magic) && string(body.Data[:len(magic)]) == string(magic) {
		return true
	}
	// Some middleboxes and a few embedded stacks truncate or rewrite the
	// payload. Falling back to the sequence number is acceptable only because
	// the reply has already been matched to the target address.
	if body.Seq == seq {
		return true
	}
	_ = m
	_ = v6
	return false
}

// quotesTarget checks that an ICMP error quotes a packet we sent to ip.
func quotesTarget(quoted []byte, ip netip.Addr) bool {
	if ip.Is4() {
		if len(quoted) < 20 {
			return false
		}
		ihl := int(quoted[0]&0x0f) * 4
		if ihl < 20 || len(quoted) < ihl {
			return false
		}
		dst, ok := netip.AddrFromSlice(quoted[16:20])
		return ok && dst == ip
	}
	if len(quoted) < 40 {
		return false
	}
	dst, ok := netip.AddrFromSlice(quoted[24:40])
	return ok && dst == ip
}

func unreachableDetail(m *icmp.Message, peer net.Addr) string {
	reason := "destination unreachable"
	switch m.Type {
	case ipv4.ICMPTypeDestinationUnreachable:
		switch m.Code {
		case 0:
			reason = "network unreachable"
		case 1:
			reason = "host unreachable"
		case 2:
			reason = "protocol unreachable"
		case 3:
			reason = "port unreachable"
		case 9:
			reason = "network administratively prohibited"
		case 10:
			reason = "host administratively prohibited"
		case 13:
			reason = "communication administratively prohibited (a filtering device answered)"
		}
	case ipv6.ICMPTypeDestinationUnreachable:
		switch m.Code {
		case 0:
			reason = "no route to destination"
		case 1:
			reason = "administratively prohibited (a filtering device answered)"
		case 3:
			reason = "address unreachable"
		case 4:
			reason = "port unreachable"
		}
	}
	return "ICMP " + reason + " from " + peerString(peer)
}

func peerString(a net.Addr) string {
	if a == nil {
		return "unknown"
	}
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.IPAddr:
		return v.IP.String()
	}
	return a.String()
}

func isRawICMP(c *icmp.PacketConn) bool {
	_, ok := c.LocalAddr().(*net.IPAddr)
	return ok
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func addrPort(ip netip.Addr, port uint16) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

var errNoSource = errors.New("segment: no usable source address")

// sourceAddrFor asks the kernel which local address it would use to reach ip,
// without sending anything (connect on a UDP socket only sets the route).
func sourceAddrFor(ip netip.Addr) (netip.Addr, error) {
	network := "udp4"
	if !ip.Is4() {
		network = "udp6"
	}
	c, err := net.Dial(network, addrPort(ip, 9))
	if err != nil {
		return netip.Addr{}, errors.Join(errNoSource, err)
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errNoSource
	}
	a, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}, errNoSource
	}
	return a.Unmap(), nil
}
