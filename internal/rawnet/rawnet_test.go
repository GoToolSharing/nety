package rawnet

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

func TestSipHashVector(t *testing.T) {
	// Reference vector from the SipHash paper: key 00..0f, message 00..0e.
	msg := make([]byte, 15)
	for i := range msg {
		msg[i] = byte(i)
	}
	k0 := uint64(0x0706050403020100)
	k1 := uint64(0x0f0e0d0c0b0a0908)
	if got := SipHash24(k0, k1, msg); got != 0xa129ca6149be45e5 {
		t.Fatalf("siphash = %#x", got)
	}
	if got := SipHash24(k0, k1, nil); got != 0x726fdb47dd0e0e31 {
		t.Fatalf("siphash(empty) = %#x", got)
	}
}

func TestCookie(t *testing.T) {
	c := NewCookieWithKey(1, 2)
	a := netip.MustParseAddr("10.0.0.1")
	if c.Sum32(a, 80, 40000, TagTCPSyn) != c.Sum32(a, 80, 40000, TagTCPSyn) {
		t.Fatal("not deterministic")
	}
	if c.Sum32(a, 80, 40000, TagTCPSyn) == c.Sum32(a, 81, 40000, TagTCPSyn) ||
		c.Sum32(a, 80, 40000, TagTCPSyn) == c.Sum32(a, 80, 40000, TagTCPAck) {
		t.Fatal("collision on distinct inputs")
	}
	if NewCookie() == NewCookie() {
		t.Fatal("random keys equal")
	}
	// 4-in-6 and plain IPv4 must hash differently from IPv6 but equal to each other only if unmapped by caller.
	if c.Sum64(netip.MustParseAddr("::1"), 1, 1, 1) == c.Sum64(a, 1, 1, 1) {
		t.Fatal("v6/v4 collision")
	}
}

func TestPermutationBijection(t *testing.T) {
	for _, n := range []uint64{1, 2, 3, 7, 16, 100, 1000, 4097, 65536 + 3} {
		p := NewPermutation(n, 42)
		seen := make([]bool, n)
		identity := true
		for i := uint64(0); i < n; i++ {
			v := p.At(i)
			if v >= n {
				t.Fatalf("n=%d: At(%d)=%d out of range", n, i, v)
			}
			if seen[v] {
				t.Fatalf("n=%d: duplicate %d", n, v)
			}
			seen[v] = true
			if v != i {
				identity = false
			}
		}
		if n >= 16 && identity {
			t.Fatalf("n=%d: identity permutation", n)
		}
	}
	a, b := NewPermutation(1000, 1), NewPermutation(1000, 2)
	same := 0
	for i := uint64(0); i < 1000; i++ {
		if a.At(i) == b.At(i) {
			same++
		}
	}
	if same > 50 {
		t.Fatalf("seeds too correlated: %d", same)
	}
}

func TestAddrSpace(t *testing.T) {
	s, err := NewAddrSpace(
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.0.128/25"), netip.MustParsePrefix("10.0.1.0/30"), netip.MustParsePrefix("2001:db8::/126")},
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/30"), netip.MustParsePrefix("10.0.0.255/32")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 256-4-1+4+4 {
		t.Fatalf("len %d", s.Len())
	}
	if s.At(0) != netip.MustParseAddr("10.0.0.4") {
		t.Fatalf("At(0)=%s", s.At(0))
	}
	for i := uint64(0); i < s.Len(); i++ {
		a := s.At(i)
		j, ok := s.Index(a)
		if !ok || j != i {
			t.Fatalf("Index(%s)=%d,%v want %d", a, j, ok, i)
		}
	}
	for _, a := range []string{"10.0.0.1", "10.0.0.255", "10.0.2.0", "2001:db8::4", "::ffff:10.0.0.3"} {
		if s.Contains(netip.MustParseAddr(a)) {
			t.Errorf("unexpected %s", a)
		}
	}
	if !s.Contains(netip.MustParseAddr("::ffff:10.0.0.5")) || !s.Contains(netip.MustParseAddr("2001:db8::3")) {
		t.Fatal("missing members")
	}
	if _, err := NewAddrSpace([]netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}, nil); err == nil {
		t.Fatal("expected too-large error")
	}
	big, err := NewAddrSpace([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if err != nil || big.Len() != 0 {
		t.Fatalf("full exclusion: %v %d", err, big.Len())
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(20000, 0)
	ctx := context.Background()
	start := time.Now()
	sent := 0
	for sent < 4000 {
		b := l.Batch()
		if err := l.Wait(ctx, b); err != nil {
			t.Fatal(err)
		}
		sent += b
	}
	el := time.Since(start)
	// 4000 tokens at 20k/s = 200ms (minus initial burst of 200).
	if el < 150*time.Millisecond || el > 600*time.Millisecond {
		t.Fatalf("elapsed %v", el)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if NewLimiter(1, 1).Wait(cctx, 1) == nil {
		t.Fatal("expected ctx error")
	}
	if err := NewLimiter(0, 0).Wait(ctx, 1_000_000); err != nil {
		t.Fatal(err)
	}
}

var (
	macA = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	macB = net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	ip4A = netip.MustParseAddr("192.168.1.10")
	ip4B = netip.MustParseAddr("192.168.1.20")
	ip6A = netip.MustParseAddr("2001:db8::a")
	ip6B = netip.MustParseAddr("2001:db8::b")
)

func TestFramesRoundTrip(t *testing.T) {
	fb := NewFrameBuilder()
	var p Packet

	f, err := fb.TCP(L2{SrcMAC: macA, DstMAC: macB}, ip4A, ip4B, 64, TCPParams{SrcPort: 40000, DstPort: 443, Seq: 0xdeadbeef, Flags: TCPSyn, SynOptions: true, TSval: 1234})
	if err != nil {
		t.Fatal(err)
	}
	if !ParseFrame(f, &p) || !p.IsIP || p.Proto != ProtoTCP || p.Src != ip4A || p.Dst != ip4B ||
		p.SrcPort != 40000 || p.DstPort != 443 || p.Seq != 0xdeadbeef || p.Flags != TCPSyn || !p.HasTS || p.TSval != 1234 || p.TTL != 64 {
		t.Fatalf("tcp parse: %+v", p)
	}
	if p.SrcMAC.String() != macA.String() || p.DstMAC.String() != macB.String() {
		t.Fatal("macs")
	}

	f, err = fb.TCP(L2{SrcMAC: macA, DstMAC: macB}, ip6A, ip6B, 0, TCPParams{SrcPort: 1, DstPort: 2, Flags: TCPAck, Ack: 99})
	if err != nil || !ParseFrame(f, &p) || p.Src != ip6A || p.Ack != 99 || p.Flags != TCPAck {
		t.Fatalf("tcp6: %v %+v", err, p)
	}

	f, err = fb.UDP(L2{SrcMAC: macA, DstMAC: macB}, ip4A, ip4B, 64, 5353, 53, []byte("hello"))
	if err != nil || !ParseFrame(f, &p) || p.Proto != ProtoUDP || string(p.Payload) != "hello" || p.DstPort != 53 {
		t.Fatalf("udp: %v %+v", err, p)
	}

	f, err = fb.ICMPEcho(L2{SrcMAC: macA, DstMAC: macB}, ip4A, ip4B, 64, 0x1234, 7, []byte{1, 2, 3, 4})
	if err != nil || !ParseFrame(f, &p) || p.ICMPType != ICMPv4EchoRequest || p.ICMPID != 0x1234 || p.ICMPSeq != 7 {
		t.Fatalf("icmp: %v %+v", err, p)
	}
	f, err = fb.ICMPEcho(L2{SrcMAC: macA, DstMAC: macB}, ip6A, ip6B, 64, 0x1234, 7, nil)
	if err != nil || !ParseFrame(f, &p) || p.Proto != ProtoICMPv6 || p.ICMPType != ICMPv6EchoRequest || p.ICMPID != 0x1234 {
		t.Fatalf("icmp6: %v %+v", err, p)
	}
	f, err = fb.ICMPTimestamp(L2{SrcMAC: macA, DstMAC: macB}, ip4A, ip4B, 64, 9, 1, 555)
	if err != nil || !ParseFrame(f, &p) || p.ICMPType != ICMPv4Timestamp || len(p.Payload) != 12 {
		t.Fatalf("timestamp: %v %+v", err, p)
	}

	f, err = fb.ARPRequest(macA, ip4A, ip4B)
	if err != nil || !ParseFrame(f, &p) || !p.IsARP || p.ARPOp != 1 || p.ARPSenderIP != ip4A || p.ARPTargetIP != ip4B {
		t.Fatalf("arp: %v %+v", err, p)
	}
	if len(f) < 60 {
		t.Fatal("not padded")
	}

	f, err = fb.NeighborSolicitation(macA, ip6A, ip6B)
	if err != nil || !ParseFrame(f, &p) || p.ICMPType != 135 || p.TTL != 255 {
		t.Fatalf("ns: %v %+v", err, p)
	}
	if g, m := SolicitedNodeMulticast(ip6B); g.String() != "ff02::1:ff00:b" || m.String() != "33:33:ff:00:00:0b" {
		t.Fatalf("solicited node %s %s", g, m)
	}
}

func TestParseICMPError(t *testing.T) {
	fb := NewFrameBuilder()
	// Build the original UDP datagram, then wrap its IP part in an ICMP port unreachable.
	orig, _ := fb.UDP(L2{SrcMAC: macA, DstMAC: macB}, ip4A, ip4B, 64, 33000, 161, []byte("x"))
	inner := append([]byte(nil), orig[14:14+28]...)
	f, err := fb.ICMPEcho(L2{SrcMAC: macB, DstMAC: macA}, ip4B, ip4A, 64, 0, 0, append(make([]byte, 0), inner...))
	if err != nil {
		t.Fatal(err)
	}
	// Patch type/code to 3/3 (checksum irrelevant to the parser).
	f[14+20] = 3
	f[14+20+1] = 3
	var p Packet
	if !ParseFrame(f, &p) || !p.HasInner || p.InnerDst != ip4B || p.InnerProto != ProtoUDP || p.InnerDstPort != 161 || p.InnerSrcPort != 33000 {
		t.Fatalf("inner: %+v", p)
	}
}

func TestBPFFilter(t *testing.T) {
	prog, err := BuildFilter(FilterSpec{
		ARP: true, LocalIPv4: ip4A, LocalIPv6: ip6A,
		IPv4Protos: []uint8{ProtoTCP, ProtoICMP}, IPv6Protos: []uint8{ProtoTCP},
	})
	if err != nil {
		t.Fatal(err)
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	fb := NewFrameBuilder()
	check := func(name string, f []byte, want bool) {
		t.Helper()
		n, err := vm.Run(f)
		if err != nil {
			t.Fatal(err)
		}
		if (n > 0) != want {
			t.Errorf("%s: accepted=%v want %v", name, n > 0, want)
		}
	}
	f, _ := fb.TCP(L2{SrcMAC: macB, DstMAC: macA}, ip4B, ip4A, 64, TCPParams{Flags: TCPSyn | TCPAck})
	check("tcp to us", f, true)
	f, _ = fb.TCP(L2{SrcMAC: macB, DstMAC: macA}, ip4A, ip4B, 64, TCPParams{Flags: TCPSyn})
	check("tcp to other", f, false)
	f, _ = fb.UDP(L2{SrcMAC: macB, DstMAC: macA}, ip4B, ip4A, 64, 1, 2, nil)
	check("udp proto not listed", f, false)
	f, _ = fb.ICMPEcho(L2{SrcMAC: macB, DstMAC: macA}, ip4B, ip4A, 64, 1, 1, nil)
	check("icmp", f, true)
	f, _ = fb.ARPRequest(macB, ip4B, ip4A)
	check("arp for us", f, true)
	f, _ = fb.ARPRequest(macB, ip4B, netip.MustParseAddr("192.168.1.99"))
	check("arp for other", f, false)
	f, _ = fb.TCP(L2{SrcMAC: macB, DstMAC: macA}, ip6B, ip6A, 64, TCPParams{Flags: TCPRst})
	check("tcp6 to us", f, true)
	f, _ = fb.TCP(L2{SrcMAC: macB, DstMAC: macA}, ip6A, ip6B, 64, TCPParams{Flags: TCPRst})
	check("tcp6 to other", f, false)

	if _, err := BuildFilter(FilterSpec{DropOutgoing: true, ARP: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := bpf.Assemble(prog); err != nil {
		t.Fatal(err)
	}
}
