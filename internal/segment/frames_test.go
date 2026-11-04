package segment

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/GoToolSharing/nety/internal/netif"
)

func TestDoubleTagFrameLayout(t *testing.T) {
	src := net.HardwareAddr{0x02, 0, 0, 0x11, 0x22, 0x33}
	dst := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	magic := []byte("0123456789abcdef")

	frame, err := doubleTagFrame(src, dst, 1, 20,
		netip.MustParseAddr("10.10.0.5"), netip.MustParseAddr("10.20.0.10"), 0x1234, 0x0001, magic)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(frame) < 60 {
		t.Errorf("frame is %d bytes, below the Ethernet minimum", len(frame))
	}

	// The dissector must see the tag stack outer-first.
	f, err := netif.DissectEthernet(frame)
	if err != nil {
		t.Fatalf("dissect: %v", err)
	}
	if len(f.VLANs) != 2 || f.VLANs[0] != 1 || f.VLANs[1] != 20 {
		t.Fatalf("VLAN stack = %v, want [1 20] (native tag outside, target tag inside)", f.VLANs)
	}
	if f.EtherType != etherTypeIPv4 {
		t.Errorf("inner ethertype = %#04x, want IPv4", f.EtherType)
	}
	if f.Src.String() != src.String() || f.Dst.String() != dst.String() {
		t.Errorf("MACs = %s -> %s", f.Src, f.Dst)
	}

	ip := f.Payload
	if ip[0] != 0x45 {
		t.Fatalf("not an IPv4 header: %#02x", ip[0])
	}
	if ip[9] != 1 {
		t.Errorf("protocol = %d, want ICMP", ip[9])
	}
	if got := net.IP(ip[12:16]).String(); got != "10.10.0.5" {
		t.Errorf("source IP = %s", got)
	}
	if got := net.IP(ip[16:20]).String(); got != "10.20.0.10" {
		t.Errorf("destination IP = %s", got)
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total != 20+8+len(magic) {
		t.Errorf("IP total length = %d, want %d", total, 20+8+len(magic))
	}

	// Both checksums must verify: a wrong one would be silently dropped by the
	// first router and the technique would look like a false negative.
	if got := verifyChecksum(ip[:20]); got != 0 {
		t.Errorf("IPv4 header checksum does not verify (%#04x)", got)
	}
	icmpMsg := ip[20:total]
	if got := verifyChecksum(icmpMsg); got != 0 {
		t.Errorf("ICMP checksum does not verify (%#04x)", got)
	}
	if icmpMsg[0] != 8 {
		t.Errorf("ICMP type = %d, want echo request", icmpMsg[0])
	}
	if id := binary.BigEndian.Uint16(icmpMsg[4:6]); id != 0x1234 {
		t.Errorf("ICMP id = %#04x", id)
	}
	if string(icmpMsg[8:]) != string(magic) {
		t.Errorf("payload = %q, want the correlation magic", icmpMsg[8:])
	}
}

// verifyChecksum recomputes the ones-complement sum over a block that already
// contains its checksum; the result must be zero.
func verifyChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func TestDoubleTagFrameRejectsBadInput(t *testing.T) {
	src := net.HardwareAddr{0x02, 0, 0, 0x11, 0x22, 0x33}
	dst := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	v4 := netip.MustParseAddr("10.10.0.5")
	v6 := netip.MustParseAddr("2001:db8::1")

	cases := []struct {
		name           string
		native, vlan   int
		src, dst       netip.Addr
		srcMAC, dstMAC net.HardwareAddr
	}{
		{"no native VLAN", 0, 20, v4, v4, src, dst},
		{"invalid target VLAN", 1, 4095, v4, v4, src, dst},
		{"IPv6 target", 1, 20, v4, v6, src, dst},
		{"short MAC", 1, 20, v4, v4, net.HardwareAddr{1, 2, 3}, dst},
	}
	for _, c := range cases {
		if _, err := doubleTagFrame(c.srcMAC, c.dstMAC, c.native, c.vlan, c.src, c.dst, 1, 1, nil); err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}
}

func TestUDPPayloadsAreServiceSpecific(t *testing.T) {
	cases := []struct {
		port    uint16
		service string
		check   func([]byte) bool
	}{
		{53, "domain", func(b []byte) bool { return len(b) > 12 && b[2] == 0x01 }},
		{123, "", func(b []byte) bool { return len(b) == 48 && b[0] == 0x23 }},
		{161, "", func(b []byte) bool { return len(b) > 2 && b[0] == 0x30 }},
		{137, "", func(b []byte) bool { return len(b) > 12 }},
		{500, "", func(b []byte) bool { return len(b) >= 28 }},
		{1900, "", func(b []byte) bool { return len(b) > 10 && string(b[:8]) == "M-SEARCH" }},
		{69, "", func(b []byte) bool { return len(b) > 2 && b[1] == 0x01 }},
	}
	for _, c := range cases {
		got := udpPayload(c.port, c.service)
		if len(got) == 0 {
			t.Errorf("port %d: empty payload", c.port)
			continue
		}
		if !c.check(got) {
			t.Errorf("port %d: payload %x does not look like the expected request", c.port, got)
		}
	}
	// An unknown service still gets a byte, so the host can answer with an
	// ICMP port-unreachable and be classified as "closed" rather than
	// "filtered".
	if got := udpPayload(9999, "mystery"); len(got) == 0 {
		t.Error("an unknown UDP service must still be probed with something")
	}
}

func TestIKEPayloadLengthField(t *testing.T) {
	b := ikeSA()
	if n := binary.BigEndian.Uint32(b[24:28]); int(n) != len(b) {
		t.Errorf("ISAKMP length field = %d, want %d", n, len(b))
	}
}
