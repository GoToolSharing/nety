package netif

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --------------------------------------------------------------------------- Fixture
// builders ---------------------------------------------------------------------------

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// ethII builds an Ethernet II frame.
func ethII(dst, src net.HardwareAddr, etherType uint16, payload []byte) []byte {
	f := make([]byte, 0, 14+len(payload))
	f = append(f, dst...)
	f = append(f, src...)
	f = binary.BigEndian.AppendUint16(f, etherType)
	return append(f, payload...)
}

// eth8023 builds an 802.3 frame with an LLC (optionally SNAP) header.
func eth8023(dst, src net.HardwareAddr, llc []byte) []byte {
	f := make([]byte, 0, 14+len(llc))
	f = append(f, dst...)
	f = append(f, src...)
	f = binary.BigEndian.AppendUint16(f, uint16(len(llc)))
	return append(f, llc...)
}

func snapHeader(oui [3]byte, pid uint16) []byte {
	h := []byte{0xaa, 0xaa, 0x03, oui[0], oui[1], oui[2]}
	return binary.BigEndian.AppendUint16(h, pid)
}

// tagVLAN wraps a frame body (payload after the src MAC) in an 802.1Q tag.
func tagVLAN(frame []byte, vlanID int) []byte {
	out := make([]byte, 0, len(frame)+4)
	out = append(out, frame[:12]...)
	out = binary.BigEndian.AppendUint16(out, etherTypeDot1Q)
	out = binary.BigEndian.AppendUint16(out, uint16(vlanID)&0x0fff)
	return append(out, frame[12:]...)
}

func cdpTLV(typ uint16, val []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(4+len(val)))
	return append(b, val...)
}

// cdpFrame builds a realistic CDPv2 advertisement from a Catalyst switch.
func cdpFrame(src net.HardwareAddr) []byte {
	var p []byte
	p = append(p, 0x02, 0xb4, 0x00, 0x00) // version 2, TTL 180, checksum 0

	p = append(p, cdpTLV(0x0001, []byte("SW-CORE-01.corp.example"))...)
	p = append(p, cdpTLV(0x0003, []byte("GigabitEthernet1/0/24"))...)
	p = append(p, cdpTLV(0x0006, []byte("cisco WS-C3850-48P"))...)
	p = append(p, cdpTLV(0x0005, []byte("Cisco IOS Software, IOS-XE Software, Version 16.9.4\nCopyright (c) 1986-2019"))...)
	caps := binary.BigEndian.AppendUint32(nil, 0x0001|0x0008) // router + switch
	p = append(p, cdpTLV(0x0004, caps)...)
	p = append(p, cdpTLV(0x000a, binary.BigEndian.AppendUint16(nil, 42))...) // native VLAN

	// Voice VLAN reply: 1 byte app id + 2 byte VLAN.
	p = append(p, cdpTLV(0x000e, []byte{0x01, 0x00, 0x6e})...) // VLAN 110

	// Management address: count(4) + protocol type(1) + proto len(1) + proto(1=0xcc) +
	// address length(2) + address(4).
	addr := binary.BigEndian.AppendUint32(nil, 1)
	addr = append(addr, 0x01, 0x01, 0xcc, 0x00, 0x04, 10, 0, 0, 1)
	p = append(p, cdpTLV(0x0016, addr)...)

	llc := append(snapHeader(ciscoOUI, ciscoPIDCDP), p...)
	return eth8023(CDPMulticast, src, llc)
}

func lldpTLV(typ uint8, val []byte) []byte {
	h := uint16(typ)<<9 | uint16(len(val))&0x1ff
	return append(binary.BigEndian.AppendUint16(nil, h), val...)
}

// lldpFrame builds an LLDP advertisement with the 802.1 PVID and LLDP-MED voice-policy
// TLVs a switch sends to an IP phone port.
func lldpFrame(src net.HardwareAddr) []byte {
	chassis := mac("00:11:22:33:44:55")
	var p []byte
	p = append(p, lldpTLV(1, append([]byte{4}, chassis...))...)           // chassis ID = MAC
	p = append(p, lldpTLV(2, append([]byte{5}, "Gi1/0/24"...))...)        // port ID = iface name
	p = append(p, lldpTLV(3, binary.BigEndian.AppendUint16(nil, 120))...) // TTL
	p = append(p, lldpTLV(4, []byte("Uplink to floor 3"))...)             // port description
	p = append(p, lldpTLV(5, []byte("SW-ACCESS-07"))...)                  // system name
	p = append(p, lldpTLV(6, []byte("Aruba JL255A\nWC.16.10.0012"))...)   // system description
	p = append(p, lldpTLV(7, []byte{0x00, 0x14, 0x00, 0x14})...)          // caps: bridge+router

	mgmt := []byte{5, 1, 10, 0, 0, 2, 2, 0, 0, 0, 24, 0}
	p = append(p, lldpTLV(8, mgmt)...)

	// 802.1 port VLAN ID = 42.
	pvid := []byte{0x00, 0x80, 0xc2, 1}
	pvid = binary.BigEndian.AppendUint16(pvid, 42)
	p = append(p, lldpTLV(127, pvid)...)

	// LLDP-MED network policy: voice, tagged, VLAN 110.
	pol := []byte{0x00, 0x12, 0xbb, 2, byte(1)}
	pol = binary.BigEndian.AppendUint16(pol, 0x4000|(110<<1))
	pol = append(pol, 0x00)
	p = append(p, lldpTLV(127, pol)...)

	p = append(p, lldpTLV(0, nil)...) // end of LLDPDU
	return ethII(LLDPMulticast, src, etherTypeLLDP, p)
}

// stpFrame builds a configuration BPDU.
func stpFrame(src net.HardwareAddr, rootPriority uint16, rootMAC net.HardwareAddr, cost uint32) []byte {
	p := make([]byte, 0, 35)
	p = binary.BigEndian.AppendUint16(p, 0) // protocol id
	p = append(p, 0x00, 0x00, 0x00)         // version, type, flags
	p = binary.BigEndian.AppendUint16(p, rootPriority)
	p = append(p, rootMAC...)
	p = binary.BigEndian.AppendUint32(p, cost)
	p = binary.BigEndian.AppendUint16(p, 0x8001)
	p = append(p, src...)
	p = binary.BigEndian.AppendUint16(p, 0x8018) // port id
	p = binary.BigEndian.AppendUint16(p, 0x0000) // message age
	p = binary.BigEndian.AppendUint16(p, 0x1400) // max age
	p = binary.BigEndian.AppendUint16(p, 0x0200) // hello
	p = binary.BigEndian.AppendUint16(p, 0x0f00) // forward delay

	llc := append([]byte{0x42, 0x42, 0x03}, p...)
	return eth8023(STPMulticast, src, llc)
}

// --------------------------------------------------------------------------- Tests
// ---------------------------------------------------------------------------

func TestDissectEthernetII(t *testing.T) {
	f, err := DissectEthernet(ethII(LLDPMulticast, mac("aa:bb:cc:dd:ee:ff"), etherTypeLLDP, []byte{1, 2, 3}))
	if err != nil {
		t.Fatalf("dissect: %v", err)
	}
	if !f.IsLLDP() {
		t.Errorf("expected LLDP, got ethertype %#04x", f.EtherType)
	}
	if got := f.Src.String(); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("src = %q", got)
	}
	if len(f.VLANs) != 0 {
		t.Errorf("unexpected VLAN tags %v", f.VLANs)
	}
}

func TestDissectEthernetVLANStack(t *testing.T) {
	inner := ethII(LLDPMulticast, mac("aa:bb:cc:dd:ee:ff"), etherTypeLLDP, []byte{1})
	frame := tagVLAN(tagVLAN(inner, 200), 10) // outer 10, inner 200
	f, err := DissectEthernet(frame)
	if err != nil {
		t.Fatalf("dissect: %v", err)
	}
	if len(f.VLANs) != 2 || f.VLANs[0] != 10 || f.VLANs[1] != 200 {
		t.Fatalf("VLANs = %v, want [10 200]", f.VLANs)
	}
	if !f.IsLLDP() {
		t.Errorf("expected LLDP after the tag stack")
	}
}

func TestDissectEthernetShort(t *testing.T) {
	if _, err := DissectEthernet([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected an error on a 3-byte frame")
	}
}

func TestCollectorCDP(t *testing.T) {
	c := NewL2Collector()
	c.Consume(cdpFrame(mac("00:11:22:33:44:55")))
	info := c.Info(time.Now())

	if len(info.Neighbors) != 1 {
		t.Fatalf("neighbors = %d, want 1 (%+v)", len(info.Neighbors), info.Neighbors)
	}
	n := info.Neighbors[0]
	if n.Protocol != "cdp" {
		t.Errorf("protocol = %q", n.Protocol)
	}
	if n.DeviceID != "SW-CORE-01.corp.example" {
		t.Errorf("device id = %q", n.DeviceID)
	}
	if n.PortID != "GigabitEthernet1/0/24" {
		t.Errorf("port id = %q", n.PortID)
	}
	if n.Platform != "cisco WS-C3850-48P" {
		t.Errorf("platform = %q", n.Platform)
	}
	if n.Software != "Cisco IOS Software, IOS-XE Software, Version 16.9.4" {
		t.Errorf("software = %q", n.Software)
	}
	if n.NativeVLAN != 42 {
		t.Errorf("native vlan = %d, want 42", n.NativeVLAN)
	}
	if n.VoiceVLAN != 110 {
		t.Errorf("voice vlan = %d, want 110", n.VoiceVLAN)
	}
	if n.MgmtAddress != "10.0.0.1" {
		t.Errorf("mgmt address = %q, want 10.0.0.1", n.MgmtAddress)
	}
	if !hasString(n.Capabilities, "router") || !hasString(n.Capabilities, "switch") {
		t.Errorf("capabilities = %v, want router+switch", n.Capabilities)
	}
	if info.NativeVLAN != 42 || info.VoiceVLAN != 110 {
		t.Errorf("aggregated VLANs = native %d voice %d", info.NativeVLAN, info.VoiceVLAN)
	}
	if info.CapturedAt == nil {
		t.Error("CapturedAt not stamped")
	}
}

func TestCollectorLLDP(t *testing.T) {
	c := NewL2Collector()
	c.Consume(lldpFrame(mac("00:11:22:33:44:66")))
	info := c.Info(time.Now())

	if len(info.Neighbors) != 1 {
		t.Fatalf("neighbors = %d, want 1 (%+v)", len(info.Neighbors), info.Neighbors)
	}
	n := info.Neighbors[0]
	if n.Protocol != "lldp" {
		t.Errorf("protocol = %q", n.Protocol)
	}
	if n.DeviceID != "SW-ACCESS-07" {
		t.Errorf("device id = %q", n.DeviceID)
	}
	if n.PortID != "Uplink to floor 3" {
		t.Errorf("port id = %q", n.PortID)
	}
	if n.Platform != "Aruba JL255A" {
		t.Errorf("platform = %q", n.Platform)
	}
	if n.Software != "WC.16.10.0012" {
		t.Errorf("software = %q", n.Software)
	}
	if n.MgmtAddress != "10.0.0.2" {
		t.Errorf("mgmt address = %q", n.MgmtAddress)
	}
	if n.NativeVLAN != 42 {
		t.Errorf("pvid = %d, want 42", n.NativeVLAN)
	}
	if n.VoiceVLAN != 110 {
		t.Errorf("voice vlan = %d, want 110", n.VoiceVLAN)
	}
	if !hasString(n.Capabilities, "switch") || !hasString(n.Capabilities, "router") {
		t.Errorf("capabilities = %v", n.Capabilities)
	}
}

func TestCollectorLLDPChassisFallback(t *testing.T) {
	// A neighbour that advertises no system name falls back to the chassis ID.
	chassis := mac("00:11:22:33:44:55")
	var p []byte
	p = append(p, lldpTLV(1, append([]byte{4}, chassis...))...)
	p = append(p, lldpTLV(2, append([]byte{3}, chassis...))...) // port ID = MAC
	p = append(p, lldpTLV(3, binary.BigEndian.AppendUint16(nil, 120))...)
	p = append(p, lldpTLV(0, nil)...)

	c := NewL2Collector()
	c.Consume(ethII(LLDPMulticast, chassis, etherTypeLLDP, p))
	info := c.Info(time.Now())
	if len(info.Neighbors) != 1 {
		t.Fatalf("neighbors = %d", len(info.Neighbors))
	}
	if info.Neighbors[0].DeviceID != "00:11:22:33:44:55" {
		t.Errorf("device id = %q, want the chassis MAC", info.Neighbors[0].DeviceID)
	}
	if info.Neighbors[0].PortID != "00:11:22:33:44:55" {
		t.Errorf("port id = %q", info.Neighbors[0].PortID)
	}
}

func TestCollectorSTPPicksLowestCostRoot(t *testing.T) {
	c := NewL2Collector()
	c.Consume(stpFrame(mac("00:11:22:33:44:55"), 0x8000|10, mac("aa:aa:aa:00:00:01"), 40))
	c.Consume(stpFrame(mac("00:11:22:33:44:66"), 0x8000|10, mac("bb:bb:bb:00:00:02"), 4))
	info := c.Info(time.Now())
	if info.STPRootBridge != "32768.10/bb:bb:bb:00:00:02" {
		t.Errorf("stp root = %q", info.STPRootBridge)
	}
}

func TestParseDTPRoundTrip(t *testing.T) {
	src := mac("00:11:22:33:44:77")
	frame := BuildDTPFrame(src, "CORP", DTPStatusDesirable, DTPTypeDot1Q)

	f, err := DissectEthernet(frame)
	if err != nil {
		t.Fatalf("dissect: %v", err)
	}
	if !f.IsDTP() {
		t.Fatalf("frame not recognised as DTP (snap=%v oui=%x pid=%#04x)", f.IsSNAP, f.SNAPOUI, f.SNAPPID)
	}
	if f.Dst.String() != CDPMulticast.String() {
		t.Errorf("dst = %s, want the Cisco multicast address", f.Dst)
	}
	d, err := ParseDTP(f.Payload)
	if err != nil {
		t.Fatalf("parse dtp: %v", err)
	}
	if d.Domain != "CORP" {
		t.Errorf("domain = %q", d.Domain)
	}
	if d.Mode != "desirable" || !d.OffersTrunk() {
		t.Errorf("mode = %q offers=%v", d.Mode, d.OffersTrunk())
	}
	if d.TypeName != "dot1q" {
		t.Errorf("type = %q", d.TypeName)
	}
	if d.Neighbor.String() != src.String() {
		t.Errorf("neighbor = %s", d.Neighbor)
	}
	if len(frame) < 60 {
		t.Errorf("frame is %d bytes, below the 60-byte Ethernet minimum", len(frame))
	}
}

func TestDTPModes(t *testing.T) {
	cases := []struct {
		status   uint8
		mode     string
		offers   bool
		trunking bool
	}{
		{DTPStatusOn, "on", true, false},
		{DTPStatusAccess, "access", false, false},
		{DTPStatusDesirable, "desirable", true, false},
		{DTPStatusAuto, "auto", true, false},
		{0x80 | DTPStatusDesirable, "desirable", true, true},
		{0x80 | DTPStatusAccess, "access", false, true},
	}
	for _, c := range cases {
		frame := BuildDTPFrame(mac("00:11:22:33:44:77"), "", c.status, DTPTypeDot1Q)
		f, err := DissectEthernet(frame)
		if err != nil {
			t.Fatalf("dissect: %v", err)
		}
		d, err := ParseDTP(f.Payload)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if d.Mode != c.mode || d.OffersTrunk() != c.offers || d.Trunking != c.trunking {
			t.Errorf("status %#02x: mode=%q offers=%v trunking=%v, want %q/%v/%v",
				c.status, d.Mode, d.OffersTrunk(), d.Trunking, c.mode, c.offers, c.trunking)
		}
	}
}

func TestCollectorDTPAndObservedVLANs(t *testing.T) {
	c := NewL2Collector()
	c.Consume(BuildDTPFrame(mac("00:11:22:33:44:77"), "CORP", DTPStatusAuto, DTPTypeDot1Q))
	// Tagged data frames on the wire reveal which VLANs the port carries.
	c.Consume(tagVLAN(ethII(mac("ff:ff:ff:ff:ff:ff"), mac("00:00:00:00:00:01"), 0x0806, make([]byte, 28)), 30))
	c.Consume(tagVLAN(ethII(mac("ff:ff:ff:ff:ff:ff"), mac("00:00:00:00:00:01"), 0x0806, make([]byte, 28)), 10))
	c.Consume(tagVLAN(ethII(mac("ff:ff:ff:ff:ff:ff"), mac("00:00:00:00:00:01"), 0x0806, make([]byte, 28)), 10))

	info := c.Info(time.Now())
	if !info.DTPSeen || info.DTPMode != "auto" {
		t.Errorf("dtp seen=%v mode=%q", info.DTPSeen, info.DTPMode)
	}
	if len(info.ObservedVLANs) != 2 || info.ObservedVLANs[0] != 10 || info.ObservedVLANs[1] != 30 {
		t.Errorf("observed vlans = %v, want sorted [10 30]", info.ObservedVLANs)
	}
	if d := c.LastDTP(); d.Domain != "CORP" {
		t.Errorf("LastDTP domain = %q", d.Domain)
	}
}

func TestCollectorDedupAndMerge(t *testing.T) {
	c := NewL2Collector()
	src := mac("00:11:22:33:44:55")
	c.Consume(cdpFrame(src))
	c.Consume(cdpFrame(src))
	c.Consume(lldpFrame(src))
	info := c.Info(time.Now())
	if len(info.Neighbors) != 2 {
		t.Fatalf("neighbors = %d, want 2 (one per protocol)", len(info.Neighbors))
	}
	if c.Frames() != 3 {
		t.Errorf("frames = %d, want 3", c.Frames())
	}
}

func TestCollectorIgnoresGarbage(t *testing.T) {
	c := NewL2Collector()
	c.Consume(nil)
	c.Consume([]byte{0xde, 0xad})
	c.Consume(make([]byte, 64)) // all zeroes: 802.3 length 0, no LLC
	info := c.Info(time.Now())
	if len(info.Neighbors) != 0 || info.DTPSeen || info.STPRootBridge != "" {
		t.Errorf("garbage produced %+v", info)
	}
	if info.CapturedAt != nil {
		t.Error("CapturedAt stamped although nothing was decoded")
	}
}

func TestCDPFrameInsideVLANTag(t *testing.T) {
	// On a trunk, control frames can arrive tagged.
	c := NewL2Collector()
	c.Consume(tagVLAN(cdpFrame(mac("00:11:22:33:44:55")), 42))
	info := c.Info(time.Now())
	if len(info.Neighbors) != 1 {
		t.Fatalf("tagged CDP not decoded: %+v", info)
	}
	if len(info.ObservedVLANs) != 1 || info.ObservedVLANs[0] != 42 {
		t.Errorf("observed vlans = %v", info.ObservedVLANs)
	}
}

func hasString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
