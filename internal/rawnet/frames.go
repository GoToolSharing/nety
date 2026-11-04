package rawnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// TCP flag bits (as found in byte 13 of the TCP header).
const (
	TCPFin uint8 = 0x01
	TCPSyn uint8 = 0x02
	TCPRst uint8 = 0x04
	TCPPsh uint8 = 0x08
	TCPAck uint8 = 0x10
	TCPUrg uint8 = 0x20
)

// BroadcastMAC is ff:ff:ff:ff:ff:ff.
var BroadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// L2 holds the Ethernet addressing of a frame. A non-zero VLAN inserts an
// 802.1Q tag (used by the segmentation engine to emit tagged frames on a
// trunk port); Priority is the PCP field of that tag.
type L2 struct {
	SrcMAC   net.HardwareAddr
	DstMAC   net.HardwareAddr
	VLAN     uint16
	Priority uint8
	// OuterVLAN, when non-zero together with VLAN, produces a double-tagged
	// (QinQ) frame: OuterVLAN is the outer tag, VLAN the inner one.
	OuterVLAN uint16
}

// NDP option types (RFC 4861 §4.6).
const (
	ndpOptSourceLinkAddr uint8 = 1
	ndpOptTargetLinkAddr uint8 = 2
)

// ICMPv6 NDP message types.
const (
	icmpv6NeighborSolicit uint8 = 135
	icmpv6NeighborAdvert  uint8 = 136
)

// SolicitedNodeAddr returns the solicited-node multicast address
// ff02::1:ffXX:XXXX of an IPv6 address.
func SolicitedNodeAddr(ip netip.Addr) netip.Addr {
	b := ip.As16()
	var out [16]byte
	out[0], out[1] = 0xff, 0x02
	out[11] = 0x01
	out[12] = 0xff
	copy(out[13:], b[13:16])
	return netip.AddrFrom16(out)
}

// SolicitedNodeMAC returns the Ethernet multicast address 33:33:ff:XX:XX:XX
// that carries frames for ip's solicited-node group.
func SolicitedNodeMAC(ip netip.Addr) net.HardwareAddr {
	b := ip.As16()
	return net.HardwareAddr{0x33, 0x33, 0xff, b[13], b[14], b[15]}
}

// MulticastMAC maps an IPv6 multicast address to its Ethernet address.
func MulticastMAC(ip netip.Addr) net.HardwareAddr {
	b := ip.As16()
	return net.HardwareAddr{0x33, 0x33, b[12], b[13], b[14], b[15]}
}

// TCPParams describes a TCP segment to build.
type TCPParams struct {
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            uint8
	Window           uint16
	// Options adds a Linux-like SYN option set (MSS, SACK-permitted,
	// timestamps with TSval, window scale). Ignored unless Flags has SYN.
	SynOptions bool
	TSval      uint32
}

// FrameBuilder serializes frames with gopacket/layers into a reusable
// buffer. The returned slice is only valid until the next call. A
// FrameBuilder is not safe for concurrent use: use one per goroutine.
type FrameBuilder struct {
	buf  gopacket.SerializeBuffer
	opts gopacket.SerializeOptions
	ipID uint16
}

// NewFrameBuilder returns a FrameBuilder.
func NewFrameBuilder() *FrameBuilder {
	return &FrameBuilder{
		buf:  gopacket.NewSerializeBufferExpectedSize(64, 256),
		opts: gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ipID: uint16(NewCookie().k0),
	}
}

// init makes a zero-value FrameBuilder usable.
func (b *FrameBuilder) init() {
	if b.buf == nil {
		b.buf = gopacket.NewSerializeBufferExpectedSize(64, 256)
		b.opts = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		b.ipID = uint16(NewCookie().k0)
	}
}

// l2Layers builds the Ethernet header (plus 802.1Q / QinQ tags) carrying
// payload type et, and returns the layer chain to prepend.
func (b *FrameBuilder) l2Layers(l2 L2, et layers.EthernetType) []gopacket.SerializableLayer {
	eth := &layers.Ethernet{SrcMAC: l2.SrcMAC, DstMAC: l2.DstMAC, EthernetType: et}
	if l2.VLAN == 0 {
		return []gopacket.SerializableLayer{eth}
	}
	inner := &layers.Dot1Q{VLANIdentifier: l2.VLAN & 0x0fff, Priority: l2.Priority, Type: et}
	if l2.OuterVLAN == 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		return []gopacket.SerializableLayer{eth, inner}
	}
	eth.EthernetType = layers.EthernetTypeDot1Q
	outer := &layers.Dot1Q{VLANIdentifier: l2.OuterVLAN & 0x0fff, Priority: l2.Priority, Type: layers.EthernetTypeDot1Q}
	return []gopacket.SerializableLayer{eth, outer, inner}
}

// ARPRequest builds a broadcast "who-has dstIP tell srcIP" request.
func (b *FrameBuilder) ARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP netip.Addr) ([]byte, error) {
	return b.ARPRequestL2(L2{SrcMAC: srcMAC, DstMAC: BroadcastMAC}, srcIP, dstIP)
}

// ARPRequestL2 builds an ARP request with explicit layer-2 addressing (so it
// can be broadcast, unicast or 802.1Q tagged).
func (b *FrameBuilder) ARPRequestL2(l2 L2, srcIP, dstIP netip.Addr) ([]byte, error) {
	if !srcIP.Is4() || !dstIP.Is4() {
		return nil, errors.New("rawnet: ARP needs IPv4 addresses")
	}
	if l2.DstMAC == nil {
		l2.DstMAC = BroadcastMAC
	}
	srcMAC := l2.SrcMAC
	s4, d4 := srcIP.As4(), dstIP.As4()
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: s4[:],
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    d4[:],
	}
	return b.serialize(append(b.l2Layers(l2, layers.EthernetTypeARP), arp)...)
}

// ipLayers returns the layer-2 chain, the IP layer (as a serializable layer
// and as a network layer for transport checksums) for src -> dst.
func (b *FrameBuilder) ipLayers(l2 L2, src, dst netip.Addr, ttl uint8, proto layers.IPProtocol) ([]gopacket.SerializableLayer, gopacket.SerializableLayer, gopacket.NetworkLayer, error) {
	if ttl == 0 {
		ttl = 64
	}
	src, dst = src.Unmap(), dst.Unmap()
	switch {
	case src.Is4() && dst.Is4():
		b.ipID++
		ip := &layers.IPv4{
			Version: 4, IHL: 5, TTL: ttl, Protocol: proto, Id: b.ipID,
			SrcIP: src.AsSlice(), DstIP: dst.AsSlice(),
		}
		return b.l2Layers(l2, layers.EthernetTypeIPv4), ip, ip, nil
	case src.Is6() && dst.Is6():
		ip := &layers.IPv6{
			Version: 6, HopLimit: ttl, NextHeader: proto,
			SrcIP: src.AsSlice(), DstIP: dst.AsSlice(),
		}
		return b.l2Layers(l2, layers.EthernetTypeIPv6), ip, ip, nil
	}
	return nil, nil, nil, fmt.Errorf("rawnet: address family mismatch %s -> %s", src, dst)
}

// TCP builds an Ethernet/IP/TCP frame.
func (b *FrameBuilder) TCP(l2 L2, src, dst netip.Addr, ttl uint8, p TCPParams) ([]byte, error) {
	eth, ip, nl, err := b.ipLayers(l2, src, dst, ttl, layers.IPProtocolTCP)
	if err != nil {
		return nil, err
	}
	win := p.Window
	if win == 0 {
		win = 64240
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(p.SrcPort), DstPort: layers.TCPPort(p.DstPort),
		Seq: p.Seq, Ack: p.Ack, Window: win,
		FIN: p.Flags&TCPFin != 0, SYN: p.Flags&TCPSyn != 0, RST: p.Flags&TCPRst != 0,
		PSH: p.Flags&TCPPsh != 0, ACK: p.Flags&TCPAck != 0, URG: p.Flags&TCPUrg != 0,
	}
	if p.SynOptions && p.Flags&TCPSyn != 0 {
		mss := uint16(1460)
		if dst.Unmap().Is6() {
			mss = 1440
		}
		var ts [8]byte
		binary.BigEndian.PutUint32(ts[:4], p.TSval)
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{byte(mss >> 8), byte(mss)}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: ts[:]},
			{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
		}
	}
	if err := tcp.SetNetworkLayerForChecksum(nl); err != nil {
		return nil, err
	}
	return b.serialize(append(eth, ip, tcp)...)
}

// UDP builds an Ethernet/IP/UDP frame.
func (b *FrameBuilder) UDP(l2 L2, src, dst netip.Addr, ttl uint8, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	eth, ip, nl, err := b.ipLayers(l2, src, dst, ttl, layers.IPProtocolUDP)
	if err != nil {
		return nil, err
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(nl); err != nil {
		return nil, err
	}
	return b.serialize(append(eth, ip, udp, gopacket.Payload(payload))...)
}

// ICMPEcho builds an ICMP (IPv4) or ICMPv6 echo request.
func (b *FrameBuilder) ICMPEcho(l2 L2, src, dst netip.Addr, ttl uint8, id, seq uint16, payload []byte) ([]byte, error) {
	if dst.Unmap().Is4() {
		eth, ip, _, err := b.ipLayers(l2, src, dst, ttl, layers.IPProtocolICMPv4)
		if err != nil {
			return nil, err
		}
		icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: id, Seq: seq}
		return b.serialize(append(eth, ip, icmp, gopacket.Payload(payload))...)
	}
	eth, ip, nl, err := b.ipLayers(l2, src, dst, ttl, layers.IPProtocolICMPv6)
	if err != nil {
		return nil, err
	}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
	if err := icmp.SetNetworkLayerForChecksum(nl); err != nil {
		return nil, err
	}
	echo := &layers.ICMPv6Echo{Identifier: id, SeqNumber: seq}
	return b.serialize(append(eth, ip, icmp, echo, gopacket.Payload(payload))...)
}

// NeighborSolicitation builds an ICMPv6 neighbour solicitation for target,
// addressed to its solicited-node multicast group, carrying the source
// link-layer address option.
func (b *FrameBuilder) NeighborSolicitation(srcMAC net.HardwareAddr, src, target netip.Addr) ([]byte, error) {
	return b.NeighborSolicitationL2(L2{SrcMAC: srcMAC, DstMAC: SolicitedNodeMAC(target)}, src, target)
}

// NeighborSolicitationL2 is NeighborSolicitation with explicit layer-2
// addressing (so the frame can be unicast or 802.1Q tagged).
func (b *FrameBuilder) NeighborSolicitationL2(l2 L2, src, target netip.Addr) ([]byte, error) {
	src, target = src.Unmap(), target.Unmap()
	if !src.Is6() || !target.Is6() {
		return nil, errors.New("rawnet: neighbour solicitation needs IPv6 addresses")
	}
	if l2.DstMAC == nil {
		l2.DstMAC = SolicitedNodeMAC(target)
	}
	eth, ip, nl, err := b.ipLayers(l2, src, SolicitedNodeAddr(target), 255, layers.IPProtocolICMPv6)
	if err != nil {
		return nil, err
	}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(icmpv6NeighborSolicit, 0)}
	if err := icmp.SetNetworkLayerForChecksum(nl); err != nil {
		return nil, err
	}
	ns := &layers.ICMPv6NeighborSolicitation{
		TargetAddress: target.AsSlice(),
		Options: layers.ICMPv6Options{{
			Type: layers.ICMPv6Opt(ndpOptSourceLinkAddr),
			Data: l2.SrcMAC,
		}},
	}
	return b.serialize(append(eth, ip, icmp, ns)...)
}

// ICMPTimestamp builds an ICMP timestamp request (IPv4 only).
func (b *FrameBuilder) ICMPTimestamp(l2 L2, src, dst netip.Addr, ttl uint8, id, seq uint16, originate uint32) ([]byte, error) {
	if !dst.Unmap().Is4() {
		return nil, errors.New("rawnet: ICMP timestamp is IPv4 only")
	}
	eth, ip, _, err := b.ipLayers(l2, src, dst, ttl, layers.IPProtocolICMPv4)
	if err != nil {
		return nil, err
	}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimestampRequest, 0), Id: id, Seq: seq}
	var body [12]byte
	binary.BigEndian.PutUint32(body[0:4], originate)
	return b.serialize(append(eth, ip, icmp, gopacket.Payload(body[:]))...)
}

func (b *FrameBuilder) serialize(ls ...gopacket.SerializableLayer) ([]byte, error) {
	// A FrameBuilder is normally made by NewFrameBuilder, but the zero value
	// has a nil buffer and would panic here. Since this sits on the packet
	// sending path, initialise lazily rather than crash the scan.
	b.init()
	if err := b.buf.Clear(); err != nil {
		return nil, err
	}
	if err := gopacket.SerializeLayers(b.buf, b.opts, ls...); err != nil {
		return nil, fmt.Errorf("rawnet: serialize: %w", err)
	}
	out := b.buf.Bytes()
	if len(out) < 60 { // pad to the Ethernet minimum (without FCS)
		pad, err := b.buf.AppendBytes(60 - len(out))
		if err != nil {
			return nil, err
		}
		clear(pad)
		out = b.buf.Bytes()
	}
	return out, nil
}

// SolicitedNodeMulticast returns the solicited-node multicast address of an
// IPv6 address and its Ethernet multicast MAC.
func SolicitedNodeMulticast(target netip.Addr) (netip.Addr, net.HardwareAddr) {
	t := target.As16()
	ip := [16]byte{0xff, 0x02, 11: 0x01, 12: 0xff, 13: t[13], 14: t[14], 15: t[15]}
	return netip.AddrFrom16(ip), net.HardwareAddr{0x33, 0x33, 0xff, t[13], t[14], t[15]}
}

// NeighborAdvertisement extracts (target, link-layer address) from a parsed
// ICMPv6 Neighbor Advertisement. The MAC aliases p's buffer.
func NeighborAdvertisement(p *Packet) (netip.Addr, net.HardwareAddr, bool) {
	if !p.IsIP || p.Proto != ProtoICMPv6 || p.ICMPType != 136 || len(p.Payload) < 16 {
		return netip.Addr{}, nil, false
	}
	target := netip.AddrFrom16([16]byte(p.Payload[:16]))
	opts := p.Payload[16:]
	for len(opts) >= 8 {
		l := int(opts[1]) * 8
		if l == 0 || l > len(opts) {
			break
		}
		if opts[0] == 2 && l >= 8 { // target link-layer address
			return target, net.HardwareAddr(opts[2:8]), true
		}
		opts = opts[l:]
	}
	// No option (solicited unicast NA may omit it): use the frame source.
	return target, p.SrcMAC, true
}
