package rawnet

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// ICMP types used by the scanners.
const (
	ICMPv4EchoReply      = 0
	ICMPv4Unreachable    = 3
	ICMPv4EchoRequest    = 8
	ICMPv4TimeExceeded   = 11
	ICMPv4Timestamp      = 13
	ICMPv4TimestampReply = 14
	ICMPv6Unreachable    = 1
	ICMPv6TimeExceeded   = 3
	ICMPv6EchoRequest    = 128
	ICMPv6EchoReply      = 129
)

// Packet is a decoded frame. Slices (MACs, Payload) alias the input buffer: copy them if
// they must outlive the next read.
type Packet struct {
	SrcMAC, DstMAC net.HardwareAddr
	EtherType      uint16
	VLAN           uint16 // 802.1Q VLAN ID when tagged in-band

	// ARP (EtherType 0x0806).
	IsARP        bool
	ARPOp        uint16
	ARPSenderMAC net.HardwareAddr
	ARPSenderIP  netip.Addr
	ARPTargetIP  netip.Addr

	// IP.
	IsIP     bool
	Src, Dst netip.Addr
	TTL      uint8 // hop limit for IPv6
	Proto    uint8
	Fragment bool // non-first fragment: no transport header

	// TCP / UDP.
	SrcPort, DstPort uint16
	Seq, Ack         uint32 // TCP
	Flags            uint8  // TCP
	Window           uint16 // TCP
	HasTS            bool   // TCP timestamp option present
	TSval, TSecr     uint32

	// ICMP / ICMPv6.
	ICMPType, ICMPCode uint8
	ICMPID, ICMPSeq    uint16 // echo / timestamp

	// Payload of UDP, or ICMP body after the 8-byte header.
	Payload []byte

	// Quoted datagram of ICMP errors (unreachable, time exceeded).
	HasInner                   bool
	InnerSrc, InnerDst         netip.Addr
	InnerProto                 uint8
	InnerSrcPort, InnerDstPort uint16
}

// ParseFrame decodes an Ethernet frame into p (reset first). It returns false for
// truncated or uninteresting frames.
func ParseFrame(data []byte, p *Packet) bool {
	*p = Packet{}
	if len(data) < 14 {
		return false
	}
	p.DstMAC = net.HardwareAddr(data[0:6])
	p.SrcMAC = net.HardwareAddr(data[6:12])
	et := binary.BigEndian.Uint16(data[12:14])
	off := 14
	for et == EtherTypeVLAN || et == 0x88a8 {
		if len(data) < off+4 {
			return false
		}
		if p.VLAN == 0 {
			p.VLAN = binary.BigEndian.Uint16(data[off:]) & 0x0fff
		}
		et = binary.BigEndian.Uint16(data[off+2:])
		off += 4
	}
	p.EtherType = et
	switch et {
	case EtherTypeARP:
		return parseARP(data[off:], p)
	case EtherTypeIPv4:
		return parseIPv4(data[off:], p)
	case EtherTypeIPv6:
		return parseIPv6(data[off:], p)
	}
	return false
}

func parseARP(b []byte, p *Packet) bool {
	if len(b) < 28 || binary.BigEndian.Uint16(b[0:]) != 1 || binary.BigEndian.Uint16(b[2:]) != EtherTypeIPv4 ||
		b[4] != 6 || b[5] != 4 {
		return false
	}
	p.IsARP = true
	p.ARPOp = binary.BigEndian.Uint16(b[6:])
	p.ARPSenderMAC = net.HardwareAddr(b[8:14])
	p.ARPSenderIP = netip.AddrFrom4([4]byte(b[14:18]))
	p.ARPTargetIP = netip.AddrFrom4([4]byte(b[24:28]))
	return true
}

func parseIPv4(b []byte, p *Packet) bool {
	if len(b) < 20 || b[0]>>4 != 4 {
		return false
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:]))
	if ihl < 20 || len(b) < ihl {
		return false
	}
	if total >= ihl && total < len(b) {
		b = b[:total] // strip Ethernet padding
	}
	p.IsIP = true
	p.TTL = b[8]
	p.Proto = b[9]
	p.Src = netip.AddrFrom4([4]byte(b[12:16]))
	p.Dst = netip.AddrFrom4([4]byte(b[16:20]))
	if binary.BigEndian.Uint16(b[6:])&0x1fff != 0 {
		p.Fragment = true
		return true
	}
	return parseTransport(b[ihl:], p, false)
}

func parseIPv6(b []byte, p *Packet) bool {
	if len(b) < 40 || b[0]>>4 != 6 {
		return false
	}
	plen := int(binary.BigEndian.Uint16(b[4:]))
	if 40+plen < len(b) {
		b = b[:40+plen]
	}
	p.IsIP = true
	p.TTL = b[7]
	p.Src = netip.AddrFrom16([16]byte(b[8:24]))
	p.Dst = netip.AddrFrom16([16]byte(b[24:40]))
	nh, rest, frag, ok := skipIPv6Ext(b[6], b[40:])
	if !ok {
		return false
	}
	p.Proto = nh
	if frag {
		p.Fragment = true
		return true
	}
	return parseTransport(rest, p, true)
}

// skipIPv6Ext walks IPv6 extension headers. frag is true for a non-first fragment.
func skipIPv6Ext(nh uint8, b []byte) (uint8, []byte, bool, bool) {
	for range 8 {
		switch nh {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(b) < 8 {
				return 0, nil, false, false
			}
			l := (int(b[1]) + 1) * 8
			if len(b) < l {
				return 0, nil, false, false
			}
			nh, b = b[0], b[l:]
		case 44: // fragment
			if len(b) < 8 {
				return 0, nil, false, false
			}
			offset := binary.BigEndian.Uint16(b[2:]) >> 3
			nh, b = b[0], b[8:]
			if offset != 0 {
				return nh, b, true, true
			}
		default:
			return nh, b, false, true
		}
	}
	return 0, nil, false, false
}

func parseTransport(b []byte, p *Packet, v6 bool) bool {
	switch p.Proto {
	case ProtoTCP:
		if len(b) < 20 {
			return false
		}
		p.SrcPort = binary.BigEndian.Uint16(b[0:])
		p.DstPort = binary.BigEndian.Uint16(b[2:])
		p.Seq = binary.BigEndian.Uint32(b[4:])
		p.Ack = binary.BigEndian.Uint32(b[8:])
		hl := int(b[12]>>4) * 4
		p.Flags = b[13]
		p.Window = binary.BigEndian.Uint16(b[14:])
		if hl > 20 && hl <= len(b) {
			parseTCPOptions(b[20:hl], p)
		}
		if hl >= 20 && hl <= len(b) {
			p.Payload = b[hl:]
		}
		return true
	case ProtoUDP:
		if len(b) < 8 {
			return false
		}
		p.SrcPort = binary.BigEndian.Uint16(b[0:])
		p.DstPort = binary.BigEndian.Uint16(b[2:])
		l := int(binary.BigEndian.Uint16(b[4:]))
		if l >= 8 && l <= len(b) {
			b = b[:l]
		}
		p.Payload = b[8:]
		return true
	case ProtoICMP, ProtoICMPv6:
		if (p.Proto == ProtoICMP) == v6 {
			return false
		}
		if len(b) < 8 {
			return false
		}
		p.ICMPType, p.ICMPCode = b[0], b[1]
		p.ICMPID = binary.BigEndian.Uint16(b[4:])
		p.ICMPSeq = binary.BigEndian.Uint16(b[6:])
		p.Payload = b[8:]
		isErr := (!v6 && (p.ICMPType == ICMPv4Unreachable || p.ICMPType == ICMPv4TimeExceeded)) ||
			(v6 && (p.ICMPType == ICMPv6Unreachable || p.ICMPType == ICMPv6TimeExceeded))
		if isErr {
			parseInner(b[8:], p)
		}
		return true
	}
	return true
}

func parseTCPOptions(o []byte, p *Packet) {
	for len(o) > 0 {
		switch o[0] {
		case 0:
			return
		case 1:
			o = o[1:]
			continue
		}
		if len(o) < 2 || int(o[1]) < 2 || int(o[1]) > len(o) {
			return
		}
		if o[0] == 8 && o[1] == 10 {
			p.HasTS = true
			p.TSval = binary.BigEndian.Uint32(o[2:])
			p.TSecr = binary.BigEndian.Uint32(o[6:])
		}
		o = o[o[1]:]
	}
}

// parseInner decodes the datagram quoted in an ICMP error.
func parseInner(b []byte, p *Packet) {
	if len(b) < 1 {
		return
	}
	var tr []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return
		}
		p.InnerProto = b[9]
		p.InnerSrc = netip.AddrFrom4([4]byte(b[12:16]))
		p.InnerDst = netip.AddrFrom4([4]byte(b[16:20]))
		tr = b[ihl:]
	case 6:
		if len(b) < 40 {
			return
		}
		p.InnerSrc = netip.AddrFrom16([16]byte(b[8:24]))
		p.InnerDst = netip.AddrFrom16([16]byte(b[24:40]))
		nh, rest, _, ok := skipIPv6Ext(b[6], b[40:])
		if !ok {
			return
		}
		p.InnerProto = nh
		tr = rest
	default:
		return
	}
	p.HasInner = true
	if (p.InnerProto == ProtoTCP || p.InnerProto == ProtoUDP) && len(tr) >= 4 {
		p.InnerSrcPort = binary.BigEndian.Uint16(tr[0:])
		p.InnerDstPort = binary.BigEndian.Uint16(tr[2:])
	}
}
