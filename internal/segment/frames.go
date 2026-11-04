package segment

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// Double tagging in one picture:
//
//	[ dst | src | 0x8100 native | 0x8100 target | IPv4 | ICMP echo ]
//
// The trunk port strips the outer tag because it matches the native VLAN
// (which a trunk sends untagged), and forwards what is left - a frame still
// carrying the target VLAN tag - into the target VLAN. Nothing comes back
// along the same path, which is why the technique is one-way: the reply, if
// any, is routed normally and only arrives if the target VLAN can reach ours.

const (
	etherTypeDot1Q = 0x8100
	etherTypeIPv4  = 0x0800
)

var errNoNativeVLAN = errors.New("segment: the native VLAN of the port is unknown; double tagging needs it")

// doubleTagFrame builds a double-tagged Ethernet frame carrying an ICMP echo
// request from src to dst. icmpID/icmpSeq let the caller recognise a reply on
// the normal path, and magic is echoed back in the payload.
func doubleTagFrame(srcMAC, dstMAC net.HardwareAddr, nativeVLAN, targetVLAN int, src, dst netip.Addr, icmpID, icmpSeq uint16, magic []byte) ([]byte, error) {
	if nativeVLAN < 1 || nativeVLAN > 4094 {
		return nil, errNoNativeVLAN
	}
	if targetVLAN < 1 || targetVLAN > 4094 {
		return nil, errors.New("segment: invalid target VLAN id")
	}
	if !src.Is4() || !dst.Is4() {
		return nil, errors.New("segment: double tagging is implemented for IPv4 only")
	}
	if len(srcMAC) != 6 || len(dstMAC) != 6 {
		return nil, errors.New("segment: double tagging needs both MAC addresses")
	}

	icmpMsg := icmpEchoRequest(icmpID, icmpSeq, magic)
	ip := ipv4Header(src, dst, 1 /* ICMP */, icmpMsg)

	f := make([]byte, 0, 18+len(ip))
	f = append(f, dstMAC...)
	f = append(f, srcMAC...)
	f = binary.BigEndian.AppendUint16(f, etherTypeDot1Q)
	f = binary.BigEndian.AppendUint16(f, uint16(nativeVLAN)&0x0fff)
	f = binary.BigEndian.AppendUint16(f, etherTypeDot1Q)
	f = binary.BigEndian.AppendUint16(f, uint16(targetVLAN)&0x0fff)
	f = binary.BigEndian.AppendUint16(f, etherTypeIPv4)
	f = append(f, ip...)
	for len(f) < 60 {
		f = append(f, 0)
	}
	return f, nil
}

func icmpEchoRequest(id, seq uint16, payload []byte) []byte {
	m := make([]byte, 8, 8+len(payload))
	m[0] = 8 // echo request
	binary.BigEndian.PutUint16(m[4:6], id)
	binary.BigEndian.PutUint16(m[6:8], seq)
	m = append(m, payload...)
	binary.BigEndian.PutUint16(m[2:4], onesComplement(m))
	return m
}

func ipv4Header(src, dst netip.Addr, proto byte, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], 0x1337)
	p[8] = 64
	p[9] = proto
	s := src.As4()
	d := dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:12], onesComplement(p[:20]))
	copy(p[20:], payload)
	return p
}

// onesComplement is the Internet checksum (RFC 1071) over b, which must
// already have its own checksum field zeroed.
func onesComplement(b []byte) uint16 {
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
