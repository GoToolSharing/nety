// Package rawnet holds the shared raw-packet plumbing used by the discovery and port
// scanning engines: AF_PACKET sockets with classic BPF filters, route / next-hop
// resolution, ARP / neighbour resolution, frame building and parsing, a high-rate token
// bucket, stateless probe validation cookies and an O(1)-memory random permutation over
// huge scan spaces.
//
// The portable pieces (cookies, permutation, address spaces, limiter, frame
// building/parsing, BPF assembly) compile and are tested on every OS. The socket/netlink
// pieces are Linux only; other platforms get stubs returning engine.ErrUnsupported and
// CanRaw() == false.
package rawnet

import (
	"crypto/rand"
	"encoding/binary"
	"math/bits"
	"net/netip"
)

// Cookie is a keyed hash used to validate replies without keeping per-probe state
// (masscan "SYN cookie" scheme): the TCP sequence number, ICMP identifier or UDP source
// port of a probe is derived from a SipHash-2-4 of the probe's (destination IP,
// destination port, source port) under a random per-scan key. A reply is accepted only if
// the field echoed by the target matches the hash recomputed from the reply's addressing.
//
// The scheme does not rely on source-port randomness: with a fixed source port
// (segmentation bypass tests) the 32-bit keyed sequence number alone authenticates
// SYN-ACKs.
type Cookie struct {
	k0, k1 uint64
}

// NewCookie returns a cookie with a fresh random 128-bit key.
func NewCookie() Cookie {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand never fails on supported platforms (Go >= 1.24 it panics internally
		// instead); keep a deterministic fallback anyway.
		binary.LittleEndian.PutUint64(b[:8], 0x736f6d6570736575)
		binary.LittleEndian.PutUint64(b[8:], 0x646f72616e646f6d)
	}
	return Cookie{k0: binary.LittleEndian.Uint64(b[:8]), k1: binary.LittleEndian.Uint64(b[8:])}
}

// NewCookieWithKey builds a cookie from an explicit key (tests, resumable scans).
func NewCookieWithKey(k0, k1 uint64) Cookie { return Cookie{k0: k0, k1: k1} }

// Sum64 returns the 64-bit keyed hash of (dst, dstPort, srcPort, tag). tag distinguishes
// probe families (e.g. SYN vs ACK vs ICMP) so that a reply to one probe type cannot
// validate another.
func (c Cookie) Sum64(dst netip.Addr, dstPort, srcPort uint16, tag uint8) uint64 {
	var msg [21]byte
	a := dst.As16()
	copy(msg[:16], a[:])
	binary.BigEndian.PutUint16(msg[16:], dstPort)
	binary.BigEndian.PutUint16(msg[18:], srcPort)
	msg[20] = tag
	return SipHash24(c.k0, c.k1, msg[:])
}

// Sum32 is the low 32 bits of Sum64 (TCP sequence numbers).
func (c Cookie) Sum32(dst netip.Addr, dstPort, srcPort uint16, tag uint8) uint32 {
	return uint32(c.Sum64(dst, dstPort, srcPort, tag))
}

// Sum16 folds Sum64 into 16 bits (ICMP identifiers, UDP ports).
func (c Cookie) Sum16(dst netip.Addr, dstPort, srcPort uint16, tag uint8) uint16 {
	h := c.Sum64(dst, dstPort, srcPort, tag)
	return uint16(h ^ h>>16 ^ h>>32 ^ h>>48)
}

// Probe family tags for Cookie sums.
const (
	TagTCPSyn uint8 = iota + 1
	TagTCPAck
	TagICMPEcho
	TagICMPTimestamp
	TagUDP
	TagSrcPort
)

// SipHash24 computes SipHash-2-4 of msg under key (k0, k1).
func SipHash24(k0, k1 uint64, msg []byte) uint64 {
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	round := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13)
		v1 ^= v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17)
		v1 ^= v2
		v2 = bits.RotateLeft64(v2, 32)
	}

	n := len(msg)
	p := msg
	for len(p) >= 8 {
		m := binary.LittleEndian.Uint64(p)
		v3 ^= m
		round()
		round()
		v0 ^= m
		p = p[8:]
	}
	var last [8]byte
	copy(last[:], p)
	last[7] = byte(n)
	m := binary.LittleEndian.Uint64(last[:])
	v3 ^= m
	round()
	round()
	v0 ^= m

	v2 ^= 0xff
	round()
	round()
	round()
	round()
	return v0 ^ v1 ^ v2 ^ v3
}
