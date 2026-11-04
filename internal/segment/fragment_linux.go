//go:build linux

package segment

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
)

// fragmentProbe sends a TCP SYN split across two IP fragments. A stateless
// filter that only inspects the first fragment never sees the destination port
// in the second one and may let the whole datagram through; the target's IP
// stack reassembles it and answers normally.
//
// The reply is read from a raw TCP socket, so the probe needs CAP_NET_RAW.
// The kernel has no socket for the source port we used and will send its own
// RST after the SYN-ACK; that is harmless and does not change the verdict,
// which is decided by the first packet we see.
func (t *Tester) fragmentProbe(ctx context.Context, s probeSpec) probeResult {
	if s.Proto == model.UDP {
		return errResult("ip-fragment only applies to TCP targets")
	}
	if !s.IP.Is4() {
		return errResult("ip-fragment is implemented for IPv4 only")
	}
	src := s.SrcAddr
	if !src.IsValid() {
		var err error
		src, err = sourceAddrFor(s.IP)
		if err != nil {
			return errResult(err.Error())
		}
	}

	sport := s.SrcPort
	if sport == 0 {
		sport = uint16(32768 + rand.IntN(28000))
	}
	seq := rand.Uint32()

	// Start listening before transmitting so nothing is missed.
	tcpConn, err := net.ListenPacket("ip4:tcp", src.String())
	if err != nil {
		return errResult("raw TCP socket: " + err.Error() + " (" + engine.ErrNeedPrivileges.Error() + ")")
	}
	defer tcpConn.Close()
	icmpConn, icmpErr := icmp.ListenPacket("ip4:icmp", src.String())
	if icmpErr == nil {
		defer icmpConn.Close()
	}

	tcp := buildSYN(src, s.IP, sport, s.Port, seq)
	frags := fragmentIPv4(src, s.IP, tcp)

	start := time.Now()
	if err := sendRawIPv4(s.IP, frags); err != nil {
		return errResult("send fragments: " + err.Error())
	}

	deadline := time.Now().Add(s.Timeout)
	type reply struct{ r probeResult }
	ch := make(chan reply, 2)

	go func() {
		_ = tcpConn.SetReadDeadline(deadline)
		buf := make([]byte, 1500)
		for {
			n, peer, err := tcpConn.ReadFrom(buf)
			if err != nil {
				ch <- reply{probeResult{Status: model.ReachFiltered,
					Detail: "fragmented SYN sent, no reply (dropped or reassembly refused)"}}
				return
			}
			// Go strips the IPv4 header from "ip4:*" reads.
			if n < 20 {
				continue
			}
			if ip, ok := peer.(*net.IPAddr); !ok || !sameIP(ip.IP, s.IP) {
				continue
			}
			rsport := binary.BigEndian.Uint16(buf[0:2])
			rdport := binary.BigEndian.Uint16(buf[2:4])
			if rsport != s.Port || rdport != sport {
				continue
			}
			flags := buf[13]
			switch {
			case flags&0x04 != 0: // RST
				ch <- reply{probeResult{Status: model.ReachClosed,
					Detail: "fragmented SYN reached the host, port closed (RST)", RTT: time.Since(start)}}
			case flags&0x12 == 0x12: // SYN+ACK
				ch <- reply{probeResult{Status: model.ReachOpen,
					Detail: "fragmented SYN answered with SYN-ACK: the filter was bypassed", RTT: time.Since(start)}}
			default:
				continue
			}
			return
		}
	}()

	if icmpErr == nil {
		go func() {
			_ = icmpConn.SetReadDeadline(deadline)
			buf := make([]byte, 1500)
			for {
				n, peer, err := icmpConn.ReadFrom(buf)
				if err != nil {
					return
				}
				m, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), buf[:n])
				if err != nil {
					continue
				}
				du, ok := m.Body.(*icmp.DstUnreach)
				if !ok || !quotesTarget(du.Data, s.IP) {
					continue
				}
				ch <- reply{probeResult{Status: model.ReachUnreachable,
					Detail: unreachableDetail(m, peer), RTT: time.Since(start)}}
				return
			}
		}()
	}

	select {
	case <-ctx.Done():
		return probeResult{Status: model.ReachError, Detail: "cancelled"}
	case r := <-ch:
		return r.r
	case <-time.After(time.Until(deadline) + 100*time.Millisecond):
		return probeResult{Status: model.ReachFiltered,
			Detail: "fragmented SYN sent, no reply before timeout"}
	}
}

func sameIP(a net.IP, b netip.Addr) bool {
	x, ok := netip.AddrFromSlice(a)
	return ok && x.Unmap() == b
}

// buildSYN builds a 20-byte TCP SYN header with a correct checksum.
func buildSYN(src, dst netip.Addr, sport, dport uint16, seq uint32) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint32(h[4:8], seq)
	h[12] = 5 << 4 // data offset = 5 words, no options
	h[13] = 0x02   // SYN
	binary.BigEndian.PutUint16(h[14:16], 65535)
	binary.BigEndian.PutUint16(h[16:18], tcpChecksum(src, dst, h))
	return h
}

func tcpChecksum(src, dst netip.Addr, tcp []byte) uint16 {
	s := src.As4()
	d := dst.As4()
	var sum uint32
	add16 := func(v uint16) { sum += uint32(v) }
	add16(binary.BigEndian.Uint16(s[0:2]))
	add16(binary.BigEndian.Uint16(s[2:4]))
	add16(binary.BigEndian.Uint16(d[0:2]))
	add16(binary.BigEndian.Uint16(d[2:4]))
	add16(uint16(unix.IPPROTO_TCP))
	add16(uint16(len(tcp)))
	for i := 0; i+1 < len(tcp); i += 2 {
		add16(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if len(tcp)%2 == 1 {
		add16(uint16(tcp[len(tcp)-1]) << 8)
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// fragmentIPv4 splits payload into two IP fragments at an 8-byte boundary.
func fragmentIPv4(src, dst netip.Addr, payload []byte) [][]byte {
	id := uint16(rand.Uint32())
	cut := 8
	if len(payload) <= cut {
		cut = len(payload)
	}
	first := ipv4Packet(src, dst, id, 0, true, payload[:cut])
	second := ipv4Packet(src, dst, id, uint16(cut/8), false, payload[cut:])
	return [][]byte{first, second}
}

func ipv4Packet(src, dst netip.Addr, id, fragOff uint16, more bool, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], id)
	flags := fragOff & 0x1fff
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(p[6:8], flags)
	p[8] = 64 // TTL
	p[9] = unix.IPPROTO_TCP
	s := src.As4()
	d := dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:12], ipChecksum(p[:20]))
	copy(p[20:], payload)
	return p
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// sendRawIPv4 transmits complete IPv4 packets through an IPPROTO_RAW socket,
// which implies IP_HDRINCL.
func sendRawIPv4(dst netip.Addr, packets [][]byte) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return engine.ErrNeedPrivileges
		}
		return err
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrInet4{Addr: dst.As4()}
	for _, p := range packets {
		if err := unix.Sendto(fd, p, 0, sa); err != nil {
			return err
		}
	}
	return nil
}
