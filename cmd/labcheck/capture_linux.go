//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/sys/unix"

	"github.com/GoToolSharing/nety/internal/netif"
	"github.com/GoToolSharing/nety/internal/rawnet"
)

// checkTaggedFrameAccepted proves the 802.1Q frames NETY builds itself are correct, by
// putting one on the wire and seeing a real 802.1Q decoder answer.
//
// Sniffing the parent to read the tag back does not work: Linux keeps the VLAN id out of
// the frame bytes (it travels in skb->vlan_tci and reaches AF_PACKET only as auxiliary
// data), so a capture shows untagged frames whatever we do. Sending is the better test
// anyway: it exercises the frame builder the double-tag technique uses, and the peer's
// VLAN sub-interface only replies if the tag we wrote is the one it is configured for.
func checkTaggedFrameAccepted(parent string, vlanID int, srcIP, dstIP netip.Addr) error {
	srcMAC, err := netif.InterfaceMAC(parent)
	if err != nil {
		return fmt.Errorf("parent MAC: %w", err)
	}
	ifi, err := net.InterfaceByName(parent)
	if err != nil {
		return err
	}

	// Listen for the reply before asking the question.
	conn, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, nil)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", parent, err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}

	frame, err := rawnet.NewFrameBuilder().ARPRequestL2(rawnet.L2{
		SrcMAC: srcMAC,
		DstMAC: rawnet.BroadcastMAC,
		VLAN:   uint16(vlanID),
	}, srcIP, dstIP)
	if err != nil {
		return fmt.Errorf("build the tagged ARP request: %w", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 10 {
			if err := netif.SendFrames(parent, frame); err != nil {
				return
			}
			time.Sleep(120 * time.Millisecond)
		}
	}()
	defer func() { <-done }()

	buf := make([]byte, 1600)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("no ARP reply to our tagged request on VLAN %d: %w", vlanID, err)
		}
		op, sender, ok := parseARPReply(buf[:n])
		if !ok {
			continue
		}
		if op == 2 && sender == dstIP {
			return nil
		}
	}
}

// parseARPReply pulls the operation and sender address out of an ARP frame, tolerating an
// 802.1Q header and stopping at the first malformed field.
func parseARPReply(f []byte) (op uint16, sender netip.Addr, ok bool) {
	if len(f) < 14 {
		return 0, netip.Addr{}, false
	}
	off := 12
	ethertype := binary.BigEndian.Uint16(f[off : off+2])
	for ethertype == 0x8100 || ethertype == 0x88a8 {
		off += 4
		if len(f) < off+2 {
			return 0, netip.Addr{}, false
		}
		ethertype = binary.BigEndian.Uint16(f[off : off+2])
	}
	if ethertype != 0x0806 {
		return 0, netip.Addr{}, false
	}
	arp := f[off+2:]
	if len(arp) < 28 {
		return 0, netip.Addr{}, false
	}
	op = binary.BigEndian.Uint16(arp[6:8])
	a, okAddr := netip.AddrFromSlice(arp[14:18])
	if !okAddr {
		return 0, netip.Addr{}, false
	}
	return op, a, true
}

// checkDTPFrame decodes the DTP advertisement NETY would put on the wire and asserts it
// byte for byte against the protocol.
//
// No switch here will answer it, but a malformed frame would be silently ignored by one
// that would, so the frame itself is worth verifying.
func checkDTPFrame() error {
	src, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		return err
	}
	frame := netif.BuildDTPFrame(src, "", netif.DTPStatusDesirable, netif.DTPTypeDot1Q)
	if len(frame) < 36 {
		return fmt.Errorf("frame is too short: %d bytes", len(frame))
	}

	// Cisco's DTP multicast destination.
	wantDst := []byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}
	if got := frame[0:6]; !equalBytes(got, wantDst) {
		return fmt.Errorf("destination MAC is %x, expected %x", got, wantDst)
	}
	if got := frame[6:12]; !equalBytes(got, src) {
		return fmt.Errorf("source MAC is %x, expected %x", got, src)
	}
	// 802.3 length, then LLC 0xAA 0xAA 0x03 and the SNAP header.
	length := int(binary.BigEndian.Uint16(frame[12:14]))
	if length != len(frame)-14 {
		return fmt.Errorf("802.3 length field is %d, frame payload is %d", length, len(frame)-14)
	}
	if frame[14] != 0xaa || frame[15] != 0xaa || frame[16] != 0x03 {
		return fmt.Errorf("LLC header is %x, expected aaaa03", frame[14:17])
	}
	if got := frame[17:20]; !equalBytes(got, []byte{0x00, 0x00, 0x0c}) {
		return fmt.Errorf("SNAP OUI is %x, expected Cisco 00000c", got)
	}
	if pid := binary.BigEndian.Uint16(frame[20:22]); pid != 0x2004 {
		return fmt.Errorf("SNAP protocol id is %#04x, expected 0x2004 (DTP)", pid)
	}
	if frame[22] != 0x01 {
		return fmt.Errorf("DTP version is %d, expected 1", frame[22])
	}

	// TLVs: 0x0001 domain (36 bytes), 0x0002 status, 0x0003 type, 0x0004 id.
	seen := map[uint16]int{}
	for off := 23; off+4 <= len(frame); {
		typ := binary.BigEndian.Uint16(frame[off : off+2])
		tlvLen := int(binary.BigEndian.Uint16(frame[off+2 : off+4]))
		if tlvLen < 4 || off+tlvLen > len(frame) {
			return fmt.Errorf("TLV %#04x at offset %d has an invalid length %d", typ, off, tlvLen)
		}
		seen[typ] = tlvLen
		if typ == 0x0002 {
			if v := frame[off+4]; v&0x07 != netif.DTPStatusDesirable {
				return fmt.Errorf("status TLV carries %#02x, expected desirable (%#02x)", v, netif.DTPStatusDesirable)
			}
		}
		if typ == 0x0003 {
			if v := frame[off+4]; v != netif.DTPTypeDot1Q {
				return fmt.Errorf("type TLV carries %#02x, expected 802.1Q (%#02x)", v, netif.DTPTypeDot1Q)
			}
		}
		off += tlvLen
	}
	for _, want := range []uint16{0x0001, 0x0002, 0x0003, 0x0004} {
		if _, found := seen[want]; !found {
			return fmt.Errorf("TLV %#04x is missing (present: %v)", want, seen)
		}
	}
	if seen[0x0001] != 36 {
		return fmt.Errorf("domain TLV is %d bytes, IOS sends 36", seen[0x0001])
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
