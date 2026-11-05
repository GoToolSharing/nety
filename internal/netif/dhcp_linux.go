//go:build linux

package netif

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// A small DHCPv4 client built directly on AF_PACKET. It has to be raw: the sub-interfaces
// created by the dot1q-subif / dtp-trunk techniques have no address yet, so a UDP socket
// cannot send the broadcast DISCOVER.

// DHCPAcquire runs a DISCOVER/OFFER/REQUEST/ACK exchange on iface and returns the granted
// lease. It does NOT configure the interface: the caller decides whether to apply it
// (ConfigureDHCP does both).
func DHCPAcquire(ctx context.Context, iface string, cfg DHCPConfig) (Lease, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return Lease{}, fmt.Errorf("netif: interface %q: %w", iface, err)
	}
	mac := cfg.ClientMAC
	if len(mac) == 0 {
		mac = ifi.HardwareAddr
	}
	if len(mac) != 6 {
		return Lease{}, fmt.Errorf("netif: %q has no usable MAC address", iface)
	}

	pcfg := &packet.Config{}
	if prog, err := dhcpClientFilter(); err == nil {
		pcfg.Filter = prog
	}
	conn, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, pcfg)
	if err != nil {
		return Lease{}, fmt.Errorf("netif: AF_PACKET on %q: %w", iface, mapPermErr(err))
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-stop:
		}
	}()

	xid := randomXID()
	var lastErr error
	for attempt := 0; attempt < cfg.retries(); attempt++ {
		lease, err := dhcpRound(ctx, conn, ifi, mac, xid+uint32(attempt), cfg)
		if err == nil {
			lease.Interface = iface
			lease.Source = "dhcp-client"
			if cfg.Release && lease.Server.IsValid() {
				srv, cli := lease.Server, lease.Address
				armDHCPRelease(iface, fmt.Sprintf("release DHCP lease %s on %s", cli, iface),
					func() error { return dhcpRelease(iface, mac, cli, srv) })
			}
			return lease, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no DHCP offer")
	}
	return Lease{}, fmt.Errorf("netif: DHCP on %q: %w", iface, lastErr)
}

func dhcpRound(ctx context.Context, conn *packet.Conn, ifi *net.Interface, mac net.HardwareAddr, xid uint32, cfg DHCPConfig) (Lease, error) {
	discover := NewDHCPDiscover(xid, mac, cfg.Hostname)
	if err := sendDHCP(conn, mac, broadcastMAC, netip.IPv4Unspecified(), netip.AddrFrom4([4]byte{255, 255, 255, 255}), discover); err != nil {
		return Lease{}, err
	}
	offer, srvMAC, err := awaitDHCP(ctx, conn, xid, mac, DHCPOffer)
	if err != nil {
		return Lease{}, err
	}
	server := offer.optAddr(OptServerID)
	if !server.IsValid() {
		server = offer.SIAddr
	}
	req := NewDHCPRequest(xid, mac, cfg.Hostname, offer.YIAddr, server)
	if err := sendDHCP(conn, mac, srvMAC, netip.IPv4Unspecified(), netip.AddrFrom4([4]byte{255, 255, 255, 255}), req); err != nil {
		return Lease{}, err
	}
	ack, _, err := awaitDHCP(ctx, conn, xid, mac, DHCPAck)
	if err != nil {
		return Lease{}, err
	}
	lease := ack.Lease("", time.Now())
	if !lease.Valid() {
		return Lease{}, errors.New("DHCP ACK without an address")
	}
	return lease, nil
}

// awaitDHCP reads frames until a DHCP message of want with matching xid and client MAC
// arrives. It returns the message and the sender's MAC.
func awaitDHCP(ctx context.Context, conn *packet.Conn, xid uint32, mac net.HardwareAddr, want DHCPMessageType) (*DHCPMessage, net.HardwareAddr, error) {
	buf := make([]byte, 1<<16)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, nil, err
		}
		f, derr := DissectEthernet(buf[:n])
		if derr != nil || f.EtherType != uint16(layers.EthernetTypeIPv4) {
			continue
		}
		payload, ok := udpPayload(f.Payload, dhcpServerPort, dhcpClientPort)
		if !ok {
			continue
		}
		m, err := ParseDHCPMessage(payload)
		if err != nil || m.XID != xid || m.Op != 2 {
			continue
		}
		if !macEqual(m.CHAddr, mac) {
			continue
		}
		switch m.Type() {
		case want:
			return m, net.HardwareAddr(append([]byte(nil), f.Src...)), nil
		case DHCPNak:
			msg := ""
			if v, ok := m.Options[OptMessage]; ok {
				msg = ": " + trimNUL(string(v))
			}
			return nil, nil, errors.New("DHCP server replied NAK" + msg)
		}
	}
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) < 6 || len(b) < 6 {
		return false
	}
	for i := range 6 {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// udpPayload extracts the UDP payload of an IPv4 packet matching the ports. Fragmented
// datagrams are ignored (DHCP never needs them).
func udpPayload(ip []byte, srcPort, dstPort uint16) ([]byte, bool) {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 || ip[9] != byte(layers.IPProtocolUDP) {
		return nil, false
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total >= ihl && total <= len(ip) {
		ip = ip[:total]
	}
	udp := ip[ihl:]
	if binary.BigEndian.Uint16(udp[0:2]) != srcPort || binary.BigEndian.Uint16(udp[2:4]) != dstPort {
		return nil, false
	}
	ulen := int(binary.BigEndian.Uint16(udp[4:6]))
	if ulen < 8 || ulen > len(udp) {
		ulen = len(udp)
	}
	return udp[8:ulen], true
}

// sendDHCP serialises and transmits one DHCP message as a complete Ethernet/IPv4/UDP
// frame.
func sendDHCP(conn *packet.Conn, src, dst net.HardwareAddr, srcIP, dstIP netip.Addr, m *DHCPMessage) error {
	eth := &layers.Ethernet{
		SrcMAC:       src,
		DstMAC:       dst,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Id:       uint16(m.XID),
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP(srcIP.AsSlice()),
		DstIP:    net.IP(dstIP.AsSlice()),
		Flags:    0,
	}
	udp := &layers.UDP{SrcPort: dhcpClientPort, DstPort: dhcpServerPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return fmt.Errorf("netif: dhcp checksum setup: %w", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(m.Marshal())); err != nil {
		return fmt.Errorf("netif: dhcp serialize: %w", err)
	}
	if _, err := conn.WriteTo(buf.Bytes(), &packet.Addr{HardwareAddr: dst}); err != nil {
		return fmt.Errorf("netif: dhcp send: %w", mapPermErr(err))
	}
	return nil
}

// dhcpRelease gives a lease back. Best effort: a failure is logged by the cleanup
// machinery, never fatal.
func dhcpRelease(iface string, mac net.HardwareAddr, client, server netip.Addr) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil // interface already deleted: the lease will simply expire
	}
	conn, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	m := NewDHCPRelease(randomXID(), mac, client, server)
	return sendDHCP(conn, mac, broadcastMAC, client, server, m)
}

func randomXID() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// dhcpClientFilter keeps only IPv4/UDP 67 -> 68 frames.
func dhcpClientFilter() ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x0800, SkipTrue: 6},
		bpf.LoadAbsolute{Off: 23, Size: 1}, // IPv4 protocol
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 17, SkipTrue: 4},
		bpf.LoadMemShift{Off: 14},                                            // X = IHL
		bpf.LoadIndirect{Off: 16, Size: 2},                                   // UDP dst port
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dhcpClientPort, SkipTrue: 1}, //
		bpf.RetConstant{Val: 1 << 16},
		bpf.RetConstant{Val: 0},
	})
}

// ConfigureDHCP obtains a lease on iface and applies it (address, and a default route via
// the lease router when iface has none). Every change is registered for cleanup.
func ConfigureDHCP(ctx context.Context, iface string, cfg DHCPConfig) (Lease, error) {
	lease, err := DHCPAcquire(ctx, iface, cfg)
	if err != nil {
		return Lease{}, err
	}
	if err := AddAddr(iface, lease.CIDR()); err != nil {
		return lease, err
	}
	return lease, nil
}

// ConfigureStatic applies a static address to iface, for when no DHCP server answers on
// the VLAN under test. Registered for cleanup.
func ConfigureStatic(iface string, addr netip.Prefix) error {
	if err := SetLinkUp(iface); err != nil {
		return err
	}
	return AddAddr(iface, addr)
}
