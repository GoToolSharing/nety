//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/netif"
	"github.com/GoToolSharing/nety/internal/portscan"
)

// The 802.1Q data path check.
//
// The segmentation engine's dot1q-subif technique does two things: it asks the
// switch for a trunk, and then it talks to another VLAN through a tagged
// sub-interface. The first half needs a real switch. The second half does not,
// and it is the half that carries the result into the client's matrix - so it
// is worth proving properly rather than assuming.
//
// This builds the data path with no switch at all: a veth pair with one end in
// a second network namespace, an 802.1Q sub-interface on each end, and a
// listener on the far side. Frames really are tagged, really leave the kernel's
// networking stack on one side and really arrive on the other, and NETY's own
// port scanner is the thing that finds the listener.

const (
	dpVLAN   = 1234
	dpHostIP = "10.77.0.1/24"
	dpPeerIP = "10.77.0.2/24"
	dpPort   = 4455
)

func runVLANDataPathCheck(hostVeth, peerVeth string) error {
	// Everything below is torn down in reverse order by the deferred closers,
	// so a failure half way through still leaves the machine clean.
	var closers []func()
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}()

	origNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("current namespace: %w", err)
	}
	defer origNS.Close()

	peerNS, err := newNamespace(origNS)
	if err != nil {
		return fmt.Errorf("create namespace: %w", err)
	}
	closers = append(closers, func() { peerNS.Close() })

	// veth pair, with the far end created directly inside the new namespace.
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: hostVeth},
		PeerName:      peerVeth,
		PeerNamespace: netlink.NsFd(peerNS),
	}); err != nil {
		return fmt.Errorf("create veth %s/%s: %w", hostVeth, peerVeth, err)
	}
	closers = append(closers, func() {
		if l, err := netlink.LinkByName(hostVeth); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	ok("veth %s ⇄ %s created, far end in its own namespace", hostVeth, peerVeth)

	if err := netif.SetLinkUp(hostVeth); err != nil {
		return fmt.Errorf("bring %s up: %w", hostVeth, err)
	}

	// Host side: this is exactly what the dot1q-subif technique does once a
	// trunk exists - a tagged sub-interface with an address in the far VLAN.
	hostSub, err := netif.AddVLAN(hostVeth, dpVLAN)
	if err != nil {
		return fmt.Errorf("sub-interface on %s: %w", hostVeth, err)
	}
	hostPrefix := netip.MustParsePrefix(dpHostIP)
	if err := netif.AddAddr(hostSub, hostPrefix); err != nil {
		return fmt.Errorf("address %s: %w", hostPrefix, err)
	}
	ok("tagged sub-interface %s up with %s (VLAN %d)", hostSub, hostPrefix, dpVLAN)

	// Far side, configured from inside the peer namespace, including the
	// listener: a socket belongs to the namespace it was created in, so it
	// keeps answering once we switch back.
	listener, err := setupPeer(peerNS, origNS, peerVeth)
	if err != nil {
		return fmt.Errorf("configure the peer: %w", err)
	}
	closers = append(closers, func() { listener.Close() })
	ok("peer namespace listening on %s:%d behind its own VLAN %d sub-interface",
		netip.MustParsePrefix(dpPeerIP).Addr(), dpPort, dpVLAN)

	go acceptLoop(listener)

	peerAddr := netip.MustParsePrefix(dpPeerIP).Addr()

	// 1. A plain connection proves tagged frames cross the wire both ways.
	if err := dialThrough(hostSub, peerAddr, dpPort); err != nil {
		return fmt.Errorf("tagged frames do not reach the peer: %w", err)
	}
	ok("TCP connection established through the tagged path")

	// 2. NETY's own scanner must find that listener, which is what actually
	//    lands in the segmentation matrix.
	found, err := scanThrough(hostSub, peerAddr)
	if err != nil {
		return fmt.Errorf("scan through the sub-interface: %w", err)
	}
	if !found {
		return fmt.Errorf("the port scanner did not find %s:%d through %s", peerAddr, dpPort, hostSub)
	}
	ok("NETY's port scanner found %s:%d through the sub-interface", peerAddr, dpPort)

	// 3. A tagged frame NETY builds itself is accepted by a real 802.1Q
	//    decoder - the frame builder the double-tag technique relies on.
	hostAddr := netip.MustParsePrefix(dpHostIP).Addr()
	if err := checkTaggedFrameAccepted(hostVeth, dpVLAN, hostAddr, peerAddr); err != nil {
		return fmt.Errorf("tagged frame: %w", err)
	}
	ok("a tagged frame built by NETY was accepted and answered on VLAN %d", dpVLAN)

	// 4. Cleanup removes only what we made.
	if err := netif.RestoreAll(); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if _, err := netif.InterfaceMAC(hostSub); err == nil {
		return fmt.Errorf("%s still exists after cleanup", hostSub)
	}
	ok("sub-interface and address removed, nothing left behind")
	return nil
}

// newNamespace creates a namespace without leaving the caller in it.
func newNamespace(orig netns.NsHandle) (netns.NsHandle, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ns, err := netns.New() // creates and enters
	if err != nil {
		return 0, err
	}
	if err := netns.Set(orig); err != nil {
		ns.Close()
		return 0, fmt.Errorf("return to the original namespace: %w", err)
	}
	return ns, nil
}

// setupPeer configures the far end and opens the listener inside its namespace.
func setupPeer(peerNS, origNS netns.NsHandle, peerVeth string) (net.Listener, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := netns.Set(peerNS); err != nil {
		return nil, err
	}
	// Whatever happens, this thread goes back where it came from.
	defer func() { _ = netns.Set(origNS) }()

	for _, name := range []string{"lo", peerVeth} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return nil, fmt.Errorf("peer link %q: %w", name, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return nil, fmt.Errorf("peer link %q up: %w", name, err)
		}
	}

	parent, err := netlink.LinkByName(peerVeth)
	if err != nil {
		return nil, err
	}
	subName := netif.VLANName(peerVeth, dpVLAN)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = subName
	attrs.ParentIndex = parent.Attrs().Index
	sub := &netlink.Vlan{LinkAttrs: attrs, VlanId: dpVLAN, VlanProtocol: netlink.VLAN_PROTOCOL_8021Q}
	if err := netlink.LinkAdd(sub); err != nil {
		return nil, fmt.Errorf("peer sub-interface: %w", err)
	}
	if err := netlink.LinkSetUp(sub); err != nil {
		return nil, err
	}
	addr, err := netlink.ParseAddr(dpPeerIP)
	if err != nil {
		return nil, err
	}
	if err := netlink.AddrAdd(sub, addr); err != nil {
		return nil, fmt.Errorf("peer address: %w", err)
	}

	addrPort := netip.AddrPortFrom(netip.MustParsePrefix(dpPeerIP).Addr(), dpPort)
	ln, err := net.Listen("tcp", addrPort.String())
	if err != nil {
		return nil, fmt.Errorf("peer listener: %w", err)
	}
	return ln, nil
}

func acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("NETY-LABCHECK\r\n"))
		_ = c.Close()
	}
}

// dialThrough connects from the tagged sub-interface to the peer.
func dialThrough(iface string, peer netip.Addr, port int) error {
	src, err := netip.ParsePrefix(dpHostIP)
	if err != nil {
		return err
	}
	d := net.Dialer{
		Timeout:   3 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IP(src.Addr().AsSlice())},
	}
	conn, err := d.Dial("tcp", netip.AddrPortFrom(peer, uint16(port)).String())
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return fmt.Errorf("connected but read nothing back: %v", err)
	}
	return nil
}

// scanThrough runs the real port scanner against the peer.
func scanThrough(iface string, peer netip.Addr) (bool, error) {
	sc := portscan.New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var found bool
	err := sc.Scan(ctx, engine.PortScanOptions{
		Interface: iface,
		Hosts:     []netip.Addr{peer},
		TCPPorts:  []uint16{22, 80, dpPort, 8443},
		Mode:      engine.ModeConnect, // deterministic here; SYN is covered in the lab scan
		Rate:      200,
		Timeout:   2 * time.Second,
	}, func(r engine.PortResult) {
		if r.Port == dpPort {
			found = true
		}
	})
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return found, err
	}
	return found, nil
}
