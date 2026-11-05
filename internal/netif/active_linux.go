//go:build linux

package netif

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/sys/unix"

	"github.com/GoToolSharing/nety/internal/engine"
)

// Active L2 transmission helpers. These are the only functions in this package that put
// frames on the wire outside of DHCP, and they are only reachable from the opt-in L2
// segmentation techniques (SegmentOptions.AllowL2Active).

// SendFrames transmits raw Ethernet frames on iface. The frames must already contain the
// complete Ethernet header (the FCS is added by the NIC).
//
// It is used by the double-tag technique, which needs to emit a frame the kernel would
// never produce by itself.
func SendFrames(iface string, frames ...[]byte) error {
	if len(frames) == 0 {
		return nil
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("netif: interface %q: %w", iface, err)
	}
	conn, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, nil)
	if err != nil {
		return fmt.Errorf("netif: AF_PACKET on %q: %w", iface, mapPermErr(err))
	}
	defer conn.Close()
	for _, f := range frames {
		if len(f) < 14 {
			continue
		}
		dst := net.HardwareAddr(append([]byte(nil), f[0:6]...))
		if _, err := conn.WriteTo(f, &packet.Addr{HardwareAddr: dst}); err != nil {
			return fmt.Errorf("netif: send on %q: %w", iface, mapPermErr(err))
		}
	}
	return nil
}

// InterfaceMAC returns the hardware address of iface.
func InterfaceMAC(iface string) (net.HardwareAddr, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("netif: interface %q: %w", iface, err)
	}
	if len(ifi.HardwareAddr) != 6 {
		return nil, fmt.Errorf("netif: %q has no Ethernet address", iface)
	}
	return ifi.HardwareAddr, nil
}

// RequestTrunk asks the switch port to form an 802.1Q trunk by sending DTP advertisements
// in "desirable" mode, then waits settle for the switch to converge. It registers a
// cleanup that advertises "access" again, which is the best NETY can do to put the port
// back: DTP has no explicit teardown, so the switch may need its own dead timer (~90s) to
// drop the trunk. The operator is told so in the result Detail.
//
// count frames are sent one second apart, mimicking the IOS advertisement interval;
// switches ignore a single stray frame.
func RequestTrunk(ctx context.Context, iface, domain string, count int, settle time.Duration) error {
	// DTP is a switch-port protocol; there is no switch port on a Wi-Fi association, and
	// the frame would go nowhere.
	if IsWireless(iface) {
		return fmt.Errorf("netif: %q is a Wi-Fi interface: %w", iface, engine.ErrWirelessUnsupported)
	}
	mac, err := InterfaceMAC(iface)
	if err != nil {
		return err
	}
	if count <= 0 {
		count = 3
	}
	frame := BuildDTPFrame(mac, domain, DTPStatusDesirable, DTPTypeDot1Q)
	for i := 0; i < count; i++ {
		if err := SendFrames(iface, frame); err != nil {
			return err
		}
		if i == 0 {
			// Registered globally as a safety net; callers that manage their own cleanup
			// (internal/segment) also call ReleaseTrunk directly.
			trackKeyed("dtp|"+iface, "advertise DTP access mode on "+iface, func() error {
				return ReleaseTrunk(iface, domain)
			})
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if settle > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(settle):
		}
	}
	return nil
}

// ReleaseTrunk advertises "access" mode on iface, asking the switch port to stop
// trunking. DTP has no explicit teardown, so this is best effort: a port in dynamic
// desirable/auto drops the trunk once its DTP timer expires (roughly 90 seconds) if
// nothing keeps asking for one.
func ReleaseTrunk(iface, domain string) error {
	mac, err := InterfaceMAC(iface)
	if err != nil {
		return nil // the interface is gone; nothing left to put back
	}
	off := BuildDTPFrame(mac, domain, DTPStatusAccess, DTPTypeDot1Q)
	err = SendFrames(iface, off, off)
	forgetKeyed("dtp|" + iface)
	return err
}
