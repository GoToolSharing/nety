//go:build !linux

package netif

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// DHCPAcquire needs AF_PACKET.
func DHCPAcquire(ctx context.Context, iface string, cfg DHCPConfig) (Lease, error) {
	return Lease{}, errUnsupportedf("DHCP client on %q", iface)
}

// ConfigureDHCP needs AF_PACKET and netlink.
func ConfigureDHCP(ctx context.Context, iface string, cfg DHCPConfig) (Lease, error) {
	return Lease{}, errUnsupportedf("DHCP configuration of %q", iface)
}

// ConfigureStatic needs netlink.
func ConfigureStatic(iface string, addr netip.Prefix) error {
	return errUnsupportedf("static configuration of %q", iface)
}

// SendFrames needs AF_PACKET.
func SendFrames(iface string, frames ...[]byte) error {
	return errUnsupportedf("transmit raw frames on %q", iface)
}

// InterfaceMAC works anywhere Go's net package can enumerate interfaces.
func InterfaceMAC(iface string) (net.HardwareAddr, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	return ifi.HardwareAddr, nil
}

// ReleaseTrunk needs AF_PACKET.
func ReleaseTrunk(iface, domain string) error {
	return errUnsupportedf("DTP trunk release on %q", iface)
}

// RequestTrunk needs AF_PACKET.
func RequestTrunk(ctx context.Context, iface, domain string, count int, settle time.Duration) error {
	return errUnsupportedf("DTP trunk negotiation on %q", iface)
}
