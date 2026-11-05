//go:build linux

package netif

import (
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/GoToolSharing/nety/internal/engine"
)

// An operator plugs into a client's network with a cable on one job and associates to its
// Wi-Fi on the next. Everything NETY does works the same either way: discovery, port
// scanning, fingerprinting, and the routing-level segmentation techniques all ride on IP
// - with one real exception: the switch-port techniques (802.1Q sub-interfaces, DTP trunk
// negotiation, double tagging) and the passive CDP/LLDP/DTP recon only exist on a wired
// port. An access point does not forward tagged frames to a station and does not speak
// those protocols over the air.
//
// So rather than let those attempts fail with a driver-level errno that means nothing to
// the operator, NETY detects the link type and says plainly that the technique does not
// apply here.

// IsWireless reports whether iface is an 802.11 interface.
func IsWireless(iface string) bool {
	if iface == "" {
		return false
	}
	base := filepath.Join("/sys/class/net", filepath.Base(iface))
	// Present for any cfg80211 device, and for the older wireless extensions.
	for _, probe := range []string{"phy80211", "wireless"} {
		if _, err := os.Lstat(filepath.Join(base, probe)); err == nil {
			return true
		}
	}
	// Some drivers only expose the type; 801 is ARPHRD_IEEE80211, 803 is
	// ARPHRD_IEEE80211_RADIOTAP (monitor mode).
	if b, err := os.ReadFile(filepath.Join(base, "type")); err == nil {
		switch strings.TrimSpace(string(b)) {
		case "801", "802", "803", "804":
			return true
		}
	}
	return false
}

// linkKind classifies an interface for the UI.
func linkKind(name string, flags net.Flags, isVLAN bool) string {
	switch {
	case flags&net.FlagLoopback != 0:
		return engine.LinkLoopback
	case isVLAN:
		return engine.LinkVLAN
	case IsWireless(name):
		return engine.LinkWireless
	}
	base := filepath.Join("/sys/class/net", filepath.Base(name))
	if _, err := os.Stat(filepath.Join(base, "bridge")); err == nil {
		return engine.LinkBridge
	}
	if _, err := os.Stat(filepath.Join(base, "tun_flags")); err == nil {
		return engine.LinkTunnel
	}
	if _, err := os.Stat(filepath.Join(base, "device")); err == nil {
		return engine.LinkEthernet
	}
	return engine.LinkOther
}
