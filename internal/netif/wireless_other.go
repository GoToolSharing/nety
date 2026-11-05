//go:build !linux

package netif

import (
	"net"

	"github.com/GoToolSharing/nety/internal/engine"
)

// IsWireless always reports false off Linux: NETY only scans from Linux, and the
// non-Linux build exists so the project compiles and tests on a developer machine.
func IsWireless(string) bool { return false }

func linkKind(_ string, flags net.Flags, isVLAN bool) string {
	switch {
	case flags&net.FlagLoopback != 0:
		return engine.LinkLoopback
	case isVLAN:
		return engine.LinkVLAN
	}
	return engine.LinkOther
}
