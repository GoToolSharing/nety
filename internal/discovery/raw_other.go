//go:build !linux

package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/GoToolSharing/nety/internal/engine"
)

const rawSupported = false

// discoverRaw needs AF_PACKET sockets (Linux only).
func (d *Discoverer) discoverRaw(context.Context, *config, *collector, *slog.Logger) error {
	return fmt.Errorf("discovery: raw engine: %w", engine.ErrUnsupported)
}

// macLookup has no portable kernel neighbour source.
func (d *Discoverer) macLookup() func(netip.Addr) net.HardwareAddr { return nil }
