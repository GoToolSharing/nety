//go:build !linux

package rawnet

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// Neighbors is unavailable outside Linux (no AF_PACKET / netlink).
type Neighbors struct{}

// NewNeighbors returns an inert resolver outside Linux.
func NewNeighbors(*slog.Logger) *Neighbors { return &Neighbors{} }

// Lookup always misses.
func (*Neighbors) Lookup(netip.Addr) (net.HardwareAddr, bool) { return nil, false }

// Set is a no-op.
func (*Neighbors) Set(netip.Addr, net.HardwareAddr) {}

// Seed is a no-op.
func (*Neighbors) Seed(*net.Interface) {}

// Resolve returns ErrUnsupported.
func (*Neighbors) Resolve(context.Context, *net.Interface, netip.Addr, netip.Addr, time.Duration) (net.HardwareAddr, error) {
	return nil, ErrUnsupported
}

// Sweep returns ErrUnsupported.
func (*Neighbors) Sweep(context.Context, SweepOptions) error { return ErrUnsupported }
