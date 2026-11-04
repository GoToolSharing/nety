//go:build !linux

package rawnet

import (
	"net"
	"net/netip"
)

// Router is unavailable outside Linux.
type Router struct{}

// NewRouter returns ErrUnsupported outside Linux.
func NewRouter(string) (*Router, error) { return nil, ErrUnsupported }

// Interface returns nil.
func (*Router) Interface() *net.Interface { return nil }

// Lookup returns ErrUnsupported.
func (*Router) Lookup(netip.Addr) (Path, error) { return Path{}, ErrUnsupported }

// InterfacePrefixes returns nil.
func (*Router) InterfacePrefixes(*net.Interface) []netip.Prefix { return nil }
