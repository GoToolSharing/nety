//go:build !linux

package rawnet

import (
	"net"
	"time"
)

// Handle is unavailable outside Linux.
type Handle struct{ Ifi *net.Interface }

// OpenHandle returns ErrUnsupported outside Linux.
func OpenHandle(*net.Interface, FilterSpec) (*Handle, error) { return nil, ErrUnsupported }

// Write returns ErrUnsupported.
func (*Handle) Write([]byte) error { return ErrUnsupported }

// Read returns ErrUnsupported.
func (*Handle) Read([]byte, time.Time) (int, error) { return 0, ErrUnsupported }

// Drops returns 0.
func (*Handle) Drops() uint32 { return 0 }

// Close is a no-op.
func (*Handle) Close() error { return nil }
