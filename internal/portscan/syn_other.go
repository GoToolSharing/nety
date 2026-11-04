//go:build !linux

package portscan

import (
	"context"
	"fmt"

	"github.com/vaadata/nety/internal/engine"
)

const synSupported = false

// synScan needs AF_PACKET sockets (Linux only).
func (s *Scanner) synScan(context.Context, *job) error {
	return fmt.Errorf("portscan: syn scan: %w", engine.ErrUnsupported)
}
