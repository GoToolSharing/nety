//go:build !linux

package segment

import (
	"syscall"
)

// dialControl is a no-op off Linux: SO_REUSEPORT exists on darwin/BSD but SO_BINDTODEVICE
// does not, and the techniques that need either are Linux-only anyway. Source-port
// binding still works, one probe at a time.
func dialControl(iface string, reusePort bool) func(network, address string, c syscall.RawConn) error {
	return nil
}
