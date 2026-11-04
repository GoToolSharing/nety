//go:build linux

package segment

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// dialControl returns the Dialer.Control hook the probes need.
//
//   - reusePort is set when the probe binds a fixed source port: several
//     concurrent probes share the same local port, and the port is often still
//     in TIME_WAIT from the previous target, so SO_REUSEADDR and SO_REUSEPORT
//     are both required.
//   - iface, when set, binds the socket to that device (SO_BINDTODEVICE) so
//     traffic leaves through the temporary 802.1Q sub-interface instead of
//     following the main routing table. It needs CAP_NET_RAW.
func dialControl(iface string, reusePort bool) func(network, address string, c syscall.RawConn) error {
	if iface == "" && !reusePort {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var ctrlErr error
		err := c.Control(func(fd uintptr) {
			if reusePort {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					ctrlErr = err
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					ctrlErr = err
					return
				}
			}
			if iface != "" {
				if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface); err != nil {
					ctrlErr = err
					return
				}
			}
		})
		if err != nil {
			return err
		}
		return ctrlErr
	}
}
