//go:build unix

package portscan

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reuseControl sets SO_REUSEADDR and SO_REUSEPORT so many sockets can share a fixed
// source port (segmentation bypass tests use e.g. 53 or 88).
func reuseControl(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
			serr = e
			return
		}
		// SO_REUSEPORT is best effort (not available everywhere).
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
