//go:build linux

package rawnet

import (
	"sync"

	"golang.org/x/sys/unix"
)

// canRaw probes the kernel once: creating an AF_PACKET socket is the only
// reliable test of the privilege (root, CAP_NET_RAW, or a user namespace
// that grants it). Protocol 0 means the socket receives nothing, so the
// probe has no side effect; it is closed immediately.
var canRaw = sync.OnceValue(func() bool {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
})

// CanRaw reports whether this process may open raw/AF_PACKET sockets, i.e.
// whether the stateless SYN scanner and raw ARP/ICMP discovery are usable.
// The answer is cached after the first call.
func CanRaw() bool { return canRaw() }
