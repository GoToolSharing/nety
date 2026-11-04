//go:build linux

package rawnet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/vaadata/nety/internal/engine"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Handle is an AF_PACKET (SOCK_RAW, ETH_P_ALL) socket bound to one interface
// with a classic BPF filter attached before bind, so no unwanted frame is
// ever queued. Write and Read may be used concurrently from different
// goroutines.
type Handle struct {
	conn *packet.Conn
	Ifi  *net.Interface

	closeOnce sync.Once
}

const (
	rcvBufSize = 32 << 20
	sndBufSize = 8 << 20
)

// OpenHandle opens a packet socket on ifi receiving frames matching spec.
func OpenHandle(ifi *net.Interface, spec FilterSpec) (*Handle, error) {
	if ifi == nil {
		return nil, errors.New("rawnet: nil interface")
	}
	prog, err := BuildFilter(spec)
	if err != nil {
		return nil, err
	}
	raw, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("rawnet: assemble bpf: %w", err)
	}
	c, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, &packet.Config{Filter: raw})
	if err != nil {
		if isPermission(err) {
			return nil, fmt.Errorf("%w: %v", engine.ErrNeedPrivileges, err)
		}
		return nil, fmt.Errorf("rawnet: open packet socket on %s: %w", ifi.Name, err)
	}
	h := &Handle{conn: c, Ifi: ifi}
	h.tuneBuffers()
	return h, nil
}

func isPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
}

func (h *Handle) tuneBuffers() {
	rc, err := h.conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		// SO_RCVBUFFORCE bypasses rmem_max but needs CAP_NET_ADMIN.
		if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, rcvBufSize) != nil {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, rcvBufSize)
		}
		if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sndBufSize) != nil {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, sndBufSize)
		}
	})
}

// Write sends one complete Ethernet frame. Transient ENOBUFS (driver queue
// full at high rates) is retried briefly.
func (h *Handle) Write(frame []byte) error {
	if len(frame) < 14 {
		return errors.New("rawnet: frame too short")
	}
	addr := &packet.Addr{HardwareAddr: net.HardwareAddr(frame[0:6])}
	var err error
	for attempt := 0; attempt < 50; attempt++ {
		if _, err = h.conn.WriteTo(frame, addr); err == nil {
			return nil
		}
		if !errors.Is(err, unix.ENOBUFS) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		time.Sleep(time.Duration(attempt+1) * 50 * time.Microsecond)
	}
	return err
}

// Read reads one frame into buf, waiting at most until deadline. On timeout
// it returns (0, nil) so receive loops can poll their context.
func (h *Handle) Read(buf []byte, deadline time.Time) (int, error) {
	if err := h.conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	n, _, err := h.conn.ReadFrom(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return 0, nil
		}
		return 0, err
	}
	return n, nil
}

// Drops returns the number of frames the kernel dropped since the previous
// call because the socket buffer was full (a hint that the rate is too high).
func (h *Handle) Drops() uint32 {
	st, err := h.conn.Stats()
	if err != nil {
		return 0
	}
	return st.Drops
}

// Close closes the socket (idempotent).
func (h *Handle) Close() error {
	var err error
	h.closeOnce.Do(func() { err = h.conn.Close() })
	return err
}
