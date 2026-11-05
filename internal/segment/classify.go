package segment

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/GoToolSharing/nety/internal/model"
)

// Turning a failed connection into a verdict is the whole point of a segmentation test,
// so this mapping is the most important twenty lines of the
// package:
//
//	connection established  -> reachable   the flow crosses the boundary
//	RST / ECONNREFUSED      -> closed      the packet reached the host; only
//	                                       the port is shut, so the boundary
//	                                       does NOT block this flow
//	silence / timeout       -> filtered    something dropped it without telling
//	ICMP unreachable        -> unreachable no route, or a device answered
//	                                       "administratively prohibited"
//
// "closed" is a finding, not a non-result: it proves the segmentation lets the packet
// through even though nothing is listening.

// classify maps a dial/read error to a reachability status and a short human explanation.
// A nil error means the probe succeeded.
func classify(err error) (model.ReachStatus, string) {
	if err == nil {
		return model.ReachOpen, "connection established"
	}

	// Cancellation is not a verdict about the target.
	if errors.Is(err, context.Canceled) {
		return model.ReachError, "cancelled"
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		if st, detail, ok := classifyErrno(errno); ok {
			return st, detail
		}
	}

	if isTimeout(err) {
		return model.ReachFiltered, "no response before timeout (silently dropped)"
	}

	// Last resort: some platforms and some wrappers only give us a string.
	switch msg := strings.ToLower(err.Error()); {
	case strings.Contains(msg, "connection refused"):
		return model.ReachClosed, "connection refused (host reachable, port closed)"
	case strings.Contains(msg, "no route to host"):
		return model.ReachUnreachable, "no route to host (ICMP host unreachable)"
	case strings.Contains(msg, "network is unreachable"):
		return model.ReachUnreachable, "network unreachable (no route to the target network)"
	case strings.Contains(msg, "connection reset"):
		return model.ReachClosed, "connection reset by peer"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return model.ReachFiltered, "no response before timeout (silently dropped)"
	}
	return model.ReachError, err.Error()
}

// classifyErrno maps the errno a connect(2)/read(2) returns. On Linux the kernel has
// already translated the incoming ICMP error for us (icmp_err_convert): port-unreachable
// becomes ECONNREFUSED, net/host unreachable and the "administratively prohibited" codes
// become ENETUNREACH/EHOSTUNREACH.
func classifyErrno(e syscall.Errno) (model.ReachStatus, string, bool) {
	switch e {
	case syscall.ECONNREFUSED:
		return model.ReachClosed, "connection refused (host reachable, port closed)", true
	case syscall.ECONNRESET:
		return model.ReachClosed, "connection reset (host reachable, port closed)", true
	case syscall.ENETUNREACH:
		return model.ReachUnreachable, "network unreachable (no route, or ICMP net-unreachable / net-prohibited)", true
	case syscall.EHOSTUNREACH:
		return model.ReachUnreachable, "host unreachable (ICMP host-unreachable or administratively prohibited)", true
	case syscall.EHOSTDOWN:
		return model.ReachUnreachable, "host down (ICMP host-unknown)", true
	case syscall.ENETDOWN:
		return model.ReachUnreachable, "local network is down", true
	case syscall.ETIMEDOUT:
		return model.ReachFiltered, "no response before timeout (silently dropped)", true
	case syscall.ENOPROTOOPT:
		return model.ReachUnreachable, "protocol unreachable (ICMP protocol-unreachable)", true
	case syscall.EACCES, syscall.EPERM:
		// A local firewall rule rejecting the packet, or a missing capability.
		return model.ReachFiltered, "blocked locally (EACCES/EPERM: local firewall rule or missing privileges)", true
	case syscall.EMSGSIZE:
		return model.ReachFiltered, "fragmentation needed but DF set (ICMP frag-needed)", true
	case syscall.EADDRNOTAVAIL:
		return model.ReachError, "cannot bind the requested source address", true
	case syscall.EADDRINUSE:
		return model.ReachError, "source port already in use", true
	case syscall.EAFNOSUPPORT:
		return model.ReachError, "address family not supported on this host", true
	case syscall.EINVAL:
		return model.ReachError, "invalid argument", true
	}
	return "", "", false
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// classifyUDP adapts classify to a UDP probe, where silence is ambiguous: a filtering
// device and a service that simply does not answer our payload look identical from here.
func classifyUDP(err error, gotReply bool) (model.ReachStatus, string) {
	if gotReply {
		return model.ReachOpen, "service answered the UDP probe"
	}
	st, detail := classify(err)
	if st == model.ReachFiltered {
		detail = "no UDP response (open or filtered: silence is ambiguous for UDP)"
	}
	if st == model.ReachClosed {
		detail = "ICMP port unreachable (host reachable, port closed)"
	}
	if st == model.ReachOpen {
		// A successful "connect" on UDP means nothing: no packet was answered.
		return model.ReachFiltered, "no UDP response (open or filtered: silence is ambiguous for UDP)"
	}
	return st, detail
}
