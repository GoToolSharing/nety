package segment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// fakeTimeout is an error that behaves like a net timeout.
type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

// dialErr wraps errno the way net.Dialer does, so the test exercises the real unwrapping
// path rather than a bare errno.
func dialErr(errno syscall.Errno) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp4",
		Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 445},
		Err:  os.NewSyscallError("connect", errno),
	}
}

func TestClassifySuccess(t *testing.T) {
	st, detail := classify(nil)
	if st != model.ReachOpen {
		t.Errorf("status = %q, want reachable", st)
	}
	if detail == "" {
		t.Error("a successful probe should still explain itself")
	}
}

// The three verdicts an auditor actually cares about must never be confused.
func TestClassifyErrnoMapping(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		want  model.ReachStatus
		words string
	}{
		{"refused", dialErr(syscall.ECONNREFUSED), model.ReachClosed, "refused"},
		{"reset", dialErr(syscall.ECONNRESET), model.ReachClosed, "reset"},
		{"net unreachable", dialErr(syscall.ENETUNREACH), model.ReachUnreachable, "network unreachable"},
		{"host unreachable", dialErr(syscall.EHOSTUNREACH), model.ReachUnreachable, "host unreachable"},
		{"host down", dialErr(syscall.EHOSTDOWN), model.ReachUnreachable, "host down"},
		{"net down", dialErr(syscall.ENETDOWN), model.ReachUnreachable, "down"},
		{"timed out", dialErr(syscall.ETIMEDOUT), model.ReachFiltered, "timeout"},
		{"protocol unreachable", dialErr(syscall.ENOPROTOOPT), model.ReachUnreachable, "protocol unreachable"},
		{"locally blocked", dialErr(syscall.EPERM), model.ReachFiltered, "locally"},
		{"locally denied", dialErr(syscall.EACCES), model.ReachFiltered, "locally"},
		{"frag needed", dialErr(syscall.EMSGSIZE), model.ReachFiltered, "fragmentation"},
		{"source bind failed", dialErr(syscall.EADDRNOTAVAIL), model.ReachError, "source address"},
		{"source port busy", dialErr(syscall.EADDRINUSE), model.ReachError, "source port"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, detail := classify(c.err)
			if st != c.want {
				t.Errorf("status = %q, want %q (detail %q)", st, c.want, detail)
			}
			if !strings.Contains(strings.ToLower(detail), c.words) {
				t.Errorf("detail %q should mention %q", detail, c.words)
			}
		})
	}
}

func TestClassifyTimeout(t *testing.T) {
	for name, err := range map[string]error{
		"net.Error":         &net.OpError{Op: "dial", Err: fakeTimeout{}},
		"deadline exceeded": context.DeadlineExceeded,
		"os deadline":       os.ErrDeadlineExceeded,
	} {
		st, detail := classify(err)
		if st != model.ReachFiltered {
			t.Errorf("%s: status = %q, want filtered", name, st)
		}
		if !strings.Contains(detail, "timeout") {
			t.Errorf("%s: detail = %q", name, detail)
		}
	}
}

func TestClassifyCancellationIsNotAVerdict(t *testing.T) {
	st, detail := classify(fmt.Errorf("dial: %w", context.Canceled))
	if st != model.ReachError {
		t.Errorf("status = %q, want error: a cancelled probe says nothing about the target", st)
	}
	if detail != "cancelled" {
		t.Errorf("detail = %q", detail)
	}
}

// Some code paths only hand us a message; the string fallback must still get the three
// important verdicts right.
func TestClassifyStringFallback(t *testing.T) {
	cases := map[string]model.ReachStatus{
		"dial tcp 10.0.0.1:445: connect: connection refused":     model.ReachClosed,
		"dial tcp 10.0.0.1:445: connect: no route to host":       model.ReachUnreachable,
		"dial tcp 10.0.0.1:445: connect: network is unreachable": model.ReachUnreachable,
		"read tcp 10.0.0.1:445: connection reset by peer":        model.ReachClosed,
		"dial tcp 10.0.0.1:445: i/o timeout":                     model.ReachFiltered,
		"dial tcp 10.0.0.1:445: context deadline exceeded":       model.ReachFiltered,
	}
	for msg, want := range cases {
		if st, _ := classify(errors.New(msg)); st != want {
			t.Errorf("%q -> %q, want %q", msg, st, want)
		}
	}
}

func TestClassifyUnknownError(t *testing.T) {
	st, detail := classify(errors.New("the gremlins ate it"))
	if st != model.ReachError {
		t.Errorf("status = %q, want error", st)
	}
	if detail != "the gremlins ate it" {
		t.Errorf("detail = %q, want the original message", detail)
	}
}

func TestClassifyUDP(t *testing.T) {
	st, detail := classifyUDP(nil, true)
	if st != model.ReachOpen || !strings.Contains(detail, "answered") {
		t.Errorf("a UDP reply must be reachable, got %q / %q", st, detail)
	}

	// A successful "connect" on UDP proves nothing: no datagram was answered.
	st, detail = classifyUDP(nil, false)
	if st != model.ReachFiltered {
		t.Errorf("silent UDP = %q, want filtered", st)
	}
	if !strings.Contains(detail, "ambiguous") {
		t.Errorf("detail = %q, should warn that UDP silence is ambiguous", detail)
	}

	st, detail = classifyUDP(dialErr(syscall.ECONNREFUSED), false)
	if st != model.ReachClosed || !strings.Contains(detail, "port unreachable") {
		t.Errorf("ICMP port unreachable = %q / %q, want closed", st, detail)
	}

	st, _ = classifyUDP(dialErr(syscall.EHOSTUNREACH), false)
	if st != model.ReachUnreachable {
		t.Errorf("host unreachable = %q, want unreachable", st)
	}

	st, _ = classifyUDP(&net.OpError{Op: "read", Err: fakeTimeout{}}, false)
	if st != model.ReachFiltered {
		t.Errorf("timeout = %q, want filtered", st)
	}
}
