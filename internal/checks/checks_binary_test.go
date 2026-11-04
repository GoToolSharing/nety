package checks

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

// ---------------------------------------------------------------------------
// VNC / RFB
// ---------------------------------------------------------------------------

// rfbServer speaks the RFB 3.8 handshake and offers the given security types.
func rfbServer(t *testing.T, version string, secTypes []byte) int {
	return fakeServer(t, func(c net.Conn) {
		if _, err := io.WriteString(c, version); err != nil {
			return
		}
		cv := make([]byte, 12)
		if _, err := io.ReadFull(c, cv); err != nil {
			return
		}
		out := append([]byte{byte(len(secTypes))}, secTypes...)
		_, _ = c.Write(out)
		// The probe must stop here: it must never send a security type back.
		rest := make([]byte, 16)
		if n, _ := c.Read(rest); n > 0 {
			t.Errorf("VNC probe sent %d bytes after the security list: % x", n, rest[:n])
		}
	})
}

func TestVNCNoAuth(t *testing.T) {
	// Security type 1 is "None": the desktop is open to anyone.
	port := rfbServer(t, "RFB 003.008\n", []byte{1, 2})
	fs := probe(t, "vnc-no-auth", tcpSvc("vnc", port))
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if !strings.Contains(fs[0].Evidence, "RFB 003.008") {
		t.Errorf("evidence: %q", fs[0].Evidence)
	}
	if fs[0].CheckID != "vnc-no-auth" {
		t.Errorf("check id = %q", fs[0].CheckID)
	}
}

func TestVNCWithAuthIsNotReportedAsOpen(t *testing.T) {
	// Only type 2 (legacy VNC authentication) is offered.
	port := rfbServer(t, "RFB 003.008\n", []byte{2})
	fs := probe(t, "vnc-no-auth", tcpSvc("vnc", port))
	for _, f := range fs {
		if f.CheckID == "vnc-no-auth" {
			t.Fatalf("password-protected VNC reported as open: %q", f.Evidence)
		}
	}
	// It is still worth reporting as weak authentication.
	if len(fs) == 1 && fs[0].CheckID != "vnc-weak-auth" {
		t.Errorf("unexpected finding %s", fs[0].CheckID)
	}
}

func TestVNCStrongAuthIsSilent(t *testing.T) {
	// Type 16 is Tight, 19 is VeNCrypt: neither is a finding.
	port := rfbServer(t, "RFB 003.008\n", []byte{16, 19})
	if fs := probe(t, "vnc-no-auth", tcpSvc("vnc", port)); len(fs) != 0 {
		t.Fatalf("reported on a server using strong auth: %+v", fs)
	}
}

func TestVNCRejectsNonRFB(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_9.2\r\n")
	})
	if fs := probe(t, "vnc-no-auth", tcpSvc("vnc", port)); len(fs) != 0 {
		t.Fatalf("non-RFB service reported: %+v", fs)
	}
}

// ---------------------------------------------------------------------------
// X11
// ---------------------------------------------------------------------------

// x11SetupReply builds a Success (status 1) connection setup reply.
func x11SetupReply(vendor string, release uint32) []byte {
	vb := []byte(vendor)
	pad := (4 - len(vb)%4) % 4
	body := make([]byte, 40)
	body[0] = 1 // Success
	binary.LittleEndian.PutUint16(body[2:], 11)
	binary.LittleEndian.PutUint16(body[4:], 0)
	binary.LittleEndian.PutUint32(body[8:], release)
	binary.LittleEndian.PutUint16(body[24:], uint16(len(vb)))
	body = append(body, vb...)
	body = append(body, make([]byte, pad)...)
	// Bytes 6..8 hold the length of the additional data in 4-byte units.
	binary.LittleEndian.PutUint16(body[6:], uint16((len(body)-8)/4))
	return body
}

func TestX11Open(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		req := make([]byte, 12)
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		// A client offering no authorization sends zero-length name and data.
		if n := binary.LittleEndian.Uint16(req[6:]); n != 0 {
			t.Errorf("X11 probe offered an authorization name of %d bytes", n)
		}
		_, _ = c.Write(x11SetupReply("The X.Org Foundation", 12101013))
	})
	fs := probe(t, "x11-open", tcpSvc("x11", port))
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if !strings.Contains(fs[0].Evidence, "X.Org Foundation") {
		t.Errorf("vendor missing from evidence: %q", fs[0].Evidence)
	}
}

func TestX11AuthRequiredIsSilent(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		req := make([]byte, 12)
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		// status 0 = Failed, with a reason string.
		reason := "No protocol specified"
		body := make([]byte, 8)
		body[0] = 0
		body[1] = byte(len(reason))
		binary.LittleEndian.PutUint16(body[2:], 11)
		_, _ = c.Write(append(body, reason...))
	})
	if fs := probe(t, "x11-open", tcpSvc("x11", port)); len(fs) != 0 {
		t.Fatalf("MIT-MAGIC-COOKIE protected display reported as open: %+v", fs)
	}
}

func TestX11ParseSetupHostileInput(t *testing.T) {
	good := x11SetupReply("vendor", 1)
	for i := 0; i < len(good); i++ {
		// Truncations must be rejected, never panic.
		_, _, _, _, _ = x11ParseSetup(good[:i])
	}
	// A vendor length far beyond the buffer must not read out of bounds.
	bad := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(bad[24:], 0xffff)
	st, _, _, info, ok := x11ParseSetup(bad)
	if ok && st == 1 && info != "" && strings.Contains(info, "vendor=\"vendor") {
		t.Fatal("oversized vendor length was trusted")
	}
	for _, junk := range [][]byte{nil, {}, {1}, {9, 0, 0, 0, 0, 0, 0, 0}} {
		_, _, _, _, _ = x11ParseSetup(junk)
	}
}

// ---------------------------------------------------------------------------
// The probes must never write anything that changes state
// ---------------------------------------------------------------------------

// TestProbesAreReadOnly records every byte the checks send to a service that
// answers nothing, and asserts none of them carries a write-shaped command.
// It is a coarse net, but it catches a destructive command added by accident.
func TestProbesAreReadOnly(t *testing.T) {
	var (
		mu   sync.Mutex
		sent []byte
	)
	port := fakeServer(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				mu.Lock()
				sent = append(sent, buf[:n]...)
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	})

	// The server never answers, so every check runs to its own timeout:
	// keep that short and run them in parallel.
	var wg sync.WaitGroup
	for _, ch := range allChecks() {
		if ch.Info.Intrusive {
			continue
		}
		ch := ch
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = recover() }()
			tg := &Target{
				Host:     model.Host{IP: "127.0.0.1"},
				IP:       "127.0.0.1",
				Service:  tcpSvc(firstService(ch.Info.Services), port),
				Services: []model.Service{tcpSvc(firstService(ch.Info.Services), port)},
				Opts:     engine.CheckOptions{Timeout: 300 * time.Millisecond},
				Timeout:  300 * time.Millisecond,
				Log:      quietLogger(),
				check:    ch,
			}
			if ch.HostLevel {
				tg.Service = model.Service{}
			}
			if ch.Applies != nil && !ch.Applies(tg) {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = ch.Run(ctx, tg)
		}()
	}
	wg.Wait()

	mu.Lock()
	upper := strings.ToUpper(string(sent))
	mu.Unlock()

	if upper == "" {
		t.Fatal("no check sent anything: the harness is not exercising the probes")
	}
	for _, forbidden := range []string{
		"FLUSHALL", "FLUSHDB", "CONFIG SET", "SHUTDOWN", "SLAVEOF", "REPLICAOF",
		"DROP TABLE", "DROP DATABASE", "DELETE FROM", "TRUNCATE",
		"RM -RF", "XP_CMDSHELL", "STOR ", "DELE ", "MKD ", "RMD ",
	} {
		if strings.Contains(upper, forbidden) {
			t.Errorf("a check sent the state-changing command %q", forbidden)
		}
	}
}
