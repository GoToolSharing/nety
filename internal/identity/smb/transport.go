// Package smb is a small, safe SMB2/3 client used by NETY for identity
// collection and light checks. It supports NEGOTIATE (with SMB 3.1.1
// negotiate contexts), NTLM SESSION_SETUP (anonymous, guest or NTLMv2),
// TREE_CONNECT, named pipe CREATE / IOCTL(FSCTL_PIPE_TRANSCEIVE) / READ /
// WRITE / CLOSE. It never signs or encrypts: it is meant for anonymous and
// guest sessions and pre-authentication fingerprinting only.
//
// Transport is direct TCP (445) or NetBIOS session service (139).
package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// MaxMessageSize bounds every message read from the network.
const MaxMessageSize = 1 << 20

// Errors.
var (
	ErrSMB1Only      = errors.New("smb: server answered with SMB1 only")
	ErrNotSMB        = errors.New("smb: not an SMB response")
	ErrNetBIOSRefuse = errors.New("smb: NetBIOS session request refused")
	ErrTooLarge      = errors.New("smb: message too large")
	ErrMalformed     = errors.New("smb: malformed response")
)

// Transport frames SMB messages over a TCP connection.
type Transport struct {
	conn    net.Conn
	timeout time.Duration
	stop    func() bool
}

// DialTransport opens a TCP connection to ip:port. For port 139 a NetBIOS
// session request is performed (called name "*SMBSERVER" unless calledName
// is given). ctx cancellation closes the connection.
func DialTransport(ctx context.Context, ip string, port int, timeout time.Duration, calledName string) (*Transport, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	t := &Transport{conn: c, timeout: timeout}
	t.stop = context.AfterFunc(ctx, func() { _ = c.Close() })
	if port == 139 {
		if err := t.netbiosSession(calledName); err != nil {
			t.Close()
			return nil, err
		}
	}
	return t, nil
}

// NewTransport wraps an existing connection (tests).
func NewTransport(c net.Conn, timeout time.Duration) *Transport {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Transport{conn: c, timeout: timeout}
}

// Close closes the underlying connection.
func (t *Transport) Close() error {
	if t.stop != nil {
		t.stop()
	}
	return t.conn.Close()
}

// RemoteAddr returns the peer address.
func (t *Transport) RemoteAddr() net.Addr { return t.conn.RemoteAddr() }

// EncodeNetBIOSName performs RFC 1001 first-level encoding of a 16 byte name.
func EncodeNetBIOSName(name string, suffix byte) []byte {
	n := []byte(strings.ToUpper(name))
	if len(n) > 15 {
		n = n[:15]
	}
	raw := make([]byte, 16)
	copy(raw, n)
	for i := len(n); i < 15; i++ {
		raw[i] = ' '
	}
	raw[15] = suffix
	if name == "*" {
		raw = make([]byte, 16)
		raw[0] = '*'
	}
	out := make([]byte, 0, 34)
	out = append(out, 32)
	for _, b := range raw {
		out = append(out, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	return append(out, 0)
}

func (t *Transport) netbiosSession(called string) error {
	if called == "" {
		called = "*SMBSERVER"
	}
	payload := append(EncodeNetBIOSName(called, 0x20), EncodeNetBIOSName("NETY", 0x00)...)
	hdr := []byte{0x81, 0, byte(len(payload) >> 8), byte(len(payload))}
	_ = t.conn.SetDeadline(time.Now().Add(t.timeout))
	if _, err := t.conn.Write(append(hdr, payload...)); err != nil {
		return err
	}
	var rh [4]byte
	if _, err := io.ReadFull(t.conn, rh[:]); err != nil {
		return err
	}
	l := int(rh[2])<<8 | int(rh[3])
	if l > 0 {
		if l > 256 {
			return ErrMalformed
		}
		if _, err := io.ReadFull(t.conn, make([]byte, l)); err != nil {
			return err
		}
	}
	switch rh[0] {
	case 0x82:
		return nil
	case 0x83:
		return ErrNetBIOSRefuse
	default:
		return fmt.Errorf("smb: unexpected NetBIOS session response 0x%02x", rh[0])
	}
}

// Send writes one framed message.
func (t *Transport) Send(msg []byte) error {
	if len(msg) > 0xffffff {
		return ErrTooLarge
	}
	b := make([]byte, 4, 4+len(msg))
	b[1], b[2], b[3] = byte(len(msg)>>16), byte(len(msg)>>8), byte(len(msg))
	b = append(b, msg...)
	_ = t.conn.SetWriteDeadline(time.Now().Add(t.timeout))
	_, err := t.conn.Write(b)
	return err
}

// Recv reads one framed message (NetBIOS keep-alives are skipped).
func (t *Transport) Recv() ([]byte, error) {
	for i := 0; i < 16; i++ {
		_ = t.conn.SetReadDeadline(time.Now().Add(t.timeout))
		var h [4]byte
		if _, err := io.ReadFull(t.conn, h[:]); err != nil {
			return nil, err
		}
		l := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
		if h[0] == 0x85 { // keep-alive
			continue
		}
		if h[0] != 0x00 {
			return nil, ErrNotSMB
		}
		if l > MaxMessageSize {
			return nil, ErrTooLarge
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(t.conn, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	return nil, ErrMalformed
}

// RoundTrip sends msg and returns the next message.
func (t *Transport) RoundTrip(msg []byte) ([]byte, error) {
	if err := t.Send(msg); err != nil {
		return nil, err
	}
	return t.Recv()
}

// IsSMB1 reports whether b starts with the SMB1 protocol id.
func IsSMB1(b []byte) bool { return len(b) >= 4 && bytes.Equal(b[:4], []byte{0xff, 'S', 'M', 'B'}) }

// IsSMB2 reports whether b starts with the SMB2 protocol id.
func IsSMB2(b []byte) bool { return len(b) >= 4 && bytes.Equal(b[:4], []byte{0xfe, 'S', 'M', 'B'}) }

// FormatGUID formats a 16 byte MS GUID (mixed endian) as
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (lowercase).
func FormatGUID(g []byte) string {
	if len(g) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(g[0:]), binary.LittleEndian.Uint16(g[4:]),
		binary.LittleEndian.Uint16(g[6:]), g[8:10], g[10:16])
}
