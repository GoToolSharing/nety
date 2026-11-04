package fingerprint

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	maxBanner     = 1024     // printable banner size kept in model.Service
	maxResponse   = 64 << 10 // max bytes read from one probe response
	defaultTimeout = 5 * time.Second
)

// dialer opens connections to one target, optionally wrapped in TLS.
type dialer struct {
	ip       netip.Addr
	port     uint16
	proto    string // "tcp" | "udp"
	timeout  time.Duration
	hostname string
}

func (d *dialer) addr() string {
	return net.JoinHostPort(d.ip.String(), strconv.Itoa(int(d.port)))
}

// dial opens a plain connection bound to ctx: cancelling ctx closes it.
func (d *dialer) dial(ctx context.Context) (net.Conn, error) {
	nd := net.Dialer{Timeout: d.timeout}
	c, err := nd.DialContext(ctx, d.proto, d.addr())
	if err != nil {
		return nil, err
	}
	return bindConn(ctx, c), nil
}

// dialTLS opens a TLS connection (handshake done) bound to ctx.
func (d *dialer) dialTLS(ctx context.Context, alpn []string) (*tls.Conn, error) {
	c, err := d.dial(ctx)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(c, clientTLSConfig(d.hostname, alpn))
	hctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return tc, nil
}

// connDial returns a dial function producing plain or TLS connections.
func (d *dialer) connDial(useTLS bool) func(context.Context) (net.Conn, error) {
	if !useTLS {
		return d.dial
	}
	return func(ctx context.Context) (net.Conn, error) {
		c, err := d.dialTLS(ctx, []string{"http/1.1"})
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}

// ctxConn closes the underlying connection when the context is cancelled so
// that blocked reads/writes return promptly.
type ctxConn struct {
	net.Conn
	stop func() bool
}

func (c *ctxConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

func bindConn(ctx context.Context, c net.Conn) net.Conn {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	return &ctxConn{Conn: c, stop: stop}
}

// readResponse reads from c until the peer closes, maxResponse bytes are
// read, total elapses, or (once some data arrived) the line stays idle for
// idle. stopFn, when non-nil, is evaluated after each read and stops early
// when it returns true. closed reports whether the peer closed the
// connection (EOF / reset).
func readResponse(c net.Conn, total, idle time.Duration, stopFn func([]byte) bool) (data []byte, closed bool, err error) {
	deadline := time.Now().Add(total)
	buf := make([]byte, 4096)
	for len(data) < maxResponse {
		dl := deadline
		if len(data) > 0 && idle > 0 {
			if t := time.Now().Add(idle); t.Before(dl) {
				dl = t
			}
		}
		_ = c.SetReadDeadline(dl)
		n, rerr := c.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if stopFn != nil && stopFn(data) {
				return data, false, nil
			}
		}
		if rerr != nil {
			if isTimeout(rerr) {
				return data, false, nil
			}
			if errors.Is(rerr, io.EOF) || isConnReset(rerr) {
				return data, true, nil
			}
			return data, false, rerr
		}
	}
	return data, false, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded)
}

func isConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, net.ErrClosed)
}

func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// printable renders raw bytes as a printable, nmap-like escaped string
// truncated to maxBanner characters.
func printable(b []byte) string {
	var sb strings.Builder
	const hexd = "0123456789ABCDEF"
	for _, c := range b {
		if sb.Len() >= maxBanner {
			break
		}
		switch {
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c == '\\':
			sb.WriteString(`\\`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			sb.WriteString(`\x`)
			sb.WriteByte(hexd[c>>4])
			sb.WriteByte(hexd[c&0xf])
		}
	}
	s := sb.String()
	if len(s) > maxBanner {
		s = s[:maxBanner]
	}
	return s
}

// cleanText keeps printable characters of s (used for version fields).
func cleanText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// avoid cutting in the middle of a UTF-8 sequence
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
