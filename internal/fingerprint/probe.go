package fingerprint

import (
	"context"
	"net"
	"time"
)

// peekResult is the outcome of the NULL probe: connect and listen for a banner the
// service volunteers on its own.
type peekResult struct {
	data   []byte // raw bytes the service sent unprompted
	closed bool   // the peer closed the connection
	err    error  // connection-level failure (dial or read)
	dialed bool   // the TCP/UDP connection was established
}

// bannerWait is how long we wait for a service to speak first.
func (d *dialer) bannerWait() time.Duration {
	return capDuration(d.timeout, 2*time.Second)
}

// handshakeTimeout bounds one TLS handshake.
func (d *dialer) handshakeTimeout() time.Duration {
	return capDuration(d.timeout, 5*time.Second)
}

func capDuration(d, max time.Duration) time.Duration {
	if d <= 0 {
		d = defaultTimeout
	}
	if d > max {
		return max
	}
	return d
}

// peek opens a connection and reads whatever the service sends on its own. A service that
// stays silent yields an empty, error-free result.
func (d *dialer) peek(ctx context.Context) peekResult {
	c, err := d.dial(ctx)
	if err != nil {
		return peekResult{err: err}
	}
	defer func() { _ = c.Close() }()
	data, closed, rerr := readResponse(c, d.bannerWait(), 300*time.Millisecond, nil)
	return peekResult{data: data, closed: closed, err: rerr, dialed: true}
}

// peekConn reads an unprompted banner from an already established connection (used inside
// a TLS tunnel).
func (d *dialer) peekConn(c net.Conn) []byte {
	data, _, _ := readResponse(c, d.bannerWait(), 300*time.Millisecond, nil)
	return data
}

// sendProbe opens a connection (optionally TLS), writes payload and reads the answer. An
// empty payload makes it a NULL probe. wait bounds the whole exchange.
func (d *dialer) sendProbe(ctx context.Context, payload []byte, useTLS bool, wait time.Duration) ([]byte, error) {
	if wait <= 0 {
		wait = d.bannerWait()
	}
	wait = capDuration(wait, 10*time.Second)

	var (
		c   net.Conn
		err error
	)
	if useTLS {
		c, err = d.dialTLS(ctx, nil)
	} else {
		c, err = d.dial(ctx)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()

	// A UDP probe must emit a datagram even when its payload is empty, or the peer never
	// hears from us at all; over TCP an empty payload is the NULL probe and nothing
	// should be written.
	if len(payload) > 0 || d.proto == "udp" {
		if err := c.SetWriteDeadline(time.Now().Add(wait)); err != nil {
			return nil, err
		}
		if _, err := c.Write(payload); err != nil {
			return nil, err
		}
	}
	data, _, rerr := readResponse(c, wait, 400*time.Millisecond, nil)
	if len(data) == 0 && rerr != nil {
		return nil, rerr
	}
	return data, nil
}
