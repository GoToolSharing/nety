package identity

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/vaadata/nety/internal/identity/ntlm"
)

// TDS packet types.
const (
	tdsPrelogin = 0x12
	tdsLogin7   = 0x10
	tdsReply    = 0x04
)

// TDS PRELOGIN encryption values.
const (
	tdsEncryptOff    = 0x00
	tdsEncryptOn     = 0x01
	tdsEncryptNotSup = 0x02
	tdsEncryptReq    = 0x03
)

const tdsMaxMessage = 1 << 20

func tdsPacket(typ byte, id byte, payload []byte) []byte {
	b := make([]byte, 8, 8+len(payload))
	b[0] = typ
	b[1] = 0x01 // EOM
	binary.BigEndian.PutUint16(b[2:], uint16(8+len(payload)))
	b[6] = id
	return append(b, payload...)
}

// buildPrelogin builds a PRELOGIN payload (VERSION, ENCRYPTION, INSTOPT,
// THREADID, MARS).
func buildPrelogin(encryption byte) []byte {
	type opt struct {
		tok  byte
		data []byte
	}
	opts := []opt{
		{0x00, []byte{0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00}},
		{0x01, []byte{encryption}},
		{0x02, []byte{0x00}},
		{0x03, []byte{0x00, 0x00, 0x00, 0x00}},
		{0x04, []byte{0x00}},
	}
	hdrLen := len(opts)*5 + 1
	var hdr, data []byte
	for _, o := range opts {
		hdr = append(hdr, o.tok)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(hdrLen+len(data)))
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(o.data)))
		data = append(data, o.data...)
	}
	hdr = append(hdr, 0xff)
	return append(hdr, data...)
}

// preloginInfo is a decoded PRELOGIN response.
type preloginInfo struct {
	Major, Minor  uint8
	Build, Sub    uint16
	HasVersion    bool
	Encryption    byte
	HasEncryption bool
}

func (p preloginInfo) Version() string {
	if !p.HasVersion {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", p.Major, p.Minor, p.Build, p.Sub)
}

// sqlProduct maps a SQL Server version to its marketing name.
func sqlProduct(major, minor uint8) string {
	switch major {
	case 8:
		return "SQL Server 2000"
	case 9:
		return "SQL Server 2005"
	case 10:
		if minor >= 50 {
			return "SQL Server 2008 R2"
		}
		return "SQL Server 2008"
	case 11:
		return "SQL Server 2012"
	case 12:
		return "SQL Server 2014"
	case 13:
		return "SQL Server 2016"
	case 14:
		return "SQL Server 2017"
	case 15:
		return "SQL Server 2019"
	case 16:
		return "SQL Server 2022"
	case 17:
		return "SQL Server 2025"
	}
	return ""
}

// parsePrelogin decodes a PRELOGIN response payload.
func parsePrelogin(b []byte) (preloginInfo, error) {
	var p preloginInfo
	for i := 0; i < 32; i++ {
		pos := i * 5
		if pos >= len(b) {
			return p, errors.New("tds: truncated prelogin")
		}
		tok := b[pos]
		if tok == 0xff {
			return p, nil
		}
		if pos+5 > len(b) {
			return p, errors.New("tds: truncated prelogin")
		}
		off := int(binary.BigEndian.Uint16(b[pos+1:]))
		l := int(binary.BigEndian.Uint16(b[pos+3:]))
		if off+l > len(b) {
			return p, errors.New("tds: prelogin option out of bounds")
		}
		d := b[off : off+l]
		switch tok {
		case 0x00:
			if len(d) >= 6 {
				p.Major, p.Minor = d[0], d[1]
				p.Build = binary.BigEndian.Uint16(d[2:])
				p.Sub = binary.BigEndian.Uint16(d[4:])
				p.HasVersion = true
			}
		case 0x01:
			if len(d) >= 1 {
				p.Encryption = d[0]
				p.HasEncryption = true
			}
		}
	}
	return p, errors.New("tds: too many prelogin options")
}

// buildLogin7SSPI builds a LOGIN7 payload requesting integrated security
// with the given SSPI blob.
func buildLogin7SSPI(server string, sspi []byte) []byte {
	const fixed = 94
	b := make([]byte, fixed)
	binary.LittleEndian.PutUint32(b[4:], 0x74000004)
	binary.LittleEndian.PutUint32(b[8:], 4096)
	binary.LittleEndian.PutUint32(b[12:], 0x07000000)
	binary.LittleEndian.PutUint32(b[16:], 4242)
	b[24] = 0xe0
	b[25] = 0x83 // fIntSecurity | fODBC | fLanguage
	binary.LittleEndian.PutUint32(b[32:], 0x0409)
	var data []byte
	str := func(field int, s string) {
		u := ntlm.EncodeUTF16(s)
		binary.LittleEndian.PutUint16(b[field:], uint16(fixed+len(data)))
		binary.LittleEndian.PutUint16(b[field+2:], uint16(len(u)/2))
		data = append(data, u...)
	}
	str(36, "NETY") // HostName
	str(40, "")     // UserName
	str(44, "")     // Password
	str(48, "nety") // AppName
	str(52, server) // ServerName
	str(56, "")     // Extension (unused)
	str(60, "nety") // CltIntName
	str(64, "")     // Language
	str(68, "")     // Database
	binary.LittleEndian.PutUint16(b[78:], uint16(fixed+len(data)))
	binary.LittleEndian.PutUint16(b[80:], uint16(len(sspi)))
	data = append(data, sspi...)
	str(82, "") // AtchDBFile
	str(86, "") // ChangePassword
	b = append(b, data...)
	binary.LittleEndian.PutUint32(b[0:], uint32(len(b)))
	return b
}

// extractSSPIToken returns the content of the first SSPI (0xED) token that
// looks like NTLMSSP or SPNEGO data.
func extractSSPIToken(payload []byte) []byte {
	for i := 0; i+3 <= len(payload); i++ {
		if payload[i] != 0xed {
			continue
		}
		l := int(binary.LittleEndian.Uint16(payload[i+1:]))
		if l == 0 || i+3+l > len(payload) {
			continue
		}
		d := payload[i+3 : i+3+l]
		if len(d) >= 8 && string(d[:7]) == "NTLMSSP" || d[0] == 0xa1 || d[0] == 0x60 {
			return d
		}
	}
	return nil
}

// tdsConn carries TDS packets, optionally with TLS negotiated inside
// PRELOGIN packets (MS-TDS 2.2.6.5 / 3.2.5.2).
type tdsConn struct {
	raw     net.Conn
	br      *bufio.Reader
	timeout time.Duration
	id      byte
	// TLS-in-TDS state
	handshaking bool
	pending     []byte
	tls         *tls.Conn
}

func (t *tdsConn) writePacket(typ byte, payload []byte) error {
	t.id++
	pkt := tdsPacket(typ, t.id, payload)
	if t.tls != nil {
		_ = t.tls.SetWriteDeadline(time.Now().Add(t.timeout))
		_, err := t.tls.Write(pkt)
		return err
	}
	_ = t.raw.SetWriteDeadline(time.Now().Add(t.timeout))
	_, err := t.raw.Write(pkt)
	return err
}

// readMessage reads TDS packets from r until EOM.
func readTDSMessage(r io.Reader) (byte, []byte, error) {
	var msg []byte
	var typ byte
	for i := 0; i < 1024; i++ {
		h := make([]byte, 8)
		if _, err := io.ReadFull(r, h); err != nil {
			return 0, nil, err
		}
		l := int(binary.BigEndian.Uint16(h[2:]))
		if l < 8 {
			return 0, nil, errors.New("tds: bad packet length")
		}
		if len(msg)+l > tdsMaxMessage {
			return 0, nil, errors.New("tds: message too large")
		}
		typ = h[0]
		body := make([]byte, l-8)
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, nil, err
		}
		msg = append(msg, body...)
		if h[1]&0x01 != 0 {
			return typ, msg, nil
		}
	}
	return 0, nil, errors.New("tds: too many packets")
}

// net.Conn adapter used by crypto/tls during the handshake.
type tdsTLSAdapter struct {
	net.Conn
	t *tdsConn
}

func (a *tdsTLSAdapter) Read(p []byte) (int, error) {
	if !a.t.handshaking {
		return a.t.br.Read(p)
	}
	if len(a.t.pending) == 0 {
		typ, msg, err := readTDSMessage(a.t.br)
		if err != nil {
			return 0, err
		}
		if typ != tdsReply && typ != tdsPrelogin {
			return 0, fmt.Errorf("tds: unexpected packet 0x%02x during TLS handshake", typ)
		}
		a.t.pending = msg
	}
	n := copy(p, a.t.pending)
	a.t.pending = a.t.pending[n:]
	return n, nil
}

func (a *tdsTLSAdapter) Write(p []byte) (int, error) {
	if !a.t.handshaking {
		return a.t.raw.Write(p)
	}
	for off := 0; off < len(p); {
		n := min(len(p)-off, 4096-8)
		a.t.id++
		if _, err := a.t.raw.Write(tdsPacket(tdsPrelogin, a.t.id, p[off:off+n])); err != nil {
			return off, err
		}
		off += n
	}
	return len(p), nil
}

// probeMSSQL reads the PRELOGIN version and requests an NTLM CHALLENGE via
// LOGIN7 integrated security. The login is never completed.
func (c *collector) probeMSSQL(ctx context.Context, sink *evidenceSink, ip string, port int) error {
	pctx, cancel := withTimeout(ctx, 3*c.ioTimeout)
	defer cancel()
	d := net.Dialer{Timeout: c.ioTimeout}
	raw, err := d.DialContext(pctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	stop := context.AfterFunc(pctx, func() { _ = raw.Close() })
	defer stop()
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(2 * c.ioTimeout))
	t := &tdsConn{raw: raw, br: bufio.NewReader(raw), timeout: c.ioTimeout}
	if err := t.writePacket(tdsPrelogin, buildPrelogin(tdsEncryptOff)); err != nil {
		return err
	}
	_, msg, err := readTDSMessage(t.br)
	if err != nil {
		return err
	}
	pl, err := parsePrelogin(msg)
	if err != nil {
		return err
	}
	attrs := map[string]string{}
	if v := pl.Version(); v != "" {
		attrs["mssql_version"] = v
		attrs["mssql_product"] = sqlProduct(pl.Major, pl.Minor)
	}
	if pl.Encryption != tdsEncryptNotSup {
		t.handshaking = true
		adapter := &tdsTLSAdapter{Conn: raw, t: t}
		tc := tls.Client(adapter, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, MinVersion: tls.VersionTLS10}) //nolint:gosec // fingerprinting only
		if err := tc.HandshakeContext(pctx); err != nil {
			return fmt.Errorf("tds: TLS handshake: %w", err)
		}
		t.handshaking = false
		t.tls = tc
	}
	if err := t.writePacket(tdsLogin7, buildLogin7SSPI(ip, ntlm.NegotiateMessage())); err != nil {
		return err
	}
	// With ENCRYPT_OFF only the LOGIN7 packet is encrypted: the reply is
	// plaintext. With ENCRYPT_ON/REQ it is TLS. Peek to decide.
	_ = raw.SetReadDeadline(time.Now().Add(c.ioTimeout))
	first, err := t.br.Peek(1)
	if err != nil {
		return err
	}
	var reply []byte
	if t.tls != nil && first[0] == 0x17 {
		_, reply, err = readTDSMessage(t.tls)
	} else {
		_, reply, err = readTDSMessage(t.br)
	}
	if err != nil {
		return err
	}
	tok := extractSSPIToken(reply)
	if tok == nil {
		tok = reply
	}
	ch, err := ntlm.FindChallenge(tok)
	if err != nil {
		return fmt.Errorf("tds: no NTLM challenge in LOGIN7 reply: %w", err)
	}
	ntlmEvidence(sink, ch, "mssql-ntlm/"+strconv.Itoa(port), attrs)
	return nil
}
