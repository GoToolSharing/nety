package checks

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"unicode/utf16"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: intrusiveInfo(checkInfo("mssql-default-credentials", "Microsoft SQL Server 'sa' account with default/empty password", model.SevCritical,
			[]string{"ms-sql-s", "mssql"},
			"The SQL Server accepts a SQL login as 'sa' with an empty or trivial password. 'sa' is sysadmin: full data access and command execution on the host (xp_cmdshell). At most two login attempts are made.")),
		Remediation: "Set a strong password on 'sa' or disable it (ALTER LOGIN sa DISABLE), prefer Windows authentication, enforce password policy (CHECK_POLICY=ON) and firewall port 1433.",
		References:  []string{"https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode"},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"ms-sql-s", "mssql", "ms-sql"}, 1433)
		},
		Run: runMSSQLDefault,
	})
}

const (
	tdsPrelogin    = 0x12
	tdsLogin7      = 0x10
	tdsReply       = 0x04
	tdsEncOff      = 0
	tdsEncOn       = 1
	tdsEncNotSup   = 2
	tdsEncRequired = 3
)

func tdsPacket(typ byte, payload []byte) []byte {
	b := make([]byte, 8, 8+len(payload))
	b[0] = typ
	b[1] = 0x01 // EOM
	binary.BigEndian.PutUint16(b[2:], uint16(8+len(payload)))
	b[6] = 1
	return append(b, payload...)
}

// tdsReadMessage reads TDS packets until EOM (bounded) and returns the type and
// concatenated payload.
func tdsReadMessage(r io.Reader) (byte, []byte, error) {
	var out []byte
	var typ byte
	for i := 0; i < 64; i++ {
		var h [8]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return 0, out, err
		}
		typ = h[0]
		l := int(binary.BigEndian.Uint16(h[2:]))
		if l < 8 {
			return 0, nil, errors.New("tds: bad packet length")
		}
		p := make([]byte, l-8)
		if _, err := io.ReadFull(r, p); err != nil {
			return 0, nil, err
		}
		out = append(out, p...)
		if len(out) > 1<<20 {
			return 0, nil, errors.New("tds: message too large")
		}
		if h[1]&0x01 != 0 {
			return typ, out, nil
		}
	}
	return 0, nil, errors.New("tds: too many packets")
}

func tdsPreloginPayload(enc byte) []byte {
	// tokens: VERSION(0) len 6, ENCRYPTION(1) len 1, INSTOPT(2) len 1, THREADID(3) len 4, terminator
	const hdr = 5*4 + 1
	b := []byte{
		0, 0, hdr, 0, 6,
		1, 0, hdr + 6, 0, 1,
		2, 0, hdr + 7, 0, 1,
		3, 0, hdr + 8, 0, 4,
		0xff,
	}
	b = append(b, 0x0f, 0x00, 0x07, 0xd0, 0, 0) // client version 15.0.2000
	b = append(b, enc)
	b = append(b, 0)          // instance: default
	b = append(b, 0, 0, 0, 0) // thread id
	return b
}

type tdsPreloginInfo struct {
	Version    string
	Encryption byte
}

func tdsParsePrelogin(b []byte) (tdsPreloginInfo, error) {
	var info tdsPreloginInfo
	info.Encryption = 0xff
	for i := 0; i < 32; i++ {
		if i*5 >= len(b) {
			return info, errors.New("tds: truncated prelogin")
		}
		p := b[i*5:]
		if p[0] == 0xff {
			return info, nil
		}
		if len(p) < 5 {
			return info, errors.New("tds: truncated prelogin")
		}
		off := int(binary.BigEndian.Uint16(p[1:]))
		l := int(binary.BigEndian.Uint16(p[3:]))
		if off+l > len(b) {
			continue
		}
		v := b[off : off+l]
		switch p[0] {
		case 0:
			if len(v) >= 4 {
				info.Version = fmt.Sprintf("%d.%d.%d", v[0], v[1], binary.BigEndian.Uint16(v[2:]))
			}
		case 1:
			if len(v) >= 1 {
				info.Encryption = v[0]
			}
		}
	}
	return info, nil
}

// tdsManglePassword applies the LOGIN7 password obfuscation.
func tdsManglePassword(p string) []byte {
	b := tdsUCS2(p)
	for i, c := range b {
		b[i] = ((c << 4) | (c >> 4)) ^ 0xa5
	}
	return b
}

func tdsUCS2(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}

func tdsLogin7Payload(user, password, host, app, server string) []byte {
	const fixed = 94
	fields := [][]byte{tdsUCS2(host), tdsUCS2(user), tdsManglePassword(password), tdsUCS2(app), tdsUCS2(server), nil, tdsUCS2("nety"), nil, nil}
	b := make([]byte, fixed)
	binary.LittleEndian.PutUint32(b[4:], 0x74000004) // TDS 7.4
	binary.LittleEndian.PutUint32(b[8:], 4096)
	binary.LittleEndian.PutUint32(b[12:], 0x07000000)
	b[24] = 0xe0 // OptionFlags1: USE_DB, INIT_DB_FATAL, SET_LANG
	b[25] = 0x03 // OptionFlags2: INIT_LANG_FATAL, ODBC
	binary.LittleEndian.PutUint32(b[32:], 0x0409)
	off := fixed
	var data []byte
	for i, f := range fields {
		binary.LittleEndian.PutUint16(b[36+4*i:], uint16(off))
		binary.LittleEndian.PutUint16(b[38+4*i:], uint16(len(f)/2))
		data = append(data, f...)
		off += len(f)
	}
	// ClientID (6 bytes) at 72, SSPI 78, AtchDBFile 82, ChangePassword 86, cbSSPILong 90
	for _, o := range []int{78, 82, 86} {
		binary.LittleEndian.PutUint16(b[o:], uint16(off))
	}
	b = append(b, data...)
	binary.LittleEndian.PutUint32(b[0:], uint32(len(b)))
	return b
}

// tdsLoginResult scans the token stream of a LOGIN7 reply.
func tdsLoginResult(b []byte) (ok bool, errMsg string) {
	p := 0
	for p < len(b) {
		tok := b[p]
		p++
		switch tok {
		case 0xad, 0xaa, 0xab, 0xe3, 0xae: // LOGINACK, ERROR, INFO, ENVCHANGE, FEATUREEXTACK
			if tok == 0xae {
				return ok, errMsg // variable format, stop scanning
			}
			if p+2 > len(b) {
				return ok, errMsg
			}
			l := int(binary.LittleEndian.Uint16(b[p:]))
			p += 2
			if p+l > len(b) {
				return ok, errMsg
			}
			v := b[p : p+l]
			if tok == 0xad {
				ok = true
			}
			if tok == 0xaa && len(v) >= 8 {
				num := binary.LittleEndian.Uint32(v)
				ml := int(binary.LittleEndian.Uint16(v[6:]))
				msg := ""
				if 8+2*ml <= len(v) {
					u := make([]uint16, ml)
					for i := range u {
						u[i] = binary.LittleEndian.Uint16(v[8+2*i:])
					}
					msg = printable([]byte(string(utf16.Decode(u))), 200)
				}
				errMsg = fmt.Sprintf("error %d: %s", num, msg)
			}
			p += l
		case 0xfd, 0xfe, 0xff: // DONE tokens (TDS 7.2+: 12 bytes)
			p += 12
		default:
			return ok, errMsg
		}
	}
	return ok, errMsg
}

// tdsTLSShim carries TLS handshake records inside TDS PRELOGIN packets, as required by
// MS-TDS; once the handshake is done, records go on the wire raw.
type tdsTLSShim struct {
	net.Conn
	handshake bool
	rbuf      []byte
}

func (s *tdsTLSShim) Write(p []byte) (int, error) {
	if !s.handshake {
		return s.Conn.Write(p)
	}
	if _, err := s.Conn.Write(tdsPacket(tdsPrelogin, p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *tdsTLSShim) Read(p []byte) (int, error) {
	if !s.handshake {
		return s.Conn.Read(p)
	}
	if len(s.rbuf) == 0 {
		var h [8]byte
		if _, err := io.ReadFull(s.Conn, h[:]); err != nil {
			return 0, err
		}
		l := int(binary.BigEndian.Uint16(h[2:]))
		if l < 8 {
			return 0, errors.New("tds: bad tls packet")
		}
		s.rbuf = make([]byte, l-8)
		if _, err := io.ReadFull(s.Conn, s.rbuf); err != nil {
			return 0, err
		}
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

// mssqlLogin performs PRELOGIN + (optional TLS) + LOGIN7 on a fresh connection. It
// returns the prelogin info and the login outcome.
func mssqlLogin(ctx context.Context, t *Target, user, password string, enc byte) (tdsPreloginInfo, bool, string, error) {
	var info tdsPreloginInfo
	c, err := t.Dial(ctx)
	if err != nil {
		return info, false, "", err
	}
	defer c.Close()
	if _, err := c.Write(tdsPacket(tdsPrelogin, tdsPreloginPayload(enc))); err != nil {
		return info, false, "", err
	}
	typ, b, err := tdsReadMessage(c)
	if err != nil {
		return info, false, "", err
	}
	if typ != tdsReply {
		return info, false, "", errors.New("tds: unexpected prelogin reply")
	}
	info, err = tdsParsePrelogin(b)
	if err != nil {
		return info, false, "", err
	}
	var rw io.ReadWriter = c
	var rd io.Reader = c
	switch {
	case enc == tdsEncNotSup && info.Encryption == tdsEncNotSup:
		// plaintext login
	case enc == tdsEncOn && (info.Encryption == tdsEncOn || info.Encryption == tdsEncRequired || info.Encryption == tdsEncOff):
		shim := &tdsTLSShim{Conn: c, handshake: true}
		tc := tls.Client(shim, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12}) //nolint:gosec // scanning
		_ = c.SetDeadline(time.Now().Add(t.Timeout))
		if err := tc.HandshakeContext(ctx); err != nil {
			return info, false, "", fmt.Errorf("tds tls: %w", err)
		}
		shim.handshake = false
		rw, rd = tc, tc
		if info.Encryption == tdsEncOff {
			rd = c // ENCRYPT_OFF: only the LOGIN7 packet is encrypted
		}
	default:
		return info, false, "", fmt.Errorf("tds: encryption negotiation %d/%d", enc, info.Encryption)
	}
	_ = c.SetDeadline(time.Now().Add(t.Timeout))
	if _, err := rw.Write(tdsPacket(tdsLogin7, tdsLogin7Payload(user, password, "nety", "nety", t.IP))); err != nil {
		return info, false, "", err
	}
	typ, b, err = tdsReadMessage(rd)
	if err != nil && len(b) == 0 {
		return info, false, "", err
	}
	if typ != tdsReply {
		return info, false, "", errors.New("tds: unexpected login reply")
	}
	ok, msg := tdsLoginResult(b)
	return info, ok, msg, nil
}

func runMSSQLDefault(ctx context.Context, t *Target) []model.Finding {
	enc := byte(tdsEncNotSup)
	for _, pw := range []string{"", "sa"} {
		if ctx.Err() != nil {
			return nil
		}
		info, ok, msg, err := mssqlLogin(ctx, t, "sa", pw, enc)
		if err != nil && enc == tdsEncNotSup && (info.Encryption == tdsEncRequired || info.Encryption == tdsEncOn) {
			// Server mandates encryption: retry the same credential over TLS.
			enc = tdsEncOn
			info, ok, msg, err = mssqlLogin(ctx, t, "sa", pw, enc)
		}
		if err != nil {
			t.Log.Debug("mssql login", "err", err)
			return nil
		}
		if ok {
			shown := pw
			if shown == "" {
				shown = "(empty password)"
			}
			return []model.Finding{t.Finding(fmt.Sprintf("SQL Server %s: login sa / %s accepted (LOGINACK)", info.Version, shown))}
		}
		t.Log.Debug("mssql login refused", "msg", msg)
	}
	return nil
}
