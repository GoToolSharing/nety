package checks

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // mysql_native_password scramble
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: intrusiveInfo(checkInfo("mysql-default-credentials", "MySQL/MariaDB root account without password", model.SevCritical,
			[]string{"mysql"},
			"The MySQL/MariaDB server accepts a network login as 'root' with an empty password, giving full control over every database and often file read/write on the host. A single login attempt is made.")),
		Remediation: "Set a strong password for every root account (or use unix_socket authentication restricted to localhost), remove remote root logins (root@'%') and firewall port 3306.",
		References:  []string{"https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html"},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"mysql", "mariadb"}, 3306)
		},
		Run: runMySQLDefault,
	})
}

const (
	mysqlClientLongPassword     = 0x00000001
	mysqlClientLongFlag         = 0x00000004
	mysqlClientProtocol41       = 0x00000200
	mysqlClientTransactions     = 0x00002000
	mysqlClientSecureConnection = 0x00008000
	mysqlClientPluginAuth       = 0x00080000
	mysqlClientSSL              = 0x00000800
)

type mysqlHandshake struct {
	ServerVersion string
	Caps          uint32
	Scramble      []byte
	Plugin        string
}

// mysqlReadPacket reads one packet (payload, sequence id).
func mysqlReadPacket(r io.Reader) ([]byte, byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, 0, err
	}
	l := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if l > 1<<20 {
		return nil, 0, errors.New("mysql: packet too large")
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, 0, err
	}
	return b, h[3], nil
}

func mysqlWritePacket(w io.Writer, seq byte, p []byte) error {
	h := []byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), seq}
	_, err := w.Write(append(h, p...))
	return err
}

var errMySQLMalformed = errors.New("mysql: malformed handshake")

func mysqlParseHandshake(p []byte) (*mysqlHandshake, error) {
	if len(p) < 1 {
		return nil, errMySQLMalformed
	}
	if p[0] == 0xff {
		return nil, fmt.Errorf("mysql: server error: %s", mysqlErrMsg(p))
	}
	if p[0] != 10 {
		return nil, errMySQLMalformed
	}
	i := bytes.IndexByte(p[1:], 0)
	if i < 0 {
		return nil, errMySQLMalformed
	}
	h := &mysqlHandshake{ServerVersion: printable(p[1:1+i], 80)}
	pos := 1 + i + 1
	if pos+4+8+1+2 > len(p) {
		return nil, errMySQLMalformed
	}
	pos += 4 // connection id
	h.Scramble = append([]byte(nil), p[pos:pos+8]...)
	pos += 9
	h.Caps = uint32(binary.LittleEndian.Uint16(p[pos:]))
	pos += 2
	if pos+1+2+2+1+10 > len(p) {
		return h, nil
	}
	pos += 3 // charset + status
	h.Caps |= uint32(binary.LittleEndian.Uint16(p[pos:])) << 16
	pos += 2
	authLen := int(p[pos])
	pos += 11
	if h.Caps&mysqlClientSecureConnection != 0 {
		n := authLen - 8
		if n < 13 {
			n = 13
		}
		if pos+n > len(p) {
			n = len(p) - pos
		}
		part := p[pos : pos+n]
		part = bytes.TrimRight(part, "\x00")
		h.Scramble = append(h.Scramble, part...)
		pos += n
	}
	if h.Caps&mysqlClientPluginAuth != 0 && pos < len(p) {
		end := bytes.IndexByte(p[pos:], 0)
		if end < 0 {
			end = len(p) - pos
		}
		h.Plugin = string(p[pos : pos+end])
	}
	return h, nil
}

func mysqlErrMsg(p []byte) string {
	if len(p) < 3 || p[0] != 0xff {
		return ""
	}
	code := binary.LittleEndian.Uint16(p[1:])
	msg := p[3:]
	if len(msg) > 6 && msg[0] == '#' {
		msg = msg[6:]
	}
	return fmt.Sprintf("%d %s", code, printable(msg, 200))
}

// mysqlNativeScramble computes the mysql_native_password response.
func mysqlNativeScramble(scramble []byte, password string) []byte {
	if password == "" {
		return nil
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(scramble)
	h.Write(h2[:])
	h3 := h.Sum(nil)
	for i := range h3 {
		h3[i] ^= h1[i]
	}
	return h3
}

// mysqlLogin attempts one login and reports success. err is non-nil when
// the outcome is unknown (protocol error, TLS required, ...).
func mysqlLogin(c net.Conn, user, password string) (ok bool, version string, detail string, err error) {
	p, _, err := mysqlReadPacket(c)
	if err != nil {
		return false, "", "", err
	}
	hs, err := mysqlParseHandshake(p)
	if err != nil {
		return false, "", "", err
	}
	if hs.Caps&mysqlClientProtocol41 == 0 {
		return false, hs.ServerVersion, "", errors.New("mysql: pre-4.1 protocol unsupported")
	}
	plugin := hs.Plugin
	if plugin == "" {
		plugin = "mysql_native_password"
	}
	var authResp []byte
	switch plugin {
	case "mysql_native_password":
		authResp = mysqlNativeScramble(hs.Scramble, password)
	case "caching_sha2_password":
		if password != "" {
			return false, hs.ServerVersion, "", errors.New("mysql: caching_sha2 with password unsupported")
		}
	default:
		// Ask for mysql_native_password through an auth switch.
		plugin = "mysql_native_password"
		authResp = mysqlNativeScramble(hs.Scramble, password)
	}
	caps := uint32(mysqlClientLongPassword | mysqlClientLongFlag | mysqlClientProtocol41 | mysqlClientTransactions | mysqlClientSecureConnection | mysqlClientPluginAuth)
	resp := binary.LittleEndian.AppendUint32(nil, caps)
	resp = binary.LittleEndian.AppendUint32(resp, 1<<24)
	resp = append(resp, 45) // utf8mb4_general_ci
	resp = append(resp, make([]byte, 23)...)
	resp = append(resp, user...)
	resp = append(resp, 0)
	resp = append(resp, byte(len(authResp)))
	resp = append(resp, authResp...)
	resp = append(resp, plugin...)
	resp = append(resp, 0)
	if err := mysqlWritePacket(c, 1, resp); err != nil {
		return false, hs.ServerVersion, "", err
	}
	for i := 0; i < 4; i++ {
		p, seq, err := mysqlReadPacket(c)
		if err != nil {
			return false, hs.ServerVersion, "", err
		}
		if len(p) == 0 {
			return false, hs.ServerVersion, "", errMySQLMalformed
		}
		switch p[0] {
		case 0x00:
			return true, hs.ServerVersion, "OK packet", nil
		case 0xff:
			return false, hs.ServerVersion, mysqlErrMsg(p), nil
		case 0x01: // caching_sha2 fast-auth result
			if len(p) >= 2 && p[1] == 0x03 {
				continue // fast auth success, OK packet follows
			}
			return false, hs.ServerVersion, "full authentication required", nil
		case 0xfe: // auth switch request
			rest := p[1:]
			end := bytes.IndexByte(rest, 0)
			if end < 0 {
				return false, hs.ServerVersion, "", errMySQLMalformed
			}
			newPlugin := string(rest[:end])
			data := bytes.TrimRight(rest[end+1:], "\x00")
			var out []byte
			switch newPlugin {
			case "mysql_native_password":
				out = mysqlNativeScramble(data, password)
			case "caching_sha2_password":
				if password != "" {
					return false, hs.ServerVersion, "", errors.New("mysql: caching_sha2 unsupported")
				}
			default:
				return false, hs.ServerVersion, "", fmt.Errorf("mysql: unsupported auth plugin %q", printable([]byte(newPlugin), 40))
			}
			if err := mysqlWritePacket(c, seq+1, out); err != nil {
				return false, hs.ServerVersion, "", err
			}
		default:
			return false, hs.ServerVersion, "", errMySQLMalformed
		}
	}
	return false, hs.ServerVersion, "", errMySQLMalformed
}

func runMySQLDefault(ctx context.Context, t *Target) []model.Finding {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer c.Close()
	ok, ver, detail, err := mysqlLogin(c, "root", "")
	if err != nil {
		t.Log.Debug("mysql login", "err", err)
		return nil
	}
	if !ok {
		t.Log.Debug("mysql login refused", "detail", detail)
		return nil
	}
	_ = mysqlWritePacket(c, 0, []byte{0x01}) // COM_QUIT
	return []model.Finding{t.Finding(fmt.Sprintf("Server %s: login root / (empty password) accepted (%s)", ver, detail))}
}
