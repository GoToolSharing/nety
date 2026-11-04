package checks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // PostgreSQL md5 auth
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: intrusiveInfo(checkInfo("postgres-default-credentials", "PostgreSQL accepts default or no credentials", model.SevCritical,
			[]string{"postgresql"},
			"The PostgreSQL server accepts a network login as 'postgres' with the default password 'postgres', or without any password (trust authentication). The postgres superuser can read all data and execute commands on the host (COPY ... PROGRAM). A single login attempt is made.")),
		Remediation: "Set a strong password for the postgres role, replace 'trust' entries in pg_hba.conf with scram-sha-256, restrict hosts allowed in pg_hba.conf and firewall port 5432.",
		References:  []string{"https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"postgresql", "postgres"}, 5432)
		},
		Run: runPostgresDefault,
	})
}

// pgMaxIterations bounds SCRAM iterations requested by the server (CPU DoS).
const pgMaxIterations = 600000

func pgStartup(user, db string) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[4:], 196608)
	for _, kv := range [][2]string{{"user", user}, {"database", db}, {"application_name", "nety"}} {
		b = append(b, kv[0]...)
		b = append(b, 0)
		b = append(b, kv[1]...)
		b = append(b, 0)
	}
	b = append(b, 0)
	binary.BigEndian.PutUint32(b, uint32(len(b)))
	return b
}

func pgMessage(typ byte, payload []byte) []byte {
	b := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)+4))
	return append(b, payload...)
}

func pgRead(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	l := int(binary.BigEndian.Uint32(h[1:]))
	if l < 4 || l > 1<<20 {
		return 0, nil, errors.New("postgres: bad message length")
	}
	b := make([]byte, l-4)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return h[0], b, nil
}

// pgErrorText extracts severity/code/message from an ErrorResponse.
func pgErrorText(b []byte) (code, msg string) {
	for len(b) > 1 {
		f := b[0]
		end := bytes.IndexByte(b[1:], 0)
		if end < 0 {
			break
		}
		v := string(b[1 : 1+end])
		switch f {
		case 'C':
			code = v
		case 'M':
			msg = printable([]byte(v), 200)
		}
		b = b[2+end:]
	}
	return
}

func pgMD5(user, password string, salt []byte) string {
	h1 := md5.Sum([]byte(password + user))
	inner := hex.EncodeToString(h1[:])
	h2 := md5.Sum(append([]byte(inner), salt...))
	return "md5" + hex.EncodeToString(h2[:])
}

// scramClient computes the SCRAM-SHA-256 client-final message and the
// expected server signature.
func scramClient(password, clientFirstBare, serverFirst, clientNonce string) (clientFinal string, serverSig []byte, err error) {
	var nonce, salt64 string
	iter := 0
	for _, part := range strings.Split(serverFirst, ",") {
		if len(part) < 2 || part[1] != '=' {
			continue
		}
		switch part[0] {
		case 'r':
			nonce = part[2:]
		case 's':
			salt64 = part[2:]
		case 'i':
			iter, _ = strconv.Atoi(part[2:])
		}
	}
	if !strings.HasPrefix(nonce, clientNonce) || len(nonce) == len(clientNonce) {
		return "", nil, errors.New("scram: bad server nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(salt64)
	if err != nil || len(salt) == 0 {
		return "", nil, errors.New("scram: bad salt")
	}
	if iter < 1 || iter > pgMaxIterations {
		return "", nil, fmt.Errorf("scram: refusing %d iterations", iter)
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		return "", nil, err
	}
	mac := func(key []byte, s string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(s))
		return m.Sum(nil)
	}
	clientKey := mac(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	withoutProof := "c=biws,r=" + nonce
	authMsg := clientFirstBare + "," + serverFirst + "," + withoutProof
	sig := mac(stored[:], authMsg)
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ sig[i]
	}
	serverKey := mac(salted, "Server Key")
	return withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof), mac(serverKey, authMsg), nil
}

// pgLogin performs one login attempt. ok=true means authentication
// succeeded; method describes the auth method used by the server.
func pgLogin(c net.Conn, user, password string) (ok bool, method string, detail string, err error) {
	if _, err := c.Write(pgStartup(user, user)); err != nil {
		return false, "", "", err
	}
	var scramFirstBare, scramNonce string
	var scramServerSig []byte
	for i := 0; i < 16; i++ {
		typ, b, err := pgRead(c)
		if err != nil {
			return false, method, "", err
		}
		switch typ {
		case 'E':
			code, msg := pgErrorText(b)
			return false, method, code + " " + msg, nil
		case 'R':
			if len(b) < 4 {
				return false, method, "", errors.New("postgres: short auth message")
			}
			switch binary.BigEndian.Uint32(b) {
			case 0:
				if method == "" {
					method = "trust"
				}
				return true, method, "AuthenticationOk", nil
			case 3:
				method = "password"
				if _, err := c.Write(pgMessage('p', append([]byte(password), 0))); err != nil {
					return false, method, "", err
				}
			case 5:
				method = "md5"
				if len(b) < 8 {
					return false, method, "", errors.New("postgres: short md5 salt")
				}
				if _, err := c.Write(pgMessage('p', append([]byte(pgMD5(user, password, b[4:8])), 0))); err != nil {
					return false, method, "", err
				}
			case 10:
				method = "scram-sha-256"
				if !bytes.Contains(b[4:], []byte("SCRAM-SHA-256\x00")) {
					return false, method, "", errors.New("postgres: no supported SASL mechanism")
				}
				nb := make([]byte, 18)
				_, _ = rand.Read(nb)
				scramNonce = base64.RawStdEncoding.EncodeToString(nb)
				scramFirstBare = "n=,r=" + scramNonce
				first := "n,," + scramFirstBare
				p := append([]byte("SCRAM-SHA-256\x00"), 0, 0, 0, 0)
				binary.BigEndian.PutUint32(p[len(p)-4:], uint32(len(first)))
				p = append(p, first...)
				if _, err := c.Write(pgMessage('p', p)); err != nil {
					return false, method, "", err
				}
			case 11:
				final, sig, err := scramClient(password, scramFirstBare, string(b[4:]), scramNonce)
				if err != nil {
					return false, method, "", err
				}
				scramServerSig = sig
				if _, err := c.Write(pgMessage('p', []byte(final))); err != nil {
					return false, method, "", err
				}
			case 12:
				v := string(b[4:])
				if !strings.HasPrefix(v, "v=") {
					return false, method, "", errors.New("scram: bad server final")
				}
				got, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[2:]))
				if err != nil || !hmac.Equal(got, scramServerSig) {
					return false, method, "", errors.New("scram: server signature mismatch")
				}
			default:
				return false, method, "", fmt.Errorf("postgres: unsupported auth request %d", binary.BigEndian.Uint32(b))
			}
		default:
			// NoticeResponse etc.
		}
	}
	return false, method, "", errors.New("postgres: too many messages")
}

func runPostgresDefault(ctx context.Context, t *Target) []model.Finding {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer c.Close()
	ok, method, detail, err := pgLogin(c, "postgres", "postgres")
	if err != nil || !ok {
		t.Log.Debug("postgres login refused", "err", err, "detail", detail)
		return nil
	}
	_, _ = c.Write(pgMessage('X', nil))
	ev := fmt.Sprintf("Login as postgres accepted (auth method: %s)", method)
	f := t.Finding(ev)
	if method == "trust" {
		f.Title = "PostgreSQL trust authentication: postgres login without password"
		f.Evidence = "Login as postgres accepted without any password (pg_hba.conf 'trust')"
	} else {
		f.Evidence += " with password 'postgres'"
	}
	return []model.Finding{f}
}
