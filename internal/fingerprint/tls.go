package fingerprint

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

var allCipherSuites = sync.OnceValue(func() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
})

// clientTLSConfig is a maximally permissive client config: the goal is to
// observe the server, not to authenticate it.
func clientTLSConfig(serverName string, alpn []string) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // fingerprinting, no trust decision
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allCipherSuites(),
		NextProtos:         alpn,
	}
	if serverName != "" && net.ParseIP(serverName) == nil {
		cfg.ServerName = serverName
	}
	return cfg
}

// tlsLadder is walked from the highest version down: the first handshake that
// succeeds tells us the highest version the server accepts. Most servers
// negotiate their best version from the first (TLS 1.3 capable) ClientHello;
// the lower rungs exist for version-intolerant middleboxes and legacy stacks.
var tlsLadder = []uint16{
	tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10,
}

// probeTLS tries to establish a TLS session on the target port. On success it
// returns the observed parameters together with the LIVE connection: the
// caller owns it and must close it. The connection is bound to ctx.
func (d *dialer) probeTLS(ctx context.Context, alpn []string) (*model.TLSInfo, *tls.Conn, error) {
	var firstErr error
	// A peer that simply drops the connection may be version-intolerant, but
	// it is far more often not a TLS service at all: allow a single retry on
	// that evidence, and the full ladder only for an explicit TLS alert.
	softRetries := 1
	for _, max := range tlsLadder {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		raw, err := d.dial(ctx)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return nil, nil, firstErr
		}
		cfg := clientTLSConfig(d.hostname, alpn)
		cfg.MaxVersion = max
		tc := tls.Client(raw, cfg)

		hctx, cancel := context.WithTimeout(ctx, d.handshakeTimeout())
		err = tc.HandshakeContext(hctx)
		cancel()
		if err == nil {
			return tlsInfoFromState(tc.ConnectionState(), time.Now()), tc, nil
		}
		_ = raw.Close()
		if firstErr == nil {
			firstErr = err
		}
		if !retryLowerTLS(err) {
			break
		}
		if !isTLSAlert(err) {
			if softRetries == 0 {
				break
			}
			softRetries--
		}
	}
	if firstErr == nil {
		firstErr = errors.New("tls: handshake failed")
	}
	return nil, nil, firstErr
}

// retryLowerTLS reports whether err is consistent with a server that speaks
// TLS but refused the version we offered. A plaintext service, a refused
// connection or a silent peer are definitive: there is nothing lower to try.
func retryLowerTLS(err error) bool {
	if err == nil {
		return false
	}
	var rec tls.RecordHeaderError
	if errors.As(err, &rec) {
		// The first record is not a TLS record: this is not a TLS service.
		return false
	}
	if isTimeout(err) || isRefused(err) || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		switch uint8(alert) {
		case 40, // handshake_failure
			47,  // illegal_parameter
			50,  // decode_error
			70,  // protocol_version
			71,  // insufficient_security
			80,  // internal_error
			109: // no_application_protocol (unlikely, but harmless to retry)
			return true
		}
		return false
	}
	// A reset or an EOF mid-handshake is the classic symptom of version
	// intolerance, so one more rung down is worth a try.
	return errors.Is(err, io.EOF) || isConnReset(err) || strings.Contains(err.Error(), "tls:")
}

// tlsInfoFromState extracts negotiated parameters and leaf certificate facts.
func tlsInfoFromState(st tls.ConnectionState, now time.Time) *model.TLSInfo {
	info := &model.TLSInfo{
		Version:     tlsVersionName(st.Version),
		CipherSuite: tls.CipherSuiteName(st.CipherSuite),
		ALPN:        st.NegotiatedProtocol,
	}
	if len(st.PeerCertificates) == 0 {
		return info
	}
	c := st.PeerCertificates[0]
	info.SubjectCN = c.Subject.CommonName
	info.Subject = c.Subject.String()
	info.Issuer = c.Issuer.String()
	info.Serial = strings.ToUpper(c.SerialNumber.Text(16))
	info.NotBefore = c.NotBefore.UTC()
	info.NotAfter = c.NotAfter.UTC()
	info.Expired = now.After(c.NotAfter)
	info.SelfSigned = isSelfSigned(c)
	info.SigAlgo = c.SignatureAlgorithm.String()
	info.KeyAlgo, info.KeyBits = keyInfo(c)
	sum := sha256.Sum256(c.Raw)
	info.SHA256 = hex.EncodeToString(sum[:])
	info.SANs = certSANs(c)
	return info
}

func certSANs(c *x509.Certificate) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, n := range c.DNSNames {
		add(n)
	}
	for _, ip := range c.IPAddresses {
		add(ip.String())
	}
	for _, e := range c.EmailAddresses {
		add("email:" + e)
	}
	for _, u := range c.URIs {
		add(u.String())
	}
	return out
}

func isSelfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	if c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
		return true
	}
	// Signature could not be verified (e.g. legacy MD5/SHA-1 algorithms are
	// refused by crypto/x509): fall back on key identifiers.
	return len(c.AuthorityKeyId) == 0 || bytes.Equal(c.AuthorityKeyId, c.SubjectKeyId)
}

func keyInfo(c *x509.Certificate) (string, int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		if k.Curve != nil {
			return "ECDSA", k.Curve.Params().BitSize
		}
		return "ECDSA", 0
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return c.PublicKeyAlgorithm.String(), 0
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30: //nolint:staticcheck // naming only
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// isTLSAlert reports whether err carries an alert sent by the peer, i.e. the
// peer really did speak TLS and refused what we offered.
func isTLSAlert(err error) bool {
	var a tls.AlertError
	return errors.As(err, &a)
}
