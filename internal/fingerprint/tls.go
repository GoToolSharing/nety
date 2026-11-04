package fingerprint

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vaadata/nety/internal/model"
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
