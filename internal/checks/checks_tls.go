package checks

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vaadata/nety/internal/model"
)

func init() {
	register(&Check{
		Info: partAInfo("tls-weak-protocols", "Deprecated SSL/TLS protocol versions accepted", model.SevMedium,
			[]string{"https", "ssl", "tls"},
			"The service accepts SSLv3, TLS 1.0 and/or TLS 1.1. These protocol versions are deprecated (RFC 8996) and affected by known weaknesses (POODLE, BEAST, weak MAC/PRF constructions)."),
		Remediation: "Disable SSLv3, TLS 1.0 and TLS 1.1 on the service; allow only TLS 1.2 and TLS 1.3 with AEAD cipher suites.",
		References:  []string{"https://datatracker.ietf.org/doc/html/rfc8996", "https://nvd.nist.gov/vuln/detail/CVE-2014-3566"},
		Applies:     tlsApplies,
		Run:         runTLSWeakProtocols,
	})
	register(&Check{
		Info: partAInfo("tls-weak-ciphers", "Weak SSL/TLS cipher suites accepted", model.SevMedium,
			[]string{"https", "ssl", "tls"},
			"The service negotiates weak cipher suites (RC4, 3DES/DES, NULL, EXPORT or anonymous key exchange) that provide insufficient confidentiality or no server authentication (SWEET32, RC4 biases, FREAK/Logjam)."),
		Remediation: "Remove RC4, DES/3DES, NULL, EXPORT and anonymous (ADH/AECDH) suites from the server configuration; prefer ECDHE with AES-GCM or ChaCha20-Poly1305.",
		References:  []string{"https://sweet32.info/", "https://datatracker.ietf.org/doc/html/rfc7465"},
		Applies:     tlsApplies,
		Run:         runTLSWeakCiphers,
	})
	register(&Check{
		Info: partAInfo("tls-cert-expired", "Expired TLS certificate", model.SevLow,
			[]string{"https", "ssl", "tls"},
			"The certificate presented by the service is expired. Users get used to ignoring certificate warnings, which makes man-in-the-middle attacks easier."),
		Remediation: "Renew the certificate and deploy it on the service; monitor expiry dates.",
		References:  []string{"https://cwe.mitre.org/data/definitions/298.html"},
		Applies:     func(t *Target) bool { return t.Service.TLS != nil },
		Run:         runTLSCertExpired,
	})
	register(&Check{
		Info: partAInfo("tls-cert-self-signed", "Self-signed TLS certificate", model.SevInfo,
			[]string{"https", "ssl", "tls"},
			"The service presents a self-signed certificate that clients cannot validate, allowing undetected man-in-the-middle attacks when users accept the warning."),
		Remediation: "Deploy a certificate issued by the internal PKI (or a public CA) and distribute the trust anchor to clients.",
		References:  []string{"https://cwe.mitre.org/data/definitions/295.html"},
		Applies:     func(t *Target) bool { return t.Service.TLS != nil && t.Service.TLS.SelfSigned },
		Run:         runTLSSelfSigned,
	})
}

// tlsStartTLSNames are services where TLS only follows a STARTTLS exchange:
// raw ClientHellos would not work, skip them.
var tlsStartTLSNames = map[string]bool{"smtp": true, "submission": true, "imap": true, "pop3": true, "ftp": true, "ldap": true, "xmpp-client": true, "postgresql": true, "mysql": true, "ms-sql-s": true, "ms-wbt-server": true, "rdp": true}

func tlsApplies(t *Target) bool {
	s := t.Service
	if s.Protocol != model.TCP {
		return false
	}
	if isTLS(s) {
		return s.Tunnel == "ssl" || !tlsStartTLSNames[strings.ToLower(s.Name)]
	}
	return false
}

// Protocol versions.
const (
	tlsVerSSL3  uint16 = 0x0300
	tlsVerTLS10 uint16 = 0x0301
	tlsVerTLS11 uint16 = 0x0302
	tlsVerTLS12 uint16 = 0x0303
)

func tlsVersionName(v uint16) string {
	switch v {
	case tlsVerSSL3:
		return "SSLv3"
	case tlsVerTLS10:
		return "TLSv1.0"
	case tlsVerTLS11:
		return "TLSv1.1"
	case tlsVerTLS12:
		return "TLSv1.2"
	case 0x0304:
		return "TLSv1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// tlsBroadCiphers is offered when probing protocol versions.
var tlsBroadCiphers = []uint16{
	0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009e, 0x009f, 0x009c, 0x009d,
	0xc013, 0xc014, 0xc009, 0xc00a, 0x0033, 0x0039, 0x0045, 0x0088,
	0x002f, 0x0035, 0x0041, 0x0084, 0x003c, 0x003d, 0xc027, 0xc028, 0xc023, 0xc024,
	0xc012, 0xc008, 0x0016, 0x000a, 0x0013, 0x0066,
	0xc011, 0xc007, 0x0005, 0x0004, 0x0015, 0x0009, 0x0012,
	0x0003, 0x0006, 0x0008, 0x0014, 0x0011,
	0x0007, 0x0096, 0x009a, 0x00ff,
}

// tlsWeakCiphers maps weak suites to their OpenSSL names.
var tlsWeakCiphers = map[uint16]string{
	0x0001: "NULL-MD5", 0x0002: "NULL-SHA", 0x003b: "NULL-SHA256", 0xc006: "ECDHE-ECDSA-NULL-SHA", 0xc010: "ECDHE-RSA-NULL-SHA",
	0x0003: "EXP-RC4-MD5", 0x0006: "EXP-RC2-CBC-MD5", 0x0008: "EXP-DES-CBC-SHA", 0x0011: "EXP-EDH-DSS-DES-CBC-SHA", 0x0014: "EXP-EDH-RSA-DES-CBC-SHA",
	0x0004: "RC4-MD5", 0x0005: "RC4-SHA", 0xc007: "ECDHE-ECDSA-RC4-SHA", 0xc011: "ECDHE-RSA-RC4-SHA", 0x0018: "ADH-RC4-MD5",
	0x0009: "DES-CBC-SHA", 0x0012: "EDH-DSS-DES-CBC-SHA", 0x0015: "EDH-RSA-DES-CBC-SHA",
	0x000a: "DES-CBC3-SHA", 0x0013: "EDH-DSS-DES-CBC3-SHA", 0x0016: "EDH-RSA-DES-CBC3-SHA", 0xc008: "ECDHE-ECDSA-DES-CBC3-SHA", 0xc012: "ECDHE-RSA-DES-CBC3-SHA", 0x001b: "ADH-DES-CBC3-SHA",
	0x0034: "ADH-AES128-SHA", 0x003a: "ADH-AES256-SHA", 0x006c: "ADH-AES128-SHA256", 0x006d: "ADH-AES256-SHA256", 0x00a6: "ADH-AES128-GCM-SHA256", 0x00a7: "ADH-AES256-GCM-SHA384",
	0xc018: "AECDH-AES128-SHA", 0xc019: "AECDH-AES256-SHA", 0xc016: "AECDH-RC4-SHA", 0xc017: "AECDH-DES-CBC3-SHA",
}

// tlsBuildClientHello builds a TLS record carrying a ClientHello.
func tlsBuildClientHello(version uint16, ciphers []uint16, sni string) []byte {
	var body []byte
	body = binary.BigEndian.AppendUint16(body, version)
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	binary.BigEndian.PutUint32(random, uint32(time.Now().Unix()))
	body = append(body, random...)
	body = append(body, 0) // session id
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(ciphers)))
	for _, c := range ciphers {
		body = binary.BigEndian.AppendUint16(body, c)
	}
	body = append(body, 1, 0) // compression: null
	if version >= tlsVerTLS10 {
		var ext []byte
		if sni != "" {
			n := []byte(sni)
			e := []byte{0, 0}
			e = binary.BigEndian.AppendUint16(e, uint16(len(n)+5))
			e = binary.BigEndian.AppendUint16(e, uint16(len(n)+3))
			e = append(e, 0)
			e = binary.BigEndian.AppendUint16(e, uint16(len(n)))
			ext = append(ext, append(e, n...)...)
		}
		// supported_groups: x25519, secp256r1, secp384r1, secp521r1
		ext = append(ext, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19)
		// ec_point_formats: uncompressed
		ext = append(ext, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)
		if version >= tlsVerTLS12 {
			// signature_algorithms
			sa := []byte{0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04, 0x08, 0x05, 0x02, 0x01, 0x02, 0x03}
			e := []byte{0x00, 0x0d}
			e = binary.BigEndian.AppendUint16(e, uint16(len(sa)+2))
			e = binary.BigEndian.AppendUint16(e, uint16(len(sa)))
			ext = append(ext, append(e, sa...)...)
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
		body = append(body, ext...)
	}
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	recVer := version
	if recVer > tlsVerTLS10 {
		recVer = tlsVerTLS10
	}
	rec := []byte{0x16, byte(recVer >> 8), byte(recVer), byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// tlsHelloResult is the server's answer to a ClientHello.
type tlsHelloResult struct {
	Accepted bool   // ServerHello received
	Version  uint16 // ServerHello.server_version
	Cipher   uint16
	Alert    byte // alert description when rejected by alert
	IsAlert  bool
}

var errTLSMalformed = errors.New("tls: malformed server response")

// tlsParseServerResponse parses the first record(s) received after a
// ClientHello: either an Alert or a Handshake starting with ServerHello.
func tlsParseServerResponse(b []byte) (*tlsHelloResult, error) {
	if len(b) < 5 {
		return nil, errTLSMalformed
	}
	typ := b[0]
	l := int(binary.BigEndian.Uint16(b[3:]))
	if b[1] != 0x03 && b[1] != 0x02 {
		return nil, errTLSMalformed
	}
	if l > len(b)-5 {
		l = len(b) - 5
	}
	frag := b[5 : 5+l]
	switch typ {
	case 0x15:
		if len(frag) < 2 {
			return nil, errTLSMalformed
		}
		return &tlsHelloResult{IsAlert: true, Alert: frag[1]}, nil
	case 0x16:
		if len(frag) < 4 || frag[0] != 0x02 {
			return nil, errTLSMalformed
		}
		hl := int(frag[1])<<16 | int(frag[2])<<8 | int(frag[3])
		h := frag[4:]
		if hl < len(h) {
			h = h[:hl]
		}
		if len(h) < 35 {
			return nil, errTLSMalformed
		}
		r := &tlsHelloResult{Accepted: true, Version: binary.BigEndian.Uint16(h)}
		sidLen := int(h[34])
		if 35+sidLen+2 > len(h) {
			return nil, errTLSMalformed
		}
		r.Cipher = binary.BigEndian.Uint16(h[35+sidLen:])
		// TLS 1.3 servers put 0x0303 in server_version and the real
		// version in supported_versions: irrelevant here since we never
		// offer TLS 1.3.
		return r, nil
	}
	return nil, errTLSMalformed
}

// tlsProbe sends a ClientHello and parses the answer.
func tlsProbe(ctx context.Context, t *Target, version uint16, ciphers []uint16) (*tlsHelloResult, error) {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.Write(tlsBuildClientHello(version, ciphers, tlsSNI(t))); err != nil {
		return nil, err
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	l := int(binary.BigEndian.Uint16(hdr[3:]))
	if l > 1<<14+2048 {
		return nil, errTLSMalformed
	}
	// ServerHello is small; read at most what is needed.
	want := l
	if want > 4096 {
		want = 4096
	}
	buf := make([]byte, want)
	n, err := io.ReadFull(c, buf)
	if err != nil && n < 2 {
		return nil, err
	}
	return tlsParseServerResponse(append(hdr, buf[:n]...))
}

func tlsSNI(t *Target) string {
	h := t.Host.Hostname
	if strings.Contains(h, ".") && !strings.ContainsAny(h, " :") {
		return h
	}
	return ""
}

func runTLSWeakProtocols(ctx context.Context, t *Target) []model.Finding {
	var accepted []string
	for _, v := range []uint16{tlsVerSSL3, tlsVerTLS10, tlsVerTLS11} {
		if ctx.Err() != nil {
			return nil
		}
		r, err := tlsProbe(ctx, t, v, tlsBroadCiphers)
		if err != nil {
			t.Log.Debug("tls probe", "version", tlsVersionName(v), "err", err)
			continue
		}
		if r.Accepted && r.Version == v {
			accepted = append(accepted, fmt.Sprintf("%s (cipher 0x%04x)", tlsVersionName(v), r.Cipher))
		}
	}
	if len(accepted) == 0 {
		return nil
	}
	f := t.Finding("Server completed a ServerHello for: " + strings.Join(accepted, ", "))
	if strings.HasPrefix(accepted[0], "SSLv3") {
		f.Title = "SSLv3 / deprecated TLS protocol versions accepted"
	}
	return []model.Finding{f}
}

func runTLSWeakCiphers(ctx context.Context, t *Target) []model.Finding {
	weak := make([]uint16, 0, len(tlsWeakCiphers))
	for c := range tlsWeakCiphers {
		weak = append(weak, c)
	}
	// deterministic order
	for i := 1; i < len(weak); i++ {
		for j := i; j > 0 && weak[j] < weak[j-1]; j-- {
			weak[j], weak[j-1] = weak[j-1], weak[j]
		}
	}
	var got []string
	seen := map[uint16]bool{}
	for _, v := range []uint16{tlsVerTLS12, tlsVerTLS10} {
		offer := weak
		// Iterate: remove the accepted suite and re-offer to enumerate a few.
		for i := 0; i < 4 && len(offer) > 0; i++ {
			if ctx.Err() != nil {
				return nil
			}
			r, err := tlsProbe(ctx, t, v, offer)
			if err != nil || !r.Accepted {
				break
			}
			name, ok := tlsWeakCiphers[r.Cipher]
			if !ok {
				break // server picked something we did not offer: ignore
			}
			if !seen[r.Cipher] {
				seen[r.Cipher] = true
				got = append(got, fmt.Sprintf("%s (%s)", name, tlsVersionName(r.Version)))
			}
			var next []uint16
			for _, c := range offer {
				if c != r.Cipher {
					next = append(next, c)
				}
			}
			offer = next
		}
		if len(got) > 0 {
			break
		}
	}
	if len(got) == 0 {
		return nil
	}
	return []model.Finding{t.Finding("Server selected weak cipher suites when only weak suites were offered: " + strings.Join(got, ", "))}
}

func runTLSCertExpired(_ context.Context, t *Target) []model.Finding {
	ti := t.Service.TLS
	if ti == nil {
		return nil
	}
	now := time.Now()
	if !ti.Expired && (ti.NotAfter.IsZero() || ti.NotAfter.After(now)) {
		return nil
	}
	return []model.Finding{t.Finding(fmt.Sprintf("Certificate CN=%q issued by %q expired on %s (SHA256 %s)",
		ti.SubjectCN, ti.Issuer, ti.NotAfter.UTC().Format("2006-01-02"), ti.SHA256))}
}

func runTLSSelfSigned(_ context.Context, t *Target) []model.Finding {
	ti := t.Service.TLS
	if ti == nil || !ti.SelfSigned {
		return nil
	}
	return []model.Finding{t.Finding(fmt.Sprintf("Self-signed certificate: subject %q, issuer %q, valid %s → %s, SHA256 %s",
		ti.Subject, ti.Issuer, ti.NotBefore.UTC().Format("2006-01-02"), ti.NotAfter.UTC().Format("2006-01-02"), ti.SHA256))}
}
