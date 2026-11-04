package fingerprint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
)

const testHTML = `<!doctype html><html><head>
<title>  Jenkins [Dashboard]  </title>
<link rel="shortcut icon" href="/favicon.ico">
</head><body><div class="jenkins-head">/static/jenkins/x.js</div></body></html>`

// testOpts keeps the per-connection budget small so the suite stays quick.
func testOpts() engine.FingerprintOptions {
	return engine.FingerprintOptions{Timeout: time.Second, Intensity: 7}
}

func newFP() engine.Fingerprinter { return New(slog.New(slog.DiscardHandler)) }

// httpServer starts an HTTP (or HTTPS) server on 127.0.0.1 and returns its
// address. cert is nil for plaintext.
func httpServer(t *testing.T, cert *tls.Certificate, h http.Handler) (netip.Addr, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if cert != nil {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*cert}})
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	ap := netip.MustParseAddrPort(ln.Addr().String())
	return ap.Addr(), ap.Port()
}

// selfSignedCert builds a throwaway certificate inside the test.
func selfSignedCert(t *testing.T, cn string, sans []string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x4e455459),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"NETY Test"},
			Country:      []string{"FR"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              sans,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func jenkinsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write([]byte("\x00\x00\x01\x00NETY-FAVICON-BYTES"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Jenkins", "2.440.1")
		w.Header().Set("X-Powered-By", "Jetty(10.0.18)")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("WWW-Authenticate", `Basic realm="Jenkins", Negotiate`)
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "secretsessionvalue"})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testHTML))
	})
	return mux
}

func TestFingerprintHTTP(t *testing.T) {
	withProbeDB(t, nil)
	ip, port := httpServer(t, nil, jenkinsHandler())

	svc, err := newFP().Fingerprint(context.Background(), ip, port, model.TCP, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if svc.State != model.PortOpen {
		t.Fatalf("state = %q", svc.State)
	}
	if svc.Name != "http" || svc.Method != MethodHTTP || svc.Confidence != ConfHTTP {
		t.Fatalf("name/method/conf: %+v", svc)
	}
	if svc.Tunnel != "" {
		t.Fatalf("plaintext service should not be tunnelled: %q", svc.Tunnel)
	}
	if svc.Product != "nginx" || svc.Version != "1.24.0" {
		t.Fatalf("product/version: %q %q", svc.Product, svc.Version)
	}
	if svc.HTTP == nil {
		t.Fatal("HTTP info missing")
	}
	h := svc.HTTP
	if h.Scheme != "http" || h.StatusCode != 200 {
		t.Fatalf("scheme/status: %+v", h)
	}
	if h.Title != "Jenkins [Dashboard]" {
		t.Fatalf("title = %q", h.Title)
	}
	if h.PoweredBy != "Jetty(10.0.18)" {
		t.Fatalf("powered-by = %q", h.PoweredBy)
	}
	if len(h.BodySHA256) != 64 {
		t.Fatalf("body sha256 = %q", h.BodySHA256)
	}
	if h.FaviconMMH3 == "" {
		t.Fatal("favicon hash missing")
	}
	if !containsStr(h.AuthSchemes, "Basic") || !containsStr(h.AuthSchemes, "Negotiate") {
		t.Fatalf("auth schemes = %v", h.AuthSchemes)
	}
	if !containsStr(h.Technologies, "Jenkins") || !containsStr(h.Technologies, "nginx") {
		t.Fatalf("technologies = %v", h.Technologies)
	}
	// Session values must never be recorded: only the cookie NAME is kept.
	if sc := h.Headers["Set-Cookie"]; sc != "JSESSIONID" {
		t.Fatalf("Set-Cookie leaked value: %q", sc)
	}
	if svc.Extra["http.title"] != "Jenkins [Dashboard]" || svc.Extra["http.status"] != "200" {
		t.Fatalf("extra = %v", svc.Extra)
	}
	if strings.Contains(svc.Banner, "secretsessionvalue") {
		t.Fatalf("session value leaked into the banner: %q", svc.Banner)
	}
	if !strings.Contains(svc.Banner, "JSESSIONID=<redacted>") {
		t.Fatalf("cookie name not reported: %q", svc.Banner)
	}
	if !strings.HasPrefix(svc.Banner, "HTTP/1.1 200 OK") {
		t.Fatalf("banner = %q", svc.Banner)
	}
	if len(svc.Banner) > maxBanner {
		t.Fatalf("banner not truncated: %d", len(svc.Banner))
	}
}

func TestFingerprintHTTPSSelfSigned(t *testing.T) {
	withProbeDB(t, nil)
	cert := selfSignedCert(t, "vcenter.corp.local", []string{"vcenter.corp.local", "vcenter"})
	ip, port := httpServer(t, cert, jenkinsHandler())

	svc, err := newFP().Fingerprint(context.Background(), ip, port, model.TCP, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if svc.Tunnel != "ssl" {
		t.Fatalf("tunnel = %q", svc.Tunnel)
	}
	if svc.TLS == nil {
		t.Fatal("TLS info missing")
	}
	ti := svc.TLS
	if ti.Version != "TLSv1.3" {
		t.Fatalf("version = %q", ti.Version)
	}
	if ti.CipherSuite == "" {
		t.Fatal("cipher suite missing")
	}
	if ti.SubjectCN != "vcenter.corp.local" {
		t.Fatalf("subject CN = %q", ti.SubjectCN)
	}
	if !strings.Contains(ti.Subject, "NETY Test") {
		t.Fatalf("subject = %q", ti.Subject)
	}
	if !containsStr(ti.SANs, "vcenter.corp.local") || !containsStr(ti.SANs, "127.0.0.1") {
		t.Fatalf("SANs = %v", ti.SANs)
	}
	if !ti.SelfSigned || ti.Expired {
		t.Fatalf("self-signed=%v expired=%v", ti.SelfSigned, ti.Expired)
	}
	if ti.KeyAlgo != "ECDSA" || ti.KeyBits != 256 {
		t.Fatalf("key = %s/%d", ti.KeyAlgo, ti.KeyBits)
	}
	if ti.SigAlgo == "" || len(ti.SHA256) != 64 {
		t.Fatalf("sig=%q sha256=%q", ti.SigAlgo, ti.SHA256)
	}
	if ti.Serial != "4E455459" {
		t.Fatalf("serial = %q", ti.Serial)
	}
	if ti.NotAfter.Before(ti.NotBefore) {
		t.Fatal("validity window inverted")
	}
	if ti.ALPN != "http/1.1" && ti.ALPN != "" {
		t.Fatalf("alpn = %q", ti.ALPN)
	}
	// The application layer must still have been probed inside the tunnel.
	if svc.Name != "http" || svc.HTTP == nil || svc.HTTP.Scheme != "https" {
		t.Fatalf("app layer inside tunnel: %+v", svc)
	}
	if svc.HTTP.Title != "Jenkins [Dashboard]" {
		t.Fatalf("title = %q", svc.HTTP.Title)
	}
}

func TestFingerprintTLSOnlyService(t *testing.T) {
	withProbeDB(t, nil)
	cert := selfSignedCert(t, "silent.corp.local", nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tln := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*cert}})
	t.Cleanup(func() { _ = tln.Close() })
	go func() {
		for {
			c, err := tln.Accept()
			if err != nil {
				return
			}
			// Complete the handshake, then say nothing at all.
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
			}()
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())

	svc, err := newFP().Fingerprint(context.Background(), ap.Addr(), ap.Port(), model.TCP, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if svc.Tunnel != "ssl" || svc.TLS == nil || svc.TLS.SubjectCN != "silent.corp.local" {
		t.Fatalf("%+v / %+v", svc, svc.TLS)
	}
	if svc.Confidence < ConfPortTable {
		t.Fatalf("confidence = %d", svc.Confidence)
	}
}

func TestFingerprintSSHBanner(t *testing.T) {
	withProbeDB(t, nil)
	ip, port := fakeServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"))
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
	})

	svc, err := newFP().Fingerprint(context.Background(), ip, port, model.TCP, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != "ssh" || svc.Method != MethodSSH || svc.Confidence != ConfSSH {
		t.Fatalf("%+v", svc)
	}
	if svc.Product != "OpenSSH" || svc.Version != "8.9p1 Ubuntu-3ubuntu0.6" {
		t.Fatalf("product/version: %q %q", svc.Product, svc.Version)
	}
	if svc.OSType != "Linux" || svc.ExtraInfo != "Ubuntu Linux; protocol 2.0" {
		t.Fatalf("os/extra: %q %q", svc.OSType, svc.ExtraInfo)
	}
	if !containsStr(svc.CPEs, "cpe:/a:openbsd:openssh:8.9p1") {
		t.Fatalf("cpes = %v", svc.CPEs)
	}
	if svc.SSH == nil || !strings.HasPrefix(svc.SSH.Banner, "SSH-2.0-OpenSSH_8.9p1") {
		t.Fatalf("ssh info: %+v", svc.SSH)
	}
}

func TestFingerprintRawBannerHeuristic(t *testing.T) {
	withProbeDB(t, nil)
	ip, port := fakeServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("220 mail.corp.local ESMTP Postfix (Debian/GNU)\r\n"))
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
	})

	svc, err := newFP().Fingerprint(context.Background(), ip, port, model.TCP, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != "smtp" || svc.Method != MethodBanner || svc.Confidence != ConfBanner {
		t.Fatalf("%+v", svc)
	}
	if svc.Product != "Postfix smtpd" {
		t.Fatalf("product = %q", svc.Product)
	}
	if !strings.HasPrefix(svc.Banner, "220 mail.corp.local ESMTP Postfix") {
		t.Fatalf("banner = %q", svc.Banner)
	}
}

// A service that sends non-printable junk must not panic, must not produce a
// non-printable banner, and must still fall back to the port table.
func TestFingerprintHostileBanner(t *testing.T) {
	withProbeDB(t, nil)
	junk := make([]byte, 4096)
	for i := range junk {
		junk[i] = byte(i * 7)
	}
	ip, port := fakeServer(t, func(c net.Conn) {
		_, _ = c.Write(junk)
		buf := make([]byte, 16)
		_, _ = c.Read(buf)
	})

	svc, err := newFP().Fingerprint(context.Background(), ip, port, model.TCP, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(svc.Banner) > maxBanner {
		t.Fatalf("banner not bounded: %d", len(svc.Banner))
	}
	for _, r := range svc.Banner {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("non printable %q in banner", r)
		}
	}
	if svc.Confidence > ConfSoftMatch {
		t.Fatalf("junk should not be identified confidently: %+v", svc)
	}
}

func TestFingerprintClosedPortFallsBackToPortTable(t *testing.T) {
	withProbeDB(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(ln.Addr().String())
	_ = ln.Close() // nothing listens there any more

	svc, err := newFP().Fingerprint(context.Background(), ap.Addr(), ap.Port(), model.TCP, testOpts())
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if svc.State != model.PortOpen || svc.Confidence > ConfPortTable {
		t.Fatalf("fallback service: %+v", svc)
	}
}

func TestFingerprintRejectsBadArguments(t *testing.T) {
	fp := newFP()
	if _, err := fp.Fingerprint(context.Background(), netip.Addr{}, 80, model.TCP, testOpts()); err == nil {
		t.Fatal("expected an error for an invalid address")
	}
	if _, err := fp.Fingerprint(context.Background(), mustAddr("127.0.0.1"), 0, model.TCP, testOpts()); err == nil {
		t.Fatal("expected an error for port 0")
	}
	if _, err := fp.Fingerprint(context.Background(), mustAddr("127.0.0.1"), 80, model.Protocol("sctp"), testOpts()); err == nil {
		t.Fatal("expected an error for an unsupported protocol")
	}
}

func TestSetExtraIsBounded(t *testing.T) {
	var svc model.Service
	for i := range maxExtraKeys * 2 {
		setExtra(&svc, fmt.Sprintf("k%d", i), "v")
	}
	if len(svc.Extra) != maxExtraKeys {
		t.Fatalf("extra keys = %d", len(svc.Extra))
	}
	setExtra(&svc, "k0", strings.Repeat("x", 4096))
	if len(svc.Extra["k0"]) > maxExtraValue {
		t.Fatalf("value not truncated: %d", len(svc.Extra["k0"]))
	}
	setExtra(&svc, "empty", "")
	if _, ok := svc.Extra["empty"]; ok {
		t.Fatal("empty value stored")
	}
}

func TestBannerRulesCompileAndMatch(t *testing.T) {
	cases := []struct{ banner, name string }{
		{`220 ProFTPD 1.3.5 Server ready`, "ftp"},
		{`+OK Dovecot ready.`, "pop3"},
		{`* OK [CAPABILITY IMAP4rev1] Dovecot ready`, "imap"},
		{`@RSYNCD: 31.0`, "rsync"},
		{`RFB 003.008`, "vnc"},
		{`-NOAUTH Authentication required.`, "redis"},
		{`SSH-2.0-OpenSSH_9.2`, "ssh"},
		{`JDWP-Handshake`, "jdwp"},
	}
	for _, c := range cases {
		got, _, ok := bannerMatch(c.banner)
		if !ok || got.name != c.name {
			t.Errorf("bannerMatch(%q) = %q, %v; want %q", c.banner, got.name, ok, c.name)
		}
	}
	if _, _, ok := bannerMatch(""); ok {
		t.Error("empty banner matched")
	}
}

func TestRetryLowerTLS(t *testing.T) {
	if retryLowerTLS(nil) {
		t.Error("nil error must not retry")
	}
	if retryLowerTLS(tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}) {
		t.Error("a plaintext service must not be retried")
	}
	if !retryLowerTLS(tls.AlertError(70)) { // protocol_version
		t.Error("protocol_version must ladder down")
	}
	if retryLowerTLS(tls.AlertError(42)) { // bad_certificate
		t.Error("bad_certificate must not ladder down")
	}
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

// udpServer answers every datagram with reply(request); a nil reply sends
// nothing back.
func udpServer(t *testing.T, reply func([]byte) []byte) (netip.Addr, uint16) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := reply(buf[:n]); out != nil {
				_, _ = pc.WriteTo(out, addr)
			}
		}
	}()
	ap := netip.MustParseAddrPort(pc.LocalAddr().String())
	return ap.Addr(), ap.Port()
}

func TestFingerprintUDPSSDP(t *testing.T) {
	withProbeDB(t, nil)
	const ssdpReply = "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"LOCATION: http://127.0.0.1:5000/rootDesc.xml\r\n" +
		"SERVER: Linux/4.19 UPnP/1.1 MiniUPnPd/2.3.0\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"USN: uuid:0000e068-20a0-00e0-20a0-00a0de68e000::upnp:rootdevice\r\n\r\n"
	ip, port := udpServer(t, func(req []byte) []byte {
		if !strings.HasPrefix(string(req), "M-SEARCH * HTTP/1.1") {
			return nil
		}
		return []byte(ssdpReply)
	})

	svc, err := newFP().Fingerprint(context.Background(), ip, port, model.UDP,
		engine.FingerprintOptions{Timeout: 300 * time.Millisecond, Intensity: 7})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Protocol != model.UDP || svc.State != model.PortOpen {
		t.Fatalf("%+v", svc)
	}
	if svc.Name != "upnp" || svc.Method != MethodUDPProbe {
		t.Fatalf("name/method: %+v", svc)
	}
	if !strings.Contains(svc.Extra["upnp.server"], "MiniUPnPd/2.3.0") {
		t.Fatalf("extra = %v", svc.Extra)
	}
	if svc.Confidence < ConfSoftMatch {
		t.Fatalf("confidence = %d", svc.Confidence)
	}
}

// A UDP service that answers with bytes nothing can decode must still produce
// a bounded, printable banner and the port-table fallback, without hanging.
func TestFingerprintUDPUndecodable(t *testing.T) {
	withProbeDB(t, nil)
	junk := make([]byte, 2048)
	for i := range junk {
		junk[i] = byte(255 - i%256)
	}
	ip, port := udpServer(t, func([]byte) []byte { return junk })

	start := time.Now()
	svc, err := newFP().Fingerprint(context.Background(), ip, port, model.UDP,
		engine.FingerprintOptions{Timeout: 300 * time.Millisecond, Intensity: 7})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 25*time.Second {
		t.Fatalf("took too long: %s", took)
	}
	if svc.Banner == "" || len(svc.Banner) > maxBanner {
		t.Fatalf("banner = %d bytes", len(svc.Banner))
	}
	if svc.Confidence > ConfPortTable {
		t.Fatalf("junk identified: %+v", svc)
	}
}

func TestFingerprintUDPSilent(t *testing.T) {
	withProbeDB(t, nil)
	ip, port := udpServer(t, func([]byte) []byte { return nil })

	svc, err := newFP().Fingerprint(context.Background(), ip, port, model.UDP,
		engine.FingerprintOptions{Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Confidence > ConfPortTable {
		t.Fatalf("silent service identified: %+v", svc)
	}
}
