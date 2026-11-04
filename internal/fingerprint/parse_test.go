package fingerprint

import (
	"bufio"
	"bytes"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

func TestMurmur3(t *testing.T) {
	cases := []struct {
		in   string
		seed uint32
		want uint32
	}{
		{"", 0, 0},
		{"", 1, 0x514e28b7},
		{"hello", 0, 0x248bfa47},
		{"The quick brown fox jumps over the lazy dog", 0, 0x2e4ff723},
		{"abc", 0, 0xb3dd93fa},
	}
	for _, c := range cases {
		if got := murmur3_32([]byte(c.in), c.seed); got != c.want {
			t.Errorf("murmur3(%q,%d) = %#x, want %#x", c.in, c.seed, got, c.want)
		}
	}
}

func TestBase64MIMEAndFaviconHash(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	// reference: python3 base64.encodebytes(bytes(range(100)))
	want := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4\n" +
		"OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiYw==\n"
	if got := string(base64MIME(data)); got != want {
		t.Fatalf("base64MIME mismatch:\n%q\n%q", got, want)
	}
	if base64MIME(nil) != nil {
		t.Fatal("empty input must encode to empty output")
	}
	// hash is signed: mmh3("hello") fits in int32 positive range
	if h := faviconHash([]byte("x")); h == "" || strings.ContainsAny(h, " \n") {
		t.Fatalf("bad hash %q", h)
	}
	if got := int32(murmur3_32(base64MIME([]byte("x")), 0)); faviconHash([]byte("x")) != strconv.FormatInt(int64(got), 10) {
		t.Fatal("faviconHash must be the signed mmh3 of the MIME base64")
	}
}

func TestExtractTitle(t *testing.T) {
	cases := map[string]string{
		"<html><head><title>  Hello\n  World </title></head></html>": "Hello World",
		"<TITLE>Caps &amp; entities</TITLE>":                         "Caps & entities",
		"<html><body>no title</body></html>":                         "",
		"<svg><title>icon</title></svg>":                             "icon",
		"":                                                           "",
		"<title>caf\xe9</title>":                                     "café",
	}
	for in, want := range cases {
		if got := extractTitle([]byte(in)); got != want {
			t.Errorf("extractTitle(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFaviconHref(t *testing.T) {
	body := `<html><head><link rel="stylesheet" href="/a.css"><link rel="shortcut icon" href="/static/fav.png"></head></html>`
	if got := faviconHref([]byte(body)); got != "/static/fav.png" {
		t.Fatalf("got %q", got)
	}
}

func TestAuthSchemes(t *testing.T) {
	got := authSchemes([]string{`Negotiate`, `NTLM`, `Basic realm="x", Digest realm="y", nonce="z"`})
	want := []string{"Negotiate", "NTLM", "Basic", "Digest"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseServerHeader(t *testing.T) {
	sp := parseServerHeader("Apache/2.4.41 (Ubuntu)")
	if sp.Product != "Apache httpd" || sp.Version != "2.4.41" || sp.Extra != "(Ubuntu)" || sp.OS != "Linux" ||
		!slices.Contains(sp.CPEs, "cpe:/a:apache:http_server:2.4.41") {
		t.Fatalf("%+v", sp)
	}
	sp = parseServerHeader("Microsoft-IIS/10.0")
	if sp.Product != "Microsoft IIS httpd" || sp.Version != "10.0" || sp.OS != "Windows" {
		t.Fatalf("%+v", sp)
	}
	sp = parseServerHeader("FooServer/3.1b extra")
	if sp.Product != "FooServer" || sp.Version != "3.1b" || sp.Extra != "extra" {
		t.Fatalf("%+v", sp)
	}
}

func TestDetectTech(t *testing.T) {
	h := http.Header{}
	h.Set("X-Jenkins", "2.400")
	h.Add("Set-Cookie", "JSESSIONID=abc; Path=/")
	got := detectTech(h, []byte(`<link href="/wp-content/x.css">`), "Dashboard [Jenkins]")
	for _, w := range []string{"Jenkins", "Java", "WordPress"} {
		if !slices.Contains(got, w) {
			t.Errorf("missing %s in %v", w, got)
		}
	}
}

func TestKexInitRoundTrip(t *testing.T) {
	k := &kexInit{
		KexAlgos:       []string{"curve25519-sha256", "diffie-hellman-group14-sha256"},
		HostKeyAlgos:   []string{"rsa-sha2-512", "ssh-ed25519"},
		CiphersC2S:     []string{"aes128-ctr"},
		CiphersS2C:     []string{"aes256-gcm@openssh.com", "aes128-ctr"},
		MACsC2S:        []string{"hmac-sha2-256"},
		MACsS2C:        []string{"hmac-sha2-256"},
		CompressionC2S: []string{"none"},
		CompressionS2C: []string{"none", "zlib@openssh.com"},
	}
	stream := append([]byte("pre-banner line\r\nSSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"), framePlainPacket(buildKexInit(k))...)
	br := bufio.NewReader(bytes.NewReader(stream))
	ident, pre, err := readSSHIdent(br)
	if err != nil || ident != "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13" || len(pre) != 1 {
		t.Fatalf("ident %q pre %v err %v", ident, pre, err)
	}
	p, err := readSSHPlainPacket(br)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseKexInit(p)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.KexAlgos, k.KexAlgos) || !slices.Equal(got.HostKeyAlgos, k.HostKeyAlgos) ||
		!slices.Equal(got.CiphersS2C, k.CiphersS2C) || !slices.Equal(got.CompressionS2C, k.CompressionS2C) ||
		len(got.LanguagesC2S) != 0 {
		t.Fatalf("mismatch %+v", got)
	}
	if _, err := parseKexInit(p[:30]); err == nil {
		t.Fatal("truncated KEXINIT must fail")
	}
}

func TestParseSSHIdent(t *testing.T) {
	p := parseSSHIdent("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
	if p.Product != "OpenSSH" || p.Version != "8.9p1 Ubuntu-3ubuntu0.6" || p.OS != "Linux" ||
		p.Extra != "Ubuntu Linux; protocol 2.0" {
		t.Fatalf("%+v", p)
	}
	p = parseSSHIdent("SSH-2.0-OpenSSH_for_Windows_8.1")
	if p.OS != "Windows" || p.Version != "8.1" {
		t.Fatalf("%+v", p)
	}
	p = parseSSHIdent("SSH-2.0-dropbear_2020.81")
	if p.Product != "Dropbear sshd" || p.Version != "2020.81" {
		t.Fatalf("%+v", p)
	}
}

func TestPrintable(t *testing.T) {
	if got := printable([]byte("220 hi\r\n\x00\xff\\")); got != `220 hi\r\n\x00\xFF\\` {
		t.Fatalf("got %q", got)
	}
	if len(printable(bytes.Repeat([]byte{0}, 5000))) > maxBanner {
		t.Fatal("not truncated")
	}
}

func TestServiceNameFallback(t *testing.T) {
	svc := model.Service{}
	finalize(&svc, 445, model.TCP)
	if svc.Name != "microsoft-ds" || svc.Method != MethodPortTable || svc.Confidence != ConfPortTable {
		t.Fatalf("%+v", svc)
	}
}

// The SNMP, NetBIOS, DNS and BER decoders live in
// internal/fingerprint/udpprobe and are tested there, against byte fixtures,
// without a socket.
