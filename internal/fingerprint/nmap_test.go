package fingerprint

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
)

const syntheticProbes = `# synthetic nmap-service-probes for tests
Exclude T:9100-9107

Probe TCP NULL q||
totalwaitms 6000
tcpwrappedms 3000
match ftp m|^220 FakeFTP (\d[\w.]+) ready\r\n|s p/FakeFTP/ v/$1/ o/Unix/ cpe:/a:fake:fakeftp:$1/
match smtp m|^220 ([\w.-]+) ESMTP Postfix|i p/Postfix smtpd/ h/$1/ cpe:/a:postfix:postfix/a
softmatch ftp m|^220[ -]|

Probe TCP GenericLines q|\r\n\r\n|
rarity 1
ports 21,23,6000-6010
sslports 990
fallback NULL
match echo m|^\r\n\r\n$|
match fakedb m|^DB\x00\x01(.)(.)| p/FakeDB/ v/$I(1,">").$I(2,">")/ i/$SUBST(0,"x","y")/

Probe TCP RareOne q|HELLO\0\r\n|
rarity 9
match rare m|^RARE| p/Rare/

Probe UDP DNSVersionBindReq q|\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03|
rarity 1
ports 53
match domain m|^\0\x06\x81.*version\x04bind.*\x10\0\x03\xc0\x0c\0\x10\0\x03....(.)([^\0]+)|s p/DNS/ v/$2/

Probe TCP Unicode q|U\r\n|
rarity 2
match uni m|^U:((?:.\0)+)$|s p/Uni/ v/$P(1)/ i/$SUBST(1,"\0","")/
`

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func loadSynthetic(t *testing.T) *probeDB {
	t.Helper()
	db, err := parseProbeDB(strings.NewReader(syntheticProbes))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestParseProbeDB(t *testing.T) {
	db := loadSynthetic(t)
	if len(db.probes) != 5 {
		t.Fatalf("probes = %d", len(db.probes))
	}
	if db.nullTCP == nil || len(db.nullTCP.matches) != 3 || !db.nullTCP.matches[2].soft {
		t.Fatal("NULL probe parsing")
	}
	gl := db.byName["tcp/GenericLines"]
	if gl == nil || string(gl.payload) != "\r\n\r\n" || gl.rarity != 1 || !gl.ports.contains(6005) ||
		gl.ports.contains(22) || !gl.sslports.contains(990) || len(gl.fallbacks) != 1 {
		t.Fatalf("GenericLines: %+v", gl)
	}
	if !db.excludeTCP.contains(9101) || db.excludeUDP.contains(9101) {
		t.Fatal("exclude")
	}
	rare := db.byName["tcp/RareOne"]
	if string(rare.payload) != "HELLO\x00\r\n" || rare.rarity != 9 {
		t.Fatal("RareOne")
	}
	smtp := db.nullTCP.matches[1]
	if !smtp.icase || smtp.tmpl.hostname != "$1" || !slices.Equal(smtp.tmpl.cpes, []string{"cpe:/a:postfix:postfix"}) {
		t.Fatalf("smtp match: %+v", smtp.tmpl)
	}
	if db.nullTCP.totalWait != 6*time.Second {
		t.Fatal("totalwaitms")
	}
}

func TestMatchAndTemplates(t *testing.T) {
	db := loadSynthetic(t)
	hard, _ := db.matchResponse(db.nullTCP, []byte("220 FakeFTP 3.0.3 ready\r\n"))
	if hard == nil || hard.service != "ftp" || hard.product != "FakeFTP" || hard.version != "3.0.3" ||
		hard.ostype != "Unix" || !slices.Equal(hard.cpes, []string{"cpe:/a:fake:fakeftp:3.0.3"}) {
		t.Fatalf("%+v", hard)
	}
	hard, _ = db.matchResponse(db.nullTCP, []byte("220 mail.corp.local esmtp POSTFIX\r\n"))
	if hard == nil || hard.service != "smtp" || hard.hostname != "mail.corp.local" {
		t.Fatalf("icase: %+v", hard)
	}
	hard, soft := db.matchResponse(db.nullTCP, []byte("220-Welcome\r\n"))
	if hard != nil || soft == nil || soft.service != "ftp" {
		t.Fatalf("softmatch: %+v %+v", hard, soft)
	}
	gl := db.byName["tcp/GenericLines"]
	hard, _ = db.matchResponse(gl, []byte("DB\x00\x01\x02\x07rest"))
	if hard == nil || hard.version != "2.7" || hard.product != "FakeDB" {
		t.Fatalf("$I: %+v", hard)
	}
	// fallback to NULL matches
	hard, _ = db.matchResponse(gl, []byte("220 FakeFTP 1.0 ready\r\n"))
	if hard == nil || hard.service != "ftp" || hard.probe != "GenericLines" {
		t.Fatalf("fallback: %+v", hard)
	}
	uni := db.byName["tcp/Unicode"]
	hard, _ = db.matchResponse(uni, []byte("U:v\x001\x00.\x002\x00"))
	if hard == nil || hard.version != "v1.2" || hard.info != "v1.2" {
		t.Fatalf("$P/$SUBST: %+v", hard)
	}
	udp := db.byName["udp/DNSVersionBindReq"]
	resp := []byte("\x00\x06\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03" +
		"\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00\x00\x07\x069.18.1")
	hard, _ = db.matchResponse(udp, resp)
	if hard == nil || hard.version != "9.18.1" {
		t.Fatalf("udp: %+v", hard)
	}
}

func TestExpandTemplate(t *testing.T) {
	groups := map[int][]byte{1: []byte("a b"), 2: {0x01, 0x00}}
	g := func(n int) ([]byte, bool) { v, ok := groups[n]; return v, ok }
	cases := map[string]string{
		"v$1":               "va b",
		`$SUBST(1," ","_")`: "a_b",
		`$I(2,"<")`:         "1",
		`$I(2,">")`:         "256",
		"$P(2)x":            "x",
		"$9 missing":        "missing",
		"plain $ dollar":    "plain $ dollar",
	}
	for in, want := range cases {
		if got := expandTemplate(in, g); got != want {
			t.Errorf("expandTemplate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCandidatesOrderAndIntensity(t *testing.T) {
	db := loadSynthetic(t)
	names := func(ps []*nmapProbe) []string {
		var out []string
		for _, p := range ps {
			out = append(out, p.name)
		}
		return out
	}
	got := names(db.tcpCandidates(model.TCP, 6001, false, 1))
	if !slices.Equal(got, []string{"GenericLines"}) {
		t.Fatalf("intensity 1: %v", got)
	}
	got = names(db.tcpCandidates(model.TCP, 12345, false, 9))
	if !slices.Equal(got, []string{"GenericLines", "RareOne", "Unicode"}) {
		t.Fatalf("intensity 9: %v", got)
	}
}

// fakeServer accepts connections and serves each with handler.
func fakeServer(t *testing.T, handler func(net.Conn)) (netip.Addr, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				handler(c)
			}()
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	return ap.Addr(), ap.Port()
}

func withProbeDB(t *testing.T, db *probeDB) {
	t.Helper()
	probeDBOnce.Do(func() {})
	old := probeDBGlobal
	probeDBGlobal = db
	t.Cleanup(func() { probeDBGlobal = old })
}

func TestFingerprintNULLProbeMatch(t *testing.T) {
	withProbeDB(t, loadSynthetic(t))
	ip, port := fakeServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("220 FakeFTP 2.3.4 ready\r\n"))
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
	})
	fp := New(slog.New(slog.DiscardHandler))
	svc, err := fp.Fingerprint(context.Background(), ip, port, model.TCP, engine.FingerprintOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != "ftp" || svc.Product != "FakeFTP" || svc.Version != "2.3.4" || svc.Method != MethodProbeMatch ||
		svc.Confidence != ConfProbeMatch || !strings.HasPrefix(svc.Banner, "220 FakeFTP") {
		t.Fatalf("%+v", svc)
	}
}

func TestFingerprintProbeAfterSilence(t *testing.T) {
	withProbeDB(t, loadSynthetic(t))
	ip, port := fakeServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "\r\n\r\n") {
			_, _ = c.Write([]byte("DB\x00\x01\x05\x01"))
		}
	})
	fp := New(slog.New(slog.DiscardHandler))
	svc, err := fp.Fingerprint(context.Background(), ip, port, model.TCP, engine.FingerprintOptions{Timeout: 2 * time.Second, Intensity: 2})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != "fakedb" || svc.Version != "5.1" {
		t.Fatalf("%+v", svc)
	}
}

func TestFingerprintCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fp := New(nil)
	if _, err := fp.Fingerprint(ctx, mustAddr("127.0.0.1"), 1, model.TCP, engine.FingerprintOptions{}); err == nil {
		t.Fatal("expected context error")
	}
}
