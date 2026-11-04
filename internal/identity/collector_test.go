package identity

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/identity/ntlm"
	"github.com/vaadata/nety/internal/model"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestCollector() *collector {
	return &collector{log: quietLogger(), ioTimeout: 300 * time.Millisecond}
}

// find returns the first evidence of the given kind.
func find(ev []model.IdentityEvidence, kind model.EvidenceKind) (model.IdentityEvidence, bool) {
	for _, e := range ev {
		if e.Kind == kind {
			return e, true
		}
	}
	return model.IdentityEvidence{}, false
}

func findValue(ev []model.IdentityEvidence, kind model.EvidenceKind, value string) bool {
	for _, e := range ev {
		if e.Kind == kind && strings.EqualFold(e.Value, value) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Evidence sink
// ---------------------------------------------------------------------------

func TestEvidenceSinkDedupeAndOrder(t *testing.T) {
	s := &evidenceSink{}
	s.add(model.EvHostname, "web01", "smb-ntlm/445", 70, map[string]string{"a": "1"})
	s.add(model.EvHostname, "WEB01", "smb-ntlm/445", 80, map[string]string{"b": "2"}) // same key, better conf
	s.add(model.EvSMBGUID, "f0e1-d2", "smb2/445", 95, nil)
	s.add(model.EvHostname, "web01", "llmnr", 65, nil) // different source: kept
	s.add(model.EvVendor, "   ", "oui", 20, nil)       // empty: dropped
	s.add(model.EvVendor, "Dell", "oui", 0, nil)       // no confidence: dropped

	got := s.evidence()
	if len(got) != 3 {
		t.Fatalf("want 3 evidence items, got %d: %+v", len(got), got)
	}
	if got[0].Kind != model.EvSMBGUID {
		t.Errorf("highest confidence must sort first, got %v", got[0].Kind)
	}
	h, _ := find(got, model.EvHostname)
	if h.Confidence != 80 {
		t.Errorf("merged confidence = %d, want 80", h.Confidence)
	}
	if h.Attributes["a"] != "1" || h.Attributes["b"] != "2" {
		t.Errorf("attributes not merged: %v", h.Attributes)
	}

	// The sink must be deterministic across runs.
	again := s.evidence()
	for i := range got {
		if got[i].Kind != again[i].Kind || got[i].Value != again[i].Value {
			t.Fatalf("evidence() is not deterministic at %d", i)
		}
	}
}

func TestEvidenceSinkCapsAttackerControlledLength(t *testing.T) {
	s := &evidenceSink{}
	s.add(model.EvHostname, strings.Repeat("a", 10000), "nbstat/137", 70,
		map[string]string{"k": strings.Repeat("b", 10000)})
	got := s.evidence()
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if len(got[0].Value) > 512 || len(got[0].Attributes["k"]) > 512 {
		t.Fatalf("value/attribute not capped: %d/%d", len(got[0].Value), len(got[0].Attributes["k"]))
	}
}

func TestEvidenceSinkConcurrent(t *testing.T) {
	s := &evidenceSink{}
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				s.add(model.EvHostname, "h", "src", 50, nil)
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if got := s.evidence(); len(got) != 1 {
		t.Fatalf("want 1 deduped item, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Evidence derived from already-collected service data
// ---------------------------------------------------------------------------

func TestFromServiceData(t *testing.T) {
	c := newTestCollector()
	s := &evidenceSink{}
	host := model.Host{IP: "10.0.0.5", MAC: "00:50:56:AB:CD:EF"}
	svcs := []model.Service{
		{Port: 22, Protocol: model.TCP, Name: "ssh", State: model.PortOpen, SSH: &model.SSHInfo{
			Banner:   "SSH-2.0-OpenSSH_9.2p1 Debian-2",
			HostKeys: []model.SSHHostKey{{Type: "ssh-ed25519", SHA256: "SHA256:abcdEFGH1234=="}},
		}},
		{Port: 443, Protocol: model.TCP, Name: "https", State: model.PortOpen, TLS: &model.TLSInfo{
			SubjectCN: "vcenter.corp.local", Issuer: "CN=vcenter.corp.local",
			SelfSigned: true, SHA256: "AA:BB:CC", KeyAlgo: "RSA", KeyBits: 2048,
		}},
		{Port: 80, Protocol: model.TCP, Name: "http", State: model.PortOpen, HTTP: &model.HTTPInfo{
			FaviconMMH3: "-1234567", Title: "Login",
		}},
	}
	c.fromServiceData(s, host, svcs)
	ev := s.evidence()

	k, ok := find(ev, model.EvSSHHostKey)
	if !ok {
		t.Fatal("no ssh host key evidence")
	}
	// Padding must be stripped so the same key always yields the same asset key.
	if k.Value != "SHA256:abcdEFGH1234" {
		t.Errorf("ssh fingerprint = %q", k.Value)
	}
	if k.Confidence != confSSHHostKey {
		t.Errorf("ssh confidence = %d", k.Confidence)
	}

	cert, ok := find(ev, model.EvTLSCert)
	if !ok {
		t.Fatal("no tls cert evidence")
	}
	if cert.Value != "aabbcc" {
		t.Errorf("cert fingerprint not normalized: %q", cert.Value)
	}
	if cert.Confidence != confTLSUnique {
		t.Errorf("unique self-signed cert should keep full confidence, got %d", cert.Confidence)
	}
	// A self-signed certificate's CN names the machine.
	if !findValue(ev, model.EvFQDN, "vcenter.corp.local") {
		t.Errorf("CN not turned into an FQDN: %+v", ev)
	}

	if _, ok := find(ev, model.EvHTTPFavicon); !ok {
		t.Error("no favicon evidence")
	}
	mac, ok := find(ev, model.EvMAC)
	if !ok {
		t.Fatal("no mac evidence")
	}
	if mac.Attributes["source"] != "arp" {
		t.Errorf("MAC must record where it came from: %v", mac.Attributes)
	}
	if v, ok := find(ev, model.EvVendor); !ok || !strings.Contains(strings.ToLower(v.Value), "vmware") {
		t.Errorf("OUI vendor not resolved: %+v", v)
	}
}

func TestSharedCertificatesAreDowngraded(t *testing.T) {
	cases := []struct {
		name   string
		tls    model.TLSInfo
		shared bool
	}{
		{"wildcard cn", model.TLSInfo{SubjectCN: "*.corp.local", SelfSigned: true}, true},
		{"wildcard san", model.TLSInfo{SubjectCN: "a.corp.local", SANs: []string{"*.corp.local"}}, true},
		{"vendor default", model.TLSInfo{SubjectCN: "localhost", SelfSigned: true}, true},
		{"public ca", model.TLSInfo{SubjectCN: "www.corp.com", Issuer: "CN=R3, O=Let's Encrypt"}, true},
		{"per machine", model.TLSInfo{SubjectCN: "esxi01.corp.local", Issuer: "CN=esxi01.corp.local", SelfSigned: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := certIsShared(&tc.tls); got != tc.shared {
				t.Fatalf("certIsShared = %v, want %v", got, tc.shared)
			}
			s := &evidenceSink{}
			ti := tc.tls
			ti.SHA256 = "deadbeef"
			tlsEvidence(s, model.Service{Port: 443, Name: "https", TLS: &ti}, "https/443")
			e, ok := find(s.evidence(), model.EvTLSCert)
			if !ok {
				t.Fatal("no cert evidence")
			}
			if tc.shared {
				if e.Confidence != confTLSShared || e.Attributes["shared"] != "true" {
					t.Fatalf("shared cert not downgraded: conf=%d attrs=%v", e.Confidence, e.Attributes)
				}
			} else if e.Confidence != confTLSUnique {
				t.Fatalf("unique cert downgraded: conf=%d", e.Confidence)
			}
		})
	}
}

func TestMACEvidenceSkipsUnusableAddresses(t *testing.T) {
	for _, mac := range []string{"", "not-a-mac", "01:00:5e:00:00:01" /* multicast */} {
		s := &evidenceSink{}
		macEvidence(s, model.Host{MAC: mac})
		if ev := s.evidence(); len(ev) != 0 {
			t.Fatalf("mac %q produced %+v", mac, ev)
		}
	}
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

func TestPlanUsesOnlyOpenServices(t *testing.T) {
	c := newTestCollector()
	addr := netip.MustParseAddr("10.0.0.5")
	names := func(ps []namedProbe) []string {
		var out []string
		for _, p := range ps {
			out = append(out, p.name)
		}
		return out
	}

	// Nothing open: only the cheap UDP queries and reverse DNS.
	base := names(c.plan(addr, nil, nil))
	for _, want := range []string{"nbstat", "mdns", "llmnr", "snmp", "rdns"} {
		if !contains(base, want) {
			t.Errorf("missing unconditional probe %q in %v", want, base)
		}
	}
	for _, unwanted := range []string{"smb", "rdp", "mssql", "http-ntlm"} {
		if contains(base, unwanted) {
			t.Errorf("probe %q scheduled without an open service: %v", unwanted, base)
		}
	}

	open := []model.Service{
		{Port: 445, Protocol: model.TCP, Name: "microsoft-ds", State: model.PortOpen},
		{Port: 139, Protocol: model.TCP, Name: "netbios-ssn", State: model.PortOpen},
		{Port: 3389, Protocol: model.TCP, Name: "ms-wbt-server", State: model.PortOpen},
		{Port: 1433, Protocol: model.TCP, Name: "ms-sql-s", State: model.PortOpen},
		{Port: 25, Protocol: model.TCP, Name: "smtp", State: model.PortOpen},
		{Port: 5985, Protocol: model.TCP, Name: "wsman", State: model.PortOpen},
	}
	got := names(c.plan(addr, open, nil))
	for _, want := range []string{"smb", "rdp", "mssql", "smtp", "http-ntlm"} {
		if !contains(got, want) {
			t.Errorf("missing probe %q in %v", want, got)
		}
	}
	// 445 and 139 are the same service: SMB must be probed once.
	if n := count(got, "smb"); n != 1 {
		t.Errorf("smb scheduled %d times, want 1", n)
	}
}

func TestSMBPortPrefers445(t *testing.T) {
	both := []model.Service{
		{Port: 139, Protocol: model.TCP, State: model.PortOpen},
		{Port: 445, Protocol: model.TCP, State: model.PortOpen},
	}
	if p, _ := smbPort(both); p != 445 {
		t.Errorf("smbPort = %d, want 445", p)
	}
	only139 := []model.Service{{Port: 139, Protocol: model.TCP, State: model.PortOpen}}
	if p, _ := smbPort(only139); p != 139 {
		t.Errorf("smbPort = %d, want 139", p)
	}
	if _, ok := smbPort(nil); ok {
		t.Error("smbPort must not fire without an open service")
	}
}

func TestOpenServicesFiltersClosedPorts(t *testing.T) {
	in := []model.Service{
		{Port: 1, State: model.PortOpen},
		{Port: 2, State: model.PortClosed},
		{Port: 3, State: model.PortFiltered},
		{Port: 4, State: model.PortOpenFiltered},
		{Port: 5, State: ""},
	}
	got := openServices(in)
	if len(got) != 3 {
		t.Fatalf("openServices kept %d services: %+v", len(got), got)
	}
}

// ---------------------------------------------------------------------------
// Collect
// ---------------------------------------------------------------------------

func TestCollectWithoutIP(t *testing.T) {
	ev, err := newTestCollector().Collect(context.Background(), model.Host{}, nil, nil)
	if err != nil || ev != nil {
		t.Fatalf("ev=%v err=%v", ev, err)
	}
}

// TestCollectOnDeadHost points every probe at a loopback address with nothing
// listening. All of them must fail quickly and harmlessly, and Collect must
// still return the evidence derivable from the service data it was handed.
func TestCollectOnDeadHost(t *testing.T) {
	c := newTestCollector()
	host := model.Host{IP: "127.0.0.1", MAC: "00:50:56:11:22:33"}
	svcs := []model.Service{
		// A closed loopback port: dialling it is refused immediately.
		{IP: "127.0.0.1", Port: 1, Protocol: model.TCP, Name: "ssh", State: model.PortOpen,
			SSH: &model.SSHInfo{HostKeys: []model.SSHHostKey{{Type: "rsa", SHA256: "SHA256:zzz"}}}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	start := time.Now()
	ev, err := c.Collect(ctx, host, svcs, nil)
	if err != nil {
		t.Fatalf("Collect returned %v", err)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("Collect took %v on a dead host", elapsed)
	}
	if !findValue(ev, model.EvSSHHostKey, "SHA256:zzz") {
		t.Errorf("service-derived evidence lost: %+v", ev)
	}
	if !findValue(ev, model.EvMAC, "00:50:56:11:22:33") {
		t.Errorf("mac evidence lost: %+v", ev)
	}
}

func TestCollectHonoursCancellation(t *testing.T) {
	c := newTestCollector()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := c.Collect(ctx, model.Host{IP: "127.0.0.1"}, nil, nil)
	if err == nil {
		t.Fatal("want a context error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation was not honoured promptly")
	}
}

// ---------------------------------------------------------------------------
// Byte-fixture parsers
// ---------------------------------------------------------------------------

// buildNBSTATReply assembles a node status response the way a Windows host
// would, so the parser is exercised against a realistic frame.
func buildNBSTATReply(id uint16, names []nbName, mac []byte) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x8400) // response, authoritative
	binary.BigEndian.PutUint16(b[6:], 1)      // ANCOUNT

	// Question name echoed in the answer: encoded "*" wildcard.
	name := make([]byte, 0, 34)
	name = append(name, 32)
	raw := make([]byte, 16)
	raw[0] = '*'
	for _, c := range raw {
		name = append(name, 'A'+(c>>4), 'A'+(c&0x0f))
	}
	name = append(name, 0)
	b = append(b, name...)
	b = binary.BigEndian.AppendUint16(b, 0x0021) // NBSTAT
	b = binary.BigEndian.AppendUint16(b, 0x0001) // IN
	b = binary.BigEndian.AppendUint32(b, 0)      // TTL

	rdata := []byte{byte(len(names))}
	for _, n := range names {
		field := make([]byte, 15)
		copy(field, n.Name)
		for i := len(n.Name); i < 15; i++ {
			field[i] = ' '
		}
		rdata = append(rdata, field...)
		rdata = append(rdata, n.Suffix)
		flags := uint16(0x0400)
		if n.Group {
			flags |= 0x8000
		}
		rdata = binary.BigEndian.AppendUint16(rdata, flags)
	}
	rdata = append(rdata, mac...)
	rdata = append(rdata, make([]byte, 40)...) // statistics block

	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

func TestParseNBSTAT(t *testing.T) {
	names := []nbName{
		{Name: "WS-0042", Suffix: 0x00},
		{Name: "WS-0042", Suffix: 0x20},
		{Name: "CORP", Suffix: 0x00, Group: true},
		{Name: "CORP", Suffix: 0x1c, Group: true},
	}
	mac := []byte{0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c}
	frame := buildNBSTATReply(0x1234, names, mac)

	r, err := parseNBSTAT(frame, 0x1234)
	if err != nil {
		t.Fatalf("parseNBSTAT: %v", err)
	}
	if len(r.Names) != 4 {
		t.Fatalf("got %d names: %+v", len(r.Names), r.Names)
	}
	if r.Names[0].Name != "WS-0042" {
		t.Errorf("name = %q (trailing padding must be trimmed)", r.Names[0].Name)
	}
	if !strings.EqualFold(r.MAC, "00:0c:29:1a:2b:3c") {
		t.Errorf("MAC = %q", r.MAC)
	}

	// The MAC is readable across a routed boundary, unlike ARP: make sure the
	// evidence records that provenance so the correlator trusts it.
	s := &evidenceSink{}
	nbstatEvidence(s, r, "nbstat/137")
	ev := s.evidence()
	m, ok := find(ev, model.EvMAC)
	if !ok || m.Attributes["source"] != "nbstat" {
		t.Fatalf("nbstat MAC evidence missing provenance: %+v", ev)
	}
	if !findValue(ev, model.EvNetBIOSName, "WS-0042") {
		t.Errorf("computer name missing: %+v", ev)
	}
	if !findValue(ev, model.EvNetBIOSDomain, "CORP") {
		t.Errorf("domain missing: %+v", ev)
	}

	// Wrong transaction id must be rejected (off-path spoofing).
	if _, err := parseNBSTAT(frame, 0x9999); err == nil {
		t.Error("transaction id not checked")
	}
}

// TestParseNBSTATHostileInput feeds truncations and absurd counts to the
// parser: it must never panic and never allocate from the wire length.
func TestParseNBSTATHostileInput(t *testing.T) {
	frame := buildNBSTATReply(1, []nbName{{Name: "A", Suffix: 0}}, []byte{1, 2, 3, 4, 5, 6})
	for i := 0; i < len(frame); i++ {
		if _, err := parseNBSTAT(frame[:i], 1); err == nil && i < len(frame)-1 {
			// A short frame may legitimately parse if it ends on a boundary;
			// the only requirement is that it does not panic.
			continue
		}
	}
	// A name count far beyond the buffer.
	bad := append([]byte(nil), frame...)
	if len(bad) > 60 {
		bad[57] = 0xff
	}
	_, _ = parseNBSTAT(bad, 1)

	for _, junk := range [][]byte{nil, {}, {0x00}, make([]byte, 11), make([]byte, 4096)} {
		_, _ = parseNBSTAT(junk, 0)
	}
}

func TestParseSNMPv3Report(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x11, 0x22, 0x33, 0x44}
	i32 := func(v int) []byte { return ntlm.DER(0x02, []byte{byte(v)}) }
	usm := ntlm.DER(0x30,
		ntlm.DER(0x04, engineID),
		i32(5),  // boots
		i32(42), // time
		ntlm.DER(0x04), ntlm.DER(0x04), ntlm.DER(0x04),
	)
	global := ntlm.DER(0x30, i32(1), ntlm.DER(0x02, []byte{0xff, 0xe3}), ntlm.DER(0x04, []byte{0x04}), i32(3))
	scoped := ntlm.DER(0x30, ntlm.DER(0x04, engineID), ntlm.DER(0x04), ntlm.DER(0xa8, i32(1), i32(0), i32(0), ntlm.DER(0x30)))
	msg := ntlm.DER(0x30, i32(3), global, ntlm.DER(0x04, usm), scoped)

	e, err := parseSNMPv3Report(msg)
	if err != nil {
		t.Fatalf("parseSNMPv3Report: %v", err)
	}
	if string(e.ID) != string(engineID) {
		t.Fatalf("engine id = %x, want %x", e.ID, engineID)
	}
	if e.Boots != 5 || e.Time != 42 {
		t.Errorf("boots=%d time=%d", e.Boots, e.Time)
	}

	// Truncating anywhere must produce an error, never a panic.
	for i := 0; i < len(msg); i++ {
		_, _ = parseSNMPv3Report(msg[:i])
	}
	for _, junk := range [][]byte{nil, {0x30}, {0x30, 0x80}, {0x30, 0x7f}} {
		_, _ = parseSNMPv3Report(junk)
	}
}

func TestSNMPv3DiscoveryIsWellFormed(t *testing.T) {
	q := buildSNMPv3Discovery(0x1234, 0x5678)
	tag, val, rest, err := ntlm.ReadTLV(q)
	if err != nil || tag != 0x30 {
		t.Fatalf("not a SEQUENCE: tag=%#x err=%v", tag, err)
	}
	if len(rest) != 0 {
		t.Errorf("%d trailing bytes", len(rest))
	}
	// version must be 3
	vtag, vval, _, err := ntlm.ReadTLV(val)
	if err != nil || vtag != 0x02 || len(vval) != 1 || vval[0] != 3 {
		t.Fatalf("version field = %#v (err %v)", vval, err)
	}
}

// ---------------------------------------------------------------------------
// In-process servers
// ---------------------------------------------------------------------------

// udpEcho starts a UDP responder on loopback that answers each datagram with
// reply(request). It returns the port it listens on.
func udpEcho(t *testing.T, reply func([]byte) []byte) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestProbeNBSTATAgainstFakeServer(t *testing.T) {
	names := []nbName{
		{Name: "FILESRV", Suffix: 0x00},
		{Name: "CORP", Suffix: 0x1c, Group: true},
	}
	port := udpEcho(t, func(req []byte) []byte {
		if len(req) < 2 {
			return nil
		}
		id := binary.BigEndian.Uint16(req[0:2])
		return buildNBSTATReply(id, names, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	})

	c := newTestCollector()
	s := &evidenceSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.probeNBSTAT(ctx, s, "127.0.0.1", port); err != nil {
		t.Fatalf("probeNBSTAT: %v", err)
	}
	ev := s.evidence()
	if !findValue(ev, model.EvNetBIOSName, "FILESRV") {
		t.Errorf("computer name not collected: %+v", ev)
	}
	if !findValue(ev, model.EvMAC, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("adapter MAC not collected: %+v", ev)
	}
}

// TestProbeNBSTATIgnoresGarbage makes sure a hostile responder cannot make the
// probe panic or emit nonsense.
func TestProbeNBSTATIgnoresGarbage(t *testing.T) {
	port := udpEcho(t, func(req []byte) []byte {
		out := make([]byte, 1400)
		for i := range out {
			out[i] = 0xff
		}
		if len(req) >= 2 {
			copy(out, req[:2])
		}
		return out
	})
	c := newTestCollector()
	s := &evidenceSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.probeNBSTAT(ctx, s, "127.0.0.1", port)
	for _, e := range s.evidence() {
		if e.Kind == model.EvMAC && e.Value == "ff:ff:ff:ff:ff:ff" {
			t.Fatal("broadcast MAC accepted as identity evidence")
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func count(s []string, v string) int {
	n := 0
	for _, x := range s {
		if x == v {
			n++
		}
	}
	return n
}
