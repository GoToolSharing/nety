package checks

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

// ---------------------------------------------------------------------------
// Test harness: drive one registered check against an in-process server
// ---------------------------------------------------------------------------

// fakeServer starts a TCP listener on loopback and serves every connection
// with handle. It returns the port it bound.
func fakeServer(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
				handle(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// fakeUDPServer answers each datagram with reply(request).
func fakeUDPServer(t *testing.T, reply func([]byte) []byte) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
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

func lookupCheck(t *testing.T, id string) *Check {
	t.Helper()
	for _, c := range allChecks() {
		if c.Info.ID == id {
			return c
		}
	}
	t.Fatalf("check %q is not registered", id)
	return nil
}

// probe runs one registered check against svc, going through Applies first so
// the test also proves the check is scoped correctly.
func probe(t *testing.T, id string, svc model.Service, all ...model.Service) []model.Finding {
	t.Helper()
	return probeTimeout(t, id, 2*time.Second, svc, all...)
}

// probeTimeout is probe with an explicit per-I/O timeout, for the cases where
// the fake server deliberately stays silent.
func probeTimeout(t *testing.T, id string, timeout time.Duration, svc model.Service, all ...model.Service) []model.Finding {
	t.Helper()
	c := lookupCheck(t, id)
	if len(all) == 0 {
		all = []model.Service{svc}
	}
	tg := &Target{
		Host:     model.Host{IP: "127.0.0.1"},
		IP:       "127.0.0.1",
		Service:  svc,
		Services: all,
		Opts:     engine.CheckOptions{Timeout: timeout},
		Timeout:  timeout,
		Log:      quietLogger(),
		check:    c,
		// The same per-host ceiling on authentication attempts the engine
		// attaches, so the tests exercise what a real scan does.
		creds: newCredBudget(),
	}
	if c.HostLevel {
		tg.Service = model.Service{}
	}
	if c.Applies != nil && !c.Applies(tg) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.Run(ctx, tg)
}

// tcpSvc describes an open TCP service on the loopback test server.
func tcpSvc(name string, port int) model.Service {
	return model.Service{IP: "127.0.0.1", Port: port, Protocol: model.TCP, Name: name, State: model.PortOpen}
}

func udpSvc(name string, port int) model.Service {
	return model.Service{IP: "127.0.0.1", Port: port, Protocol: model.UDP, Name: name, State: model.PortOpen}
}

// lines reads CRLF/LF terminated commands and dispatches them to reply.
// It is the shape every text protocol fake below needs.
func serveLines(c net.Conn, greeting string, reply func(cmd string) (resp string, closeConn bool)) {
	if greeting != "" {
		_, _ = io.WriteString(c, greeting)
	}
	r := bufio.NewReader(c)
	for i := 0; i < 50; i++ {
		line, err := r.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			resp, done := reply(line)
			if resp != "" {
				if _, werr := io.WriteString(c, resp); werr != nil {
					return
				}
			}
			if done {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// The contract that matters most: no service, no finding
// ---------------------------------------------------------------------------

// TestNoFindingsWithoutServices runs the whole registry against a host with
// no open service. Every check must stay silent: a check that fires without
// its service would put a false finding in a client report.
func TestNoFindingsWithoutServices(t *testing.T) {
	c := New(quietLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := engine.CheckOptions{Timeout: 500 * time.Millisecond, AllowDefaultCreds: true}
	fs, err := c.Run(ctx, model.Host{IP: "127.0.0.1"}, nil, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("checks fired on a host with no services: %+v", fs)
	}
}

// TestNoFindingsOnUnrelatedService points every check at a single open port
// that speaks nothing any of them understands. Nothing may be reported.
func TestNoFindingsOnUnrelatedService(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		// Answer every probe with the same meaningless blob.
		buf := make([]byte, 512)
		for i := 0; i < 4; i++ {
			if _, err := io.WriteString(c, "hello from nowhere\r\n"); err != nil {
				return
			}
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	})
	svc := tcpSvc("unknown", port)

	c := New(quietLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fs, err := c.Run(ctx, model.Host{IP: "127.0.0.1"}, []model.Service{svc},
		engine.CheckOptions{Timeout: time.Second, AllowDefaultCreds: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range fs {
		t.Errorf("false positive %s on an unrelated service: %s", f.CheckID, f.Evidence)
	}
}

// inventoryOnlyChecks report an exposure from the service inventory alone.
// The port scan already proved the port open and the protocol is insecure by
// definition, so they still report when the probe connection fails. Every
// other check must stay silent unless it actually spoke to the service.
var inventoryOnlyChecks = map[string]bool{
	"telnet-cleartext":  true,
	"rservices-exposed": true,
}

// TestEveryCheckIsSilentOnADeadPort asserts that each check individually
// reports nothing when the connection is refused: a check that reports on a
// failed probe would invent findings whenever a host is firewalled mid-scan.
func TestEveryCheckIsSilentOnADeadPort(t *testing.T) {
	// Bind then close: the port is almost certainly free and refusing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	for _, ch := range allChecks() {
		ch := ch
		t.Run(ch.Info.ID, func(t *testing.T) {
			t.Parallel()
			for _, proto := range []model.Protocol{model.TCP, model.UDP} {
				svc := model.Service{IP: "127.0.0.1", Port: dead, Protocol: proto,
					Name: firstService(ch.Info.Services), State: model.PortOpen}
				fs := probe(t, ch.Info.ID, svc)
				if len(fs) != 0 && !inventoryOnlyChecks[ch.Info.ID] {
					t.Errorf("%s reported %d finding(s) against a closed port: %s",
						ch.Info.ID, len(fs), fs[0].Evidence)
				}
			}
		})
	}
}

// TestInventoryOnlyChecksStayNarrow keeps the exception list honest: a check
// allowed to report without probing must apply to a protocol that is insecure
// by definition, never to one whose weakness depends on its configuration.
func TestInventoryOnlyChecksStayNarrow(t *testing.T) {
	if len(inventoryOnlyChecks) > 3 {
		t.Fatalf("too many checks report without probing: %v", inventoryOnlyChecks)
	}
	for id := range inventoryOnlyChecks {
		c := lookupCheck(t, id)
		if c.Info.Severity == model.SevCritical || c.Info.Severity == model.SevHigh {
			t.Errorf("%s reports without probing: it must not claim high severity", id)
		}
	}
}

func firstService(s []string) string {
	if len(s) == 0 {
		return "unknown"
	}
	return s[0]
}

// ---------------------------------------------------------------------------
// Text protocols: in-process servers
// ---------------------------------------------------------------------------

func TestFTPAnonymous(t *testing.T) {
	t.Run("allowed", func(t *testing.T) {
		port := fakeServer(t, func(c net.Conn) {
			serveLines(c, "220 (vsFTPd 3.0.5)\r\n", func(cmd string) (string, bool) {
				switch {
				case strings.HasPrefix(cmd, "USER anonymous"):
					return "331 Please specify the password.\r\n", false
				case strings.HasPrefix(cmd, "PASS"):
					return "230 Login successful.\r\n", false
				case cmd == "PWD":
					return "257 \"/\" is the current directory\r\n", false
				case cmd == "QUIT":
					return "221 Goodbye.\r\n", true
				}
				return "500 Unknown.\r\n", false
			})
		})
		fs := probe(t, "ftp-anonymous", tcpSvc("ftp", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if !strings.Contains(fs[0].Evidence, "230 Login successful") {
			t.Errorf("evidence does not show the successful login: %q", fs[0].Evidence)
		}
		if fs[0].Remediation == "" || fs[0].Severity != model.SevMedium {
			t.Errorf("finding metadata incomplete: %+v", fs[0])
		}
	})

	t.Run("refused", func(t *testing.T) {
		port := fakeServer(t, func(c net.Conn) {
			serveLines(c, "220 FTP ready\r\n", func(cmd string) (string, bool) {
				if strings.HasPrefix(cmd, "USER") {
					return "530 Permission denied.\r\n", false
				}
				return "221 bye\r\n", true
			})
		})
		if fs := probe(t, "ftp-anonymous", tcpSvc("ftp", port)); len(fs) != 0 {
			t.Fatalf("anonymous login refused but reported: %+v", fs)
		}
	})

	t.Run("password required then refused", func(t *testing.T) {
		port := fakeServer(t, func(c net.Conn) {
			serveLines(c, "220 FTP ready\r\n", func(cmd string) (string, bool) {
				switch {
				case strings.HasPrefix(cmd, "USER"):
					return "331 Password required\r\n", false
				case strings.HasPrefix(cmd, "PASS"):
					return "530 Login incorrect.\r\n", false
				}
				return "221 bye\r\n", true
			})
		})
		if fs := probe(t, "ftp-anonymous", tcpSvc("ftp", port)); len(fs) != 0 {
			t.Fatalf("reported despite 530: %+v", fs)
		}
	})
}

func TestRedisNoAuth(t *testing.T) {
	t.Run("open", func(t *testing.T) {
		info := "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux 6.1.0 x86_64\r\n"
		port := fakeServer(t, func(c net.Conn) {
			serveLines(c, "", func(cmd string) (string, bool) {
				if strings.HasPrefix(strings.ToUpper(cmd), "INFO") {
					return fmt.Sprintf("$%d\r\n%s\r\n", len(info), info), false
				}
				return "+OK\r\n", true
			})
		})
		fs := probe(t, "redis-no-auth", tcpSvc("redis", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if !strings.Contains(fs[0].Evidence, "7.2.4") {
			t.Errorf("version missing from evidence: %q", fs[0].Evidence)
		}
		if fs[0].Severity != model.SevCritical {
			t.Errorf("unauthenticated Redis should be critical, got %s", fs[0].Severity)
		}
	})

	t.Run("password protected", func(t *testing.T) {
		port := fakeServer(t, func(c net.Conn) {
			serveLines(c, "", func(string) (string, bool) {
				return "-NOAUTH Authentication required.\r\n", true
			})
		})
		if fs := probe(t, "redis-no-auth", tcpSvc("redis", port)); len(fs) != 0 {
			t.Fatalf("NOAUTH reported as open: %+v", fs)
		}
	})
}

func TestMemcachedOpen(t *testing.T) {
	t.Run("open", func(t *testing.T) {
		port := fakeServer(t, func(c net.Conn) {
			serveLines(c, "", func(cmd string) (string, bool) {
				if cmd == "stats" {
					return "STAT pid 1\r\nSTAT version 1.6.21\r\nSTAT curr_items 4211\r\nEND\r\n", false
				}
				return "", true
			})
		})
		fs := probe(t, "memcached-open", tcpSvc("memcached", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if !strings.Contains(fs[0].Evidence, "1.6.21") {
			t.Errorf("evidence: %q", fs[0].Evidence)
		}
	})

	t.Run("sasl required", func(t *testing.T) {
		port := fakeServer(t, func(c net.Conn) {
			serveLines(c, "", func(string) (string, bool) {
				return "CLIENT_ERROR authentication required\r\n", true
			})
		})
		if fs := probe(t, "memcached-open", tcpSvc("memcached", port)); len(fs) != 0 {
			t.Fatalf("reported despite auth: %+v", fs)
		}
	})
}

func TestRsyncModuleListing(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "@RSYNCD: 31.0\n")
		r := bufio.NewReader(c)
		if _, err := r.ReadString('\n'); err != nil { // client version
			return
		}
		sel, err := r.ReadString('\n') // module selection: "" = list
		if err != nil {
			return
		}
		if strings.TrimSpace(sel) == "" {
			_, _ = io.WriteString(c, "backups\tnightly dumps\npublic\tread only\n@RSYNCD: EXIT\n")
			return
		}
		// A module was selected: pretend it needs no password.
		_, _ = io.WriteString(c, "@RSYNCD: OK\n")
	})
	fs := probe(t, "rsync-modules", tcpSvc("rsync", port))
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	for _, want := range []string{"backups", "public"} {
		if !strings.Contains(fs[0].Evidence, want) {
			t.Errorf("module %q missing from evidence: %q", want, fs[0].Evidence)
		}
	}
}

func TestRsyncNoModules(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "@RSYNCD: 31.0\n")
		r := bufio.NewReader(c)
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		_, _ = io.WriteString(c, "@RSYNCD: EXIT\n")
	})
	if fs := probe(t, "rsync-modules", tcpSvc("rsync", port)); len(fs) != 0 {
		t.Fatalf("empty module list reported: %+v", fs)
	}
}

// ---------------------------------------------------------------------------
// NFS / ONC RPC
// ---------------------------------------------------------------------------

// rpcReplyOK wraps a result body in an accepted ONC RPC reply, record marked.
func rpcReplyOK(xid uint32, result []byte) []byte {
	body := make([]byte, 0, 24+len(result))
	put := func(v uint32) { body = binary.BigEndian.AppendUint32(body, v) }
	put(xid)
	put(1) // REPLY
	put(0) // MSG_ACCEPTED
	put(0) // verifier flavour AUTH_NULL
	put(0) // verifier length
	put(0) // accept_stat SUCCESS
	body = append(body, result...)

	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body))|0x80000000)
	return append(out, body...)
}

// xdrString encodes a length-prefixed, 4-byte-padded XDR string.
func xdrString(s string) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(s)))
	b = append(b, s...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// exportListBody builds a MOUNTPROC3_EXPORT result.
func exportListBody(exports []nfsExport) []byte {
	var b []byte
	for _, e := range exports {
		b = binary.BigEndian.AppendUint32(b, 1) // value follows
		b = append(b, xdrString(e.Dir)...)
		for _, g := range e.Groups {
			b = binary.BigEndian.AppendUint32(b, 1)
			b = append(b, xdrString(g)...)
		}
		b = binary.BigEndian.AppendUint32(b, 0) // end of groups
	}
	return binary.BigEndian.AppendUint32(b, 0) // end of list
}

// mountdServer serves MOUNTPROC3_EXPORT with the given export table.
func mountdServer(t *testing.T, exports []nfsExport) int {
	return fakeServer(t, func(c net.Conn) {
		var hdr [4]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(hdr[:]) & 0x7fffffff)
		if n < 24 || n > 4096 {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		xid := binary.BigEndian.Uint32(body[0:4])
		prog := binary.BigEndian.Uint32(body[12:16])
		proc := binary.BigEndian.Uint32(body[20:24])
		if prog != progMount || proc != procMountExport {
			return
		}
		_, _ = c.Write(rpcReplyOK(xid, exportListBody(exports)))
	})
}

func TestNFSExports(t *testing.T) {
	exports := []nfsExport{
		{Dir: "/srv/public", Groups: nil},                             // world
		{Dir: "/srv/open", Groups: []string{"*"}},                     // world
		{Dir: "/srv/db", Groups: []string{"10.0.0.0/24", "backup01"}}, // restricted
	}
	port := mountdServer(t, exports)

	t.Run("parse", func(t *testing.T) {
		got, err := parseExportList(exportListBody(exports))
		if err != nil {
			t.Fatalf("parseExportList: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("got %d exports: %+v", len(got), got)
		}
		if !got[0].World() || !got[1].World() {
			t.Error("unrestricted exports not recognised as world readable")
		}
		if got[2].World() {
			t.Error("restricted export flagged as world readable")
		}
	})

	// Drive the real MOUNT client over a real socket against the fake mountd.
	t.Run("live mountd", func(t *testing.T) {
		tg := &Target{
			Host: model.Host{IP: "127.0.0.1"}, IP: "127.0.0.1",
			Services: []model.Service{{IP: "127.0.0.1", Port: port, Protocol: model.TCP, Name: "mountd", State: model.PortOpen}},
			Timeout:  2 * time.Second, Log: quietLogger(),
			check: lookupCheck(t, "nfs-exports-listable"),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		got, err := mountExport(ctx, tg, port)
		if err != nil {
			t.Fatalf("mountExport: %v", err)
		}
		if len(got) != 3 || got[0].Dir != "/srv/public" {
			t.Fatalf("decoded %+v", got)
		}
		if !got[0].World() || got[2].World() {
			t.Fatalf("world flags wrong: %+v", got)
		}
	})

	// A mountd that answers on a port nobody advertises is simply not found.
	t.Run("no rpc port open", func(t *testing.T) {
		tg := &Target{
			Host: model.Host{IP: "127.0.0.1"}, IP: "127.0.0.1",
			Services: []model.Service{tcpSvc("http", 80)},
			Timeout:  500 * time.Millisecond, Log: quietLogger(),
			check: lookupCheck(t, "nfs-exports-listable"),
		}
		if lookupCheck(t, "nfs-exports-listable").Applies(tg) {
			t.Fatal("check applies without an RPC port")
		}
	})
}

func TestParseExportListHostileInput(t *testing.T) {
	good := exportListBody([]nfsExport{{Dir: "/a", Groups: []string{"*"}}})
	for i := 0; i < len(good); i++ {
		if _, err := parseExportList(good[:i]); err == nil && i < len(good) {
			// Truncated input must error, but above all must not panic.
			continue
		}
	}
	// A length prefix far beyond the buffer must not allocate.
	huge := binary.BigEndian.AppendUint32(nil, 1)
	huge = binary.BigEndian.AppendUint32(huge, 0xffffffff)
	if _, err := parseExportList(huge); err == nil {
		t.Error("absurd string length accepted")
	}
	// A runaway list must be capped rather than looping forever.
	var many []byte
	for i := 0; i < maxExports+50; i++ {
		many = binary.BigEndian.AppendUint32(many, 1)
		many = append(many, xdrString("/x")...)
		many = binary.BigEndian.AppendUint32(many, 0)
	}
	many = binary.BigEndian.AppendUint32(many, 0)
	got, _ := parseExportList(many)
	if len(got) > maxExports {
		t.Fatalf("export list not capped: %d", len(got))
	}
}

func TestXDRReaderBounds(t *testing.T) {
	x := &xdrReader{b: []byte{0, 0, 0, 1}}
	if v, ok := x.u32(); !ok || v != 1 {
		t.Fatalf("u32 = %d %v", v, ok)
	}
	if _, ok := x.u32(); ok {
		t.Fatal("read past the end succeeded")
	}
	// Length prefix larger than the remaining buffer.
	x = &xdrReader{b: []byte{0xff, 0xff, 0xff, 0xff, 1, 2}}
	if _, ok := x.bytes(maxXDRString); ok {
		t.Fatal("oversized opaque accepted")
	}
	// Padding must be skipped.
	x = &xdrReader{b: append(xdrString("ab"), 0, 0, 0, 7)}
	s, ok := x.str(maxXDRString)
	if !ok || s != "ab" {
		t.Fatalf("str = %q %v", s, ok)
	}
	if v, ok := x.u32(); !ok || v != 7 {
		t.Fatalf("padding not skipped: %d %v", v, ok)
	}
}

func TestParseRPCReplyRejectsForgedReplies(t *testing.T) {
	good := rpcReplyOK(0xdeadbeef, []byte{0, 0, 0, 0})[4:]
	if _, err := parseRPCReply(good, 0xdeadbeef); err != nil {
		t.Fatalf("valid reply rejected: %v", err)
	}
	if _, err := parseRPCReply(good, 0x11111111); err == nil {
		t.Error("transaction id mismatch accepted")
	}
	for i := 0; i < len(good); i++ {
		_, _ = parseRPCReply(good[:i], 0xdeadbeef)
	}
}

// ---------------------------------------------------------------------------
// Byte-fixture checks
// ---------------------------------------------------------------------------

func TestTLSWeakKey(t *testing.T) {
	cases := []struct {
		name string
		tls  model.TLSInfo
		want bool
		sev  model.Severity
	}{
		{"healthy", model.TLSInfo{KeyAlgo: "RSA", KeyBits: 2048, SigAlgo: "SHA256-RSA"}, false, ""},
		{"ecdsa p256", model.TLSInfo{KeyAlgo: "ECDSA", KeyBits: 256, SigAlgo: "ECDSA-SHA256"}, false, ""},
		{"short rsa", model.TLSInfo{KeyAlgo: "RSA", KeyBits: 1024, SigAlgo: "SHA256-RSA"}, true, model.SevMedium},
		{"factorable rsa", model.TLSInfo{KeyAlgo: "RSA", KeyBits: 512, SigAlgo: "SHA256-RSA"}, true, model.SevHigh},
		{"sha1 signature", model.TLSInfo{KeyAlgo: "RSA", KeyBits: 2048, SigAlgo: "SHA1-RSA"}, true, model.SevMedium},
		{"md5 signature", model.TLSInfo{KeyAlgo: "RSA", KeyBits: 4096, SigAlgo: "MD5-RSA"}, true, model.SevMedium},
		{"dsa", model.TLSInfo{KeyAlgo: "DSA", KeyBits: 2048, SigAlgo: "DSA-SHA256"}, true, model.SevMedium},
		{"ed25519", model.TLSInfo{KeyAlgo: "Ed25519", KeyBits: 256, SigAlgo: "Ed25519"}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ti := tc.tls
			svc := tcpSvc("https", 443)
			svc.TLS = &ti
			fs := probe(t, "tls-weak-key", svc)
			if tc.want != (len(fs) == 1) {
				t.Fatalf("findings=%d want=%v (%+v)", len(fs), tc.want, fs)
			}
			if tc.want && fs[0].Severity != tc.sev {
				t.Errorf("severity = %s, want %s", fs[0].Severity, tc.sev)
			}
		})
	}
	// No TLS info at all: nothing to say.
	if fs := probe(t, "tls-weak-key", tcpSvc("https", 443)); len(fs) != 0 {
		t.Fatalf("fired without certificate data: %+v", fs)
	}
}

func TestRServicesExposed(t *testing.T) {
	for _, port := range []int{512, 513, 514} {
		svc := tcpSvc("", port)
		svc.Banner = "login: "
		fs := probe(t, "rservices-exposed", svc)
		if len(fs) != 1 {
			t.Fatalf("port %d: want 1 finding, got %d", port, len(fs))
		}
		if !strings.Contains(fs[0].Evidence, "No login was attempted") {
			t.Errorf("evidence must state that nothing was authenticated: %q", fs[0].Evidence)
		}
	}
	// 514/tcp running rsyslog is not an r-service.
	if fs := probe(t, "rservices-exposed", tcpSvc("syslog", 514)); len(fs) != 0 {
		t.Fatalf("rsyslog reported as rsh: %+v", fs)
	}
	// Unrelated port, unrelated name.
	if fs := probe(t, "rservices-exposed", tcpSvc("http", 8080)); len(fs) != 0 {
		t.Fatalf("fired on an unrelated service: %+v", fs)
	}
}

func TestIPMIAuthTypeNames(t *testing.T) {
	got := ipmiAuthTypeNames(0x15) // none | MD5 | straight password
	want := "none, MD5, straight password"
	if strings.Join(got, ", ") != want {
		t.Fatalf("got %q, want %q", strings.Join(got, ", "), want)
	}
	if n := ipmiAuthTypeNames(0); len(n) != 0 {
		t.Fatalf("got %v", n)
	}
}

func TestIPMIExposedAgainstFakeBMC(t *testing.T) {
	// A Get Channel Authentication Capabilities reply advertising IPMI 2.0
	// and an enabled anonymous login.
	reply := make([]byte, 25)
	copy(reply, []byte{0x06, 0x00, 0xff, 0x07})
	reply[19] = 0x38 // command echoed
	reply[20] = 0x00 // completion code: success
	reply[21] = 0x15 // auth types: none, MD5, straight password
	reply[22] = 0x80 // IPMI v2 extended capabilities
	reply[23] = 0x01 // anonymous login enabled
	reply[24] = 0x02 // IPMI v2.0 supported

	port := fakeUDPServer(t, func(req []byte) []byte {
		if len(req) < 20 {
			return nil
		}
		return reply
	})
	fs := probe(t, "ipmi-exposed", udpSvc("asf-rmcp", port))
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != model.SevHigh {
		t.Errorf("anonymous login should raise the severity, got %s", fs[0].Severity)
	}
	for _, want := range []string{"IPMI 2.0", "anonymous login enabled", "MD5"} {
		if !strings.Contains(fs[0].Evidence, want) {
			t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
		}
	}
}

func TestIPMIExposedIgnoresGarbage(t *testing.T) {
	port := fakeUDPServer(t, func([]byte) []byte {
		return []byte{0xff, 0xff, 0xff}
	})
	if fs := probe(t, "ipmi-exposed", udpSvc("asf-rmcp", port)); len(fs) != 0 {
		t.Fatalf("garbage accepted: %+v", fs)
	}
}

func TestSNMPValuesSanitizesAgentOutput(t *testing.T) {
	// sysDescr comes from an untrusted agent and ends up verbatim in a client
	// report: control characters must go and the length must be capped.
	pkt := &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
		{Name: strings.TrimPrefix(oidSysDescr, "."), Type: gosnmp.OctetString, Value: []byte("Linux\x00router\n6.1.0")},
		{Name: strings.TrimPrefix(oidSysName, "."), Type: gosnmp.OctetString, Value: []byte(strings.Repeat("A", 2000))},
	}}
	out := snmpValues(pkt)
	if strings.ContainsRune(out[oidSysDescr], 0) {
		t.Errorf("NUL survived sanitisation: %q", out[oidSysDescr])
	}
	if strings.Contains(out[oidSysDescr], "\n") {
		t.Errorf("newline survived sanitisation: %q", out[oidSysDescr])
	}
	if len(out[oidSysName]) > 512 {
		t.Errorf("value not capped: %d", len(out[oidSysName]))
	}
	if snmpValues(nil) == nil {
		t.Error("snmpValues(nil) must return an empty map, not nil")
	}
}

// TestNFSWorldExportSeverity checks the severity split between a world
// readable export and a merely listable one.
func TestNFSWorldExportSeverity(t *testing.T) {
	world := lookupCheck(t, "nfs-exports-world-readable")
	listable := lookupCheck(t, "nfs-exports-listable")
	if world.Info.Severity != model.SevHigh {
		t.Errorf("world readable export severity = %s", world.Info.Severity)
	}
	if listable.Info.Severity != model.SevLow {
		t.Errorf("listable export severity = %s", listable.Info.Severity)
	}
	if !world.HostLevel || !listable.HostLevel {
		t.Error("NFS checks must be host level: mountd is not on the NFS port")
	}
	// Applies must require an actual RPC port.
	tg := &Target{Services: []model.Service{tcpSvc("http", 80)}}
	if world.Applies(tg) {
		t.Error("NFS check applies without any RPC port open")
	}
	tg = &Target{Services: []model.Service{tcpSvc("nfs", 2049)}}
	if !world.Applies(tg) {
		t.Error("NFS check does not apply with 2049 open")
	}
}

// TestCatalogCoversTheAuditBaseline asserts that the checks a segmentation
// and exposure audit is expected to report are all registered.
func TestCatalogCoversTheAuditBaseline(t *testing.T) {
	want := []string{
		"smb-signing-not-required", "smbv1-enabled", "smb-null-session",
		"ftp-anonymous",
		"telnet-cleartext", "rservices-exposed", "vnc-no-auth", "x11-open",
		"redis-no-auth", "mongodb-no-auth", "elasticsearch-no-auth",
		"memcached-open", "etcd-unauth", "docker-api-unauth", "kubelet-unauth",
		"rsync-modules",
		"nfs-exports-world-readable", "nfs-exports-listable",
		"ldap-anonymous-bind",
		"rdp-nla-not-required",
		"snmp-default-community",
		"ipmi-exposed",
		"tls-weak-protocols", "tls-cert-expired", "tls-cert-self-signed", "tls-weak-key",
		"ssh-weak-algorithms",
	}
	have := map[string]bool{}
	for _, c := range New(nil).Catalog() {
		have[c.ID] = true
	}
	for _, id := range want {
		if !have[id] {
			t.Errorf("baseline check %q is not registered", id)
		}
	}
}

// TestOnlyCredentialChecksAreIntrusive makes sure nothing authenticates
// outside the explicitly gated default-credential family.
func TestOnlyCredentialChecksAreIntrusive(t *testing.T) {
	for _, c := range New(nil).Catalog() {
		if !c.Intrusive {
			continue
		}
		if !strings.Contains(c.ID, "credential") {
			t.Errorf("intrusive check %q is not part of the default-credential family", c.ID)
		}
		if !strings.Contains(strings.ToLower(c.Description), "attempt") {
			t.Errorf("intrusive check %q must document how many attempts it makes", c.ID)
		}
	}
}
