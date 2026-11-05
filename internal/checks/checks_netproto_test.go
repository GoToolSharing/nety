package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/identity/ntlm"
	"github.com/GoToolSharing/nety/internal/identity/smb"
	"github.com/GoToolSharing/nety/internal/model"
)

// probeHost is probe with host facts attached, for the checks whose scope comes from what
// the scan already learned about the host.
func probeHost(t *testing.T, id string, host model.Host, svc model.Service, all ...model.Service) []model.Finding {
	t.Helper()
	c := lookupCheck(t, id)
	if len(all) == 0 {
		all = []model.Service{svc}
	}
	if host.IP == "" {
		host.IP = "127.0.0.1"
	}
	tg := &Target{
		Host:     host,
		IP:       host.IP,
		Service:  svc,
		Services: all,
		Opts:     engine.CheckOptions{Timeout: 2 * time.Second},
		Timeout:  2 * time.Second,
		Log:      quietLogger(),
		check:    c,
		creds:    newCredBudget(),
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

// ---------------------------------------------------------------------------
// dns-zone-transfer
// ---------------------------------------------------------------------------

// dnsZoneServer serves AXFR for exactly one zone and refuses everything else.
func dnsZoneServer(t *testing.T, zone string, records []string, refuse bool) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	rrs := make([]dns.RR, 0, len(records))
	for _, s := range records {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("bad test record %q: %v", s, err)
		}
		rrs = append(rrs, rr)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		defer w.Close()
		if refuse || len(req.Question) != 1 || req.Question[0].Qtype != dns.TypeAXFR ||
			!strings.EqualFold(req.Question[0].Name, dns.Fqdn(zone)) {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		tr := new(dns.Transfer)
		ch := make(chan *dns.Envelope, 1)
		ch <- &dns.Envelope{RR: rrs}
		close(ch)
		_ = tr.Out(w, req, ch)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ln.Addr().(*net.TCPAddr).Port
}

func TestDNSZoneTransfer(t *testing.T) {
	zone := []string{
		"corp.test. 3600 IN SOA ns1.corp.test. hostmaster.corp.test. 2026110501 7200 3600 1209600 3600",
		"corp.test. 3600 IN NS ns1.corp.test.",
		"ns1.corp.test. 3600 IN A 10.0.0.53",
		"dc01.corp.test. 3600 IN A 10.0.0.10",
		"backup-old.corp.test. 3600 IN A 10.9.9.9",
		"_ldap._tcp.corp.test. 600 IN SRV 0 100 389 dc01.corp.test.",
		"corp.test. 3600 IN SOA ns1.corp.test. hostmaster.corp.test. 2026110501 7200 3600 1209600 3600",
	}

	t.Run("transfer accepted", func(t *testing.T) {
		port := dnsZoneServer(t, "corp.test", zone, false)
		fs := probeHost(t, "dns-zone-transfer", model.Host{Domain: "corp.test"}, tcpSvc("domain", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevHigh {
			t.Errorf("severity = %s, want high", fs[0].Severity)
		}
		for _, want := range []string{`"corp.test"`, "Records transferred: 7", "SOA:", "ns1.corp.test"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
		// The zone content itself must stay out of the report.
		for _, leak := range []string{"backup-old", "10.9.9.9"} {
			if strings.Contains(fs[0].Evidence, leak) {
				t.Errorf("evidence dumps the zone (%q): %q", leak, fs[0].Evidence)
			}
		}
	})

	t.Run("transfer refused", func(t *testing.T) {
		port := dnsZoneServer(t, "corp.test", zone, true)
		if fs := probeHost(t, "dns-zone-transfer", model.Host{Domain: "corp.test"}, tcpSvc("domain", port)); len(fs) != 0 {
			t.Fatalf("refused transfer reported: %+v", fs)
		}
	})

	t.Run("other zone only", func(t *testing.T) {
		port := dnsZoneServer(t, "other.test", zone, false)
		if fs := probeHost(t, "dns-zone-transfer", model.Host{Domain: "corp.test"}, tcpSvc("domain", port)); len(fs) != 0 {
			t.Fatalf("reported a zone the server does not serve: %+v", fs)
		}
	})
}

func TestDNSZoneCandidatesStayPlausible(t *testing.T) {
	tg := &Target{IP: "10.1.2.3", Host: model.Host{
		Domain:    "corp.test",
		Hostnames: []string{"dc01.ad.corp.test", "bad host name", ""},
	}}
	got := dnsZoneCandidates(tg)
	want := map[string]bool{"corp.test.": true, "ad.corp.test.": true, "2.1.10.in-addr.arpa.": true}
	for _, z := range got {
		if !want[z] {
			t.Errorf("unexpected candidate zone %q", z)
		}
	}
	if len(got) != len(want) {
		t.Errorf("candidates = %v, want %d of %v", got, len(want), want)
	}
}

// ---------------------------------------------------------------------------
// ldap-signing-not-required
// ---------------------------------------------------------------------------

// ldapSigningServer answers the anonymous bind and the rootDSE read, then answers the
// simple bind with simpleCode. ad=false serves a rootDSE that is not Active Directory's.
func ldapSigningServer(t *testing.T, simpleCode int, ad bool) int {
	return fakeServer(t, func(c net.Conn) {
		binds := 0
		for i := 0; i < 8; i++ {
			m, err := readLDAPMessage(c)
			if err != nil {
				return
			}
			switch m.Op {
			case 0x42: // unbind
				return
			case 0x60:
				binds++
				code := 0
				if binds > 1 {
					code = simpleCode
				}
				if _, err := c.Write(ldapBindResponse(m.ID, code)); err != nil {
					return
				}
			case 0x63:
				attrs := map[string][]string{
					"dnsHostName":             {"dc01.corp.local"},
					"supportedLDAPVersion":    {"3"},
					"supportedSASLMechanisms": {"GSSAPI", "GSS-SPNEGO", "EXTERNAL"},
				}
				if ad {
					attrs["defaultNamingContext"] = []string{"DC=corp,DC=local"}
				} else {
					delete(attrs, "supportedSASLMechanisms")
					attrs["namingContexts"] = []string{"dc=example,dc=org"}
				}
				out := append(ldapSearchEntry(m.ID, "", attrs), ldapSearchDone(m.ID, 0)...)
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}
	})
}

func TestLDAPSigningNotRequired(t *testing.T) {
	t.Run("signing not required", func(t *testing.T) {
		port := ldapSigningServer(t, ldapResultInvalidCredentials, true)
		fs := probe(t, "ldap-signing-not-required", tcpSvc("ldap", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevHigh {
			t.Errorf("severity = %s, want high", fs[0].Severity)
		}
		for _, want := range []string{"invalidCredentials", "nety-probe-", "dc01.corp.local"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
		if !strings.Contains(strings.ToLower(fs[0].Description), "smb-signing-not-required") {
			t.Error("the description must pair this finding with the SMB side")
		}
	})

	t.Run("signing required", func(t *testing.T) {
		port := ldapSigningServer(t, ldapResultUnwillingToPerform, true)
		if fs := probe(t, "ldap-signing-not-required", tcpSvc("ldap", port)); len(fs) != 0 {
			t.Fatalf("directory that refuses the bind reported: %+v", fs)
		}
	})

	t.Run("not active directory", func(t *testing.T) {
		port := ldapSigningServer(t, ldapResultInvalidCredentials, false)
		if fs := probe(t, "ldap-signing-not-required", tcpSvc("ldap", port)); len(fs) != 0 {
			t.Fatalf("reported against a directory that is not AD: %+v", fs)
		}
	})

	t.Run("ldaps is out of scope", func(t *testing.T) {
		c := lookupCheck(t, "ldap-signing-not-required")
		tg := &Target{Service: tcpSvc("ldaps", 636)}
		if c.Applies(tg) {
			t.Error("the check must not run on the TLS port: TLS already provides integrity")
		}
	})
}

// ---------------------------------------------------------------------------
// ms-rprn-spooler
// ---------------------------------------------------------------------------

// smbFake is a scripted SMB2 server, just enough of one to take an anonymous session as
// far as a DCE/RPC bind on a named pipe.
type smbFake struct {
	allowSession bool
	allowTree    bool
	allowPipe    bool
	bindAck      bool
}

func smbFakeHeader(cmd uint16, status uint32, msgID uint64, tree uint32, sess uint64) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:], 64)
	binary.LittleEndian.PutUint32(h[8:], status)
	binary.LittleEndian.PutUint16(h[12:], cmd)
	binary.LittleEndian.PutUint16(h[14:], 1)
	binary.LittleEndian.PutUint32(h[16:], 1) // response
	binary.LittleEndian.PutUint64(h[24:], msgID)
	binary.LittleEndian.PutUint32(h[36:], tree)
	binary.LittleEndian.PutUint64(h[40:], sess)
	return h
}

func (f *smbFake) serve(c net.Conn) {
	tr := smb.NewTransport(c, 3*time.Second)
	legs := 0
	for {
		raw, err := tr.Recv()
		if err != nil || !smb.IsSMB2(raw) || len(raw) < 64 {
			return
		}
		cmd := binary.LittleEndian.Uint16(raw[12:])
		id := binary.LittleEndian.Uint64(raw[24:])
		var out []byte
		switch cmd {
		case smb.CmdNegotiate:
			blob := ntlm.SPNEGOInit(nil)
			b := make([]byte, 64)
			binary.LittleEndian.PutUint16(b[0:], 65)
			binary.LittleEndian.PutUint16(b[2:], smb.SigningEnabled)
			binary.LittleEndian.PutUint16(b[4:], smb.Dialect300)
			binary.LittleEndian.PutUint32(b[24:], 0x2f)
			binary.LittleEndian.PutUint32(b[28:], 8388608)
			binary.LittleEndian.PutUint32(b[32:], 8388608)
			binary.LittleEndian.PutUint32(b[36:], 8388608)
			binary.LittleEndian.PutUint16(b[56:], 128)
			binary.LittleEndian.PutUint16(b[58:], uint16(len(blob)))
			b = append(b, blob...)
			out = append(smbFakeHeader(cmd, 0, id, 0, 0), b...)
		case smb.CmdSessionSetup:
			legs++
			if legs == 1 {
				blob := ntlm.SPNEGOResponse(smbFakeChallenge())
				body := make([]byte, 8)
				binary.LittleEndian.PutUint16(body, 9)
				binary.LittleEndian.PutUint16(body[4:], 72)
				binary.LittleEndian.PutUint16(body[6:], uint16(len(blob)))
				out = append(append(smbFakeHeader(cmd, smb.StatusMoreProcessingRequired, id, 0, 0x1122), body...), blob...)
				break
			}
			if !f.allowSession {
				out = append(smbFakeHeader(cmd, smb.StatusAccessDenied, id, 0, 0x1122), 9, 0, 0, 0, 0, 0, 0, 0, 0)
				break
			}
			body := make([]byte, 8)
			binary.LittleEndian.PutUint16(body, 9)
			binary.LittleEndian.PutUint16(body[2:], smb.SessionFlagNull)
			out = append(smbFakeHeader(cmd, 0, id, 0, 0x1122), body...)
		case smb.CmdTreeConnect:
			if !f.allowTree {
				out = append(smbFakeHeader(cmd, smb.StatusAccessDenied, id, 0, 0x1122), 9, 0, 0, 0, 0, 0, 0, 0, 0)
				break
			}
			body := make([]byte, 16)
			binary.LittleEndian.PutUint16(body, 16)
			body[2] = 2
			binary.LittleEndian.PutUint32(body[12:], 0x1f01ff)
			out = append(smbFakeHeader(cmd, 0, id, 7, 0x1122), body...)
		case smb.CmdCreate:
			if !f.allowPipe {
				out = append(smbFakeHeader(cmd, smb.StatusAccessDenied, id, 7, 0x1122), 9, 0, 0, 0, 0, 0, 0, 0, 0)
				break
			}
			body := make([]byte, 88)
			binary.LittleEndian.PutUint16(body, 89)
			for i := 64; i < 80; i++ {
				body[i] = 0xab
			}
			out = append(smbFakeHeader(cmd, 0, id, 7, 0x1122), body...)
		case smb.CmdIoctl:
			data := smbFakeBindAck()
			if !f.bindAck {
				data = smbFakeBindNak()
			}
			body := make([]byte, 48)
			binary.LittleEndian.PutUint16(body, 49)
			binary.LittleEndian.PutUint32(body[32:], 64+48)
			binary.LittleEndian.PutUint32(body[36:], uint32(len(data)))
			out = append(append(smbFakeHeader(cmd, 0, id, 7, 0x1122), body...), data...)
		case smb.CmdClose, smb.CmdTreeDisconnect, smb.CmdLogoff:
			body := make([]byte, 60)
			binary.LittleEndian.PutUint16(body, 60)
			out = append(smbFakeHeader(cmd, 0, id, 7, 0x1122), body...)
		default:
			return
		}
		if err := tr.Send(out); err != nil {
			return
		}
	}
}

func smbFakeChallenge() []byte {
	av := func(id uint16, s string) []byte {
		v := ntlm.EncodeUTF16(s)
		b := make([]byte, 4+len(v))
		binary.LittleEndian.PutUint16(b, id)
		binary.LittleEndian.PutUint16(b[2:], uint16(len(v)))
		copy(b[4:], v)
		return b
	}
	var ti []byte
	ti = append(ti, av(ntlm.AvNbDomainName, "CORP")...)
	ti = append(ti, av(ntlm.AvNbComputerName, "PRINT01")...)
	ti = append(ti, 0, 0, 0, 0)
	b := make([]byte, 56)
	copy(b, ntlm.Signature)
	binary.LittleEndian.PutUint32(b[8:], 2)
	binary.LittleEndian.PutUint32(b[20:], ntlm.FlagUnicode|ntlm.FlagTargetInfo)
	binary.LittleEndian.PutUint16(b[40:], uint16(len(ti)))
	binary.LittleEndian.PutUint16(b[42:], uint16(len(ti)))
	binary.LittleEndian.PutUint32(b[44:], 56)
	return append(b, ti...)
}

// smbFakeBindAck builds the shortest BIND_ACK rpcCheckBindAck accepts.
func smbFakeBindAck() []byte {
	body := make([]byte, 10)
	binary.LittleEndian.PutUint16(body[0:], rpcMaxFrag)
	binary.LittleEndian.PutUint16(body[2:], rpcMaxFrag)
	binary.LittleEndian.PutUint32(body[4:], 0x1234)
	binary.LittleEndian.PutUint16(body[8:], 0) // secondary address length
	for (len(body)+16)%4 != 0 {
		body = append(body, 0)
	}
	body = append(body, 1, 0, 0, 0) // one result
	result := make([]byte, 24)      // result=0 reason=0 transfer syntax
	body = append(body, result...)
	return append(rpcHeader(rpcPtypeBindAck, rpcFlagFirst|rpcFlagLast, 16+len(body), 1), body...)
}

func smbFakeBindNak() []byte {
	body := []byte{0, 0, 0}
	return append(rpcHeader(rpcPtypeBindNak, rpcFlagFirst|rpcFlagLast, 16+len(body), 1), body...)
}

func smbFakeServer(t *testing.T, f *smbFake) int {
	t.Helper()
	return fakeServer(t, f.serve)
}

func TestMSRPRNSpooler(t *testing.T) {
	t.Run("spooler reachable", func(t *testing.T) {
		port := smbFakeServer(t, &smbFake{allowSession: true, allowTree: true, allowPipe: true, bindAck: true})
		fs := probe(t, "ms-rprn-spooler", tcpSvc("microsoft-ds", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevMedium {
			t.Errorf("severity = %s, want medium", fs[0].Severity)
		}
		for _, want := range []string{"spoolss", "12345678-1234-abcd-ef00-0123456789ab", "no printer call"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
	})

	t.Run("pipe refused", func(t *testing.T) {
		port := smbFakeServer(t, &smbFake{allowSession: true, allowTree: true})
		if fs := probe(t, "ms-rprn-spooler", tcpSvc("microsoft-ds", port)); len(fs) != 0 {
			t.Fatalf("reported although the pipe could not be opened: %+v", fs)
		}
	})

	t.Run("bind rejected", func(t *testing.T) {
		port := smbFakeServer(t, &smbFake{allowSession: true, allowTree: true, allowPipe: true})
		if fs := probe(t, "ms-rprn-spooler", tcpSvc("microsoft-ds", port)); len(fs) != 0 {
			t.Fatalf("reported on a rejected bind: %+v", fs)
		}
	})

	t.Run("anonymous session refused", func(t *testing.T) {
		port := smbFakeServer(t, &smbFake{})
		if fs := probe(t, "ms-rprn-spooler", tcpSvc("microsoft-ds", port)); len(fs) != 0 {
			t.Fatalf("reported without a session: %+v", fs)
		}
	})
}

// ---------------------------------------------------------------------------
// cisco-smart-install
// ---------------------------------------------------------------------------

func TestCiscoSmartInstall(t *testing.T) {
	t.Run("client active", func(t *testing.T) {
		port := fakeServer(t, func(c net.Conn) {
			req := make([]byte, len(smiProbe))
			if _, err := io.ReadFull(c, req); err != nil {
				return
			}
			reply := make([]byte, 12)
			binary.BigEndian.PutUint32(reply[0:], 1)
			binary.BigEndian.PutUint32(reply[4:], smiHelloReply)
			_, _ = c.Write(reply)
		})
		fs := probe(t, "cisco-smart-install", tcpSvc("smart-install", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevHigh {
			t.Errorf("severity = %s, want high", fs[0].Severity)
		}
		if !strings.Contains(fs[0].Evidence, "hello reply") {
			t.Errorf("evidence: %q", fs[0].Evidence)
		}
	})

	t.Run("other protocol on 4786", func(t *testing.T) {
		port := fakeServer(t, func(c net.Conn) {
			_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		})
		if fs := probe(t, "cisco-smart-install", tcpSvc("smart-install", port)); len(fs) != 0 {
			t.Fatalf("reported against a server that is not Smart Install: %+v", fs)
		}
	})
}

// ---------------------------------------------------------------------------
// smtp-open-relay / smtp-vrfy-expn
// ---------------------------------------------------------------------------

// smtpServer answers EHLO and dispatches the rest to reply. It fails the test if a check
// ever sends DATA.
func smtpServer(t *testing.T, reply func(cmd string) string) int {
	t.Helper()
	return fakeServer(t, func(c net.Conn) {
		serveLines(c, "220 mail.corp.test ESMTP Postfix\r\n", func(cmd string) (string, bool) {
			up := strings.ToUpper(cmd)
			switch {
			case strings.HasPrefix(up, "EHLO"):
				return "250-mail.corp.test\r\n250-PIPELINING\r\n250 8BITMIME\r\n", false
			case strings.HasPrefix(up, "HELO"):
				return "250 mail.corp.test\r\n", false
			case up == "DATA":
				t.Error("a check sent DATA: no check may ever submit a message")
				return "554 refused\r\n", true
			case up == "RSET":
				return "250 2.0.0 Ok\r\n", false
			case up == "QUIT":
				return "221 2.0.0 Bye\r\n", true
			}
			return reply(cmd), false
		})
	})
}

func TestSMTPOpenRelay(t *testing.T) {
	t.Run("relay accepted", func(t *testing.T) {
		port := smtpServer(t, func(cmd string) string {
			up := strings.ToUpper(cmd)
			if strings.HasPrefix(up, "MAIL FROM") || strings.HasPrefix(up, "RCPT TO") {
				return "250 2.1.5 Ok\r\n"
			}
			return "502 5.5.2 Error\r\n"
		})
		fs := probe(t, "smtp-open-relay", tcpSvc("smtp", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevMedium {
			t.Errorf("severity = %s, want medium", fs[0].Severity)
		}
		for _, want := range []string{"RCPT TO", "RSET sent, DATA never sent", smtpRelayRecipient} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
	})

	t.Run("relay refused", func(t *testing.T) {
		port := smtpServer(t, func(cmd string) string {
			if strings.HasPrefix(strings.ToUpper(cmd), "MAIL FROM") {
				return "250 2.1.0 Ok\r\n"
			}
			return "554 5.7.1 Relay access denied\r\n"
		})
		if fs := probe(t, "smtp-open-relay", tcpSvc("smtp", port)); len(fs) != 0 {
			t.Fatalf("refused relay reported: %+v", fs)
		}
	})
}

func TestSMTPVrfyExpn(t *testing.T) {
	t.Run("vrfy distinguishes accounts", func(t *testing.T) {
		port := smtpServer(t, func(cmd string) string {
			up := strings.ToUpper(cmd)
			switch {
			case strings.HasPrefix(up, "VRFY ROOT"):
				return "250 2.1.5 root <root@corp.test>\r\n"
			case strings.HasPrefix(up, "VRFY") || strings.HasPrefix(up, "EXPN"):
				return "550 5.1.1 User unknown\r\n"
			}
			return "502 5.5.2 Error\r\n"
		})
		fs := probe(t, "smtp-vrfy-expn", tcpSvc("smtp", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		for _, want := range []string{"VRFY root", "rejected"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
	})

	t.Run("server answers the same for everything", func(t *testing.T) {
		port := smtpServer(t, func(cmd string) string {
			up := strings.ToUpper(cmd)
			if strings.HasPrefix(up, "VRFY") || strings.HasPrefix(up, "EXPN") {
				return "252 2.0.0 Cannot VRFY user\r\n"
			}
			return "502 5.5.2 Error\r\n"
		})
		if fs := probe(t, "smtp-vrfy-expn", tcpSvc("smtp", port)); len(fs) != 0 {
			t.Fatalf("252 reported as user enumeration: %+v", fs)
		}
	})

	t.Run("server confirms every name", func(t *testing.T) {
		port := smtpServer(t, func(cmd string) string {
			up := strings.ToUpper(cmd)
			if strings.HasPrefix(up, "VRFY") || strings.HasPrefix(up, "EXPN") {
				return "250 2.1.5 Ok\r\n"
			}
			return "502 5.5.2 Error\r\n"
		})
		if fs := probe(t, "smtp-vrfy-expn", tcpSvc("smtp", port)); len(fs) != 0 {
			t.Fatalf("a server that confirms anything was reported: %+v", fs)
		}
	})
}

// ---------------------------------------------------------------------------
// tftp-anonymous-read
// ---------------------------------------------------------------------------

// tftpServer serves the named files and answers "file not found" otherwise.
func tftpServer(t *testing.T, files map[string]string) int {
	t.Helper()
	return fakeUDPServer(t, func(req []byte) []byte {
		if len(req) < 4 || binary.BigEndian.Uint16(req) != tftpOpRRQ {
			return nil
		}
		parts := strings.Split(string(req[2:]), "\x00")
		if len(parts) < 2 {
			return nil
		}
		body, ok := files[parts[0]]
		if !ok {
			out := []byte{0, tftpOpError, 0, 1}
			out = append(out, "File not found"...)
			return append(out, 0)
		}
		out := []byte{0, tftpOpData, 0, 1}
		return append(out, body...)
	})
}

func TestTFTPAnonymousRead(t *testing.T) {
	t.Run("file served", func(t *testing.T) {
		port := tftpServer(t, map[string]string{
			"startup-config": "!\nversion 15.2\nhostname sw-access-01\nenable secret 5 $1$redacted\n",
		})
		fs := probe(t, "tftp-anonymous-read", udpSvc("tftp", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevMedium {
			t.Errorf("severity = %s, want medium", fs[0].Severity)
		}
		for _, want := range []string{"startup-config", "version 15.2", "not downloaded"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
	})

	t.Run("nothing served", func(t *testing.T) {
		port := tftpServer(t, nil)
		if fs := probe(t, "tftp-anonymous-read", udpSvc("tftp", port)); len(fs) != 0 {
			t.Fatalf("server that refuses every name reported: %+v", fs)
		}
	})
}

func TestTFTPNameListStaysSmall(t *testing.T) {
	if len(tftpWellKnownNames) > 12 {
		t.Fatalf("%d file names probed: the check must stay a spot check, not a brute force", len(tftpWellKnownNames))
	}
}

// --------------------------------------------------------------------------- ntp-monlist
// ---------------------------------------------------------------------------

// ntpMonlistReply builds a mode 7 MON_GETLIST_1 reply listing peers.
func ntpMonlistReply(peers []string) []byte {
	b := make([]byte, 8)
	b[0] = 0x97 // response bit set, version 2, mode 7
	b[2] = 0x03
	b[3] = 0x2a
	binary.BigEndian.PutUint16(b[4:], uint16(len(peers)))
	binary.BigEndian.PutUint16(b[6:], ntpMonItemSize)
	for _, p := range peers {
		item := make([]byte, ntpMonItemSize)
		copy(item[16:20], net.ParseIP(p).To4())
		b = append(b, item...)
	}
	return b
}

func TestNTPMonlist(t *testing.T) {
	t.Run("monlist answered", func(t *testing.T) {
		port := fakeUDPServer(t, func(req []byte) []byte {
			if len(req) < 4 || req[0] != 0x17 || req[3] != 0x2a {
				return nil
			}
			return ntpMonlistReply([]string{"10.0.0.5", "10.0.0.6", "192.168.40.9"})
		})
		fs := probe(t, "ntp-monlist", udpSvc("ntp", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevMedium {
			t.Errorf("severity = %s, want medium", fs[0].Severity)
		}
		for _, want := range []string{"3 entries", "10.0.0.5", "192.168.40.9", "Amplification"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
	})

	t.Run("monlist disabled", func(t *testing.T) {
		port := fakeUDPServer(t, func(req []byte) []byte {
			if len(req) < 4 || req[0] != 0x17 {
				return nil
			}
			// ntpd answers an unimplemented request with error code 3.
			b := make([]byte, 8)
			b[0] = 0x97
			b[2] = 0x03
			b[3] = 0x2a
			b[4] = 0x30
			return b
		})
		if fs := probeTimeout(t, "ntp-monlist", 400*time.Millisecond, udpSvc("ntp", port)); len(fs) != 0 {
			t.Fatalf("refused monlist reported: %+v", fs)
		}
	})

	t.Run("plain ntp server", func(t *testing.T) {
		port := fakeUDPServer(t, func([]byte) []byte { return make([]byte, 48) })
		if fs := probeTimeout(t, "ntp-monlist", 400*time.Millisecond, udpSvc("ntp", port)); len(fs) != 0 {
			t.Fatalf("a plain NTP reply was read as a monlist: %+v", fs)
		}
	})
}

// ---------------------------------------------------------------------------
// snmp-write-community
// ---------------------------------------------------------------------------

func TestSNMPWriteCommunity(t *testing.T) {
	values := map[string]string{
		oidSysDescr: "Cisco IOS Software, C2960 Software",
		oidSysName:  "sw-core-01",
	}

	t.Run("write community answers", func(t *testing.T) {
		port := snmpAgent(t, map[string]bool{"public": true, "write": true}, values)
		fs := probe(t, "snmp-write-community", udpSvc("snmp", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevMedium {
			t.Errorf("severity = %s, want medium", fs[0].Severity)
		}
		for _, want := range []string{`"write"`, "sw-core-01", "No SET was attempted"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
	})

	t.Run("only the read community answers", func(t *testing.T) {
		port := snmpAgent(t, map[string]bool{"public": true}, values)
		if fs := probeTimeout(t, "snmp-write-community", 400*time.Millisecond, udpSvc("snmp", port)); len(fs) != 0 {
			t.Fatalf("reported without a write community: %+v", fs)
		}
	})
}

// TestSNMPWriteListDoesNotRepeatTheDefaultCheck keeps the two SNMP checks from reporting
// the same community string twice in one report.
func TestSNMPWriteListDoesNotRepeatTheDefaultCheck(t *testing.T) {
	if len(snmpWriteCommunities) > 3 {
		t.Fatalf("%d write communities tried; the list must stay a spot check", len(snmpWriteCommunities))
	}
	for _, w := range snmpWriteCommunities {
		for _, d := range snmpDefaultCommunities {
			if w == d.name {
				t.Errorf("community %q is tried by snmp-default-community already", w)
			}
		}
	}
}

// TestNewProbesSendNoWrite walks the request builders that have a destructive counterpart
// and asserts the destructive opcode never appears.
func TestNewProbesSendNoWrite(t *testing.T) {
	if binary.BigEndian.Uint16(ntpMonlistRequest[2:]) != 0x032a {
		t.Fatalf("the NTP probe is not MON_GETLIST_1: %x", ntpMonlistRequest[:4])
	}
	if ntpMonlistRequest[0]&0x80 != 0 {
		t.Error("the NTP probe has the response bit set")
	}
	// TFTP: a read request, never a write request (opcode 2).
	if binary.BigEndian.Uint16([]byte{0, tftpOpRRQ}) != 1 {
		t.Fatal("tftpOpRRQ is not the read opcode")
	}
	if got := fmt.Sprintf("%x", smiProbe[4:8]); got != "00000001" {
		t.Errorf("the Smart Install probe is not the hello message: %s", got)
	}
}
