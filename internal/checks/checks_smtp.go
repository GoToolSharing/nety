package checks

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("smtp-open-relay", "SMTP server relays mail for an unauthorised client", model.SevMedium,
			[]string{"smtp", "smtps", "submission"},
			"The mail server accepted an envelope from an external sender to an external recipient without authenticating the client. An open relay is used to send phishing that appears to come from inside the organisation, which defeats the recipient's trust in internal mail and in SPF, and it puts the organisation's addresses on public block lists. Internally it is worse than it looks: a relay on a user VLAN lets anyone send mail as any internal address, which is the first step of most credential phishing that actually works."),
		Remediation: "Restrict relaying to authenticated sessions and to the networks that genuinely need it (mynetworks / smtpd_relay_restrictions on Postfix, the receive connector permission groups on Exchange). Mail for domains the server is not responsible for must be refused at RCPT TO.",
		References: []string{
			"https://datatracker.ietf.org/doc/html/rfc5321#section-7.2",
			"https://cwe.mitre.org/data/definitions/269.html",
		},
		Applies: smtpApplies,
		Run:     runSMTPOpenRelay,
	})
	register(&Check{
		Info: checkInfo("smtp-vrfy-expn", "SMTP server confirms whether an account exists (VRFY / EXPN)", model.SevMedium,
			[]string{"smtp", "smtps", "submission"},
			"The mail server answers VRFY or EXPN, telling an unauthenticated client whether a mailbox exists and, for EXPN, who is on a distribution list. On a Windows estate the mailbox name is usually the account name, so this turns into a user list for the domain: the raw material for password spraying, and an easy way to find the service accounts and the leavers nobody disabled."),
		Remediation: "Disable the commands (disable_vrfy_command=yes on Postfix, 'noexpn'/'novrfy' on Sendmail, and the equivalent on the appliance) and make sure the server answers the same way for a mailbox that exists and one that does not.",
		References: []string{
			"https://datatracker.ietf.org/doc/html/rfc5321#section-3.5",
			"https://attack.mitre.org/techniques/T1087/003/",
		},
		Applies: smtpApplies,
		Run:     runSMTPVrfyExpn,
	})
}

func smtpApplies(t *Target) bool {
	return svcIs(t.Service, model.TCP, []string{"smtp", "smtps", "submission", "ssmtp"}, 25, 465, 587, 2525)
}

// smtpSession is a line oriented SMTP client that only ever issues the commands below.
// DATA is never sent by any check here, which is what guarantees no mail can leave the
// server as a result of a scan.
type smtpSession struct {
	c       net.Conn
	r       *bufio.Reader
	timeout time.Duration
	ehlo    []string
	greet   string
}

const smtpMaxLine = 2000

// smtpDial opens the session and reads the greeting. Port 465 is implicit TLS; STARTTLS
// is not negotiated because none of these checks sends anything worth protecting.
func smtpDial(ctx context.Context, t *Target) (*smtpSession, error) {
	raw, err := t.Dial(ctx)
	if err != nil {
		return nil, err
	}
	var c net.Conn = raw
	if isTLS(t.Service) || t.Service.Port == 465 || strings.EqualFold(t.Service.Name, "smtps") {
		tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // scanner
		_ = tc.SetDeadline(time.Now().Add(t.Timeout))
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		c = tc
	}
	s := &smtpSession{c: c, r: bufio.NewReaderSize(c, 4096), timeout: t.Timeout}
	code, line, err := s.readReply()
	if err != nil {
		s.close()
		return nil, err
	}
	if code != 220 {
		s.close()
		return nil, fmt.Errorf("smtp: greeting %d", code)
	}
	s.greet = line
	return s, nil
}

func (s *smtpSession) close() {
	// QUIT is the polite way out and leaves the server's log tidy.
	_, _, _ = s.cmd("QUIT")
	_ = s.c.Close()
}

// readReply reads one complete (possibly multi-line) SMTP reply.
func (s *smtpSession) readReply() (int, string, error) {
	_ = s.c.SetDeadline(time.Now().Add(s.timeout))
	var (
		code  int
		lines []string
	)
	for i := 0; i < 64; i++ {
		line, err := s.r.ReadString('\n')
		if err != nil && line == "" {
			return 0, "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) > smtpMaxLine {
			line = line[:smtpMaxLine]
		}
		lines = append(lines, line)
		if len(line) < 3 {
			return 0, strings.Join(lines, " / "), fmt.Errorf("smtp: short reply %q", line)
		}
		n, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, strings.Join(lines, " / "), fmt.Errorf("smtp: non-numeric reply %q", printable([]byte(line), 80))
		}
		code = n
		if len(line) == 3 || line[3] != '-' {
			break
		}
	}
	return code, strings.Join(lines, " / "), nil
}

func (s *smtpSession) cmd(format string, args ...any) (int, string, error) {
	_ = s.c.SetDeadline(time.Now().Add(s.timeout))
	if _, err := fmt.Fprintf(s.c, format+"\r\n", args...); err != nil {
		return 0, "", err
	}
	return s.readReply()
}

// hello sends EHLO, falling back to HELO on servers that do not speak ESMTP.
func (s *smtpSession) hello(name string) error {
	code, line, err := s.cmd("EHLO %s", name)
	if err != nil {
		return err
	}
	if code != 250 {
		if code, line, err = s.cmd("HELO %s", name); err != nil {
			return err
		}
		if code != 250 {
			return fmt.Errorf("smtp: HELO refused (%d)", code)
		}
	}
	s.ehlo = strings.Split(line, " / ")
	return nil
}

// smtpHeloName is the name NETY announces itself with. It is in a reserved domain so it
// can never be confused with a real host.
const smtpHeloName = "nety-scanner.invalid"

// Reserved domains (RFC 2606): no mail can reach them and no real recipient can be
// affected by the envelope below.
const (
	smtpRelaySender    = "nety-relay-test@example.com"
	smtpRelayRecipient = "nety-relay-test@example.net"
)

// runSMTPOpenRelay offers an envelope from an external sender to an external recipient
// and reads the answer to RCPT TO. The session is then reset with RSET and closed with
// QUIT: DATA is never sent, so the server is never given a message and nothing can be
// delivered.
func runSMTPOpenRelay(ctx context.Context, t *Target) []model.Finding {
	s, err := smtpDial(ctx, t)
	if err != nil {
		return nil
	}
	defer s.close()
	if err := s.hello(smtpHeloName); err != nil {
		return nil
	}
	code, mailLine, err := s.cmd("MAIL FROM:<%s>", smtpRelaySender)
	if err != nil {
		return nil
	}
	if code != 250 {
		t.Log.Debug("smtp: sender refused", "code", code)
		return nil
	}
	rcptCode, rcptLine, err := s.cmd("RCPT TO:<%s>", smtpRelayRecipient)
	if err != nil {
		return nil
	}
	// Whatever the answer, put the session back to a clean state before leaving. RSET
	// discards the envelope the server has been holding.
	_, _, _ = s.cmd("RSET")
	if rcptCode != 250 && rcptCode != 251 {
		t.Log.Debug("smtp: relay refused", "code", rcptCode)
		return nil
	}
	ev := fmt.Sprintf("Relay envelope from an external sender to an external recipient was accepted without authentication:\n"+
		"  greeting   %s\n"+
		"  EHLO %s\n"+
		"  MAIL FROM:<%s>  -> %s\n"+
		"  RCPT TO:<%s>    -> %s\n"+
		"  RSET sent, DATA never sent: no message was submitted and nothing was delivered.\n"+
		"Both domains are reserved by RFC 2606 and cannot receive mail.",
		printable([]byte(s.greet), 200), smtpHeloName,
		smtpRelaySender, printable([]byte(mailLine), 200),
		smtpRelayRecipient, printable([]byte(rcptLine), 200))
	return []model.Finding{t.Finding(ev)}
}

// smtpVrfyProbes are the names asked about. "root" and "postmaster" exist on almost every
// mail system, which is the point: the check needs one name that should resolve and one
// that cannot.
var smtpVrfyProbes = []string{"root", "postmaster"}

// runSMTPVrfyExpn establishes that VRFY or EXPN really distinguishes accounts rather than
// answering the same thing to everything. A server that confirms a random name as readily
// as a real one tells an attacker nothing, so it is not reported.
func runSMTPVrfyExpn(ctx context.Context, t *Target) []model.Finding {
	s, err := smtpDial(ctx, t)
	if err != nil {
		return nil
	}
	defer s.close()
	if err := s.hello(smtpHeloName); err != nil {
		return nil
	}
	rnd := make([]byte, 8)
	_, _ = rand.Read(rnd)
	absent := "nety-" + hex.EncodeToString(rnd)

	var lines []string
	for _, verb := range []string{"VRFY", "EXPN"} {
		if ctx.Err() != nil {
			break
		}
		absentCode, _, err := s.cmd("%s %s", verb, absent)
		if err != nil {
			break
		}
		if smtpConfirms(absentCode) {
			// Answers 250 for a name that cannot exist: no information here.
			lines = append(lines, fmt.Sprintf("  %s answers %d for a name that cannot exist: it does not distinguish accounts", verb, absentCode))
			continue
		}
		for _, name := range smtpVrfyProbes {
			code, line, err := s.cmd("%s %s", verb, name)
			if err != nil {
				break
			}
			if !smtpConfirms(code) {
				continue
			}
			lines = append(lines, fmt.Sprintf("  %s %-12s -> %s\n  %s %-12s -> %d (rejected)",
				verb, name, printable([]byte(line), 200), verb, truncate(absent, 12), absentCode))
			break
		}
	}
	// Only the lines that prove a difference are a finding.
	var proof []string
	for _, l := range lines {
		if strings.Contains(l, "rejected") {
			proof = append(proof, l)
		}
	}
	if len(proof) == 0 {
		return nil
	}
	ev := "The server distinguishes an existing mailbox from one that cannot exist:\n" + strings.Join(proof, "\n")
	return []model.Finding{t.Finding(ev)}
}

// smtpConfirms reports whether a reply code confirms the address. 252 is explicitly
// "cannot verify, will try to deliver" and discloses nothing.
func smtpConfirms(code int) bool { return code == 250 || code == 251 }
