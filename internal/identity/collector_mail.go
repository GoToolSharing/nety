package identity

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vaadata/nety/internal/identity/ntlm"
	"github.com/vaadata/nety/internal/model"
)

type mailProto int

const (
	mailSMTP mailProto = iota
	mailIMAP
	mailPOP3
)

func (m mailProto) String() string {
	switch m {
	case mailSMTP:
		return "smtp"
	case mailIMAP:
		return "imap"
	default:
		return "pop3"
	}
}

// lineConn is a deadline-refreshing line protocol helper.
type lineConn struct {
	conn    net.Conn
	r       *bufio.Reader
	timeout time.Duration
}

func newLineConn(c net.Conn, timeout time.Duration) *lineConn {
	return &lineConn{conn: c, r: bufio.NewReaderSize(io.LimitReader(c, 1<<20), 4096), timeout: timeout}
}

func (l *lineConn) upgradeTLS(ctx context.Context) error {
	tc := tls.Client(l.conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // fingerprinting only
	_ = tc.SetDeadline(time.Now().Add(l.timeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	l.conn = tc
	l.r = bufio.NewReaderSize(io.LimitReader(tc, 1<<20), 4096)
	return nil
}

func (l *lineConn) send(s string) error {
	_ = l.conn.SetWriteDeadline(time.Now().Add(l.timeout))
	_, err := io.WriteString(l.conn, s+"\r\n")
	return err
}

// line reads one line (max 8 KiB).
func (l *lineConn) line() (string, error) {
	_ = l.conn.SetReadDeadline(time.Now().Add(l.timeout))
	var sb strings.Builder
	for {
		frag, isPrefix, err := l.r.ReadLine()
		if err != nil {
			return "", err
		}
		if sb.Len()+len(frag) > 8192 {
			return "", errors.New("line too long")
		}
		sb.Write(frag)
		if !isPrefix {
			return sb.String(), nil
		}
	}
}

// smtpReply reads a (multi-line) SMTP reply and returns code and lines.
func (l *lineConn) smtpReply() (int, []string, error) {
	var lines []string
	for i := 0; i < 128; i++ {
		s, err := l.line()
		if err != nil {
			return 0, lines, err
		}
		if len(s) < 3 {
			return 0, lines, fmt.Errorf("smtp: short reply %q", s)
		}
		code, err := strconv.Atoi(s[:3])
		if err != nil {
			return 0, lines, fmt.Errorf("smtp: bad reply %q", s)
		}
		lines = append(lines, strings.TrimSpace(s[min(4, len(s)):]))
		if len(s) == 3 || s[3] != '-' {
			return code, lines, nil
		}
	}
	return 0, lines, errors.New("smtp: reply too long")
}

func decodeB64Challenge(s string) (*ntlm.Challenge, error) {
	s = strings.TrimSpace(s)
	if len(s) > 64<<10 {
		return nil, errors.New("challenge too large")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return ntlm.FindChallenge(raw)
}

func (c *collector) probeMail(ctx context.Context, sink *evidenceSink, ip string, s model.Service, proto mailProto) error {
	pctx, cancel := withTimeout(ctx, 3*c.ioTimeout)
	defer cancel()
	d := net.Dialer{Timeout: c.ioTimeout}
	raw, err := d.DialContext(pctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(s.Port)))
	if err != nil {
		return err
	}
	lc := newLineConn(raw, c.ioTimeout)
	stop := context.AfterFunc(pctx, func() { _ = raw.Close() })
	defer stop()
	defer func() { _ = lc.conn.Close() }()
	if isTLSService(s, 465, 993, 995) {
		if err := lc.upgradeTLS(pctx); err != nil {
			return err
		}
	}
	var ch *ntlm.Challenge
	switch proto {
	case mailSMTP:
		ch, err = smtpNTLM(pctx, lc)
	case mailIMAP:
		ch, err = imapNTLM(pctx, lc)
	default:
		ch, err = pop3NTLM(lc)
	}
	if err != nil {
		return err
	}
	ntlmEvidence(sink, ch, proto.String()+"-ntlm/"+strconv.Itoa(s.Port), nil)
	return nil
}

func smtpNTLM(ctx context.Context, lc *lineConn) (*ntlm.Challenge, error) {
	code, _, err := lc.smtpReply()
	if err != nil {
		return nil, err
	}
	if code != 220 {
		return nil, fmt.Errorf("smtp: banner code %d", code)
	}
	ehlo := func() (ntlmAuth, starttls bool, err error) {
		if err := lc.send("EHLO nety.local"); err != nil {
			return false, false, err
		}
		code, lines, err := lc.smtpReply()
		if err != nil {
			return false, false, err
		}
		if code != 250 {
			return false, false, fmt.Errorf("smtp: EHLO code %d", code)
		}
		for _, l := range lines {
			u := strings.ToUpper(l)
			if strings.HasPrefix(u, "AUTH") && strings.Contains(u, "NTLM") {
				ntlmAuth = true
			}
			if u == "STARTTLS" {
				starttls = true
			}
		}
		return ntlmAuth, starttls, nil
	}
	hasNTLM, starttls, err := ehlo()
	if err != nil {
		return nil, err
	}
	if !hasNTLM && starttls {
		if err := lc.send("STARTTLS"); err != nil {
			return nil, err
		}
		if code, _, err := lc.smtpReply(); err != nil || code != 220 {
			return nil, fmt.Errorf("smtp: STARTTLS refused (%v)", err)
		}
		if err := lc.upgradeTLS(ctx); err != nil {
			return nil, err
		}
		if hasNTLM, _, err = ehlo(); err != nil {
			return nil, err
		}
	}
	if !hasNTLM {
		_ = lc.send("QUIT")
		return nil, errors.New("smtp: AUTH NTLM not offered")
	}
	if err := lc.send("AUTH NTLM " + base64.StdEncoding.EncodeToString(ntlm.NegotiateMessage())); err != nil {
		return nil, err
	}
	code, lines, err := lc.smtpReply()
	if err != nil {
		return nil, err
	}
	if code == 334 && len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		// server wants the initial response on a separate line
		if err := lc.send(base64.StdEncoding.EncodeToString(ntlm.NegotiateMessage())); err != nil {
			return nil, err
		}
		code, lines, err = lc.smtpReply()
		if err != nil {
			return nil, err
		}
	}
	if code != 334 || len(lines) == 0 {
		return nil, fmt.Errorf("smtp: AUTH NTLM code %d", code)
	}
	ch, err := decodeB64Challenge(lines[0])
	_ = lc.send("*")
	_, _, _ = lc.smtpReply()
	_ = lc.send("QUIT")
	return ch, err
}

func imapNTLM(ctx context.Context, lc *lineConn) (*ntlm.Challenge, error) {
	greet, err := lc.line()
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(greet, "* OK") && !strings.HasPrefix(greet, "* PREAUTH") {
		return nil, fmt.Errorf("imap: bad greeting %q", truncateStr(greet, 64))
	}
	caps := func(tag string) (string, error) {
		if err := lc.send(tag + " CAPABILITY"); err != nil {
			return "", err
		}
		var capLine string
		for i := 0; i < 64; i++ {
			l, err := lc.line()
			if err != nil {
				return "", err
			}
			if strings.HasPrefix(strings.ToUpper(l), "* CAPABILITY") {
				capLine = strings.ToUpper(l)
			}
			if strings.HasPrefix(l, tag+" ") {
				return capLine, nil
			}
		}
		return "", errors.New("imap: no tagged reply")
	}
	cl, err := caps("a1")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(cl, "AUTH=NTLM") && strings.Contains(cl, "STARTTLS") {
		if err := lc.send("a2 STARTTLS"); err != nil {
			return nil, err
		}
		l, err := lc.line()
		if err != nil || !strings.HasPrefix(strings.ToUpper(l), "A2 OK") {
			return nil, fmt.Errorf("imap: STARTTLS refused")
		}
		if err := lc.upgradeTLS(ctx); err != nil {
			return nil, err
		}
		if cl, err = caps("a3"); err != nil {
			return nil, err
		}
	}
	if !strings.Contains(cl, "AUTH=NTLM") {
		_ = lc.send("a9 LOGOUT")
		return nil, errors.New("imap: AUTH=NTLM not offered")
	}
	if err := lc.send("a4 AUTHENTICATE NTLM"); err != nil {
		return nil, err
	}
	l, err := lc.line()
	if err != nil || !strings.HasPrefix(l, "+") {
		return nil, fmt.Errorf("imap: AUTHENTICATE refused")
	}
	if err := lc.send(base64.StdEncoding.EncodeToString(ntlm.NegotiateMessage())); err != nil {
		return nil, err
	}
	l, err = lc.line()
	if err != nil || !strings.HasPrefix(l, "+") {
		return nil, fmt.Errorf("imap: no challenge")
	}
	ch, err := decodeB64Challenge(strings.TrimPrefix(l, "+"))
	_ = lc.send("*")
	_, _ = lc.line()
	_ = lc.send("a5 LOGOUT")
	return ch, err
}

func pop3NTLM(lc *lineConn) (*ntlm.Challenge, error) {
	greet, err := lc.line()
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(greet, "+OK") {
		return nil, fmt.Errorf("pop3: bad greeting")
	}
	if err := lc.send("AUTH NTLM"); err != nil {
		return nil, err
	}
	l, err := lc.line()
	if err != nil || !strings.HasPrefix(l, "+") {
		return nil, fmt.Errorf("pop3: AUTH NTLM refused")
	}
	if err := lc.send(base64.StdEncoding.EncodeToString(ntlm.NegotiateMessage())); err != nil {
		return nil, err
	}
	l, err = lc.line()
	if err != nil || !strings.HasPrefix(l, "+") {
		return nil, fmt.Errorf("pop3: no challenge")
	}
	ch, err := decodeB64Challenge(strings.TrimPrefix(l, "+"))
	_ = lc.send("*")
	_, _ = lc.line()
	_ = lc.send("QUIT")
	return ch, err
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
