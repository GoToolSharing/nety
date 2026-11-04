package checks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

// ---------------------------------------------------------------------------
// ftp-anonymous
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("ftp-anonymous", "FTP anonymous login allowed", model.SevMedium,
			[]string{"ftp", "ftps"},
			"The FTP server accepts the 'anonymous' account. Files exposed to anonymous users can be downloaded by anyone on the network, and anonymous write access, if granted, allows planting files."),
		Remediation: "Disable anonymous FTP (e.g. anonymous_enable=NO for vsftpd) unless it is a deliberate public repository, and review the files and write permissions exposed to it. Prefer SFTP.",
		References:  []string{"https://cwe.mitre.org/data/definitions/284.html"},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"ftp", "ftps", "ssl/ftp"}, 21, 990)
		},
		Run: runFTPAnonymous,
	})
}

// ftpReadReply reads a (possibly multi-line) FTP reply.
func ftpReadReply(r *bufio.Reader) (int, string, error) {
	var lines []string
	code := 0
	for i := 0; i < 200; i++ {
		l, err := r.ReadString('\n')
		l = strings.TrimRight(l, "\r\n")
		if err != nil && l == "" {
			return 0, strings.Join(lines, "\n"), err
		}
		lines = append(lines, l)
		if len(l) >= 3 {
			if c, e := strconv.Atoi(l[:3]); e == nil {
				if code == 0 {
					code = c
				}
				if c == code && (len(l) == 3 || l[3] == ' ') {
					return code, strings.Join(lines, "\n"), nil
				}
			}
		}
		if err != nil {
			break
		}
	}
	if code == 0 {
		return 0, strings.Join(lines, "\n"), fmt.Errorf("ftp: malformed reply")
	}
	return code, strings.Join(lines, "\n"), nil
}

func ftpCmd(c net.Conn, r *bufio.Reader, t *Target, cmd string) (int, string, error) {
	refreshDeadline(c, t.Timeout)
	if _, err := io.WriteString(c, cmd+"\r\n"); err != nil {
		return 0, "", err
	}
	return ftpReadReply(r)
}

func runFTPAnonymous(ctx context.Context, t *Target) []model.Finding {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer c.Close()
	if isTLS(t.Service) || t.Service.Port == 990 {
		c = svcTLSClient(c)
	}
	r := bufio.NewReader(io.LimitReader(c, 64<<10))
	code, banner, err := ftpReadReply(r)
	if err != nil || code != 220 {
		return nil
	}
	code, userReply, err := ftpCmd(c, r, t, "USER anonymous")
	if err != nil {
		return nil
	}
	var passReply string
	switch code {
	case 230:
		passReply = userReply
	case 331:
		code, passReply, err = ftpCmd(c, r, t, "PASS nety@example.com")
		if err != nil || code != 230 {
			return nil
		}
	default:
		return nil
	}
	ev := fmt.Sprintf("Banner: %s\nUSER anonymous -> %s\nPASS -> %s",
		printable([]byte(banner), 300), printable([]byte(firstLine(userReply)), 200), printable([]byte(passReply), 300))
	if pc, pwd, err := ftpCmd(c, r, t, "PWD"); err == nil && pc == 257 {
		ev += "\nPWD -> " + printable([]byte(pwd), 200)
	}
	_, _, _ = ftpCmd(c, r, t, "QUIT")
	return []model.Finding{t.Finding(ev)}
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// ---------------------------------------------------------------------------
// telnet-cleartext
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("telnet-cleartext", "Telnet service (cleartext remote administration)", model.SevMedium,
			[]string{"telnet"},
			"A Telnet service is exposed. Telnet transmits credentials and session content in cleartext, allowing any attacker able to sniff or intercept traffic (ARP spoofing, compromised switch...) to capture administrator passwords."),
		Remediation: "Disable Telnet and use SSH instead; if Telnet is unavoidable, restrict it to a dedicated management network.",
		References:  []string{"https://cwe.mitre.org/data/definitions/319.html"},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"telnet"}, 23, 2323)
		},
		Run: runTelnet,
	})
}

const (
	telnetIAC  = 255
	telnetDONT = 254
	telnetDO   = 253
	telnetWONT = 252
	telnetWILL = 251
	telnetSB   = 250
	telnetSE   = 240
)

// telnetStrip removes IAC sequences from data and returns the printable
// payload plus the negative replies to send (WONT for DO, DONT for WILL).
func telnetStrip(data []byte) (text []byte, reply []byte, sawIAC bool) {
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b != telnetIAC {
			text = append(text, b)
			continue
		}
		sawIAC = true
		if i+1 >= len(data) {
			break
		}
		cmd := data[i+1]
		switch cmd {
		case telnetIAC:
			text = append(text, telnetIAC)
			i++
		case telnetDO, telnetDONT, telnetWILL, telnetWONT:
			if i+2 >= len(data) {
				return text, reply, sawIAC
			}
			opt := data[i+2]
			if cmd == telnetDO {
				reply = append(reply, telnetIAC, telnetWONT, opt)
			} else if cmd == telnetWILL {
				reply = append(reply, telnetIAC, telnetDONT, opt)
			}
			i += 2
		case telnetSB:
			j := i + 2
			for j+1 < len(data) && !(data[j] == telnetIAC && data[j+1] == telnetSE) {
				j++
			}
			i = j + 1
		default:
			i++
		}
	}
	return text, reply, sawIAC
}

func runTelnet(ctx context.Context, t *Target) []model.Finding {
	named := strings.EqualFold(t.Service.Name, "telnet")
	var banner []byte
	sawIAC := false
	if c, err := t.Dial(ctx); err == nil {
		defer c.Close()
		buf := make([]byte, 4096)
		for round := 0; round < 4 && len(banner) < 2048; round++ {
			n, err := readWithDeadline(c, minDur(t.Timeout, 3e9), buf)
			if n > 0 {
				txt, reply, iac := telnetStrip(buf[:n])
				sawIAC = sawIAC || iac
				banner = append(banner, txt...)
				if len(reply) > 0 {
					_ = c.SetWriteDeadline(timeNowPlus(t.Timeout))
					_, _ = c.Write(reply)
				}
			}
			if err != nil {
				break
			}
		}
	}
	text := strings.TrimSpace(printable(banner, 300))
	if !named && !sawIAC {
		// Unidentified service on a telnet port without telnet negotiation:
		// only report when it presents a login prompt.
		low := strings.ToLower(text)
		if !strings.Contains(low, "login") && !strings.Contains(low, "username") && !strings.Contains(low, "password") {
			return nil
		}
	}
	ev := "Telnet service reachable (cleartext protocol)"
	if text != "" {
		ev += "\nBanner: " + text
	}
	return []model.Finding{t.Finding(ev)}
}
