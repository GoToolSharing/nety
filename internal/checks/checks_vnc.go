package checks

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

var vncWeakAuthCheck = &Check{
	Info: checkInfo("vnc-weak-auth", "VNC uses legacy VNC authentication", model.SevInfo,
		[]string{"vnc"},
		"The VNC server only offers the legacy 'VNC Authentication' scheme: passwords are limited to 8 characters, the DES challenge/response can be cracked offline once captured, and the session itself is not encrypted."),
	Remediation: "Prefer VNC servers supporting encrypted authentication (VeNCrypt/TLS, RA2) or tunnel VNC through SSH/VPN, use strong passwords and restrict access to administration networks.",
	References:  []string{"https://datatracker.ietf.org/doc/html/rfc6143#section-7.2.2"},
	// Emitted by vnc-no-auth (single connection), never scheduled on its own.
	Applies: func(*Target) bool { return false },
	Run:     func(context.Context, *Target) []model.Finding { return nil },
}

func init() {
	register(&Check{
		Info: checkInfo("vnc-no-auth", "VNC server without authentication", model.SevCritical,
			[]string{"vnc"},
			"The VNC server offers the 'None' security type: anyone on the network can view and control the remote desktop without credentials."),
		Remediation: "Configure a VNC password or, better, an authenticated and encrypted security type (VeNCrypt, RA2), and restrict VNC to administration networks or SSH tunnels.",
		References:  []string{"https://datatracker.ietf.org/doc/html/rfc6143#section-7.1.2"},
		Applies: func(t *Target) bool {
			s := t.Service
			if s.Protocol != model.TCP {
				return false
			}
			if strings.Contains(strings.ToLower(s.Name), "vnc") || strings.HasPrefix(s.Banner, "RFB ") {
				return true
			}
			return svcIs(s, model.TCP, nil, 5900, 5901, 5902, 5903)
		},
		Run: runVNC,
	})
	register(vncWeakAuthCheck)
}

var vncSecNames = map[byte]string{
	0: "Invalid", 1: "None", 2: "VNC Authentication", 5: "RA2", 6: "RA2ne", 16: "Tight", 17: "Ultra",
	18: "TLS", 19: "VeNCrypt", 20: "GTK-VNC SASL", 21: "MD5 hash", 22: "Colin Dean xvp", 30: "Apple ARD", 113: "MSLogonII",
}

func vncSecName(b byte) string {
	if n, ok := vncSecNames[b]; ok {
		return n
	}
	return fmt.Sprintf("type %d", b)
}

// vncHandshake reads the server version and security types. It never selects a security
// type.
func vncHandshake(c net.Conn) (version string, types []byte, reason string, err error) {
	ver := make([]byte, 12)
	if _, err = io.ReadFull(c, ver); err != nil {
		return
	}
	if string(ver[:4]) != "RFB " || ver[11] != '\n' {
		return "", nil, "", fmt.Errorf("vnc: not RFB")
	}
	version = strings.TrimSpace(string(ver[4:11]))
	var major, minor int
	if _, e := fmt.Sscanf(version, "%03d.%03d", &major, &minor); e != nil {
		return version, nil, "", fmt.Errorf("vnc: bad version")
	}
	reply := "RFB 003.008\n"
	legacy := major == 3 && minor < 7
	if legacy {
		reply = "RFB 003.003\n"
	} else if major == 3 && minor == 7 {
		reply = "RFB 003.007\n"
	}
	if _, err = c.Write([]byte(reply)); err != nil {
		return
	}
	if legacy {
		var b [4]byte
		if _, err = io.ReadFull(c, b[:]); err != nil {
			return
		}
		st, _ := beU32(b[:], 0)
		if st == 0 {
			reason = vncReadReason(c)
			return
		}
		if st > 255 {
			return version, nil, "", fmt.Errorf("vnc: bad security type")
		}
		return version, []byte{byte(st)}, "", nil
	}
	var n [1]byte
	if _, err = io.ReadFull(c, n[:]); err != nil {
		return
	}
	if n[0] == 0 {
		reason = vncReadReason(c)
		return
	}
	types = make([]byte, n[0])
	_, err = io.ReadFull(c, types)
	return
}

func vncReadReason(c net.Conn) string {
	var b [4]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return ""
	}
	l, _ := beU32(b[:], 0)
	if l > 1024 {
		l = 1024
	}
	msg := make([]byte, l)
	n, _ := io.ReadFull(c, msg)
	return printable(msg[:n], 200)
}

func runVNC(ctx context.Context, t *Target) []model.Finding {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer c.Close()
	ver, types, reason, err := vncHandshake(c)
	if err != nil || len(types) == 0 {
		if reason != "" {
			t.Log.Debug("vnc refused", "reason", reason)
		}
		return nil
	}
	names := make([]string, 0, len(types))
	hasNone, onlyVNC := false, true
	for _, ty := range types {
		names = append(names, vncSecName(ty))
		if ty == 1 {
			hasNone = true
		}
		if ty != 2 {
			onlyVNC = false
		}
	}
	ev := fmt.Sprintf("RFB %s, security types offered: %s", ver, strings.Join(names, ", "))
	if hasNone {
		return []model.Finding{t.Finding(ev)}
	}
	if onlyVNC {
		f := t.Finding(ev)
		c := vncWeakAuthCheck
		f.CheckID, f.Title, f.Severity, f.Description, f.Remediation = c.Info.ID, c.Info.Title, c.Info.Severity, c.Info.Description, c.Remediation
		f.References = append([]string(nil), c.References...)
		return []model.Finding{f}
	}
	return nil
}
