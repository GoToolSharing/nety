package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/vaadata/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("x11-open", "X11 server accepts unauthenticated connections", model.SevHigh,
			[]string{"x11"},
			"The X11 display server accepts connections without any authorization (xhost +). Anyone on the network can capture screenshots, log keystrokes and inject input into the graphical session."),
		Remediation: "Disable TCP listening for X (-nolisten tcp, the default in modern distributions), remove 'xhost +' and use SSH X11 forwarding with MIT-MAGIC-COOKIE authentication.",
		References:  []string{"https://www.x.org/releases/X11R7.7/doc/man/man1/Xsecurity.1.xhtml"},
		Applies: func(t *Target) bool {
			s := t.Service
			if s.Protocol != model.TCP {
				return false
			}
			if strings.HasPrefix(strings.ToLower(s.Name), "x11") {
				return true
			}
			return s.Port >= 6000 && s.Port <= 6063 && svcIs(s, model.TCP, nil, s.Port)
		},
		Run: runX11,
	})
}

// x11SetupRequest is a little-endian connection setup with no authorization.
var x11SetupRequest = []byte{'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// x11ParseSetup parses the setup reply header: status (0 failed, 1 success,
// 2 authenticate), protocol version, vendor (on success) or reason.
func x11ParseSetup(b []byte) (status byte, major, minor uint16, info string, ok bool) {
	if len(b) < 8 {
		return 0, 0, 0, "", false
	}
	status = b[0]
	major = binary.LittleEndian.Uint16(b[2:])
	minor = binary.LittleEndian.Uint16(b[4:])
	switch status {
	case 0:
		l := int(b[1])
		if 8+l <= len(b) {
			info = printable(b[8:8+l], 200)
		}
		return status, major, minor, info, true
	case 1:
		if len(b) < 40 {
			return status, major, minor, "", true
		}
		release := binary.LittleEndian.Uint32(b[8:])
		vl := int(binary.LittleEndian.Uint16(b[24:]))
		vendor := ""
		if 40+vl <= len(b) {
			vendor = printable(b[40:40+vl], 120)
		}
		return status, major, minor, fmt.Sprintf("vendor=%q release=%d", vendor, release), true
	case 2:
		return status, major, minor, "authentication required", true
	}
	return status, 0, 0, "", false
}

func runX11(ctx context.Context, t *Target) []model.Finding {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer c.Close()
	if _, err := c.Write(x11SetupRequest); err != nil {
		return nil
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil
	}
	if buf[0] == 1 {
		// additional data length in 4-byte units; read enough for vendor.
		extra := int(binary.LittleEndian.Uint16(buf[6:])) * 4
		if extra > 4096 {
			extra = 4096
		}
		more := make([]byte, extra)
		n, _ := io.ReadFull(c, more)
		buf = append(buf, more[:n]...)
	} else if buf[0] == 0 {
		more := make([]byte, int(buf[1])+3)
		n, _ := io.ReadFull(c, more)
		buf = append(buf, more[:n]...)
	}
	st, major, minor, info, ok := x11ParseSetup(buf)
	if !ok || st != 1 || major != 11 {
		return nil
	}
	return []model.Finding{t.Finding(fmt.Sprintf("X11 connection setup without authorization succeeded: X%d.%d display :%d, %s", major, minor, t.Service.Port-6000, info))}
}
