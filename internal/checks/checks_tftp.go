package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("tftp-anonymous-read", "TFTP server hands out files without authentication", model.SevMedium,
			[]string{"tftp"},
			"A TFTP service served a file to an unauthenticated reader. TFTP has no concept of a user: whoever can reach the port can read any file whose name they can name, and on an internal network these servers almost always exist to stage network device configurations and PXE boot images. Device configurations carry enable secrets, SNMP communities, RADIUS shared secrets and VPN pre-shared keys; boot images and their answer files carry the local administrator password used to build every workstation."),
		Remediation: "Restrict the service to the management addresses that need it with a firewall rule, keep the TFTP root to the files being staged and remove configuration backups from it when the work is done. For device provisioning prefer SCP or HTTPS, which at least authenticate the client.",
		References: []string{
			"https://datatracker.ietf.org/doc/html/rfc1350",
			"https://cwe.mitre.org/data/definitions/306.html",
		},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.UDP, []string{"tftp"}, 69)
		},
		Run: runTFTPAnonymousRead,
	})
}

// tftpWellKnownNames is a short list of the names network equipment and PXE setups
// actually use. It is not a wordlist and must not become one: the point is to show that
// an unauthenticated read works, not to find out what else the server holds.
var tftpWellKnownNames = []string{
	"running-config",
	"startup-config",
	"config.text",
	"router-confg",
	"switch-confg",
	"vlan.dat",
	"pxelinux.0",
	"boot.ipxe",
	"000000000000.cfg",
	"network.cfg",
}

// TFTP opcodes (RFC 1350).
const (
	tftpOpRRQ   = 1
	tftpOpData  = 3
	tftpOpError = 5
)

func runTFTPAnonymousRead(ctx context.Context, t *Target) []model.Finding {
	for _, name := range tftpWellKnownNames {
		if ctx.Err() != nil {
			break
		}
		size, snippet, err := tftpReadFirstBlock(ctx, t, name)
		if err != nil {
			t.Log.Debug("tftp read refused", "file", name, "err", err)
			continue
		}
		ev := fmt.Sprintf("Read request for %q was answered with data block 1 (%d bytes) by %s, with no authentication of any kind.\n", name, size, t.Addr())
		if snippet != "" {
			ev += fmt.Sprintf("First bytes of the file: %s\n", snippet)
		}
		ev += "The transfer was aborted after the first block, so the file was not downloaded."
		return []model.Finding{t.Finding(ev)}
	}
	return nil
}

// tftpReadFirstBlock asks for one file and stops at the first data block. An ERROR packet
// is sent back so the server releases the transfer immediately instead of retransmitting
// until it times out. Nothing is written: a read request is the only operation used, and
// the WRQ opcode is never sent.
//
// The socket is deliberately unconnected. A TFTP server answers a read request from a
// fresh ephemeral port rather than from port 69, so a connected socket would drop the
// reply it is waiting for.
func tftpReadFirstBlock(ctx context.Context, t *Target, name string) (int, string, error) {
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return 0, "", err
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { _ = pc.Close() })
	defer stop()

	srv, err := net.ResolveUDPAddr("udp", t.AddrPort(t.Service.Port))
	if err != nil {
		return 0, "", err
	}
	req := []byte{0, tftpOpRRQ}
	req = append(req, name...)
	req = append(req, 0)
	req = append(req, "octet"...)
	req = append(req, 0)
	_ = pc.SetDeadline(time.Now().Add(t.Timeout))
	if _, err := pc.WriteTo(req, srv); err != nil {
		return 0, "", err
	}
	buf := make([]byte, 1024)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		return 0, "", err
	}
	if n < 4 {
		return 0, "", fmt.Errorf("tftp: short reply (%d bytes)", n)
	}
	switch binary.BigEndian.Uint16(buf[0:]) {
	case tftpOpData:
	case tftpOpError:
		return 0, "", fmt.Errorf("tftp: error %d %q", binary.BigEndian.Uint16(buf[2:]), printable(buf[4:n], 120))
	default:
		return 0, "", fmt.Errorf("tftp: unexpected opcode %d", binary.BigEndian.Uint16(buf[0:]))
	}
	if binary.BigEndian.Uint16(buf[2:]) != 1 {
		return 0, "", fmt.Errorf("tftp: unexpected block %d", binary.BigEndian.Uint16(buf[2:]))
	}
	data := buf[4:n]
	// The abort goes back to the ephemeral port that answered, not to 69.
	tftpAbort(pc, from)
	return len(data), tftpSnippet(data), nil
}

// tftpAbort tells the server to drop the transfer.
func tftpAbort(pc net.PacketConn, to net.Addr) {
	// ERROR, code 0 (not defined), with a message that says who sent it.
	pkt := []byte{0, tftpOpError, 0, 0}
	pkt = append(pkt, "aborted by scanner"...)
	pkt = append(pkt, 0)
	_ = pc.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = pc.WriteTo(pkt, to)
}

// tftpSnippet shows just enough of the file to prove it was served. The content is kept
// short on purpose: these files hold secrets, and a client report is not the place to
// copy them.
func tftpSnippet(b []byte) string {
	if len(b) > 100 {
		b = b[:100]
	}
	s := strings.TrimSpace(printable(b, 100))
	if s == "" {
		return ""
	}
	return s + " (truncated, the file was not recorded)"
}
