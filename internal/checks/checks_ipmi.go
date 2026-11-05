package checks

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("ipmi-cipher-zero", "IPMI 2.0 cipher suite zero accepted", model.SevHigh,
			[]string{"asf-rmcp", "ipmi"},
			"The BMC accepts RMCP+ sessions using cipher suite 0 (no authentication, no integrity, no confidentiality). An attacker who knows a valid user name can execute arbitrary IPMI commands (power control, user management) with any password."),
		Remediation: "Disable cipher suite 0 on the BMC (e.g. 'ipmitool lan set <ch> cipher_privs' with 'X' for suite 0), restrict IPMI to a dedicated management VLAN and update the BMC firmware.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2013-4782", "https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_cipher_zero/"},
		Applies:     ipmiApplies,
		Run:         runIPMICipherZero,
	})
	register(&Check{
		Info: checkInfo("ipmi-rakp-hash-disclosure", "IPMI 2.0 RAKP password hash disclosure", model.SevHigh,
			[]string{"asf-rmcp", "ipmi"},
			"The IPMI 2.0 RAKP protocol returns a salted HMAC-SHA1 of the user's password to unauthenticated clients that supply a valid user name. The hash can be cracked offline (hashcat mode 7300) to recover BMC credentials. This is a design flaw of IPMI 2.0."),
		Remediation: "Restrict IPMI (UDP 623) to an isolated management network, use long random BMC passwords, disable unused default accounts, and disable IPMI-over-LAN when not required.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2013-4786", "https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/"},
		Applies:     ipmiApplies,
		Run:         runIPMIRakp,
	})
}

func ipmiApplies(t *Target) bool {
	return svcIs(t.Service, model.UDP, []string{"asf-rmcp", "ipmi", "rmcp"}, 623)
}

// ipmiGetChannelAuthCaps is the IPMI v1.5 "Get Channel Authentication Capabilities"
// request asking for IPMI v2 extended data.
var ipmiGetChannelAuthCaps = []byte{
	0x06, 0x00, 0xff, 0x07, // RMCP
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth none, seq, session id
	0x09,                               // length
	0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, // rsAddr, netFn, cksum, rqAddr, rqSeq, cmd
	0x8e, 0x04, 0xb5, // channel (v2 ext), priv admin, cksum
}

// ipmiAuthCaps reports whether the reply advertises IPMI 2.0.
func ipmiAuthCaps(b []byte) (v2 bool, err error) {
	if len(b) < 25 || b[0] != 0x06 || b[3] != 0x07 {
		return false, errors.New("ipmi: malformed reply")
	}
	if b[19] != 0x38 || b[20] != 0x00 {
		return false, fmt.Errorf("ipmi: get channel auth caps failed (cc 0x%02x)", b[20])
	}
	return b[22]&0x80 != 0 && b[24]&0x02 != 0, nil
}

// ipmiOpenSession builds an RMCP+ Open Session Request.
func ipmiOpenSession(consoleID []byte, auth, integ, conf byte) []byte {
	p := make([]byte, 32)
	p[0] = 0x00
	p[1] = 0x00 // max privilege available
	copy(p[4:8], consoleID)
	copy(p[8:], []byte{0x00, 0, 0, 0x08, auth, 0, 0, 0})
	copy(p[16:], []byte{0x01, 0, 0, 0x08, integ, 0, 0, 0})
	copy(p[24:], []byte{0x02, 0, 0, 0x08, conf, 0, 0, 0})
	return ipmiRMCPPlus(0x10, p)
}

func ipmiRMCPPlus(payloadType byte, payload []byte) []byte {
	b := []byte{0x06, 0x00, 0xff, 0x07, 0x06, payloadType, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(b[14:], uint16(len(payload)))
	return append(b, payload...)
}

// ipmiPayload extracts an RMCP+ payload of the expected type.
func ipmiPayload(b []byte, typ byte) ([]byte, error) {
	if len(b) < 16 || b[0] != 0x06 || b[3] != 0x07 || b[4] != 0x06 {
		return nil, errors.New("ipmi: not an RMCP+ reply")
	}
	if b[5]&0x3f != typ {
		return nil, fmt.Errorf("ipmi: unexpected payload type 0x%02x", b[5])
	}
	l := int(binary.LittleEndian.Uint16(b[14:]))
	if l > len(b)-16 {
		return nil, errors.New("ipmi: truncated payload")
	}
	return b[16 : 16+l], nil
}

// ipmiOpenSessionResp is the decoded Open Session Response.
type ipmiOpenSessionResp struct {
	Status    byte
	ConsoleID []byte
	ManagedID []byte
	Auth      byte
	Integ     byte
	Conf      byte
}

func ipmiParseOpenSession(b []byte) (*ipmiOpenSessionResp, error) {
	p, err := ipmiPayload(b, 0x11)
	if err != nil {
		return nil, err
	}
	if len(p) < 8 {
		return nil, errors.New("ipmi: short open session response")
	}
	r := &ipmiOpenSessionResp{Status: p[1], ConsoleID: append([]byte(nil), p[4:8]...)}
	if r.Status == 0 {
		if len(p) < 36 {
			return nil, errors.New("ipmi: short open session response")
		}
		r.ManagedID = append([]byte(nil), p[8:12]...)
		r.Auth, r.Integ, r.Conf = p[16]&0x3f, p[24]&0x3f, p[32]&0x3f
	}
	return r, nil
}

// ipmiRAKP1 builds RAKP Message 1.
func ipmiRAKP1(managedID, consoleRandom []byte, user string) []byte {
	p := make([]byte, 28, 28+len(user))
	copy(p[4:8], managedID)
	copy(p[8:24], consoleRandom)
	p[24] = 0x14 // administrator, name-only lookup
	p[27] = byte(len(user))
	p = append(p, user...)
	return ipmiRMCPPlus(0x12, p)
}

// ipmiRAKP2 is RAKP Message 2.
type ipmiRAKP2 struct {
	Status        byte
	ConsoleID     []byte
	ManagedRandom []byte
	ManagedGUID   []byte
	HMAC          []byte
}

func ipmiParseRAKP2(b []byte) (*ipmiRAKP2, error) {
	p, err := ipmiPayload(b, 0x13)
	if err != nil {
		return nil, err
	}
	if len(p) < 8 {
		return nil, errors.New("ipmi: short RAKP2")
	}
	r := &ipmiRAKP2{Status: p[1], ConsoleID: append([]byte(nil), p[4:8]...)}
	if r.Status == 0 {
		if len(p) < 60 {
			return nil, errors.New("ipmi: short RAKP2")
		}
		r.ManagedRandom = append([]byte(nil), p[8:24]...)
		r.ManagedGUID = append([]byte(nil), p[24:40]...)
		r.HMAC = append([]byte(nil), p[40:60]...)
	}
	return r, nil
}

// ipmiExchange sends req and returns the first reply, retrying once.
func ipmiExchange(c net.Conn, timeout time.Duration, req []byte, ok func([]byte) bool) ([]byte, error) {
	buf := make([]byte, 1500)
	var lastErr error = errors.New("ipmi: no reply")
	for try := 0; try < 2; try++ {
		if _, err := c.Write(req); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(timeout)
		_ = c.SetReadDeadline(deadline)
		for time.Now().Before(deadline) {
			n, err := c.Read(buf)
			if err != nil {
				lastErr = err
				break
			}
			if ok(buf[:n]) {
				return append([]byte(nil), buf[:n]...), nil
			}
		}
	}
	return nil, lastErr
}

func ipmiIsV2(ctx context.Context, t *Target) (net.Conn, bool) {
	c, err := t.DialUDP(ctx, t.Service.Port)
	if err != nil {
		return nil, false
	}
	to := ipmiTimeout(t)
	reply, err := ipmiExchange(c, to, ipmiGetChannelAuthCaps, func(b []byte) bool { return len(b) >= 21 && b[19] == 0x38 })
	if err != nil {
		c.Close()
		return nil, false
	}
	v2, err := ipmiAuthCaps(reply)
	if err != nil || !v2 {
		c.Close()
		return nil, false
	}
	return c, true
}

func ipmiTimeout(t *Target) time.Duration {
	if t.Timeout > 3*time.Second {
		return 3 * time.Second
	}
	return t.Timeout
}

func ipmiOpen(c net.Conn, to time.Duration, auth, integ, conf byte) (*ipmiOpenSessionResp, []byte, error) {
	consoleID := make([]byte, 4)
	_, _ = rand.Read(consoleID)
	reply, err := ipmiExchange(c, to, ipmiOpenSession(consoleID, auth, integ, conf), func(b []byte) bool {
		r, err := ipmiParseOpenSession(b)
		return err == nil && string(r.ConsoleID) == string(consoleID)
	})
	if err != nil {
		return nil, nil, err
	}
	r, err := ipmiParseOpenSession(reply)
	return r, consoleID, err
}

func runIPMICipherZero(ctx context.Context, t *Target) []model.Finding {
	c, ok := ipmiIsV2(ctx, t)
	if !ok {
		return nil
	}
	defer c.Close()
	r, _, err := ipmiOpen(c, ipmiTimeout(t), 0, 0, 0)
	if err != nil {
		t.Log.Debug("ipmi open session", "err", err)
		return nil
	}
	if r.Status != 0 || r.Auth != 0 || r.Integ != 0 || r.Conf != 0 {
		return nil
	}
	return []model.Finding{t.Finding(fmt.Sprintf(
		"RMCP+ Open Session Request with cipher suite 0 (auth=none, integrity=none, confidentiality=none) accepted: status 0, managed system session id %s",
		hex.EncodeToString(r.ManagedID)))}
}

// ipmiUsers are the user names tried (at most 4 attempts, no password is ever sent: RAKP1
// only asks for the server's HMAC).
var ipmiUsers = []string{"ADMIN", "admin", "root", "Administrator"}

func runIPMIRakp(ctx context.Context, t *Target) []model.Finding {
	c, ok := ipmiIsV2(ctx, t)
	if !ok {
		return nil
	}
	defer c.Close()
	to := ipmiTimeout(t)
	for _, user := range ipmiUsers {
		if ctx.Err() != nil {
			return nil
		}
		os, consoleID, err := ipmiOpen(c, to, 1, 1, 1) // HMAC-SHA1, HMAC-SHA1-96, AES-CBC-128
		if err != nil || os.Status != 0 {
			t.Log.Debug("ipmi open session (rakp)", "err", err)
			return nil
		}
		consoleRandom := make([]byte, 16)
		_, _ = rand.Read(consoleRandom)
		reply, err := ipmiExchange(c, to, ipmiRAKP1(os.ManagedID, consoleRandom, user), func(b []byte) bool {
			r, err := ipmiParseRAKP2(b)
			return err == nil && string(r.ConsoleID) == string(consoleID)
		})
		if err != nil {
			continue
		}
		r2, err := ipmiParseRAKP2(reply)
		if err != nil || r2.Status != 0 || ipmiAllZero(r2.HMAC) {
			continue
		}
		salt := make([]byte, 0, 58+len(user))
		salt = append(salt, consoleID...)
		salt = append(salt, os.ManagedID...)
		salt = append(salt, consoleRandom...)
		salt = append(salt, r2.ManagedRandom...)
		salt = append(salt, r2.ManagedGUID...)
		salt = append(salt, 0x14, byte(len(user)))
		salt = append(salt, user...)
		return []model.Finding{t.Finding(fmt.Sprintf(
			"RAKP Message 2 returned an HMAC-SHA1 for valid user %q (offline crackable, hashcat -m 7300):\n%s:%s",
			user, hex.EncodeToString(salt), hex.EncodeToString(r2.HMAC)))}
	}
	return nil
}

func ipmiAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
