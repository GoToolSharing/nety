package checks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

// RDP negotiation protocols (MS-RDPBCGR 2.2.1.1.1).
const (
	rdpProtoRDP      uint32 = 0x0
	rdpProtoSSL      uint32 = 0x1
	rdpProtoHybrid   uint32 = 0x2
	rdpProtoRDSTLS   uint32 = 0x4
	rdpProtoHybridEx uint32 = 0x8
)

func init() {
	register(&Check{
		Info: checkInfo("rdp-nla-not-required", "RDP Network Level Authentication not required", model.SevMedium,
			[]string{"ms-wbt-server", "rdp"},
			"The RDP service accepts connections without Network Level Authentication (CredSSP). Unauthenticated users reach the Windows logon screen, which exposes the host to pre-authentication vulnerabilities (e.g. BlueKeep CVE-2019-0708), resource exhaustion and username disclosure, and weakens protection against man-in-the-middle attacks."),
		Remediation: "Require NLA: enable 'Require user authentication for remote connections by using Network Level Authentication' (GPO) or set UserAuthentication=1 under RDP-Tcp.",
		References:  []string{"https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access", "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"},
		Applies:     rdpApplies,
		Run:         runRDPNLA,
	})
	register(&Check{
		Info: checkInfo("rdp-standard-security", "RDP accepts legacy Standard RDP Security", model.SevMedium,
			[]string{"ms-wbt-server", "rdp"},
			"The RDP service accepts the legacy 'Standard RDP Security' layer (proprietary RC4 encryption without server authentication). Connections can be intercepted and decrypted by a man-in-the-middle attacker."),
		Remediation: "Set the security layer to SSL/TLS or Negotiate with NLA required (SecurityLayer=2, UserAuthentication=1) via GPO 'Require use of specific security layer for remote (RDP) connections'.",
		References:  []string{"https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8e8b2cca-c1fa-456c-8ecb-a82fc60b2322"},
		Applies:     rdpApplies,
		Run:         runRDPStandard,
	})
}

func rdpApplies(t *Target) bool {
	return svcIs(t.Service, model.TCP, []string{"ms-wbt-server", "rdp", "ms-term-serv"}, 3389)
}

// rdpBuildCR builds a TPKT + X.224 Connection Request with an RDP_NEG_REQ.
func rdpBuildCR(protocols uint32) []byte {
	cookie := []byte("Cookie: mstshash=nety\r\n")
	neg := []byte{0x01, 0x00, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(neg[4:], protocols)
	x224 := []byte{0, 0xe0, 0, 0, 0, 0, 0}
	x224 = append(x224, cookie...)
	x224 = append(x224, neg...)
	x224[0] = byte(len(x224) - 1)
	pkt := []byte{3, 0, 0, 0}
	binary.BigEndian.PutUint16(pkt[2:], uint16(4+len(x224)))
	return append(pkt, x224...)
}

// rdpNegResult is the decoded X.224 Connection Confirm.
type rdpNegResult struct {
	HasNeg      bool   // RDP_NEG_RSP / FAILURE present
	Failure     bool   // RDP_NEG_FAILURE
	Selected    uint32 // selectedProtocol (when !Failure)
	FailureCode uint32
	Flags       byte
}

var errRDPMalformed = errors.New("rdp: malformed connection confirm")

// rdpParseCC parses a TPKT + X.224 Connection Confirm.
func rdpParseCC(b []byte) (*rdpNegResult, error) {
	if len(b) < 11 || b[0] != 3 {
		return nil, errRDPMalformed
	}
	tl := int(binary.BigEndian.Uint16(b[2:]))
	if tl < 11 || tl > len(b) {
		return nil, errRDPMalformed
	}
	b = b[4:tl]
	li := int(b[0])
	if li+1 > len(b) || li < 6 {
		return nil, errRDPMalformed
	}
	if b[1]&0xf0 != 0xd0 {
		return nil, fmt.Errorf("rdp: unexpected X.224 TPDU 0x%02x", b[1])
	}
	r := &rdpNegResult{}
	v := b[7 : li+1]
	if len(v) >= 8 {
		switch v[0] {
		case 0x02:
			r.HasNeg = true
			r.Flags = v[1]
			r.Selected = binary.LittleEndian.Uint32(v[4:])
		case 0x03:
			r.HasNeg, r.Failure = true, true
			r.FailureCode = binary.LittleEndian.Uint32(v[4:])
		}
	}
	return r, nil
}

func rdpFailureName(code uint32) string {
	switch code {
	case 1:
		return "SSL_REQUIRED_BY_SERVER"
	case 2:
		return "SSL_NOT_ALLOWED_BY_SERVER"
	case 3:
		return "SSL_CERT_NOT_ON_SERVER"
	case 4:
		return "INCONSISTENT_FLAGS"
	case 5:
		return "HYBRID_REQUIRED_BY_SERVER"
	case 6:
		return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
	}
	return fmt.Sprintf("failure-%d", code)
}

func rdpProtoName(p uint32) string {
	switch p {
	case rdpProtoRDP:
		return "PROTOCOL_RDP (standard RDP security)"
	case rdpProtoSSL:
		return "PROTOCOL_SSL (TLS without NLA)"
	case rdpProtoHybrid:
		return "PROTOCOL_HYBRID (CredSSP/NLA)"
	case rdpProtoRDSTLS:
		return "PROTOCOL_RDSTLS"
	case rdpProtoHybridEx:
		return "PROTOCOL_HYBRID_EX (CredSSP/NLA)"
	}
	return fmt.Sprintf("0x%x", p)
}

// rdpNegotiate sends one connection request and returns the server answer.
func rdpNegotiate(ctx context.Context, t *Target, protocols uint32) (*rdpNegResult, error) {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.Write(rdpBuildCR(protocols)); err != nil {
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 3 {
		return nil, errRDPMalformed
	}
	l := int(binary.BigEndian.Uint16(hdr[2:]))
	if l < 11 || l > 1024 {
		return nil, errRDPMalformed
	}
	rest := make([]byte, l-4)
	if _, err := io.ReadFull(c, rest); err != nil {
		return nil, err
	}
	return rdpParseCC(append(hdr, rest...))
}

func runRDPNLA(ctx context.Context, t *Target) []model.Finding {
	r, err := rdpNegotiate(ctx, t, rdpProtoSSL)
	if err != nil {
		t.Log.Debug("rdp negotiate", "err", err)
		return nil
	}
	var ev string
	switch {
	case !r.HasNeg:
		ev = "Server answered a TLS-only connection request with a legacy Connection Confirm (no RDP negotiation): only standard RDP security is supported, NLA cannot be enforced."
	case r.Failure:
		return nil // HYBRID_REQUIRED / SSL_WITH_USER_AUTH etc.: NLA (or stronger) enforced
	case r.Selected == rdpProtoSSL || r.Selected == rdpProtoRDP:
		ev = fmt.Sprintf("Connection request offering only PROTOCOL_SSL was accepted: server selected %s.", rdpProtoName(r.Selected))
	default:
		return nil
	}
	return []model.Finding{t.Finding(ev)}
}

func runRDPStandard(ctx context.Context, t *Target) []model.Finding {
	r, err := rdpNegotiate(ctx, t, rdpProtoRDP)
	if err != nil {
		t.Log.Debug("rdp negotiate", "err", err)
		return nil
	}
	if r.Failure {
		return nil
	}
	if r.HasNeg && r.Selected != rdpProtoRDP {
		return nil
	}
	var sb strings.Builder
	sb.WriteString("Connection request offering only PROTOCOL_RDP (standard RDP security) was accepted")
	if !r.HasNeg {
		sb.WriteString(" (legacy server without negotiation support)")
	}
	return []model.Finding{t.Finding(sb.String())}
}
