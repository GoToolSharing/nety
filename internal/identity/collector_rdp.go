package identity

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/GoToolSharing/nety/internal/identity/ntlm"
)

// RDP negotiation protocols.
const (
	rdpProtoRDP      uint32 = 0x00
	rdpProtoSSL      uint32 = 0x01
	rdpProtoHybrid   uint32 = 0x02
	rdpProtoRDSTLS   uint32 = 0x04
	rdpProtoHybridEx uint32 = 0x08
)

// buildX224ConnectionRequest builds a TPKT + X.224 CR with an RDP_NEG_REQ.
func buildX224ConnectionRequest(protocols uint32) []byte {
	cookie := []byte("Cookie: mstshash=nety\r\n")
	neg := make([]byte, 8)
	neg[0] = 0x01 // TYPE_RDP_NEG_REQ
	binary.LittleEndian.PutUint16(neg[2:], 8)
	binary.LittleEndian.PutUint32(neg[4:], protocols)
	x224 := []byte{0, 0xe0, 0, 0, 0, 0, 0}
	x224 = append(x224, cookie...)
	x224 = append(x224, neg...)
	x224[0] = byte(len(x224) - 1)
	tpkt := []byte{3, 0, 0, 0}
	binary.BigEndian.PutUint16(tpkt[2:], uint16(4+len(x224)))
	return append(tpkt, x224...)
}

// x224Result is the decoded X.224 Connection Confirm.
type x224Result struct {
	HasNeg      bool
	Selected    uint32 // RDP_NEG_RSP selectedProtocol
	Failure     bool
	FailureCode uint32
	Flags       uint8
}

var errNotX224 = errors.New("rdp: not an X.224 connection confirm")

// parseX224ConnectionConfirm parses TPKT + X.224 CC (+ optional RDP_NEG_RSP / FAILURE).
func parseX224ConnectionConfirm(b []byte) (*x224Result, error) {
	if len(b) < 11 || b[0] != 3 {
		return nil, errNotX224
	}
	l := int(binary.BigEndian.Uint16(b[2:]))
	if l < 11 || l > len(b) {
		return nil, errNotX224
	}
	b = b[:l]
	li := int(b[4])
	if b[5]&0xf0 != 0xd0 || 5+li > len(b) || li < 6 {
		return nil, errNotX224
	}
	r := &x224Result{}
	rest := b[4+7 : 5+li] // after LI(1)+CC(1)+dst(2)+src(2)+class(1)
	if len(rest) >= 8 {
		switch rest[0] {
		case 0x02:
			r.HasNeg = true
			r.Flags = rest[1]
			r.Selected = binary.LittleEndian.Uint32(rest[4:])
		case 0x03:
			r.HasNeg = true
			r.Failure = true
			r.FailureCode = binary.LittleEndian.Uint32(rest[4:])
		}
	}
	return r, nil
}

// buildTSRequest builds a CredSSP TSRequest carrying one negoToken.
func buildTSRequest(version int, token []byte) []byte {
	ver := ntlm.DER(0xa0, ntlm.DER(0x02, []byte{byte(version)}))
	nego := ntlm.DER(0xa1, ntlm.DER(0x30, ntlm.DER(0x30, ntlm.DER(0xa0, ntlm.DER(0x04, token)))))
	return ntlm.DER(0x30, ver, nego)
}

// tsRequest is a decoded TSRequest (subset).
type tsRequest struct {
	Version   int
	NegoToken []byte
	ErrorCode uint32
	HasError  bool
}

// parseTSRequest decodes a TSRequest DER structure.
func parseTSRequest(b []byte) (*tsRequest, error) {
	tag, seq, _, err := ntlm.ReadTLV(b)
	if err != nil || tag != 0x30 {
		return nil, errors.New("credssp: not a TSRequest")
	}
	r := &tsRequest{}
	for len(seq) > 0 {
		t, v, rest, err := ntlm.ReadTLV(seq)
		if err != nil {
			return r, err
		}
		seq = rest
		switch t {
		case 0xa0:
			if it, iv, _, err := ntlm.ReadTLV(v); err == nil && it == 0x02 && len(iv) > 0 && len(iv) <= 4 {
				r.Version = int(derUint(iv))
			}
		case 0xa1:
			// NegoData: SEQUENCE OF SEQUENCE { [0] OCTET STRING }
			if st, sv, _, err := ntlm.ReadTLV(v); err == nil && st == 0x30 {
				if it, iv, _, err := ntlm.ReadTLV(sv); err == nil && it == 0x30 {
					if ct, cv, _, err := ntlm.ReadTLV(iv); err == nil && ct == 0xa0 {
						if ot, ov, _, err := ntlm.ReadTLV(cv); err == nil && ot == 0x04 {
							r.NegoToken = ov
						}
					}
				}
			}
		case 0xa4:
			if it, iv, _, err := ntlm.ReadTLV(v); err == nil && it == 0x02 && len(iv) > 0 && len(iv) <= 5 {
				r.ErrorCode = uint32(derUint(iv))
				r.HasError = true
			}
		}
	}
	return r, nil
}

func derUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// readDER reads one complete DER TLV from r (max 64 KiB).
func readDER(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	l := int(hdr[1])
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 {
			return nil, ntlm.ErrBadDER
		}
		ext := make([]byte, n)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		hdr = append(hdr, ext...)
		l = 0
		for _, x := range ext {
			l = l<<8 | int(x)
		}
	}
	if l > 64<<10 {
		return nil, errors.New("credssp: message too large")
	}
	body := make([]byte, l)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// probeRDP performs X.224 negotiation then CredSSP NTLM NEGOTIATE to obtain
// the server CHALLENGE. Authentication is never completed.
func (c *collector) probeRDP(ctx context.Context, sink *evidenceSink, ip string, port int) error {
	pctx, cancel := withTimeout(ctx, 3*c.ioTimeout)
	defer cancel()
	d := net.Dialer{Timeout: c.ioTimeout}
	conn, err := d.DialContext(pctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	stop := context.AfterFunc(pctx, func() { _ = conn.Close() })
	defer stop()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.ioTimeout))
	if _, err := conn.Write(buildX224ConnectionRequest(rdpProtoSSL | rdpProtoHybrid | rdpProtoHybridEx)); err != nil {
		return err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	l := int(binary.BigEndian.Uint16(hdr[2:]))
	if hdr[0] != 3 || l < 11 || l > 1024 {
		return errNotX224
	}
	rest := make([]byte, l-4)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return err
	}
	cc, err := parseX224ConnectionConfirm(append(hdr, rest...))
	if err != nil {
		return err
	}
	if cc.Failure {
		return fmt.Errorf("rdp: negotiation failure code %d", cc.FailureCode)
	}
	if !cc.HasNeg || (cc.Selected != rdpProtoHybrid && cc.Selected != rdpProtoHybridEx) {
		return fmt.Errorf("rdp: CredSSP not selected (protocol %d)", cc.Selected)
	}
	tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // fingerprinting only
	_ = tconn.SetDeadline(time.Now().Add(c.ioTimeout))
	if err := tconn.HandshakeContext(pctx); err != nil {
		return err
	}
	if _, err := tconn.Write(buildTSRequest(6, ntlm.NegotiateMessage())); err != nil {
		return err
	}
	resp, err := readDER(tconn)
	if err != nil {
		return err
	}
	ts, err := parseTSRequest(resp)
	var ch *ntlm.Challenge
	if err == nil && len(ts.NegoToken) > 0 {
		ch, err = ntlm.FindChallenge(ts.NegoToken)
	} else {
		ch, err = ntlm.FindChallenge(resp)
	}
	if err != nil {
		return err
	}
	attrs := map[string]string{}
	if ts != nil && ts.Version > 0 {
		attrs["credssp_version"] = strconv.Itoa(ts.Version)
	}
	ntlmEvidence(sink, ch, "rdp-ntlm/"+strconv.Itoa(port), attrs)
	return nil
}
