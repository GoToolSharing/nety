package checks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vaadata/nety/internal/identity/smb"
)

// Minimal SMB1 (CIFS) client used by the smbv1 / signing / MS17-010 checks.
// It only implements NEGOTIATE (NT LM 0.12), anonymous SESSION_SETUP_ANDX
// (non extended security), TREE_CONNECT_ANDX and TRANSACTION
// (PeekNamedPipe), which is exactly what nmap's safe scripts use.

const (
	smb1CmdNegotiate    byte = 0x72
	smb1CmdSessionSetup byte = 0x73
	smb1CmdTreeConnect  byte = 0x75
	smb1CmdTrans        byte = 0x25

	smb1Flags2LongNames uint16 = 0x0001
	smb1Flags2NTStatus  uint16 = 0x4000

	smb1HeaderLen = 32
)

var errSMB1Malformed = errors.New("smb1: malformed response")

// smb1Packet is a decoded SMB1 response.
type smb1Packet struct {
	Command byte
	Status  uint32
	Flags   byte
	Flags2  uint16
	TID     uint16
	UID     uint16
	MID     uint16
	Words   []byte
	Bytes   []byte
}

// smb1Parse decodes one SMB1 message (without transport framing).
func smb1Parse(b []byte) (*smb1Packet, error) {
	if !smb.IsSMB1(b) {
		if smb.IsSMB2(b) {
			return nil, errors.New("smb1: server answered with SMB2")
		}
		return nil, errSMB1Malformed
	}
	if len(b) < smb1HeaderLen+1 {
		return nil, errSMB1Malformed
	}
	p := &smb1Packet{
		Command: b[4],
		Status:  binary.LittleEndian.Uint32(b[5:]),
		Flags:   b[9],
		Flags2:  binary.LittleEndian.Uint16(b[10:]),
		TID:     binary.LittleEndian.Uint16(b[24:]),
		UID:     binary.LittleEndian.Uint16(b[28:]),
		MID:     binary.LittleEndian.Uint16(b[30:]),
	}
	wc := int(b[32])
	pos := 33
	if pos+2*wc > len(b) {
		return nil, errSMB1Malformed
	}
	p.Words = b[pos : pos+2*wc]
	pos += 2 * wc
	if pos+2 <= len(b) {
		bc := int(binary.LittleEndian.Uint16(b[pos:]))
		pos += 2
		if bc > len(b)-pos {
			bc = len(b) - pos // tolerate short byte counts
		}
		p.Bytes = b[pos : pos+bc]
	}
	return p, nil
}

func smb1Header(cmd byte, tid, uid, mid uint16) []byte {
	h := make([]byte, smb1HeaderLen)
	copy(h, []byte{0xff, 'S', 'M', 'B'})
	h[4] = cmd
	h[9] = 0x18 // case insensitive, canonicalized paths
	binary.LittleEndian.PutUint16(h[10:], smb1Flags2LongNames|smb1Flags2NTStatus)
	binary.LittleEndian.PutUint16(h[24:], tid)
	binary.LittleEndian.PutUint16(h[26:], 0xfeff) // PID
	binary.LittleEndian.PutUint16(h[28:], uid)
	binary.LittleEndian.PutUint16(h[30:], mid)
	return h
}

func smb1Message(hdr []byte, words []byte, data []byte) []byte {
	b := make([]byte, 0, len(hdr)+3+len(words)+len(data))
	b = append(b, hdr...)
	b = append(b, byte(len(words)/2))
	b = append(b, words...)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// smb1BuildNegotiate builds a NEGOTIATE offering only "NT LM 0.12".
func smb1BuildNegotiate() []byte {
	return smb1Message(smb1Header(smb1CmdNegotiate, 0, 0, 1), nil, []byte("\x02NT LM 0.12\x00"))
}

// smb1NegInfo is what an NT LM 0.12 negotiate response tells.
type smb1NegInfo struct {
	Accepted        bool
	DialectIndex    uint16
	SecurityMode    byte
	SigningEnabled  bool
	SigningRequired bool
	Capabilities    uint32
	SystemTime      time.Time
}

func smb1ParseNegotiate(b []byte) (*smb1NegInfo, error) {
	p, err := smb1Parse(b)
	if err != nil {
		return nil, err
	}
	if p.Command != smb1CmdNegotiate {
		return nil, errSMB1Malformed
	}
	if p.Status != 0 {
		return nil, fmt.Errorf("smb1: negotiate failed: %s", smb.StatusName(p.Status))
	}
	if len(p.Words) < 2 {
		return nil, errSMB1Malformed
	}
	ni := &smb1NegInfo{DialectIndex: binary.LittleEndian.Uint16(p.Words)}
	if ni.DialectIndex == 0xffff || len(p.Words) < 34 {
		return ni, nil
	}
	ni.Accepted = true
	ni.SecurityMode = p.Words[2]
	ni.SigningEnabled = ni.SecurityMode&0x04 != 0
	ni.SigningRequired = ni.SecurityMode&0x08 != 0
	ni.Capabilities = binary.LittleEndian.Uint32(p.Words[19:])
	ft := binary.LittleEndian.Uint64(p.Words[23:])
	const epochDiff = 116444736000000000
	if ft > epochDiff {
		d := ft - epochDiff
		ni.SystemTime = time.Unix(int64(d/10000000), 0).UTC()
	}
	return ni, nil
}

// smb1BuildSessionSetupAnon builds an anonymous SESSION_SETUP_ANDX
// (non extended security, empty account and passwords).
func smb1BuildSessionSetupAnon(mid uint16) []byte {
	w := make([]byte, 26)
	w[0] = 0xff // no AndX
	binary.LittleEndian.PutUint16(w[4:], 0xffff)
	binary.LittleEndian.PutUint16(w[6:], 2)
	binary.LittleEndian.PutUint32(w[22:], 0x00000050) // NT_SMBS | NT_STATUS
	data := []byte("\x00\x00Windows 2000 2195\x00Windows 2000 5.0\x00")
	return smb1Message(smb1Header(smb1CmdSessionSetup, 0, 0, mid), w, data)
}

// smb1BuildTreeConnect builds a TREE_CONNECT_ANDX to \\ip\share.
func smb1BuildTreeConnect(ip, share string, uid, mid uint16) []byte {
	w := make([]byte, 8)
	w[0] = 0xff
	binary.LittleEndian.PutUint16(w[6:], 1) // password length
	data := []byte{0}
	data = append(data, []byte(`\\`+ip+`\`+share)...)
	data = append(data, 0)
	data = append(data, []byte("?????\x00")...)
	return smb1Message(smb1Header(smb1CmdTreeConnect, 0, uid, mid), w, data)
}

// smb1BuildPeekNamedPipe builds the TRANSACTION PeekNamedPipe request on
// FID 0 used by the MS17-010 safe detection (same bytes as nmap).
func smb1BuildPeekNamedPipe(tid, uid, mid uint16) []byte {
	w := make([]byte, 32)
	binary.LittleEndian.PutUint16(w[4:], 0xffff)  // max parameter count
	binary.LittleEndian.PutUint16(w[6:], 0xffff)  // max data count
	binary.LittleEndian.PutUint16(w[20:], 0x004a) // parameter offset
	binary.LittleEndian.PutUint16(w[24:], 0x004a) // data offset
	w[26] = 2                                     // setup count
	binary.LittleEndian.PutUint16(w[28:], 0x0023) // PeekNamedPipe
	binary.LittleEndian.PutUint16(w[30:], 0)      // FID 0
	return smb1Message(smb1Header(smb1CmdTrans, tid, uid, mid), w, []byte("\\PIPE\\\x00"))
}

// smb1Client is a tiny stateful SMB1 session.
type smb1Client struct {
	t   *smb.Transport
	ip  string
	uid uint16
	tid uint16
	mid uint16
	neg *smb1NegInfo
}

func smb1Dial(ctx context.Context, ip string, port int, timeout time.Duration) (*smb1Client, error) {
	tr, err := smb.DialTransport(ctx, ip, port, timeout, "")
	if err != nil {
		return nil, err
	}
	return &smb1Client{t: tr, ip: ip, mid: 1}, nil
}

func (c *smb1Client) Close() { _ = c.t.Close() }

func (c *smb1Client) roundTrip(msg []byte) (*smb1Packet, error) {
	raw, err := c.t.RoundTrip(msg)
	if err != nil {
		return nil, err
	}
	return smb1Parse(raw)
}

func (c *smb1Client) Negotiate() (*smb1NegInfo, error) {
	raw, err := c.t.RoundTrip(smb1BuildNegotiate())
	if err != nil {
		return nil, err
	}
	ni, err := smb1ParseNegotiate(raw)
	if err != nil {
		return nil, err
	}
	c.neg = ni
	return ni, nil
}

func (c *smb1Client) SessionSetupAnon() error {
	c.mid++
	p, err := c.roundTrip(smb1BuildSessionSetupAnon(c.mid))
	if err != nil {
		return err
	}
	if p.Status != 0 {
		return fmt.Errorf("smb1: session setup: %s", smb.StatusName(p.Status))
	}
	c.uid = p.UID
	return nil
}

func (c *smb1Client) TreeConnect(share string) error {
	c.mid++
	p, err := c.roundTrip(smb1BuildTreeConnect(c.ip, share, c.uid, c.mid))
	if err != nil {
		return err
	}
	if p.Status != 0 {
		return fmt.Errorf("smb1: tree connect %s: %s", share, smb.StatusName(p.Status))
	}
	c.tid = p.TID
	return nil
}

// PeekNamedPipe returns the NT status of the PeekNamedPipe transaction.
func (c *smb1Client) PeekNamedPipe() (uint32, error) {
	c.mid++
	p, err := c.roundTrip(smb1BuildPeekNamedPipe(c.tid, c.uid, c.mid))
	if err != nil {
		return 0, err
	}
	if p.Command != smb1CmdTrans {
		return 0, errSMB1Malformed
	}
	return p.Status, nil
}

func smb1CapsString(caps uint32) string {
	var out []string
	names := []struct {
		bit  uint32
		name string
	}{{0x4, "unicode"}, {0x8, "large-files"}, {0x10, "nt-smbs"}, {0x40, "nt-status"}, {0x80000000, "extended-security"}}
	for _, n := range names {
		if caps&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return strings.Join(out, ",")
}
