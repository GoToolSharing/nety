package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/vaadata/nety/internal/identity/ntlm"
)

// SMB1 constants.
const (
	smb1CmdNegotiate    = 0x72
	smb1CmdSessionSetup = 0x73

	smb1Flags2LongNames     uint16 = 0x0001
	smb1Flags2ExtSecurity   uint16 = 0x0800
	smb1Flags2NTStatus      uint16 = 0x4000
	smb1Flags2Unicode       uint16 = 0x8000
	smb1CapExtendedSecurity uint32 = 0x80000000
)

// SMB1Info is what an SMB1 NEGOTIATE + anonymous SESSION_SETUP_ANDX reveal
// (the classic smb-os-discovery technique).
type SMB1Info struct {
	Dialect          string
	SecurityMode     uint8
	UserLevel        bool
	EncryptPasswords bool
	SigningEnabled   bool
	SigningRequired  bool
	Capabilities     uint32
	ExtendedSecurity bool
	MaxBufferSize    uint32
	SystemTime       time.Time
	TimeZoneMinutes  int // ServerTimeZone (minutes, as sent by the server)
	Challenge        []byte
	Domain           string // from NEGOTIATE (non extended security)
	Server           string // from NEGOTIATE (non extended security)
	ServerGUID       string // from NEGOTIATE (extended security)

	// SESSION_SETUP_ANDX (anonymous)
	SessionStatus uint32
	SessionOK     bool
	Guest         bool
	NativeOS      string
	NativeLanMan  string
	PrimaryDomain string
}

// ErrSMB1Malformed is returned for unparsable SMB1 responses.
var ErrSMB1Malformed = errors.New("smb1: malformed response")

func smb1Header(cmd byte, flags2 uint16) []byte {
	h := make([]byte, 32)
	copy(h, []byte{0xff, 'S', 'M', 'B'})
	h[4] = cmd
	h[9] = 0x18 // case insensitive, canonicalized paths
	binary.LittleEndian.PutUint16(h[10:], flags2)
	binary.LittleEndian.PutUint16(h[26:], 0xfeff) // PID low
	binary.LittleEndian.PutUint16(h[30:], 1)      // MID
	return h
}

// BuildSMB1Negotiate builds an SMB1 NEGOTIATE request offering "NT LM 0.12"
// without extended security (so the server returns its domain/server names).
func BuildSMB1Negotiate() []byte {
	b := smb1Header(smb1CmdNegotiate, smb1Flags2NTStatus|smb1Flags2LongNames)
	dialects := []byte("\x02NT LM 0.12\x00")
	b = append(b, 0) // word count
	b = binary.LittleEndian.AppendUint16(b, uint16(len(dialects)))
	return append(b, dialects...)
}

// BuildSMB1SessionSetupAnon builds an anonymous SESSION_SETUP_ANDX (non
// extended security, OEM strings).
func BuildSMB1SessionSetupAnon(uid uint16) []byte {
	b := smb1Header(smb1CmdSessionSetup, smb1Flags2NTStatus|smb1Flags2LongNames)
	binary.LittleEndian.PutUint16(b[28:], uid)
	w := make([]byte, 1+26)
	w[0] = 13
	w[1] = 0xff                                  // no AndX
	binary.LittleEndian.PutUint16(w[5:], 0xffff) // MaxBufferSize
	binary.LittleEndian.PutUint16(w[7:], 2)      // MaxMpxCount
	binary.LittleEndian.PutUint32(w[23:], 0x50)  // CAP_STATUS32 | CAP_NT_SMBS
	data := []byte("\x00\x00Unix\x00NETY\x00")   // account "", domain "", NativeOS, NativeLanMan
	b = append(b, w...)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

type smb1Resp struct {
	cmd      byte
	status   uint32
	flags2   uint16
	uid      uint16
	words    []byte
	bytes    []byte
	bytesOff int // offset of bytes in the message
}

func parseSMB1(b []byte) (*smb1Resp, error) {
	if !IsSMB1(b) || len(b) < 35 {
		return nil, ErrSMB1Malformed
	}
	r := &smb1Resp{
		cmd:    b[4],
		status: binary.LittleEndian.Uint32(b[5:]),
		flags2: binary.LittleEndian.Uint16(b[10:]),
		uid:    binary.LittleEndian.Uint16(b[28:]),
	}
	wc := int(b[32])
	end := 33 + 2*wc
	if end+2 > len(b) {
		return nil, ErrSMB1Malformed
	}
	r.words = b[33:end]
	bc := int(binary.LittleEndian.Uint16(b[end:]))
	r.bytesOff = end + 2
	if bc > len(b)-r.bytesOff {
		bc = len(b) - r.bytesOff
	}
	r.bytes = b[r.bytesOff : r.bytesOff+bc]
	return r, nil
}

// readStr reads a NUL terminated string (OEM or UTF-16LE) from b at pos.
// For unicode strings, pos is aligned on an even message offset when align
// is true (base is the offset of b within the message).
func readStr(b []byte, pos int, unicode bool, base int, align bool) (string, int) {
	if pos >= len(b) || pos < 0 {
		return "", len(b)
	}
	if !unicode {
		i := bytes.IndexByte(b[pos:], 0)
		if i < 0 {
			return sanitizeOEM(b[pos:]), len(b)
		}
		return sanitizeOEM(b[pos : pos+i]), pos + i + 1
	}
	if align && (base+pos)%2 == 1 {
		pos++
	}
	for i := pos; i+1 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			return ntlm.DecodeUTF16(b[pos:i]), i + 2
		}
	}
	if pos > len(b) {
		return "", len(b)
	}
	return ntlm.DecodeUTF16(b[pos:]), len(b)
}

func sanitizeOEM(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		}
	}
	return string(bytes.TrimSpace(out))
}

// ParseSMB1Negotiate decodes an SMB1 NEGOTIATE response.
func ParseSMB1Negotiate(b []byte) (*SMB1Info, uint16, error) {
	r, err := parseSMB1(b)
	if err != nil {
		return nil, 0, err
	}
	if r.cmd != smb1CmdNegotiate {
		return nil, 0, ErrSMB1Malformed
	}
	if r.status != 0 {
		return nil, 0, &StatusError{Command: smb1CmdNegotiate, Status: r.status}
	}
	if len(r.words) < 34 {
		return nil, 0, ErrSMB1Malformed
	}
	w := r.words
	idx := binary.LittleEndian.Uint16(w[0:])
	if idx == 0xffff {
		return nil, 0, errors.New("smb1: no common dialect")
	}
	info := &SMB1Info{
		Dialect:         "NT LM 0.12",
		SecurityMode:    w[2],
		MaxBufferSize:   binary.LittleEndian.Uint32(w[7:]),
		Capabilities:    binary.LittleEndian.Uint32(w[19:]),
		SystemTime:      ntlm.FiletimeToTime(binary.LittleEndian.Uint64(w[23:])),
		TimeZoneMinutes: int(int16(binary.LittleEndian.Uint16(w[31:]))),
	}
	info.UserLevel = info.SecurityMode&0x01 != 0
	info.EncryptPasswords = info.SecurityMode&0x02 != 0
	info.SigningEnabled = info.SecurityMode&0x04 != 0
	info.SigningRequired = info.SecurityMode&0x08 != 0
	info.ExtendedSecurity = info.Capabilities&smb1CapExtendedSecurity != 0
	chLen := int(w[33])
	bs := r.bytes
	if info.ExtendedSecurity {
		if len(bs) >= 16 {
			info.ServerGUID = FormatGUID(bs[:16])
			if allZero(bs[:16]) {
				info.ServerGUID = ""
			}
		}
		return info, r.uid, nil
	}
	if chLen > len(bs) {
		chLen = len(bs)
	}
	info.Challenge = append([]byte(nil), bs[:chLen]...)
	uni := r.flags2&smb1Flags2Unicode != 0
	var p int
	info.Domain, p = readStr(bs, chLen, uni, r.bytesOff, false)
	info.Server, _ = readStr(bs, p, uni, r.bytesOff, false)
	return info, r.uid, nil
}

// ParseSMB1SessionSetup fills info from a SESSION_SETUP_ANDX response.
func ParseSMB1SessionSetup(b []byte, info *SMB1Info) error {
	r, err := parseSMB1(b)
	if err != nil {
		return err
	}
	if r.cmd != smb1CmdSessionSetup {
		return ErrSMB1Malformed
	}
	info.SessionStatus = r.status
	if r.status != 0 {
		return &StatusError{Command: smb1CmdSessionSetup, Status: r.status}
	}
	info.SessionOK = true
	if len(r.words) >= 6 {
		info.Guest = binary.LittleEndian.Uint16(r.words[4:])&0x1 != 0
	}
	uni := r.flags2&smb1Flags2Unicode != 0
	var p int
	info.NativeOS, p = readStr(r.bytes, 0, uni, r.bytesOff, true)
	info.NativeLanMan, p = readStr(r.bytes, p, uni, r.bytesOff, false)
	info.PrimaryDomain, _ = readStr(r.bytes, p, uni, r.bytesOff, false)
	return nil
}

// SMB1Probe negotiates SMB1 and performs an anonymous session setup to read
// the server's NativeOS / NativeLanMan / domain strings. An error is returned
// only when SMB1 negotiation fails; a refused session setup leaves the
// session fields empty.
func SMB1Probe(ctx context.Context, ip string, port int, timeout time.Duration) (*SMB1Info, error) {
	t, err := DialTransport(ctx, ip, port, timeout, "")
	if err != nil {
		return nil, err
	}
	defer t.Close()
	resp, err := t.RoundTrip(BuildSMB1Negotiate())
	if err != nil {
		return nil, err
	}
	if IsSMB2(resp) {
		return nil, errors.New("smb1: server answered SMB2")
	}
	info, uid, err := ParseSMB1Negotiate(resp)
	if err != nil {
		return nil, err
	}
	if info.ExtendedSecurity {
		// The server insists on extended security: NTLM data is collected
		// through SMB2 instead. Native strings are not available.
		return info, nil
	}
	resp, err = t.RoundTrip(BuildSMB1SessionSetupAnon(uid))
	if err != nil {
		return info, nil
	}
	_ = ParseSMB1SessionSetup(resp, info)
	return info, nil
}
