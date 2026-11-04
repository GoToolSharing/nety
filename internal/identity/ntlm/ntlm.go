// Package ntlm implements the subset of MS-NLMP needed by NETY to fingerprint
// Windows hosts and to open anonymous / low-privilege sessions:
//
//   - building NEGOTIATE (type 1) messages,
//   - parsing CHALLENGE (type 2) messages, including the TargetInfo AV pairs
//     and the OS Version structure,
//   - building AUTHENTICATE (type 3) messages, anonymous or NTLMv2,
//   - minimal SPNEGO (RFC 4178) wrapping used by SMB, HTTP Negotiate, etc.
//
// Every parser is written for hostile input: all offsets are bounds checked and
// no function panics on malformed data.
package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// Signature is the 8 byte NTLMSSP message signature.
var Signature = []byte("NTLMSSP\x00")

// Negotiate flags (MS-NLMP 2.2.2.5).
const (
	FlagUnicode                 uint32 = 0x00000001
	FlagOEM                     uint32 = 0x00000002
	FlagRequestTarget           uint32 = 0x00000004
	FlagSign                    uint32 = 0x00000010
	FlagSeal                    uint32 = 0x00000020
	FlagLMKey                   uint32 = 0x00000080
	FlagNTLM                    uint32 = 0x00000200
	FlagAnonymous               uint32 = 0x00000800
	FlagOEMDomainSupplied       uint32 = 0x00001000
	FlagOEMWorkstationSupplied  uint32 = 0x00002000
	FlagAlwaysSign              uint32 = 0x00008000
	FlagTargetTypeDomain        uint32 = 0x00010000
	FlagTargetTypeServer        uint32 = 0x00020000
	FlagExtendedSessionSecurity uint32 = 0x00080000
	FlagIdentify                uint32 = 0x00100000
	FlagRequestNonNTSessionKey  uint32 = 0x00400000
	FlagTargetInfo              uint32 = 0x00800000
	FlagVersion                 uint32 = 0x02000000
	Flag128                     uint32 = 0x20000000
	FlagKeyExchange             uint32 = 0x40000000
	Flag56                      uint32 = 0x80000000
)

// DefaultNegotiateFlags are the flags sent in NEGOTIATE messages. They request
// the target name, target info and version so the CHALLENGE leaks as much
// identity information as possible.
const DefaultNegotiateFlags = FlagUnicode | FlagOEM | FlagRequestTarget | FlagNTLM |
	FlagAlwaysSign | FlagExtendedSessionSecurity | FlagTargetInfo | FlagVersion |
	Flag128 | Flag56

// AV pair identifiers (MS-NLMP 2.2.2.1).
const (
	AvEOL             uint16 = 0
	AvNbComputerName  uint16 = 1
	AvNbDomainName    uint16 = 2
	AvDNSComputerName uint16 = 3
	AvDNSDomainName   uint16 = 4
	AvDNSTreeName     uint16 = 5
	AvFlags           uint16 = 6
	AvTimestamp       uint16 = 7
	AvSingleHost      uint16 = 8
	AvTargetName      uint16 = 9
	AvChannelBindings uint16 = 10
)

// Errors returned by the parsers.
var (
	ErrNotNTLM     = errors.New("ntlm: not an NTLMSSP message")
	ErrWrongType   = errors.New("ntlm: unexpected message type")
	ErrTruncated   = errors.New("ntlm: truncated message")
	ErrNoChallenge = errors.New("ntlm: no CHALLENGE message found")
)

// Version is the NTLM VERSION structure (MS-NLMP 2.2.2.10).
type Version struct {
	Major        uint8  `json:"major"`
	Minor        uint8  `json:"minor"`
	Build        uint16 `json:"build"`
	NTLMRevision uint8  `json:"ntlm_revision"`
}

// String returns "major.minor.build", e.g. "10.0.17763".
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build)
}

// Challenge is a decoded CHALLENGE (type 2) message.
type Challenge struct {
	Flags           uint32
	ServerChallenge [8]byte
	TargetName      string
	NetBIOSComputer string
	NetBIOSDomain   string
	DNSComputer     string
	DNSDomain       string
	DNSTree         string
	TargetSPN       string
	AvFlags         uint32
	HasAvFlags      bool
	Timestamp       time.Time // zero when absent
	RawTimestamp    []byte    // 8 bytes FILETIME, nil when absent
	Version         *Version  // nil when absent
	TargetInfo      []byte    // raw AV pair list (copied)
}

// NegotiateMessage builds a NEGOTIATE (type 1) message with DefaultNegotiateFlags.
func NegotiateMessage() []byte { return NegotiateMessageFlags(DefaultNegotiateFlags) }

// NegotiateMessageFlags builds a NEGOTIATE message with custom flags. When
// FlagVersion is set, a Windows 10 style version block is included (servers
// ignore it, it only makes the message look like a stock client).
func NegotiateMessageFlags(flags uint32) []byte {
	b := make([]byte, 40)
	copy(b, Signature)
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], flags)
	// DomainNameFields and WorkstationFields: len=0 max=0 offset=40
	binary.LittleEndian.PutUint32(b[20:], 40)
	binary.LittleEndian.PutUint32(b[28:], 40)
	// Version: 10.0.19041, NTLM revision 15
	b[32] = 10
	b[33] = 0
	binary.LittleEndian.PutUint16(b[34:], 19041)
	b[39] = 15
	if flags&FlagVersion == 0 {
		return b[:32]
	}
	return b
}

// secBuf reads a security buffer descriptor (len, maxlen, offset) at off and
// returns the referenced bytes, bounds checked.
func secBuf(msg []byte, off int) ([]byte, bool) {
	if off+8 > len(msg) {
		return nil, false
	}
	l := int(binary.LittleEndian.Uint16(msg[off:]))
	o := int(binary.LittleEndian.Uint32(msg[off+4:]))
	if l == 0 {
		return nil, true
	}
	if o < 0 || o > len(msg) || l > len(msg)-o {
		return nil, false
	}
	return msg[o : o+l], true
}

// ParseChallenge decodes a CHALLENGE message starting at the NTLMSSP signature.
func ParseChallenge(msg []byte) (*Challenge, error) {
	if len(msg) < 32 {
		if len(msg) >= 8 && bytes.Equal(msg[:8], Signature) {
			return nil, ErrTruncated
		}
		return nil, ErrNotNTLM
	}
	if !bytes.Equal(msg[:8], Signature) {
		return nil, ErrNotNTLM
	}
	if t := binary.LittleEndian.Uint32(msg[8:]); t != 2 {
		return nil, fmt.Errorf("%w: %d", ErrWrongType, t)
	}
	c := &Challenge{}
	c.Flags = binary.LittleEndian.Uint32(msg[20:])
	copy(c.ServerChallenge[:], msg[24:32])
	unicode := c.Flags&FlagUnicode != 0
	if tn, ok := secBuf(msg, 12); ok && len(tn) > 0 {
		if unicode {
			c.TargetName = decodeUTF16(tn)
		} else {
			c.TargetName = sanitize(string(tn))
		}
	}
	// Payload start: the smallest non-zero offset among the buffers tells us
	// whether the optional TargetInfo / Version fields are present.
	payloadStart := len(msg)
	if l := binary.LittleEndian.Uint16(msg[12:]); l > 0 {
		if o := int(binary.LittleEndian.Uint32(msg[16:])); o < payloadStart {
			payloadStart = o
		}
	}
	if len(msg) >= 48 {
		if l := binary.LittleEndian.Uint16(msg[40:]); l > 0 {
			if o := int(binary.LittleEndian.Uint32(msg[44:])); o < payloadStart {
				payloadStart = o
			}
		}
		if ti, ok := secBuf(msg, 40); ok && len(ti) > 0 && payloadStart >= 48 {
			c.TargetInfo = append([]byte(nil), ti...)
			c.parseAV(ti)
		}
	}
	if len(msg) >= 56 && payloadStart >= 56 && c.Flags&FlagVersion != 0 {
		v := &Version{Major: msg[48], Minor: msg[49], Build: binary.LittleEndian.Uint16(msg[50:]), NTLMRevision: msg[55]}
		if v.Major != 0 || v.Build != 0 {
			c.Version = v
		}
	}
	return c, nil
}

func (c *Challenge) parseAV(ti []byte) {
	for _, av := range ParseAVPairs(ti) {
		switch av.ID {
		case AvNbComputerName:
			c.NetBIOSComputer = decodeUTF16(av.Value)
		case AvNbDomainName:
			c.NetBIOSDomain = decodeUTF16(av.Value)
		case AvDNSComputerName:
			c.DNSComputer = decodeUTF16(av.Value)
		case AvDNSDomainName:
			c.DNSDomain = decodeUTF16(av.Value)
		case AvDNSTreeName:
			c.DNSTree = decodeUTF16(av.Value)
		case AvTargetName:
			c.TargetSPN = decodeUTF16(av.Value)
		case AvFlags:
			if len(av.Value) >= 4 {
				c.AvFlags = binary.LittleEndian.Uint32(av.Value)
				c.HasAvFlags = true
			}
		case AvTimestamp:
			if len(av.Value) >= 8 {
				c.RawTimestamp = append([]byte(nil), av.Value[:8]...)
				c.Timestamp = FiletimeToTime(binary.LittleEndian.Uint64(av.Value))
			}
		}
	}
}

// AVPair is one TargetInfo attribute/value pair.
type AVPair struct {
	ID    uint16
	Value []byte
}

// ParseAVPairs decodes an AV pair list, stopping at MsvAvEOL or at the first
// malformed entry.
func ParseAVPairs(b []byte) []AVPair {
	var out []AVPair
	for len(b) >= 4 && len(out) < 64 {
		id := binary.LittleEndian.Uint16(b)
		l := int(binary.LittleEndian.Uint16(b[2:]))
		if id == AvEOL {
			break
		}
		if 4+l > len(b) {
			break
		}
		out = append(out, AVPair{ID: id, Value: b[4 : 4+l]})
		b = b[4+l:]
	}
	return out
}

// FindChallenge locates and parses an NTLMSSP CHALLENGE message anywhere in
// buf (e.g. inside SPNEGO, CredSSP, or an SMB security blob).
func FindChallenge(buf []byte) (*Challenge, error) {
	var lastErr error = ErrNoChallenge
	rest := buf
	base := 0
	for {
		i := bytes.Index(rest, Signature)
		if i < 0 {
			return nil, lastErr
		}
		c, err := ParseChallenge(rest[i:])
		if err == nil {
			return c, nil
		}
		lastErr = err
		base += i + len(Signature)
		rest = buf[base:]
	}
}

// FiletimeToTime converts a Windows FILETIME (100ns since 1601) to time.Time.
// Returns the zero time for 0 or absurd values.
func FiletimeToTime(ft uint64) time.Time {
	const epochDiff = 116444736000000000 // 1601 -> 1970 in 100ns
	if ft <= epochDiff || ft > epochDiff+uint64(400*365*24*3600)*10000000 {
		return time.Time{}
	}
	d := ft - epochDiff
	return time.Unix(int64(d/10000000), int64(d%10000000)*100).UTC()
}

// TimeToFiletime converts t to a Windows FILETIME.
func TimeToFiletime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UnixNano()/100) + 116444736000000000
}

func decodeUTF16(b []byte) string {
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return sanitize(string(utf16.Decode(u)))
}

// DecodeUTF16 decodes UTF-16LE bytes, dropping control characters.
func DecodeUTF16(b []byte) string { return decodeUTF16(b) }

// EncodeUTF16 encodes s as UTF-16LE.
func EncodeUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}

// sanitize strips NUL and control characters and trims spaces.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// ---------------------------------------------------------------------------
// AUTHENTICATE messages
// ---------------------------------------------------------------------------

// AnonymousAuthenticate builds an anonymous AUTHENTICATE message (null session,
// MS-NLMP 3.1.5.1.2: empty NT response, LM response Z(1)).
func AnonymousAuthenticate(ch *Challenge) []byte {
	flags := FlagUnicode | FlagNTLM | FlagAnonymous | FlagAlwaysSign | FlagExtendedSessionSecurity | Flag128 | Flag56 | FlagVersion
	if ch != nil && ch.Flags&FlagTargetInfo != 0 {
		flags |= FlagTargetInfo
	}
	return buildAuthenticate(flags, []byte{0}, nil, "", "", "", nil)
}

// Credentials used for NTLMv2 authentication.
type Credentials struct {
	Domain      string
	User        string
	Password    string
	Workstation string
}

// AuthResult is an NTLMv2 AUTHENTICATE message plus the derived session key.
type AuthResult struct {
	Message    []byte
	SessionKey []byte // SessionBaseKey (16 bytes), used for SMB signing
}

// Authenticate builds an NTLMv2 AUTHENTICATE message answering ch.
func Authenticate(ch *Challenge, cred Credentials) (AuthResult, error) {
	var cc [8]byte
	if _, err := rand.Read(cc[:]); err != nil {
		return AuthResult{}, err
	}
	return AuthenticateWith(ch, cred, cc, time.Now())
}

// NTOWFv2 computes the NTLMv2 response key.
func NTOWFv2(user, password, domain string) []byte {
	h := md4.New()
	h.Write(EncodeUTF16(password))
	nt := h.Sum(nil)
	m := hmac.New(md5.New, nt)
	m.Write(EncodeUTF16(strings.ToUpper(user) + domain))
	return m.Sum(nil)
}

func hmacMD5(key []byte, parts ...[]byte) []byte {
	m := hmac.New(md5.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// AuthenticateWith is Authenticate with an explicit client challenge and
// timestamp (deterministic, used by tests). The server timestamp from the
// CHALLENGE is preferred when present (as Windows does).
func AuthenticateWith(ch *Challenge, cred Credentials, clientChallenge [8]byte, now time.Time) (AuthResult, error) {
	if ch == nil {
		return AuthResult{}, errors.New("ntlm: nil challenge")
	}
	key := NTOWFv2(cred.User, cred.Password, cred.Domain)
	ts := make([]byte, 8)
	if len(ch.RawTimestamp) == 8 {
		copy(ts, ch.RawTimestamp)
	} else {
		binary.LittleEndian.PutUint64(ts, TimeToFiletime(now))
	}
	temp := make([]byte, 0, 28+len(ch.TargetInfo)+4)
	temp = append(temp, 1, 1, 0, 0, 0, 0, 0, 0)
	temp = append(temp, ts...)
	temp = append(temp, clientChallenge[:]...)
	temp = append(temp, 0, 0, 0, 0)
	ti := ch.TargetInfo
	if len(ti) == 0 {
		ti = []byte{0, 0, 0, 0}
	}
	temp = append(temp, ti...)
	temp = append(temp, 0, 0, 0, 0)
	proof := hmacMD5(key, ch.ServerChallenge[:], temp)
	nt := append(append([]byte{}, proof...), temp...)
	var lm []byte
	if len(ch.RawTimestamp) == 8 {
		lm = make([]byte, 24)
	} else {
		lm = append(hmacMD5(key, ch.ServerChallenge[:], clientChallenge[:]), clientChallenge[:]...)
	}
	sessionKey := hmacMD5(key, proof)
	flags := FlagUnicode | FlagRequestTarget | FlagNTLM | FlagAlwaysSign | FlagExtendedSessionSecurity |
		Flag128 | Flag56 | FlagVersion
	if ch.Flags&FlagTargetInfo != 0 {
		flags |= FlagTargetInfo
	}
	msg := buildAuthenticate(flags, lm, nt, cred.Domain, cred.User, cred.Workstation, nil)
	return AuthResult{Message: msg, SessionKey: sessionKey}, nil
}

func buildAuthenticate(flags uint32, lm, nt []byte, domain, user, ws string, encKey []byte) []byte {
	d, u, w := EncodeUTF16(domain), EncodeUTF16(user), EncodeUTF16(ws)
	const hdr = 72
	b := make([]byte, hdr, hdr+len(lm)+len(nt)+len(d)+len(u)+len(w)+len(encKey))
	copy(b, Signature)
	binary.LittleEndian.PutUint32(b[8:], 3)
	off := hdr
	put := func(field int, data []byte) {
		binary.LittleEndian.PutUint16(b[field:], uint16(len(data)))
		binary.LittleEndian.PutUint16(b[field+2:], uint16(len(data)))
		binary.LittleEndian.PutUint32(b[field+4:], uint32(off))
		off += len(data)
	}
	put(12, lm)
	put(20, nt)
	put(28, d)
	put(36, u)
	put(44, w)
	put(52, encKey)
	binary.LittleEndian.PutUint32(b[60:], flags)
	b[64] = 10
	binary.LittleEndian.PutUint16(b[66:], 19041)
	b[71] = 15
	b = append(b, lm...)
	b = append(b, nt...)
	b = append(b, d...)
	b = append(b, u...)
	b = append(b, w...)
	b = append(b, encKey...)
	return b
}
