package smb

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vaadata/nety/internal/identity/ntlm"
)

// SMB2 commands.
const (
	CmdNegotiate      uint16 = 0x0000
	CmdSessionSetup   uint16 = 0x0001
	CmdLogoff         uint16 = 0x0002
	CmdTreeConnect    uint16 = 0x0003
	CmdTreeDisconnect uint16 = 0x0004
	CmdCreate         uint16 = 0x0005
	CmdClose          uint16 = 0x0006
	CmdRead           uint16 = 0x0008
	CmdWrite          uint16 = 0x0009
	CmdIoctl          uint16 = 0x000b
)

// NT status codes used by callers.
const (
	StatusSuccess                 uint32 = 0x00000000
	StatusPending                 uint32 = 0x00000103
	StatusBufferOverflow          uint32 = 0x80000005
	StatusMoreProcessingRequired  uint32 = 0xc0000016
	StatusAccessDenied            uint32 = 0xc0000022
	StatusLogonFailure            uint32 = 0xc000006d
	StatusAccountDisabled         uint32 = 0xc0000072
	StatusBadNetworkName          uint32 = 0xc00000cc
	StatusNotSupported            uint32 = 0xc00000bb
	StatusObjectNameNotFound      uint32 = 0xc0000034
	StatusPipeNotAvailable        uint32 = 0xc00000ac
	StatusUserSessionDeleted      uint32 = 0xc0000203
	StatusInsuffServerResources   uint32 = 0xc0000205
	StatusInvalidParameter        uint32 = 0xc000000d
	StatusEndOfFile               uint32 = 0xc0000011
	StatusPipeBroken              uint32 = 0xc000014b
	StatusNetworkSessionExpired   uint32 = 0xc000035c
	StatusAccountRestriction      uint32 = 0xc000006e
	StatusPasswordExpired         uint32 = 0xc0000071
	StatusPasswordMustChange      uint32 = 0xc0000224
	StatusAccountLockedOut        uint32 = 0xc0000234
	StatusInvalidLogonHours       uint32 = 0xc000006f
	StatusInvalidWorkstation      uint32 = 0xc0000070
	StatusWrongPassword           uint32 = 0xc000006a
	StatusNoSuchUser              uint32 = 0xc0000064
	StatusBadImpersonationLevel   uint32 = 0xc00000a5
	StatusRequestNotAccepted      uint32 = 0xc00000d0
	StatusInvalidDeviceRequest    uint32 = 0xc0000010
	StatusFSDriverRequired        uint32 = 0xc000019c
	StatusNotFound                uint32 = 0xc0000225
	StatusSMBBadUID               uint32 = 0x005b0002
	StatusNetworkNameDeleted      uint32 = 0xc00000c9
	StatusIOTimeout               uint32 = 0xc00000b5
	StatusPipeDisconnected        uint32 = 0xc00000b0
	StatusPipeEmpty               uint32 = 0xc00000d9
	StatusBadNetworkPath          uint32 = 0xc00000be
	StatusInvalidHandle           uint32 = 0xc0000008
	StatusSharingViolation        uint32 = 0xc0000043
	StatusNoMoreFiles             uint32 = 0x80000006
	StatusNotImplemented          uint32 = 0xc0000002
	StatusInvalidInfoClass        uint32 = 0xc0000003
	StatusUnsuccessful            uint32 = 0xc0000001
	StatusInsufficientResources   uint32 = 0xc000009a
	StatusNetworkAccessDenied     uint32 = 0xc00000ca
	StatusLogonTypeNotGranted     uint32 = 0xc000015b
	StatusTrustedRelationshipFail uint32 = 0xc000018d
)

// Dialects.
const (
	Dialect202 uint16 = 0x0202
	Dialect210 uint16 = 0x0210
	Dialect300 uint16 = 0x0300
	Dialect302 uint16 = 0x0302
	Dialect311 uint16 = 0x0311
)

// DialectName returns "2.0.2", "3.1.1"...
func DialectName(d uint16) string {
	switch d {
	case Dialect202:
		return "2.0.2"
	case Dialect210:
		return "2.1"
	case Dialect300:
		return "3.0"
	case Dialect302:
		return "3.0.2"
	case Dialect311:
		return "3.1.1"
	case 0x02ff:
		return "2.x (wildcard)"
	}
	return fmt.Sprintf("0x%04x", d)
}

// Security mode bits.
const (
	SigningEnabled  uint16 = 0x0001
	SigningRequired uint16 = 0x0002
)

// Session flags.
const (
	SessionFlagGuest   uint16 = 0x0001
	SessionFlagNull    uint16 = 0x0002
	SessionFlagEncrypt uint16 = 0x0004
)

// StatusError is a non-success NT status.
type StatusError struct {
	Command uint16
	Status  uint32
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("smb2: command 0x%02x failed: %s", e.Command, StatusName(e.Status))
}

// StatusOf returns the NT status carried by err, or 0.
func StatusOf(err error) uint32 {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// StatusName returns a symbolic name for well known statuses.
func StatusName(s uint32) string {
	if n, ok := statusNames[s]; ok {
		return n
	}
	return fmt.Sprintf("0x%08x", s)
}

var statusNames = map[uint32]string{
	StatusSuccess:                "STATUS_SUCCESS",
	StatusPending:                "STATUS_PENDING",
	StatusBufferOverflow:         "STATUS_BUFFER_OVERFLOW",
	StatusMoreProcessingRequired: "STATUS_MORE_PROCESSING_REQUIRED",
	StatusAccessDenied:           "STATUS_ACCESS_DENIED",
	StatusLogonFailure:           "STATUS_LOGON_FAILURE",
	StatusAccountDisabled:        "STATUS_ACCOUNT_DISABLED",
	StatusBadNetworkName:         "STATUS_BAD_NETWORK_NAME",
	StatusNotSupported:           "STATUS_NOT_SUPPORTED",
	StatusObjectNameNotFound:     "STATUS_OBJECT_NAME_NOT_FOUND",
	StatusPipeNotAvailable:       "STATUS_PIPE_NOT_AVAILABLE",
	StatusUserSessionDeleted:     "STATUS_USER_SESSION_DELETED",
	StatusInsuffServerResources:  "STATUS_INSUFF_SERVER_RESOURCES",
	StatusInvalidParameter:       "STATUS_INVALID_PARAMETER",
	StatusAccountLockedOut:       "STATUS_ACCOUNT_LOCKED_OUT",
	StatusPasswordExpired:        "STATUS_PASSWORD_EXPIRED",
	StatusPasswordMustChange:     "STATUS_PASSWORD_MUST_CHANGE",
	StatusAccountRestriction:     "STATUS_ACCOUNT_RESTRICTION",
	StatusPipeBroken:             "STATUS_PIPE_BROKEN",
	StatusNetworkAccessDenied:    "STATUS_NETWORK_ACCESS_DENIED",
	StatusLogonTypeNotGranted:    "STATUS_LOGON_TYPE_NOT_GRANTED",
	StatusRequestNotAccepted:     "STATUS_REQUEST_NOT_ACCEPTED",
	StatusInvalidHandle:          "STATUS_INVALID_HANDLE",
	StatusEndOfFile:              "STATUS_END_OF_FILE",
}

// NegotiateInfo is what a NEGOTIATE response reveals.
type NegotiateInfo struct {
	Dialect         uint16
	SecurityMode    uint16
	SigningEnabled  bool
	SigningRequired bool
	ServerGUID      string // canonical lowercase GUID
	Capabilities    uint32
	MaxTransactSize uint32
	MaxReadSize     uint32
	MaxWriteSize    uint32
	SystemTime      time.Time
	ServerStartTime time.Time
	SecurityBlob    []byte
	Ciphers         []uint16 // SMB 3.1.1 encryption context
	SigningAlgos    []uint16
	Compression     []uint16
}

// DialectString returns the human dialect name.
func (n *NegotiateInfo) DialectString() string { return DialectName(n.Dialect) }

// Conn is an SMB2 connection.
type Conn struct {
	t            *Transport
	msgID        uint64
	sessionID    uint64
	Negotiated   *NegotiateInfo
	SessionFlags uint16
	ip           string
}

// Dial opens an SMB connection (no negotiation yet).
func Dial(ctx context.Context, ip string, port int, timeout time.Duration) (*Conn, error) {
	t, err := DialTransport(ctx, ip, port, timeout, "")
	if err != nil {
		return nil, err
	}
	return &Conn{t: t, ip: ip}, nil
}

// NewConn wraps a transport (tests).
func NewConn(t *Transport, ip string) *Conn { return &Conn{t: t, ip: ip} }

// Close closes the connection (best effort LOGOFF first when a session exists).
func (c *Conn) Close() error {
	if c.sessionID != 0 {
		_, _ = c.request(CmdLogoff, 0, []byte{4, 0, 0, 0})
		c.sessionID = 0
	}
	return c.t.Close()
}

// SessionID returns the current session id.
func (c *Conn) SessionID() uint64 { return c.sessionID }

func (c *Conn) header(cmd uint16, treeID uint32) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:], 64)
	if c.Negotiated != nil && c.Negotiated.Dialect != Dialect202 {
		binary.LittleEndian.PutUint16(h[6:], 1) // credit charge
	}
	binary.LittleEndian.PutUint16(h[12:], cmd)
	binary.LittleEndian.PutUint16(h[14:], 31) // credits requested
	binary.LittleEndian.PutUint64(h[24:], c.msgID)
	binary.LittleEndian.PutUint32(h[32:], 0xfeff)
	binary.LittleEndian.PutUint32(h[36:], treeID)
	binary.LittleEndian.PutUint64(h[40:], c.sessionID)
	return h
}

// Response is a decoded SMB2 response header + body.
type Response struct {
	Status    uint32
	Command   uint16
	Flags     uint32
	MessageID uint64
	TreeID    uint32
	SessionID uint64
	Raw       []byte // whole message (offsets in bodies are relative to it)
	Body      []byte
}

// ParseResponse decodes an SMB2 header.
func ParseResponse(b []byte) (*Response, error) {
	if IsSMB1(b) {
		return nil, ErrSMB1Only
	}
	if !IsSMB2(b) || len(b) < 64 {
		return nil, ErrNotSMB
	}
	r := &Response{
		Status:    binary.LittleEndian.Uint32(b[8:]),
		Command:   binary.LittleEndian.Uint16(b[12:]),
		Flags:     binary.LittleEndian.Uint32(b[16:]),
		MessageID: binary.LittleEndian.Uint64(b[24:]),
		SessionID: binary.LittleEndian.Uint64(b[40:]),
		Raw:       b,
		Body:      b[64:],
	}
	if r.Flags&0x2 == 0 { // sync
		r.TreeID = binary.LittleEndian.Uint32(b[36:])
	}
	if next := binary.LittleEndian.Uint32(b[20:]); next != 0 && int(next) <= len(b) && next >= 64 {
		r.Raw = b[:next] // ignore compounded tail
		r.Body = b[64:next]
	}
	return r, nil
}

// request sends cmd with body and waits for the matching final response.
// Responses with non-success status are returned along with a *StatusError,
// except STATUS_MORE_PROCESSING_REQUIRED and STATUS_BUFFER_OVERFLOW which
// are informational.
func (c *Conn) request(cmd uint16, treeID uint32, body []byte) (*Response, error) {
	msg := append(c.header(cmd, treeID), body...)
	id := c.msgID
	c.msgID++
	if err := c.t.Send(msg); err != nil {
		return nil, err
	}
	for i := 0; i < 32; i++ {
		raw, err := c.t.Recv()
		if err != nil {
			return nil, err
		}
		r, err := ParseResponse(raw)
		if err != nil {
			return nil, err
		}
		if r.MessageID != id && r.MessageID != ^uint64(0) {
			continue // stray response
		}
		if r.MessageID == ^uint64(0) { // oplock break notification
			continue
		}
		if r.Status == StatusPending && r.Flags&0x2 != 0 {
			continue // interim async response
		}
		switch r.Status {
		case StatusSuccess, StatusMoreProcessingRequired, StatusBufferOverflow:
			return r, nil
		}
		return r, &StatusError{Command: cmd, Status: r.Status}
	}
	return nil, ErrMalformed
}

// buildNegotiate builds the NEGOTIATE request body.
func buildNegotiate(dialects []uint16, clientGUID, salt []byte) []byte {
	b := make([]byte, 36)
	binary.LittleEndian.PutUint16(b[0:], 36)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(b[4:], SigningEnabled)
	binary.LittleEndian.PutUint32(b[8:], 0x45) // DFS | LARGE_MTU | ENCRYPTION
	copy(b[12:28], clientGUID)
	has311 := false
	for _, d := range dialects {
		var x [2]byte
		binary.LittleEndian.PutUint16(x[:], d)
		b = append(b, x[:]...)
		if d == Dialect311 {
			has311 = true
		}
	}
	if !has311 {
		return b
	}
	for (64+len(b))%8 != 0 {
		b = append(b, 0)
	}
	binary.LittleEndian.PutUint32(b[28:], uint32(64+len(b)))
	binary.LittleEndian.PutUint16(b[32:], 3)
	// preauth integrity: SHA-512 + 32 byte salt
	pre := make([]byte, 6+len(salt))
	binary.LittleEndian.PutUint16(pre[0:], 1)
	binary.LittleEndian.PutUint16(pre[2:], uint16(len(salt)))
	binary.LittleEndian.PutUint16(pre[4:], 1)
	copy(pre[6:], salt)
	b = appendContext(b, 1, pre)
	// encryption: AES-128-GCM, AES-128-CCM, AES-256-GCM, AES-256-CCM
	enc := []byte{4, 0, 2, 0, 1, 0, 4, 0, 3, 0}
	b = appendContext(b, 2, enc)
	// signing: AES-CMAC, HMAC-SHA256, AES-GMAC
	sig := []byte{3, 0, 1, 0, 0, 0, 2, 0}
	b = appendContext(b, 8, sig)
	return b
}

func appendContext(b []byte, typ uint16, data []byte) []byte {
	for (64+len(b))%8 != 0 {
		b = append(b, 0)
	}
	h := make([]byte, 8)
	binary.LittleEndian.PutUint16(h[0:], typ)
	binary.LittleEndian.PutUint16(h[2:], uint16(len(data)))
	b = append(b, h...)
	return append(b, data...)
}

// DefaultDialects are offered in NEGOTIATE.
var DefaultDialects = []uint16{Dialect202, Dialect210, Dialect300, Dialect302, Dialect311}

// Negotiate performs SMB2 NEGOTIATE. ErrSMB1Only is returned when the server
// only speaks SMB1.
func (c *Conn) Negotiate(dialects ...uint16) (*NegotiateInfo, error) {
	if len(dialects) == 0 {
		dialects = DefaultDialects
	}
	guid := make([]byte, 16)
	salt := make([]byte, 32)
	_, _ = rand.Read(guid)
	_, _ = rand.Read(salt)
	r, err := c.request(CmdNegotiate, 0, buildNegotiate(dialects, guid, salt))
	if err != nil {
		return nil, err
	}
	ni, err := ParseNegotiateResponse(r.Raw)
	if err != nil {
		return nil, err
	}
	c.Negotiated = ni
	return ni, nil
}

// ParseNegotiateResponse decodes a full SMB2 NEGOTIATE response message.
func ParseNegotiateResponse(raw []byte) (*NegotiateInfo, error) {
	r, err := ParseResponse(raw)
	if err != nil {
		return nil, err
	}
	if r.Command != CmdNegotiate {
		return nil, ErrMalformed
	}
	if r.Status != StatusSuccess {
		return nil, &StatusError{Command: CmdNegotiate, Status: r.Status}
	}
	b := r.Body
	if len(b) < 64 || binary.LittleEndian.Uint16(b) != 65 {
		return nil, ErrMalformed
	}
	ni := &NegotiateInfo{
		SecurityMode:    binary.LittleEndian.Uint16(b[2:]),
		Dialect:         binary.LittleEndian.Uint16(b[4:]),
		ServerGUID:      FormatGUID(b[8:24]),
		Capabilities:    binary.LittleEndian.Uint32(b[24:]),
		MaxTransactSize: binary.LittleEndian.Uint32(b[28:]),
		MaxReadSize:     binary.LittleEndian.Uint32(b[32:]),
		MaxWriteSize:    binary.LittleEndian.Uint32(b[36:]),
		SystemTime:      ntlm.FiletimeToTime(binary.LittleEndian.Uint64(b[40:])),
		ServerStartTime: ntlm.FiletimeToTime(binary.LittleEndian.Uint64(b[48:])),
	}
	ni.SigningEnabled = ni.SecurityMode&SigningEnabled != 0
	ni.SigningRequired = ni.SecurityMode&SigningRequired != 0
	if allZero(b[8:24]) {
		ni.ServerGUID = ""
	}
	off := int(binary.LittleEndian.Uint16(b[56:]))
	l := int(binary.LittleEndian.Uint16(b[58:]))
	if l > 0 && off >= 64 && off+l <= len(r.Raw) {
		ni.SecurityBlob = append([]byte(nil), r.Raw[off:off+l]...)
	}
	if ni.Dialect == Dialect311 {
		cnt := int(binary.LittleEndian.Uint16(b[6:]))
		coff := int(binary.LittleEndian.Uint32(b[60:]))
		parseNegContexts(ni, r.Raw, coff, cnt)
	}
	return ni, nil
}

func parseNegContexts(ni *NegotiateInfo, raw []byte, off, cnt int) {
	if cnt > 16 {
		cnt = 16
	}
	for i := 0; i < cnt; i++ {
		for off%8 != 0 {
			off++
		}
		if off < 64 || off+8 > len(raw) {
			return
		}
		typ := binary.LittleEndian.Uint16(raw[off:])
		l := int(binary.LittleEndian.Uint16(raw[off+2:]))
		d := off + 8
		if d+l > len(raw) {
			return
		}
		data := raw[d : d+l]
		list := func(skip int) []uint16 {
			if len(data) < skip+2 {
				return nil
			}
			n := int(binary.LittleEndian.Uint16(data[skip:]))
			var out []uint16
			for j := 0; j < n && skip+2+2*j+2 <= len(data); j++ {
				out = append(out, binary.LittleEndian.Uint16(data[skip+2+2*j:]))
			}
			return out
		}
		switch typ {
		case 2:
			ni.Ciphers = list(0)
		case 3:
			ni.Compression = list(0)
		case 8:
			ni.SigningAlgos = list(0)
		}
		off = d + l
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// SessionSetup sends one SESSION_SETUP round with the given security blob.
// It returns the response (status MORE_PROCESSING_REQUIRED or SUCCESS) and
// the server security blob.
func (c *Conn) SessionSetup(blob []byte) (*Response, []byte, error) {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b[0:], 25)
	b[3] = byte(SigningEnabled)
	binary.LittleEndian.PutUint16(b[12:], 64+24)
	binary.LittleEndian.PutUint16(b[14:], uint16(len(blob)))
	b = append(b, blob...)
	r, err := c.request(CmdSessionSetup, 0, b)
	if r != nil && r.SessionID != 0 && (err == nil) {
		c.sessionID = r.SessionID
	}
	if err != nil {
		return r, nil, err
	}
	if len(r.Body) < 8 {
		return r, nil, ErrMalformed
	}
	c.SessionFlags = binary.LittleEndian.Uint16(r.Body[2:])
	off := int(binary.LittleEndian.Uint16(r.Body[4:]))
	l := int(binary.LittleEndian.Uint16(r.Body[6:]))
	var out []byte
	if l > 0 && off >= 64 && off+l <= len(r.Raw) {
		out = r.Raw[off : off+l]
	}
	return r, out, nil
}

// Challenge performs the first NTLM SESSION_SETUP leg and returns the server
// CHALLENGE. The session is left half open (call Authenticate or Close).
func (c *Conn) Challenge() (*ntlm.Challenge, error) {
	r, blob, err := c.SessionSetup(ntlm.SPNEGOInit(ntlm.NegotiateMessage()))
	if err != nil {
		return nil, err
	}
	if r.Status != StatusMoreProcessingRequired {
		return nil, fmt.Errorf("smb2: unexpected session setup status %s", StatusName(r.Status))
	}
	return ntlm.FindChallenge(blob)
}

// SessionInfo describes an established session.
type SessionInfo struct {
	Challenge *ntlm.Challenge
	Guest     bool
	Null      bool
	Encrypt   bool // server demands encryption: further requests will fail
}

// Login performs a full NTLM authentication. cred == nil means anonymous
// (null session).
func (c *Conn) Login(cred *ntlm.Credentials) (*SessionInfo, error) {
	ch, err := c.Challenge()
	if err != nil {
		return nil, err
	}
	var tok []byte
	if cred == nil {
		tok = ntlm.AnonymousAuthenticate(ch)
	} else {
		res, err := ntlm.Authenticate(ch, *cred)
		if err != nil {
			return nil, err
		}
		tok = res.Message
	}
	_, _, err = c.SessionSetup(ntlm.SPNEGOResponse(tok))
	if err != nil {
		c.sessionID = 0
		return &SessionInfo{Challenge: ch}, err
	}
	return &SessionInfo{
		Challenge: ch,
		Guest:     c.SessionFlags&SessionFlagGuest != 0,
		Null:      c.SessionFlags&SessionFlagNull != 0 || cred == nil,
		Encrypt:   c.SessionFlags&SessionFlagEncrypt != 0,
	}, nil
}

// Tree is a connected share.
type Tree struct {
	ID            uint32
	ShareType     uint8 // 1 disk, 2 pipe, 3 print
	ShareFlags    uint32
	Capabilities  uint32
	MaximalAccess uint32
}

// TreeConnect connects to \\ip\share.
func (c *Conn) TreeConnect(share string) (*Tree, error) {
	path := ntlm.EncodeUTF16(`\\` + c.ip + `\` + share)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b[0:], 9)
	binary.LittleEndian.PutUint16(b[4:], 64+8)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(path)))
	b = append(b, path...)
	r, err := c.request(CmdTreeConnect, 0, b)
	if err != nil {
		return nil, err
	}
	if len(r.Body) < 16 {
		return nil, ErrMalformed
	}
	return &Tree{
		ID:            r.TreeID,
		ShareType:     r.Body[2],
		ShareFlags:    binary.LittleEndian.Uint32(r.Body[4:]),
		Capabilities:  binary.LittleEndian.Uint32(r.Body[8:]),
		MaximalAccess: binary.LittleEndian.Uint32(r.Body[12:]),
	}, nil
}

// TreeDisconnect disconnects a tree.
func (c *Conn) TreeDisconnect(t *Tree) error {
	_, err := c.request(CmdTreeDisconnect, t.ID, []byte{4, 0, 0, 0})
	return err
}

// FileID is an SMB2 file handle.
type FileID [16]byte

// OpenPipe opens a named pipe (e.g. "srvsvc") on an IPC$ tree.
func (c *Conn) OpenPipe(t *Tree, name string) (FileID, error) {
	return c.Create(t, strings.TrimPrefix(name, `\`), 0x0012019f, 0x00000007, 1, 0x00400040)
}

// Create issues a CREATE. access/share/disposition/options are raw SMB2 values.
func (c *Conn) Create(t *Tree, name string, access, share, disposition, options uint32) (FileID, error) {
	var fid FileID
	n := ntlm.EncodeUTF16(name)
	b := make([]byte, 56)
	binary.LittleEndian.PutUint16(b[0:], 57)
	binary.LittleEndian.PutUint32(b[4:], 2) // impersonation
	binary.LittleEndian.PutUint32(b[24:], access)
	binary.LittleEndian.PutUint32(b[32:], share)
	binary.LittleEndian.PutUint32(b[36:], disposition)
	binary.LittleEndian.PutUint32(b[40:], options)
	binary.LittleEndian.PutUint16(b[44:], 64+56)
	binary.LittleEndian.PutUint16(b[46:], uint16(len(n)))
	b = append(b, n...)
	if len(n) == 0 {
		b = append(b, 0)
	}
	r, err := c.request(CmdCreate, t.ID, b)
	if err != nil {
		return fid, err
	}
	if len(r.Body) < 80 {
		return fid, ErrMalformed
	}
	copy(fid[:], r.Body[64:80])
	return fid, nil
}

// CloseFile closes a handle.
func (c *Conn) CloseFile(t *Tree, fid FileID) error {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b[0:], 24)
	copy(b[8:], fid[:])
	_, err := c.request(CmdClose, t.ID, b)
	return err
}

// Write writes data at offset 0 (pipes).
func (c *Conn) Write(t *Tree, fid FileID, data []byte) (int, error) {
	b := make([]byte, 48)
	binary.LittleEndian.PutUint16(b[0:], 49)
	binary.LittleEndian.PutUint16(b[2:], 64+48)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	copy(b[16:], fid[:])
	b = append(b, data...)
	r, err := c.request(CmdWrite, t.ID, b)
	if err != nil {
		return 0, err
	}
	if len(r.Body) < 8 {
		return 0, ErrMalformed
	}
	return int(binary.LittleEndian.Uint32(r.Body[4:])), nil
}

// Read reads up to n bytes. The returned bool is true when more data is
// pending in the pipe message (STATUS_BUFFER_OVERFLOW).
func (c *Conn) Read(t *Tree, fid FileID, n int) ([]byte, bool, error) {
	if n <= 0 || n > 1<<16 {
		n = 1 << 16
	}
	b := make([]byte, 49)
	binary.LittleEndian.PutUint16(b[0:], 49)
	b[2] = 0x50
	binary.LittleEndian.PutUint32(b[4:], uint32(n))
	copy(b[16:], fid[:])
	r, err := c.request(CmdRead, t.ID, b)
	if err != nil {
		return nil, false, err
	}
	data, err := readBody(r)
	return data, r.Status == StatusBufferOverflow, err
}

func readBody(r *Response) ([]byte, error) {
	if len(r.Body) < 16 {
		return nil, ErrMalformed
	}
	off := int(r.Body[2])
	l := int(binary.LittleEndian.Uint32(r.Body[4:]))
	if l == 0 {
		return nil, nil
	}
	if off < 64 || l > len(r.Raw)-off {
		return nil, ErrMalformed
	}
	return append([]byte(nil), r.Raw[off:off+l]...), nil
}

// FSCTLPipeTransceive is the IOCTL code for a pipe write+read.
const FSCTLPipeTransceive uint32 = 0x0011c017

// Transceive writes in to the pipe and reads the full reply message
// (following up with READs on STATUS_BUFFER_OVERFLOW). The reply is capped
// at maxOut bytes total (default 1 MiB).
func (c *Conn) Transceive(t *Tree, fid FileID, in []byte, maxOut int) ([]byte, error) {
	if maxOut <= 0 || maxOut > MaxMessageSize {
		maxOut = MaxMessageSize
	}
	b := make([]byte, 56)
	binary.LittleEndian.PutUint16(b[0:], 57)
	binary.LittleEndian.PutUint32(b[4:], FSCTLPipeTransceive)
	copy(b[8:], fid[:])
	binary.LittleEndian.PutUint32(b[24:], 64+56)
	binary.LittleEndian.PutUint32(b[28:], uint32(len(in)))
	binary.LittleEndian.PutUint32(b[40:], 64+56+uint32(len(in)))
	chunk := 4280
	if c.Negotiated != nil && c.Negotiated.MaxTransactSize > 0 && int(c.Negotiated.MaxTransactSize) < 65536 {
		chunk = int(c.Negotiated.MaxTransactSize)
	}
	binary.LittleEndian.PutUint32(b[44:], uint32(chunk))
	binary.LittleEndian.PutUint32(b[48:], 1) // IS_FSCTL
	b = append(b, in...)
	r, err := c.request(CmdIoctl, t.ID, b)
	if err != nil {
		return nil, err
	}
	if len(r.Body) < 48 {
		return nil, ErrMalformed
	}
	off := int(binary.LittleEndian.Uint32(r.Body[32:]))
	l := int(binary.LittleEndian.Uint32(r.Body[36:]))
	var out []byte
	if l > 0 {
		if off < 64 || off > len(r.Raw) || l > len(r.Raw)-off {
			return nil, ErrMalformed
		}
		out = append(out, r.Raw[off:off+l]...)
	}
	more := r.Status == StatusBufferOverflow
	for more && len(out) < maxOut {
		var data []byte
		data, more, err = c.Read(t, fid, chunk)
		if err != nil {
			return out, err
		}
		if len(data) == 0 {
			break
		}
		out = append(out, data...)
	}
	if len(out) > maxOut {
		out = out[:maxOut]
	}
	return out, nil
}
