package checks

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Minimal DCE/RPC (connection oriented, MS-RPCE) over SMB named pipes: BIND / BIND_ACK
// and REQUEST / RESPONSE with fragment reassembly, plus the NDR encoding of srvsvc
// NetrShareEnum (opnum 15) level 1.

const (
	rpcPtypeRequest  = 0
	rpcPtypeResponse = 2
	rpcPtypeFault    = 3
	rpcPtypeBind     = 11
	rpcPtypeBindAck  = 12
	rpcPtypeBindNak  = 13

	rpcFlagFirst = 0x01
	rpcFlagLast  = 0x02

	rpcMaxFrag = 4280
	// rpcMaxStub bounds reassembled responses.
	rpcMaxStub = 4 << 20
)

var (
	errRPCMalformed = errors.New("dcerpc: malformed PDU")
	// srvsvc 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0
	rpcSrvsvcUUID = rpcUUID("4b324fc8-1670-01d3-1278-5a47bf6ee188")
	// NDR transfer syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 v2
	rpcNDRUUID = rpcUUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
)

// rpcUUID encodes a textual UUID in its mixed-endian wire format. Only used with constant
// inputs.
func rpcUUID(s string) []byte {
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != 16 {
		panic("bad uuid " + s)
	}
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}

func rpcHeader(ptype byte, flags byte, fragLen int, callID uint32) []byte {
	h := make([]byte, 16)
	h[0], h[1], h[2], h[3] = 5, 0, ptype, flags
	h[4] = 0x10 // little endian, ASCII, IEEE
	binary.LittleEndian.PutUint16(h[8:], uint16(fragLen))
	binary.LittleEndian.PutUint32(h[12:], callID)
	return h
}

// rpcBuildBind builds a BIND for one interface with the NDR transfer syntax.
func rpcBuildBind(iface []byte, major, minor uint16, callID uint32) []byte {
	body := make([]byte, 0, 56)
	body = binary.LittleEndian.AppendUint16(body, rpcMaxFrag)
	body = binary.LittleEndian.AppendUint16(body, rpcMaxFrag)
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = append(body, 1, 0, 0, 0) // n_context_elem
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = append(body, 1, 0) // n_transfer_syn
	body = append(body, iface...)
	body = binary.LittleEndian.AppendUint16(body, major)
	body = binary.LittleEndian.AppendUint16(body, minor)
	body = append(body, rpcNDRUUID...)
	body = binary.LittleEndian.AppendUint32(body, 2)
	return append(rpcHeader(rpcPtypeBind, rpcFlagFirst|rpcFlagLast, 16+len(body), callID), body...)
}

// rpcPDU is one decoded PDU.
type rpcPDU struct {
	Ptype  byte
	Flags  byte
	CallID uint32
	Body   []byte // after the 16 byte header, without auth trailer
}

// rpcParsePDUs splits a byte stream into PDUs.
func rpcParsePDUs(b []byte) ([]rpcPDU, []byte, error) {
	var out []rpcPDU
	for len(b) >= 16 {
		if b[0] != 5 {
			return out, nil, errRPCMalformed
		}
		if b[4]&0x10 == 0 {
			return out, nil, fmt.Errorf("dcerpc: big endian data representation unsupported")
		}
		fl := int(binary.LittleEndian.Uint16(b[8:]))
		al := int(binary.LittleEndian.Uint16(b[10:]))
		if fl < 16 {
			return out, nil, errRPCMalformed
		}
		if fl > len(b) {
			return out, b, nil // incomplete
		}
		bodyEnd := fl
		if al > 0 {
			bodyEnd = fl - al - 8
			if bodyEnd < 16 {
				return out, nil, errRPCMalformed
			}
		}
		out = append(out, rpcPDU{Ptype: b[2], Flags: b[3], CallID: binary.LittleEndian.Uint32(b[12:]), Body: b[16:bodyEnd]})
		b = b[fl:]
	}
	return out, b, nil
}

// rpcCheckBindAck validates a BIND_ACK and returns an error on NAK/rejection.
func rpcCheckBindAck(b []byte) error {
	pdus, _, err := rpcParsePDUs(b)
	if err != nil {
		return err
	}
	if len(pdus) == 0 {
		return errRPCMalformed
	}
	p := pdus[0]
	switch p.Ptype {
	case rpcPtypeBindNak:
		return errors.New("dcerpc: bind rejected (bind_nak)")
	case rpcPtypeBindAck:
	default:
		return fmt.Errorf("dcerpc: unexpected ptype %d in bind response", p.Ptype)
	}
	body := p.Body
	if len(body) < 10 {
		return errRPCMalformed
	}
	secLen := int(binary.LittleEndian.Uint16(body[8:]))
	pos := 10 + secLen
	// align to 4 relative to PDU start (header is 16 bytes)
	for (pos+16)%4 != 0 {
		pos++
	}
	if pos+4 > len(body) {
		return errRPCMalformed
	}
	n := int(body[pos])
	pos += 4
	if n < 1 || pos+24 > len(body) {
		return errRPCMalformed
	}
	if res := binary.LittleEndian.Uint16(body[pos:]); res != 0 {
		return fmt.Errorf("dcerpc: presentation context rejected (result %d, reason %d)", res, binary.LittleEndian.Uint16(body[pos+2:]))
	}
	return nil
}

// rpcBuildRequest builds a single-fragment REQUEST (stubs here are tiny).
func rpcBuildRequest(opnum uint16, stub []byte, callID uint32) []byte {
	body := make([]byte, 8, 8+len(stub))
	binary.LittleEndian.PutUint32(body[0:], uint32(len(stub)))
	binary.LittleEndian.PutUint16(body[4:], 0)
	binary.LittleEndian.PutUint16(body[6:], opnum)
	body = append(body, stub...)
	return append(rpcHeader(rpcPtypeRequest, rpcFlagFirst|rpcFlagLast, 16+len(body), callID), body...)
}

// rpcFaultError is a DCE/RPC fault.
type rpcFaultError struct{ Status uint32 }

func (e *rpcFaultError) Error() string {
	switch e.Status {
	case 5:
		return "dcerpc fault: access denied"
	case 0x1c010003:
		return "dcerpc fault: nca_s_op_rng_error"
	}
	return fmt.Sprintf("dcerpc fault 0x%08x", e.Status)
}

// rpcAssembleResponse reassembles RESPONSE fragments from data. It returns the stub and
// done=true once the LAST fragment has been seen.
func rpcAssembleResponse(data []byte) (stub []byte, done bool, err error) {
	pdus, _, err := rpcParsePDUs(data)
	if err != nil {
		return nil, false, err
	}
	for _, p := range pdus {
		switch p.Ptype {
		case rpcPtypeFault:
			if len(p.Body) >= 12 {
				return nil, true, &rpcFaultError{Status: binary.LittleEndian.Uint32(p.Body[8:])}
			}
			return nil, true, &rpcFaultError{}
		case rpcPtypeResponse:
			if len(p.Body) < 8 {
				return nil, false, errRPCMalformed
			}
			stub = append(stub, p.Body[8:]...)
			if len(stub) > rpcMaxStub {
				return nil, false, errors.New("dcerpc: response too large")
			}
			if p.Flags&rpcFlagLast != 0 {
				return stub, true, nil
			}
		default:
			return nil, false, fmt.Errorf("dcerpc: unexpected ptype %d", p.Ptype)
		}
	}
	return stub, false, nil
}

// --------------------------------------------------------------------------- NDR helpers
// ---------------------------------------------------------------------------

type ndrWriter struct{ b []byte }

func (w *ndrWriter) align(n int) {
	for len(w.b)%n != 0 {
		w.b = append(w.b, 0)
	}
}
func (w *ndrWriter) u32(v uint32) { w.align(4); w.b = binary.LittleEndian.AppendUint32(w.b, v) }

// wstring writes a conformant varying NUL terminated UTF-16 string.
func (w *ndrWriter) wstring(s string) {
	u := utf16.Encode([]rune(s))
	u = append(u, 0)
	w.u32(uint32(len(u)))
	w.u32(0)
	w.u32(uint32(len(u)))
	for _, c := range u {
		w.b = binary.LittleEndian.AppendUint16(w.b, c)
	}
	w.align(4)
}

type ndrReader struct {
	b   []byte
	pos int
	err error
}

func (r *ndrReader) align(n int) {
	for r.pos%n != 0 {
		r.pos++
	}
}

func (r *ndrReader) u32() uint32 {
	if r.err != nil {
		return 0
	}
	r.align(4)
	if r.pos+4 > len(r.b) {
		r.err = errRPCMalformed
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v
}

// wstring reads a conformant varying UTF-16 string.
func (r *ndrReader) wstring() string {
	max := r.u32()
	off := r.u32()
	act := r.u32()
	if r.err != nil {
		return ""
	}
	if act > max || off > max || act > 1<<16 {
		r.err = errRPCMalformed
		return ""
	}
	n := int(act) * 2
	if r.pos+n > len(r.b) {
		r.err = errRPCMalformed
		return ""
	}
	u := make([]uint16, act)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(r.b[r.pos+2*i:])
	}
	r.pos += n
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return partASanitize(string(utf16.Decode(u)))
}

func partASanitize(s string) string {
	out := make([]rune, 0, len(s))
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// rpcNetShareEnumRequest encodes NetrShareEnum(ServerName, level 1, MaxLen 0xffffffff,
// ResumeHandle 0).
func rpcNetShareEnumRequest(server string) []byte {
	w := &ndrWriter{}
	w.u32(0x00020000) // referent ServerName
	w.wstring(`\\` + server)
	w.u32(1)          // Level
	w.u32(1)          // union switch
	w.u32(0x00020004) // referent SHARE_INFO_1_CONTAINER
	w.u32(0)          // EntriesRead
	w.u32(0)          // Buffer NULL
	w.u32(0xffffffff) // PreferedMaximumLength
	w.u32(0x00020008) // referent ResumeHandle
	w.u32(0)
	return w.b
}

// rpcShare is one SHARE_INFO_1 entry.
type rpcShare struct {
	Name   string
	Type   uint32
	Remark string
}

// TypeName describes the share type.
func (s rpcShare) TypeName() string {
	base := ""
	switch s.Type & 0x0fffffff {
	case 0:
		base = "disk"
	case 1:
		base = "printer"
	case 2:
		base = "device"
	case 3:
		base = "ipc"
	default:
		base = fmt.Sprintf("type-%d", s.Type&0x0fffffff)
	}
	if s.Type&0x80000000 != 0 {
		base += ",special"
	}
	if s.Type&0x40000000 != 0 {
		base += ",temporary"
	}
	return base
}

const rpcMaxShares = 1024

// rpcParseNetShareEnumResponse decodes the NetrShareEnum level 1 response stub and
// returns the shares (WERROR != 0 is reported as an error).
func rpcParseNetShareEnumResponse(stub []byte) ([]rpcShare, error) {
	if len(stub) < 4 {
		return nil, errRPCMalformed
	}
	if werr := binary.LittleEndian.Uint32(stub[len(stub)-4:]); werr != 0 && werr != 234 /* ERROR_MORE_DATA */ {
		if werr == 5 {
			return nil, errors.New("srvsvc: access denied")
		}
		return nil, fmt.Errorf("srvsvc: WERROR 0x%08x", werr)
	}
	r := &ndrReader{b: stub}
	level := r.u32()
	_ = r.u32() // switch
	if r.err == nil && level != 1 {
		return nil, fmt.Errorf("srvsvc: unexpected level %d", level)
	}
	if ptr := r.u32(); ptr == 0 || r.err != nil {
		return nil, errRPCMalformed
	}
	count := r.u32()
	bufPtr := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if bufPtr == 0 || count == 0 {
		return nil, nil
	}
	max := r.u32()
	if r.err != nil || max < count || count > rpcMaxShares {
		return nil, errRPCMalformed
	}
	type ent struct{ namePtr, typ, remPtr uint32 }
	ents := make([]ent, 0, count)
	for i := uint32(0); i < count; i++ {
		e := ent{r.u32(), r.u32(), r.u32()}
		if r.err != nil {
			return nil, r.err
		}
		ents = append(ents, e)
	}
	shares := make([]rpcShare, 0, count)
	for _, e := range ents {
		s := rpcShare{Type: e.typ}
		if e.namePtr != 0 {
			s.Name = r.wstring()
		}
		if e.remPtr != 0 {
			s.Remark = r.wstring()
		}
		if r.err != nil {
			return shares, r.err
		}
		shares = append(shares, s)
	}
	return shares, nil
}
