package ntlm

import "errors"

// OIDs (DER encoded, without tag/length).
var (
	oidSPNEGO  = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	oidNTLMSSP = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

// derLen encodes a DER length.
func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// DER wraps content with tag and a DER length.
func DER(tag byte, content ...[]byte) []byte {
	n := 0
	for _, c := range content {
		n += len(c)
	}
	out := make([]byte, 0, n+5)
	out = append(out, tag)
	out = append(out, derLen(n)...)
	for _, c := range content {
		out = append(out, c...)
	}
	return out
}

// SPNEGOInit wraps an NTLM NEGOTIATE token in a GSS-API InitialContextToken carrying a
// NegTokenInit that offers only NTLMSSP.
func SPNEGOInit(token []byte) []byte {
	mechTypes := DER(0xa0, DER(0x30, DER(0x06, oidNTLMSSP)))
	mechToken := DER(0xa2, DER(0x04, token))
	negTokenInit := DER(0xa0, DER(0x30, mechTypes, mechToken))
	return DER(0x60, DER(0x06, oidSPNEGO), negTokenInit)
}

// SPNEGOResponse wraps an NTLM AUTHENTICATE token in a NegTokenResp.
func SPNEGOResponse(token []byte) []byte {
	return DER(0xa1, DER(0x30, DER(0xa2, DER(0x04, token))))
}

// ErrBadDER is returned by ReadTLV on malformed DER.
var ErrBadDER = errors.New("ntlm: malformed DER")

// ReadTLV reads one DER TLV from b and returns tag, value and the remaining bytes. Only
// definite lengths up to 4 bytes are accepted.
func ReadTLV(b []byte) (tag byte, val, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, ErrBadDER
	}
	tag = b[0]
	l := int(b[1])
	p := 2
	if l&0x80 != 0 {
		nb := l & 0x7f
		if nb == 0 || nb > 4 || len(b) < 2+nb {
			return 0, nil, nil, ErrBadDER
		}
		l = 0
		for i := 0; i < nb; i++ {
			l = l<<8 | int(b[2+i])
		}
		p += nb
	}
	if l < 0 || l > len(b)-p {
		return 0, nil, nil, ErrBadDER
	}
	return tag, b[p : p+l], b[p+l:], nil
}
