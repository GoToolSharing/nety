package udpprobe

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// Minimal, bounded BER/DER codec. Only what SNMP needs: definite lengths,
// single-byte tags, no indefinite form. Every parse step is bounds-checked and
// no allocation is driven by a peer-supplied length.

const (
	tagInteger   byte = 0x02
	tagOctetStr  byte = 0x04
	tagNull      byte = 0x05
	tagOID       byte = 0x06
	tagSequence  byte = 0x30
	tagIPAddress byte = 0x40
	tagCounter32 byte = 0x41
	tagGauge32   byte = 0x42
	tagTimeTicks byte = 0x43
	tagOpaque    byte = 0x44
	tagCounter64 byte = 0x46
)

type tlv struct {
	tag     byte
	content []byte
}

// parseTLV decodes one element and returns the bytes following it.
func parseTLV(b []byte) (t tlv, rest []byte, ok bool) {
	if len(b) < 2 {
		return t, nil, false
	}
	t.tag = b[0]
	if t.tag&0x1f == 0x1f {
		return t, nil, false // high-tag-number form: never used by SNMP
	}
	i := 1
	l := int(b[i])
	i++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || i+n > len(b) {
			return t, nil, false
		}
		var acc uint64
		for k := 0; k < n; k++ {
			acc = acc<<8 | uint64(b[i+k])
		}
		i += n
		if acc > uint64(len(b)) {
			return t, nil, false
		}
		l = int(acc)
	}
	if l < 0 || l > len(b)-i {
		return t, nil, false
	}
	t.content = b[i : i+l]
	return t, b[i+l:], true
}

// parseSeq decodes one element, requires the given tag and returns its content.
func parseSeq(b []byte, tag byte) ([]byte, bool) {
	t, _, ok := parseTLV(b)
	if !ok || t.tag != tag {
		return nil, false
	}
	return t.content, true
}

// berInt decodes a two's-complement INTEGER body.
func berInt(content []byte) (int64, bool) {
	if len(content) == 0 || len(content) > 8 {
		return 0, false
	}
	v := int64(int8(content[0]))
	for _, c := range content[1:] {
		v = v<<8 | int64(c)
	}
	return v, true
}

// berUint decodes an unsigned integer body (Counter32/Gauge32/TimeTicks), which
// may carry a leading zero padding byte.
func berUint(content []byte) (uint64, bool) {
	if len(content) == 0 || len(content) > 9 {
		return 0, false
	}
	var v uint64
	for _, c := range content {
		v = v<<8 | uint64(c)
	}
	return v, true
}

const maxOIDArcs = 64

// decodeOID renders an OID body as a dotted string, capped at maxOIDArcs arcs.
func decodeOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	first := int(b[0])
	a0, a1 := first/40, first%40
	if first >= 80 {
		a0, a1 = 2, first-80
	}
	sb.WriteString(itoa(a0))
	sb.WriteByte('.')
	sb.WriteString(itoa(a1))
	var v uint64
	arcs := 0
	for _, c := range b[1:] {
		if arcs >= maxOIDArcs {
			break
		}
		if v > 1<<55 {
			return sb.String() // absurd arc, stop rather than wrap
		}
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			sb.WriteByte('.')
			sb.WriteString(strconv.FormatUint(v, 10))
			v = 0
			arcs++
		}
	}
	return sb.String()
}

// --- encoding -------------------------------------------------------------

func encLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func enc(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+4)
	out = append(out, tag)
	out = append(out, encLen(len(content))...)
	return append(out, content...)
}

func encInt(v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	i := 0
	for i < 7 {
		if b[i] == 0x00 && b[i+1]&0x80 == 0 {
			i++
			continue
		}
		if b[i] == 0xff && b[i+1]&0x80 != 0 {
			i++
			continue
		}
		break
	}
	return enc(tagInteger, b[i:])
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func encSeq(parts ...[]byte) []byte { return enc(tagSequence, concat(parts...)) }
