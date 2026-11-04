package fingerprint

import (
	"errors"
)

// Minimal BER/DER helpers for the UDP probes (SNMP, CLDAP, Kerberos).

type berTLV struct {
	class       byte // 0 universal, 1 application, 2 context, 3 private
	constructed bool
	tag         int
	value       []byte
}

var errBER = errors.New("ber: malformed element")

// parseBER decodes one element and returns the remaining bytes.
func parseBER(b []byte) (berTLV, []byte, error) {
	var t berTLV
	if len(b) < 2 {
		return t, nil, errBER
	}
	id := b[0]
	t.class = id >> 6
	t.constructed = id&0x20 != 0
	t.tag = int(id & 0x1f)
	i := 1
	if t.tag == 0x1f { // high tag number form
		t.tag = 0
		for {
			if i >= len(b) || i > 5 {
				return t, nil, errBER
			}
			c := b[i]
			i++
			t.tag = t.tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return t, nil, errBER
	}
	l := int(b[i])
	i++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || i+n > len(b) {
			return t, nil, errBER
		}
		l = 0
		for j := 0; j < n; j++ {
			l = l<<8 | int(b[i+j])
		}
		i += n
	}
	if l < 0 || i+l > len(b) {
		return t, nil, errBER
	}
	t.value = b[i : i+l]
	return t, b[i+l:], nil
}

// berChildren decodes all elements contained in a constructed value.
func berChildren(b []byte) []berTLV {
	var out []berTLV
	for len(b) > 0 {
		t, rest, err := parseBER(b)
		if err != nil {
			break
		}
		out = append(out, t)
		b = rest
	}
	return out
}

func berInt(v []byte) int64 {
	var n int64
	for i, c := range v {
		if i == 0 && c&0x80 != 0 {
			n = -1
		}
		n = n<<8 | int64(c)
	}
	return n
}

// ---- encoding ----

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n)}, tmp...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(tmp))}, tmp...)
}

func berTLVBytes(id byte, content ...[]byte) []byte {
	n := 0
	for _, c := range content {
		n += len(c)
	}
	out := []byte{id}
	out = append(out, berLen(n)...)
	for _, c := range content {
		out = append(out, c...)
	}
	return out
}

func berSeq(content ...[]byte) []byte { return berTLVBytes(0x30, content...) }

func berIntBytes(v int64) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
		if (v == 0 && b[0]&0x80 == 0) || (v == -1 && b[0]&0x80 != 0) {
			break
		}
	}
	return berTLVBytes(0x02, b)
}

func berOctets(s string) []byte { return berTLVBytes(0x04, []byte(s)) }

// berOID encodes a dotted OID given as integers.
func berOID(arcs ...int) []byte {
	if len(arcs) < 2 {
		return nil
	}
	b := []byte{byte(arcs[0]*40 + arcs[1])}
	for _, a := range arcs[2:] {
		var tmp []byte
		tmp = append(tmp, byte(a&0x7f))
		a >>= 7
		for a > 0 {
			tmp = append([]byte{byte(a&0x7f) | 0x80}, tmp...)
			a >>= 7
		}
		b = append(b, tmp...)
	}
	return berTLVBytes(0x06, b)
}
