package fingerprint

import (
	"encoding/base64"
	"math/bits"
	"strconv"
)

// murmur3_32 is MurmurHash3 x86 32-bit.
func murmur3_32(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h := seed
	n := len(data)
	nblocks := n / 4
	for i := 0; i < nblocks; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// base64MIME mimics Python's base64.encodebytes: standard alphabet, a "\n" after every 76
// characters and at the end.
func base64MIME(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	enc := base64.StdEncoding.EncodeToString(b)
	out := make([]byte, 0, len(enc)+len(enc)/76+1)
	for len(enc) > 76 {
		out = append(out, enc[:76]...)
		out = append(out, '\n')
		enc = enc[76:]
	}
	out = append(out, enc...)
	out = append(out, '\n')
	return out
}

// faviconHash returns the Shodan-style favicon hash:
// mmh3.hash(base64.encodebytes(data)) as a signed 32-bit decimal string.
func faviconHash(data []byte) string {
	return strconv.FormatInt(int64(int32(murmur3_32(base64MIME(data), 0))), 10)
}
