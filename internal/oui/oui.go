// Package oui resolves a MAC address to its IEEE-registered vendor.
//
// The database is an embedded, gzip-compressed snapshot of the IEEE MA-L (24-bit), MA-M
// (28-bit) and MA-S/IAB (36-bit) registries. It is decoded lazily, on the first lookup,
// so a process that never resolves a MAC pays nothing for it. Decoding is a single pass
// over a few hundred kilobytes and takes a handful of milliseconds; vendor strings are
// slices of one shared string, so lookups themselves never allocate.
//
// Regenerate the embedded file from the repository root with:
//
//	go run internal/oui/gen/main.go
//
// # Lookup behaviour
//
// [Lookup] matches the longest registered prefix first (36 → 28 → 24 bits), because MA-M
// and MA-S ranges are carved out of MA-L blocks that IEEE registers to the block
// administrator; the administrator placeholder entries ("IEEE Registration Authority",
// "Private") are omitted from the database so they can never shadow a real vendor.
//
// Locally administered addresses, those with the U/L bit set (randomized Wi-Fi MACs,
// container and hypervisor-generated MACs), are reported as
// follows:
//
//	Lookup("02:00:00:00:00:01")  == "(randomized)"           // LA, unregistered
//	Lookup("00:50:56:aa:bb:cc")  == "VMware, Inc."           // registered
//	Lookup("<LA address in a registered block>") == "<Vendor> (locally administered)"
//
// An unknown, globally administered address yields "". Invalid input yields "" and never
// panics.
//
// The multicast / group bit (the least-significant bit of the first octet) is masked off
// before the registry lookup, so group addresses still resolve to the vendor that owns
// the matching unicast OUI: 01:00:0C (Cisco CDP/PVST+) resolves to Cisco. The broadcast
// address FF:FF:FF:FF:FF:FF is reported as unknown.
package oui

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"io"
	"strings"
	"sync"
)

//go:generate go run ./gen/main.go -out oui.bin.gz

//go:embed oui.bin.gz
var dbGz []byte

const (
	magic   = "NETYOUI2"
	version = 1

	// Randomized is returned by [Lookup] for a locally administered address that matches
	// no registered block.
	Randomized = "(randomized)"

	// LocalSuffix is appended by [Lookup] when a locally administered address
	// nevertheless falls inside a registered block.
	LocalSuffix = " (locally administered)"
)

// Random is a deprecated alias for [Randomized].
//
// Deprecated: use [Randomized].
const Random = Randomized

// database is the decoded, read-only vendor table. All fields are built once and never
// mutated afterwards, so concurrent use is safe without locking.
type database struct {
	pool string   // every vendor name, concatenated
	off  []uint32 // len(names)+1 offsets into pool

	// Parallel, key-sorted slices, one pair per assignment size.
	mal, malName []uint32 // 24-bit keys
	mam, mamName []uint32 // 28-bit keys
	mas          []uint64 // 36-bit keys
	masName      []uint32
}

// load decodes the embedded database exactly once. On a corrupt or truncated blob it
// returns an empty database rather than failing: a missing vendor name must never take
// the scanner down.
var load = sync.OnceValue(func() *database {
	d := &database{}
	zr, err := gzip.NewReader(bytes.NewReader(dbGz))
	if err != nil {
		return d
	}
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		return d
	}
	if decode(d, raw) != nil {
		return &database{}
	}
	return d
})

type errString string

func (e errString) Error() string { return string(e) }

const errCorrupt = errString("oui: corrupt embedded database")

// cursor is a bounds-checked reader over the decompressed blob.
type cursor struct {
	b   []byte
	i   int
	bad bool
}

func (c *cursor) uvarint() uint64 {
	if c.bad {
		return 0
	}
	v, n := binary.Uvarint(c.b[c.i:])
	if n <= 0 {
		c.bad = true
		return 0
	}
	c.i += n
	return v
}

func (c *cursor) bytes(n uint64) []byte {
	if c.bad || n > uint64(len(c.b)-c.i) {
		c.bad = true
		return nil
	}
	s := c.b[c.i : c.i+int(n)]
	c.i += int(n)
	return s
}

func decode(d *database, raw []byte) error {
	if len(raw) < len(magic)+1 || string(raw[:len(magic)]) != magic || raw[len(magic)] != version {
		return errCorrupt
	}
	c := &cursor{b: raw, i: len(magic) + 1}

	n := c.uvarint()
	if c.bad || n > uint64(len(raw)) {
		return errCorrupt
	}
	off := make([]uint32, n+1)
	var total uint64
	for i := uint64(0); i < n; i++ {
		total += c.uvarint()
		if total > uint64(len(raw)) {
			return errCorrupt
		}
		off[i+1] = uint32(total)
	}
	pool := c.bytes(total)
	if c.bad {
		return errCorrupt
	}
	d.pool, d.off = string(pool), off

	sections := [3]struct {
		k32  *[]uint32
		k64  *[]uint64
		name *[]uint32
	}{
		{k32: &d.mal, name: &d.malName},
		{k32: &d.mam, name: &d.mamName},
		{k64: &d.mas, name: &d.masName},
	}
	for _, sec := range sections {
		cnt := c.uvarint()
		if c.bad || cnt > uint64(len(raw)) {
			return errCorrupt
		}
		var k32 []uint32
		var k64 []uint64
		if sec.k32 != nil {
			k32 = make([]uint32, cnt)
		} else {
			k64 = make([]uint64, cnt)
		}
		var prev uint64
		for i := uint64(0); i < cnt; i++ {
			prev += c.uvarint()
			if sec.k32 != nil {
				k32[i] = uint32(prev)
			} else {
				k64[i] = prev
			}
		}
		names := make([]uint32, cnt)
		for i := uint64(0); i < cnt; i++ {
			v := c.uvarint()
			if v >= n {
				return errCorrupt
			}
			names[i] = uint32(v)
		}
		if c.bad {
			return errCorrupt
		}
		if sec.k32 != nil {
			*sec.k32 = k32
		} else {
			*sec.k64 = k64
		}
		*sec.name = names
	}
	return nil
}

// name returns the interned vendor name i as a slice of the shared pool.
func (d *database) name(i uint32) string {
	if int(i)+1 >= len(d.off) {
		return ""
	}
	return d.pool[d.off[i]:d.off[i+1]]
}

// find32 and find64 are explicit binary searches over the sorted key slices; they avoid
// the closure sort.Search would need and never allocate.
func (d *database) find32(keys, names []uint32, key uint32) (string, bool) {
	lo, hi := 0, len(keys)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		switch {
		case keys[mid] < key:
			lo = mid + 1
		case keys[mid] > key:
			hi = mid
		default:
			return d.name(names[mid]), true
		}
	}
	return "", false
}

func (d *database) find64(keys []uint64, names []uint32, key uint64) (string, bool) {
	lo, hi := 0, len(keys)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		switch {
		case keys[mid] < key:
			lo = mid + 1
		case keys[mid] > key:
			hi = mid
		default:
			return d.name(names[mid]), true
		}
	}
	return "", false
}

// Parse decodes a MAC address written in any of the common notations into its octets.
// Accepted forms, case-insensitive and with surrounding whitespace
// ignored:
//
//	00:50:56:aa:bb:cc     00-50-56-AA-BB-CC     0:50:56:aa:bb:cc
//	0050.56aa.bbcc        005056aabbcc
//	00:50:56              00-50-56              005056      (bare OUI prefix)
//	0050561               005056aab                         (MA-M / MA-S prefix)
//	00:50:56:ff:fe:aa:bb:cc                                 (EUI-64)
//
// The returned slice holds 3, 4 or 6 octets; bits reports how many leading bits of it are
// significant (24, 28, 36 or 48). EUI-64 input is truncated to its first six octets,
// which is all a vendor lookup needs. ok is false for anything else; Parse never panics.
func Parse(mac string) (addr []byte, bits int, ok bool) {
	var buf [8]byte
	n, bits, ok := parseRaw(mac, &buf)
	if !ok {
		return nil, 0, false
	}
	return append([]byte(nil), buf[:n]...), bits, true
}

// parseRaw is the allocation-free core of [Parse]: it decodes mac into out and reports
// how many octets it wrote and how many leading bits are significant. Keeping it separate
// lets [Lookup], [IsLocallyAdministered] and [IsMulticast] run without touching the heap.
func parseRaw(mac string, out *[8]byte) (n, bits int, ok bool) {
	s := strings.TrimSpace(mac)
	if s == "" || len(s) > 64 {
		return 0, 0, false
	}

	// Collapse the separators into a hex-digit buffer. Single-digit groups in colon/dash
	// notation are zero-padded ("0:50:56" -> "005056"); dot notation pads each group to
	// four digits ("50.56aa.bbcc" -> "005056aabbcc"). Empty colon/dash groups are
	// skipped, which makes a malformed run of separators fall through to the length check
	// below.
	var hex [16]byte
	h := 0
	switch {
	case strings.ContainsAny(s, ":-"):
		for i, start := 0, -1; i <= len(s); i++ {
			if i < len(s) && s[i] != ':' && s[i] != '-' {
				if start < 0 {
					start = i
				}
				continue
			}
			if start < 0 {
				continue
			}
			g := s[start:i]
			start = -1
			if len(g) > 2 || h+2 > len(hex) {
				return 0, 0, false
			}
			if len(g) == 1 {
				hex[h] = '0'
				h++
			}
			h += copy(hex[h:], g)
		}
	case strings.IndexByte(s, '.') >= 0:
		for i, start := 0, 0; i <= len(s); i++ {
			if i < len(s) && s[i] != '.' {
				continue
			}
			g := s[start:i]
			start = i + 1
			if len(g) == 0 || len(g) > 4 || h+4 > len(hex) {
				return 0, 0, false
			}
			for j := len(g); j < 4; j++ {
				hex[h] = '0'
				h++
			}
			h += copy(hex[h:], g)
		}
	default:
		if len(s) > len(hex) {
			return 0, 0, false
		}
		h = copy(hex[:], s)
	}

	switch h {
	case 6:
		bits = 24
	case 7:
		bits = 28
	case 9:
		bits = 36
	case 12:
		bits = 48
	case 16:
		bits = 64
	default:
		return 0, 0, false
	}

	// An odd number of digits is a sub-byte prefix: pad it to whole octets, the padding
	// bits lying outside `bits` and therefore being ignored.
	if h%2 == 1 {
		hex[h] = '0'
		h++
	}
	n = h / 2
	for i := 0; i < n; i++ {
		hi, lo := hexVal(hex[2*i]), hexVal(hex[2*i+1])
		if hi > 15 || lo > 15 {
			return 0, 0, false
		}
		out[i] = hi<<4 | lo
	}
	if bits == 64 { // EUI-64: the first six octets are all a lookup needs
		n, bits = 6, 48
	}
	return n, bits, true
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0xff
}

// Normalize returns the MAC as lowercase "aa:bb:cc:dd:ee:ff", or "" when mac is not a
// full six-octet address.
func Normalize(mac string) string {
	var b [8]byte
	_, bits, ok := parseRaw(mac, &b)
	if !ok || bits != 48 {
		return ""
	}
	const hx = "0123456789abcdef"
	var out [17]byte
	for i, x := range b[:6] {
		if i > 0 {
			out[3*i-1] = ':'
		}
		out[3*i] = hx[x>>4]
		out[3*i+1] = hx[x&0x0f]
	}
	return string(out[:])
}

// IsLocallyAdministered reports whether mac has the U/L bit set: the
// second-least-significant bit of the first octet. Such addresses are assigned by the
// local network or generated at random (Wi-Fi MAC randomization, containers, hypervisors)
// rather than by IEEE. It is false for invalid input.
func IsLocallyAdministered(mac string) bool {
	var b [8]byte
	_, _, ok := parseRaw(mac, &b)
	return ok && b[0]&0x02 != 0
}

// IsMulticast reports whether mac has the I/G (group) bit set: the least-significant bit
// of the first octet. It is false for invalid input.
func IsMulticast(mac string) bool {
	var b [8]byte
	_, _, ok := parseRaw(mac, &b)
	return ok && b[0]&0x01 != 0
}

// Lookup returns the IEEE-registered vendor for mac, or "" when the prefix is not
// registered and the address is globally administered.
//
// It accepts every notation [Parse] accepts, including a bare 24-, 28- or 36-bit prefix,
// so Lookup("00:50:56") works. Locally administered addresses are reported as described
// in the package documentation: "(randomized)" when unregistered, "<Vendor> (locally
// administered)" when the prefix is nevertheless registered.
func Lookup(mac string) string {
	var b [8]byte
	_, bits, ok := parseRaw(mac, &b)
	if !ok {
		return ""
	}
	local := b[0]&0x02 != 0

	// Broadcast is neither a vendor nor a randomized address.
	if bits == 48 && b[0] == 0xff && b[1] == 0xff && b[2] == 0xff &&
		b[3] == 0xff && b[4] == 0xff && b[5] == 0xff {
		return ""
	}

	// Registries index unicast OUIs; clear the group bit so multicast addresses still
	// resolve to the owner of the matching unicast block.
	b0 := b[0] &^ 0x01

	d := load()
	var vendor string
	if bits >= 36 {
		key := uint64(b0)<<28 | uint64(b[1])<<20 | uint64(b[2])<<12 |
			uint64(b[3])<<4 | uint64(b[4])>>4
		vendor, _ = d.find64(d.mas, d.masName, key)
	}
	if vendor == "" && bits >= 28 {
		key := uint32(b0)<<20 | uint32(b[1])<<12 | uint32(b[2])<<4 | uint32(b[3])>>4
		vendor, _ = d.find32(d.mam, d.mamName, key)
	}
	if vendor == "" && bits >= 24 {
		key := uint32(b0)<<16 | uint32(b[1])<<8 | uint32(b[2])
		vendor, _ = d.find32(d.mal, d.malName, key)
	}

	switch {
	case vendor == "" && local:
		return Randomized
	case vendor == "":
		return ""
	case local:
		return vendor + LocalSuffix
	}
	return vendor
}
