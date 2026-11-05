package rawnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
)

// MaxAddrSpace bounds the number of addresses an AddrSpace may hold (IPv6 /64s cannot be
// swept).
const MaxAddrSpace = 1 << 32

// AddrSpace is an indexable, de-duplicated set of IP addresses built from target prefixes
// minus exclusion prefixes. Memory is O(number of ranges), independent of the number of
// addresses.
type AddrSpace struct {
	ranges []addrRange
	cum    []uint64 // cum[i] = number of addresses in ranges[:i]
	total  uint64
}

type addrRange struct {
	lo, hi u128 // inclusive
	v4     bool
}

// NewAddrSpace builds the space targets \ excludes. IPv4 and IPv6 prefixes may be mixed.
// It fails when the result exceeds MaxAddrSpace addresses.
func NewAddrSpace(targets, excludes []netip.Prefix) (*AddrSpace, error) {
	inc, err := toRanges(targets)
	if err != nil {
		return nil, err
	}
	exc, err := toRanges(excludes)
	if err != nil {
		return nil, err
	}
	rs := subtract(merge(inc), merge(exc))
	s := &AddrSpace{ranges: rs, cum: make([]uint64, len(rs))}
	for i, r := range rs {
		s.cum[i] = s.total
		size := r.hi.sub(r.lo)
		if size.hi != 0 || size.lo >= MaxAddrSpace {
			return nil, fmt.Errorf("rawnet: target range %s-%s too large", r.lo.addr(r.v4), r.hi.addr(r.v4))
		}
		s.total += size.lo + 1
		if s.total > MaxAddrSpace {
			return nil, fmt.Errorf("rawnet: target space exceeds %d addresses", uint64(MaxAddrSpace))
		}
	}
	return s, nil
}

// NewAddrSpaceFromAddrs builds a space from individual addresses.
func NewAddrSpaceFromAddrs(addrs []netip.Addr) (*AddrSpace, error) {
	ps := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if a.IsValid() {
			ps = append(ps, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	return NewAddrSpace(ps, nil)
}

// Len returns the number of addresses.
func (s *AddrSpace) Len() uint64 { return s.total }

// At returns the i-th address (ascending order), i in [0, Len()).
func (s *AddrSpace) At(i uint64) netip.Addr {
	if i >= s.total {
		return netip.Addr{}
	}
	k := sort.Search(len(s.cum), func(j int) bool { return s.cum[j] > i }) - 1
	r := s.ranges[k]
	return r.lo.add(i - s.cum[k]).addr(r.v4)
}

// Index returns the index of a, or false when a is not in the space.
func (s *AddrSpace) Index(a netip.Addr) (uint64, bool) {
	if !a.IsValid() {
		return 0, false
	}
	a = a.Unmap()
	v := fromAddr(a)
	is4 := a.Is4()
	k := sort.Search(len(s.ranges), func(j int) bool {
		r := s.ranges[j]
		if r.v4 != is4 {
			return !r.v4 // IPv6 ranges sort after every IPv4 range
		}
		return !r.hi.less(v)
	})
	if k == len(s.ranges) || v.less(s.ranges[k].lo) || s.ranges[k].v4 != is4 {
		return 0, false
	}
	return s.cum[k] + v.sub(s.ranges[k].lo).lo, true
}

// Contains reports whether a is in the space.
func (s *AddrSpace) Contains(a netip.Addr) bool {
	_, ok := s.Index(a)
	return ok
}

// Ranges returns the inclusive [first, last] address ranges of the space.
func (s *AddrSpace) Ranges() [][2]netip.Addr {
	out := make([][2]netip.Addr, len(s.ranges))
	for i, r := range s.ranges {
		out[i] = [2]netip.Addr{r.lo.addr(r.v4), r.hi.addr(r.v4)}
	}
	return out
}

func toRanges(ps []netip.Prefix) ([]addrRange, error) {
	out := make([]addrRange, 0, len(ps))
	for _, p := range ps {
		if !p.IsValid() {
			return nil, errors.New("rawnet: invalid prefix")
		}
		a := p.Addr().Unmap()
		bits := p.Bits()
		if p.Addr().Is4In6() {
			bits -= 96
			if bits < 0 {
				bits = 0
			}
		}
		p = netip.PrefixFrom(a, bits).Masked()
		lo := fromAddr(p.Addr())
		hostBits := uint(a.BitLen() - p.Bits())
		hi := lo.or(u128{}.ones(hostBits))
		out = append(out, addrRange{lo: lo, hi: hi, v4: a.Is4()})
	}
	return out, nil
}

func merge(rs []addrRange) []addrRange {
	if len(rs) == 0 {
		return nil
	}
	slices.SortFunc(rs, cmpRange)
	out := []addrRange{rs[0]}
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if last.v4 == r.v4 && !last.hi.less(r.lo.dec()) { // overlapping or adjacent
			if last.hi.less(r.hi) {
				last.hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// cmpRange orders IPv4 ranges before IPv6 ones, then by first address.
func cmpRange(a, b addrRange) int {
	if a.v4 != b.v4 {
		if a.v4 {
			return -1
		}
		return 1
	}
	return a.lo.cmp(b.lo)
}

func subtract(inc, exc []addrRange) []addrRange {
	if len(exc) == 0 {
		return inc
	}
	var out []addrRange
	for _, r := range inc {
		cur := r
		alive := true
		for _, e := range exc {
			if !alive {
				break
			}
			if e.v4 != cur.v4 || e.hi.less(cur.lo) || cur.hi.less(e.lo) {
				continue
			}
			// overlap
			if cur.lo.less(e.lo) {
				out = append(out, addrRange{lo: cur.lo, hi: e.lo.dec(), v4: cur.v4})
			}
			if e.hi.less(cur.hi) {
				cur.lo = e.hi.inc()
			} else {
				alive = false
			}
		}
		if alive {
			out = append(out, cur)
		}
	}
	return out
}

// u128 is a big-endian 128-bit unsigned integer (IPv4 stored in the low 32 bits; families
// are tracked separately so they never mix).
type u128 struct{ hi, lo uint64 }

func fromAddr(a netip.Addr) u128 {
	if a.Is4() {
		b := a.As4()
		return u128{lo: uint64(binary.BigEndian.Uint32(b[:]))}
	}
	b := a.As16()
	return u128{hi: binary.BigEndian.Uint64(b[:8]), lo: binary.BigEndian.Uint64(b[8:])}
}

func (u u128) addr(v4 bool) netip.Addr {
	if v4 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(u.lo))
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], u.hi)
	binary.BigEndian.PutUint64(b[8:], u.lo)
	return netip.AddrFrom16(b)
}

func (u u128) cmp(v u128) int {
	switch {
	case u.hi < v.hi:
		return -1
	case u.hi > v.hi:
		return 1
	case u.lo < v.lo:
		return -1
	case u.lo > v.lo:
		return 1
	}
	return 0
}

func (u u128) less(v u128) bool { return u.cmp(v) < 0 }

func (u u128) add(n uint64) u128 {
	lo := u.lo + n
	hi := u.hi
	if lo < u.lo {
		hi++
	}
	return u128{hi, lo}
}

func (u u128) sub(v u128) u128 {
	lo := u.lo - v.lo
	hi := u.hi - v.hi
	if u.lo < v.lo {
		hi--
	}
	return u128{hi, lo}
}

func (u u128) inc() u128 { return u.add(1) }

func (u u128) dec() u128 {
	if u.lo == 0 && u.hi == 0 {
		return u // saturate: used only for adjacency tests
	}
	return u.sub(u128{lo: 1})
}

func (u u128) or(v u128) u128 { return u128{u.hi | v.hi, u.lo | v.lo} }

// ones returns a value with the n low bits set.
func (u128) ones(n uint) u128 {
	switch {
	case n == 0:
		return u128{}
	case n < 64:
		return u128{lo: (uint64(1) << n) - 1}
	case n == 64:
		return u128{lo: ^uint64(0)}
	case n < 128:
		return u128{hi: (uint64(1) << (n - 64)) - 1, lo: ^uint64(0)}
	default:
		return u128{^uint64(0), ^uint64(0)}
	}
}
