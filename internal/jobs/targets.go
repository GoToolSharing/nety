package jobs

import (
	"fmt"
	"net/netip"
	"strings"
)

// Target parsing. Accepted forms, comma/space/newline separated:
//
//	10.0.0.0/24          CIDR
//	10.0.0.5             single address
//	10.0.0.1-10.0.0.50   inclusive range
//	10.0.0.1-50          short range (last octet)
//	2001:db8::/64        IPv6 CIDR
//
// Everything is normalised to a list of prefixes; ranges are decomposed into
// the smallest set of prefixes that covers them exactly, so the rest of the
// pipeline only ever deals with prefixes.

// ParseTargets expands a target specification into prefixes.
func ParseTargets(specs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range specs {
		for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
		}) {
			p, err := parseTarget(strings.TrimSpace(tok))
			if err != nil {
				return nil, err
			}
			out = append(out, p...)
		}
	}
	return out, nil
}

func parseTarget(tok string) ([]netip.Prefix, error) {
	if tok == "" {
		return nil, nil
	}
	if strings.Contains(tok, "/") {
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", tok, err)
		}
		return []netip.Prefix{p.Masked()}, nil
	}
	if lo, hi, isRange := strings.Cut(tok, "-"); isRange {
		start, err := netip.ParseAddr(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("invalid range start %q: %w", lo, err)
		}
		hi = strings.TrimSpace(hi)
		var end netip.Addr
		if strings.ContainsAny(hi, ".:") {
			if end, err = netip.ParseAddr(hi); err != nil {
				return nil, fmt.Errorf("invalid range end %q: %w", hi, err)
			}
		} else {
			// Short form "10.0.0.1-50": replace the last octet.
			if !start.Is4() {
				return nil, fmt.Errorf("short range %q is only supported for IPv4", tok)
			}
			var last int
			if _, err := fmt.Sscanf(hi, "%d", &last); err != nil || last < 0 || last > 255 {
				return nil, fmt.Errorf("invalid range end %q", hi)
			}
			b := start.As4()
			b[3] = byte(last)
			end = netip.AddrFrom4(b)
		}
		return rangeToPrefixes(start, end)
	}
	addr, err := netip.ParseAddr(tok)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", tok, err)
	}
	return []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}, nil
}

// rangeToPrefixes covers [start, end] with the fewest CIDR blocks.
func rangeToPrefixes(start, end netip.Addr) ([]netip.Prefix, error) {
	if start.Is4In6() {
		start = start.Unmap()
	}
	if end.Is4In6() {
		end = end.Unmap()
	}
	if start.BitLen() != end.BitLen() {
		return nil, fmt.Errorf("range %s-%s mixes address families", start, end)
	}
	if end.Less(start) {
		return nil, fmt.Errorf("range %s-%s is reversed", start, end)
	}
	var out []netip.Prefix
	cur := start
	for {
		bits := cur.BitLen()
		size := bits
		// Grow the block while it stays aligned and within the range.
		for size > 0 {
			candidate := netip.PrefixFrom(cur, size-1).Masked()
			if candidate.Addr() != cur {
				break
			}
			if last := lastAddr(candidate); last.Compare(end) > 0 {
				break
			}
			size--
		}
		p := netip.PrefixFrom(cur, size)
		out = append(out, p)
		last := lastAddr(p)
		if last.Compare(end) >= 0 {
			return out, nil
		}
		cur = last.Next()
		if !cur.IsValid() {
			return out, nil
		}
		if len(out) > 1_000_000 {
			return nil, fmt.Errorf("range %s-%s is too fragmented", start, end)
		}
	}
}

// lastAddr returns the broadcast-equivalent (highest) address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		shift := bits - i*8
		switch {
		case shift >= 8:
			// fully covered by the prefix, keep it
		case shift <= 0:
			b[i] = 0xff
		default:
			b[i] |= byte(0xff >> shift)
		}
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
}

// CountAddresses reports how many addresses a prefix list covers, capped at
// max to keep the arithmetic cheap for very wide IPv6 prefixes.
func CountAddresses(prefixes []netip.Prefix, cap int64) int64 {
	var total int64
	for _, p := range prefixes {
		bits := p.Addr().BitLen() - p.Bits()
		if bits >= 62 {
			return cap
		}
		total += int64(1) << uint(bits)
		if total >= cap {
			return cap
		}
	}
	return total
}

// ExcludeFilter decides whether an address is in scope.
type ExcludeFilter struct {
	excludes []netip.Prefix
}

// NewExcludeFilter builds a filter from exclusion prefixes.
func NewExcludeFilter(excludes []netip.Prefix) ExcludeFilter {
	return ExcludeFilter{excludes: excludes}
}

// Allows reports whether addr is NOT excluded.
func (f ExcludeFilter) Allows(addr netip.Addr) bool {
	for _, p := range f.excludes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// IterateAddresses calls fn for every address of the prefixes that passes the
// filter. Network and broadcast addresses are included: hosts do answer on
// them often enough to matter on an internal audit, and skipping them would be
// wrong anyway for the prefixes produced by decomposing an explicit range.
// It never materialises the whole space, so a /8 costs no memory. fn returning
// false stops iteration.
func IterateAddresses(prefixes []netip.Prefix, f ExcludeFilter, fn func(netip.Addr) bool) {
	for _, p := range prefixes {
		addr := p.Masked().Addr()
		last := lastAddr(p)
		for {
			if f.Allows(addr) {
				if !fn(addr) {
					return
				}
			}
			if addr.Compare(last) >= 0 {
				break
			}
			addr = addr.Next()
			if !addr.IsValid() {
				break
			}
		}
	}
}

// ChunkAddresses splits the address space into slices of at most size
// addresses, calling fn for each chunk. Used to build resumable work units.
func ChunkAddresses(prefixes []netip.Prefix, f ExcludeFilter, size int, fn func([]netip.Addr) bool) {
	if size <= 0 {
		size = 256
	}
	batch := make([]netip.Addr, 0, size)
	stopped := false
	IterateAddresses(prefixes, f, func(a netip.Addr) bool {
		batch = append(batch, a)
		if len(batch) >= size {
			cp := make([]netip.Addr, len(batch))
			copy(cp, batch)
			batch = batch[:0]
			if !fn(cp) {
				stopped = true
				return false
			}
		}
		return true
	})
	if !stopped && len(batch) > 0 {
		cp := make([]netip.Addr, len(batch))
		copy(cp, batch)
		fn(cp)
	}
}

// PrefixStrings renders prefixes for storage/display.
func PrefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}

// AddrStrings renders addresses for storage.
func AddrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

// ParseAddrs parses stored address strings, skipping invalid entries.
func ParseAddrs(in []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, s := range in {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}
