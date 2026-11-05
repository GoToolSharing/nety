package store

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

// Addresses are stored as text, which makes both of the things an operator wants to do
// with them impossible as written: `ORDER BY ip` puts 10.0.0.100 before 10.0.0.9 because
// it compares digit by digit, and `ip LIKE '10.0.0.%'` cannot express a subnet that does
// not fall on a dot boundary.
//
// Both problems have the same fix: a second column holding a key derived from the
// address, built so that a plain text comparison is the numeric order of the address.
// Sorting is then `ORDER BY ip_sort`, and a prefix is the range between the keys of its
// first and last address.

// ipSortKey computes the sortable key of a textual address.
//
// The key is a family tag followed by the address as fixed-width hex. Fixed width is the
// whole point: every key of a family is the same length, so a byte-by-byte comparison of
// two keys compares the two addresses as numbers. The family tag keeps IPv4 and IPv6 in
// separate blocks instead of letting a short v4 key sort into the middle of the v6 ones.
//
// An address that does not parse gets an empty key. It sorts before every real address
// and matches no prefix, which keeps the row in its table rather than losing it; nothing
// writes an unparsable address today, and a row that does not say where it is cannot be
// placed among those that do.
func ipSortKey(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	return ipSortKeyOf(addr)
}

func ipSortKeyOf(addr netip.Addr) string {
	// A v4-mapped v6 address is the same machine as the v4 address it wraps, and the zone
	// of a link-local address says which interface it was seen on, not which address it
	// is. Both would sort somewhere of their own.
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		b := addr.As4()
		return "4:" + hex.EncodeToString(b[:])
	}
	b := addr.As16()
	return "6:" + hex.EncodeToString(b[:])
}

// AddressFilter narrows a listing to one address or to one CIDR prefix. The zero value
// matches everything, which is what a listing with no `ip` parameter asks for.
//
// It is built by ParseAddressFilter so a malformed value is refused at the edge, with a
// message saying what was wrong, rather than reaching SQL.
type AddressFilter struct {
	// exact is the single address the operator typed, in the canonical form the scanners
	// write. Empty when the filter is a prefix or absent.
	exact string
	// lo and hi are the sort keys of the first and last address of a prefix.
	lo, hi string
}

// ParseAddressFilter reads the `ip` parameter of a result listing. It accepts a single
// address or a CIDR prefix, IPv4 or IPv6, and an empty string for no filter at all.
func ParseAddressFilter(value string) (AddressFilter, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return AddressFilter{}, nil
	}
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return AddressFilter{}, fmt.Errorf(
				"%q is not a CIDR prefix: write it as 10.20.0.0/24 or 2001:db8::/32", v)
		}
		p = p.Masked()
		return AddressFilter{
			lo: ipSortKeyOf(p.Addr()),
			hi: ipSortKeyOf(lastInPrefix(p)),
		}, nil
	}
	addr, err := netip.ParseAddr(v)
	if err != nil {
		return AddressFilter{}, fmt.Errorf(
			"%q is not an address or a CIDR prefix: write it as 10.20.0.7 or 10.20.0.0/24", v)
	}
	return AddressFilter{exact: addr.Unmap().WithZone("").String()}, nil
}

// Empty reports whether the filter lets every row through.
func (f AddressFilter) Empty() bool { return f.exact == "" && f.lo == "" }

// where builds the condition for this filter, as SQL and its arguments.
//
// ipColumn and sortColumn name the columns of the table being listed. They are written by
// the listing itself and never come from a caller, so they are the only part of the query
// built by concatenation.
//
// A single address is an equality on the address itself rather than on the key: it is
// exact either way, and reading the query makes it obvious which address was asked for.
func (f AddressFilter) where(ipColumn, sortColumn string) (string, []any) {
	switch {
	case f.exact != "":
		return ` AND ` + ipColumn + ` = ?`, []any{f.exact}
	case f.lo != "":
		return ` AND ` + sortColumn + ` BETWEEN ? AND ?`, []any{f.lo, f.hi}
	}
	return "", nil
}

// lastInPrefix is the highest address of a prefix: the network address with every host
// bit set.
func lastInPrefix(p netip.Prefix) netip.Addr {
	addr := p.Addr()
	if addr.Is4() {
		b := addr.As4()
		setHostBits(b[:], p.Bits())
		return netip.AddrFrom4(b)
	}
	b := addr.As16()
	setHostBits(b[:], p.Bits())
	return netip.AddrFrom16(b)
}

// setHostBits turns on every bit of b past the first prefixBits.
func setHostBits(b []byte, prefixBits int) {
	for i := range b {
		switch lead := i * 8; {
		case lead >= prefixBits:
			b[i] = 0xff
		case lead+8 > prefixBits:
			b[i] |= 0xff >> (prefixBits - lead)
		}
	}
}

// --------------------------------------------------------------------------- Sorting
// ---------------------------------------------------------------------------

// orderBy builds the ORDER BY clause of a listing.
//
// key is whatever the caller asked to sort on and is only ever used to look up an entry
// in allowed, so a caller's string never reaches the query. An unknown key falls back to
// the listing's own default instead of being an error: a bookmarked URL or a tab left
// open across a release should still show the table.
//
// tiebreak is the primary key of the table and is always appended. Without it two rows
// holding the same value in the sorted column have no defined order, and paging through a
// sorted listing could show one of them twice and miss the other entirely.
func orderBy(allowed map[string][]string, key string, desc bool, fallback []string, tiebreak string) string {
	columns, ok := allowed[strings.ToLower(strings.TrimSpace(key))]
	if !ok {
		columns = fallback
	}
	// The tiebreaker takes the direction of the sort as well, so that asking for the
	// reverse of a listing reverses all of it rather than most of it.
	direction := " ASC"
	if desc {
		direction = " DESC"
	}
	parts := make([]string, 0, len(columns)+1)
	for _, c := range columns {
		parts = append(parts, c+direction)
	}
	parts = append(parts, tiebreak+direction)
	return ` ORDER BY ` + strings.Join(parts, ", ")
}
