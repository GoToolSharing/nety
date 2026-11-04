// Package ports parses port specifications ("top100", "22,80,8000-8100",
// "all" ...) and ships curated top-N port lists and a well-known port to
// service-name table.
package ports

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

// MaxPort is the highest valid port number.
const MaxPort = 65535

// Parse expands a port specification into a sorted, de-duplicated list.
//
// Accepted tokens (comma or whitespace separated, combinable):
//
//	top100, top1000, topN (N >= 1, capped to the list length), top-100
//	all, *, -           -> 1-65535
//	22                   -> single port
//	8000-8100            -> inclusive range
//	-1024 / 60000-       -> open ranges (1-1024 / 60000-65535)
//
// proto selects the protocol of the top-N lists (TCP when empty).
// Port 0 is rejected. An empty spec is an error.
func Parse(spec string, proto model.Protocol) ([]uint16, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("ports: empty port specification")
	}
	tokens := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == ';'
	})
	if len(tokens) == 0 {
		return nil, errors.New("ports: empty port specification")
	}

	var set bitset
	for _, tok := range tokens {
		if err := addToken(&set, strings.ToLower(strings.TrimSpace(tok)), proto); err != nil {
			return nil, err
		}
	}
	out := set.list()
	if len(out) == 0 {
		return nil, fmt.Errorf("ports: specification %q selects no port", spec)
	}
	return out, nil
}

// MustParse is Parse that panics on error; intended for constant specs in
// tests and package-level defaults.
func MustParse(spec string, proto model.Protocol) []uint16 {
	p, err := Parse(spec, proto)
	if err != nil {
		panic(err)
	}
	return p
}

func addToken(set *bitset, tok string, proto model.Protocol) error {
	switch tok {
	case "":
		return nil
	case "all", "*", "-", "full":
		set.addRange(1, MaxPort)
		return nil
	}
	if rest, ok := strings.CutPrefix(tok, "top"); ok {
		rest = strings.TrimLeft(rest, "-_ ")
		n, err := strconv.Atoi(rest)
		if err != nil || n <= 0 {
			return fmt.Errorf("ports: invalid top-N token %q", tok)
		}
		var list []uint16
		if proto == model.UDP {
			list = TopUDP(n)
		} else {
			list = TopTCP(n)
		}
		for _, p := range list {
			set.add(p)
		}
		return nil
	}
	// Optional "t:"/"u:" prefixes are accepted for convenience and only
	// honoured when they match proto (nmap style "T:22,U:53").
	if len(tok) > 2 && tok[1] == ':' {
		switch tok[0] {
		case 't':
			if proto == model.UDP {
				return nil
			}
		case 'u':
			if proto != model.UDP {
				return nil
			}
		default:
			return fmt.Errorf("ports: invalid token %q", tok)
		}
		tok = tok[2:]
	}
	if lo, hi, isRange := strings.Cut(tok, "-"); isRange {
		a, b := 1, MaxPort
		var err error
		if lo != "" {
			if a, err = parsePort(lo); err != nil {
				return err
			}
		}
		if hi != "" {
			if b, err = parsePort(hi); err != nil {
				return err
			}
		}
		if a > b {
			return fmt.Errorf("ports: invalid range %q (start > end)", tok)
		}
		set.addRange(a, b)
		return nil
	}
	p, err := parsePort(tok)
	if err != nil {
		return err
	}
	set.add(uint16(p))
	return nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("ports: invalid port %q", s)
	}
	if n < 1 || n > MaxPort {
		return 0, fmt.Errorf("ports: port %d out of range 1-65535", n)
	}
	return n, nil
}

// bitset over the 65536 port space (8 KiB).
type bitset [65536 / 64]uint64

func (b *bitset) add(p uint16) {
	if p == 0 {
		return
	}
	b[p/64] |= 1 << (p % 64)
}

func (b *bitset) addRange(lo, hi int) {
	for p := lo; p <= hi; p++ {
		b.add(uint16(p))
	}
}

func (b *bitset) list() []uint16 {
	n := 0
	for _, w := range b {
		for x := w; x != 0; x &= x - 1 {
			n++
		}
	}
	out := make([]uint16, 0, n)
	for i, w := range b {
		for j := 0; w != 0; j++ {
			if w&1 != 0 {
				out = append(out, uint16(i*64+j))
			}
			w >>= 1
		}
	}
	return out
}

// TopTCP returns the n most common TCP ports, sorted ascending. n larger than
// the curated list (1000) is capped.
func TopTCP(n int) []uint16 { return topN(tcpByFrequency(), n) }

// TopUDP returns the n most common UDP ports, sorted ascending. n larger than
// the curated list (100) is capped.
func TopUDP(n int) []uint16 { return topN(udpByFrequency(), n) }

// TopTCPOrdered returns the n most common TCP ports in frequency order (most
// common first), useful for scanners that want to probe likely ports first.
func TopTCPOrdered(n int) []uint16 { return headCopy(tcpByFrequency(), n) }

// TopUDPOrdered is TopTCPOrdered for UDP.
func TopUDPOrdered(n int) []uint16 { return headCopy(udpByFrequency(), n) }

func headCopy(list []uint16, n int) []uint16 {
	if n <= 0 {
		return nil
	}
	if n > len(list) {
		n = len(list)
	}
	return slices.Clone(list[:n])
}

func topN(list []uint16, n int) []uint16 {
	out := headCopy(list, n)
	slices.Sort(out)
	return out
}
