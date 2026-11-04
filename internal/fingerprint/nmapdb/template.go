package nmapdb

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// expandTemplate substitutes nmap's version template into a concrete string.
//
// Supported: $1..$9 (and $0, the whole match) for capture groups, $$ for a
// literal dollar, and the helper functions $P(n) (drop unprintable bytes),
// $SUBST(n,"from","to") (replace every occurrence) and $I(n,"<"|">") (read the
// group's bytes as an unsigned little- or big-endian integer).
//
// An absent or unmatched group expands to the empty string. Anything that does
// not parse — an unknown helper, a missing parenthesis, a truncated template —
// is copied through literally; the function never fails and never panics.
func expandTemplate(tmpl string, groups [][]byte) string {
	if tmpl == "" || !strings.ContainsRune(tmpl, '$') {
		return tmpl
	}
	out := make([]byte, 0, len(tmpl)+16)
	for i := 0; i < len(tmpl); {
		c := tmpl[i]
		if c != '$' || i+1 >= len(tmpl) {
			out = append(out, c)
			i++
			continue
		}
		switch n := tmpl[i+1]; {
		case n == '$':
			out = append(out, '$')
			i += 2
		case n >= '0' && n <= '9':
			out = append(out, group(groups, int(n-'0'))...)
			i += 2
		case n >= 'A' && n <= 'Z':
			v, w, ok := expandFunc(tmpl[i:], groups)
			if !ok {
				out = append(out, '$')
				i++
				continue
			}
			out = append(out, v...)
			i += w
		default:
			out = append(out, '$')
			i++
		}
	}
	return string(out)
}

// group returns capture group n, or nil when it is absent or did not match.
func group(groups [][]byte, n int) []byte {
	if n < 0 || n >= len(groups) {
		return nil
	}
	return groups[n]
}

// expandFunc expands a helper call at the start of s (which begins with '$').
// It reports the expansion and how many bytes of s it consumed.
func expandFunc(s string, groups [][]byte) (string, int, bool) {
	j := 1
	for j < len(s) && s[j] >= 'A' && s[j] <= 'Z' {
		j++
	}
	name := s[1:j]
	if j >= len(s) || s[j] != '(' {
		return "", 0, false
	}
	args, n, ok := parseArgs(s[j:])
	if !ok {
		return "", 0, false
	}
	width := j + n

	switch name {
	case "P":
		if len(args) != 1 {
			return "", 0, false
		}
		idx, ok := argIndex(args[0])
		if !ok {
			return "", 0, false
		}
		return printableOnly(group(groups, idx)), width, true

	case "SUBST":
		if len(args) != 3 {
			return "", 0, false
		}
		idx, ok := argIndex(args[0])
		if !ok {
			return "", 0, false
		}
		g := string(group(groups, idx))
		return strings.ReplaceAll(g, args[1], args[2]), width, true

	case "I":
		if len(args) != 2 {
			return "", 0, false
		}
		idx, ok := argIndex(args[0])
		if !ok {
			return "", 0, false
		}
		v, ok := bytesToUint(group(groups, idx), args[1])
		if !ok {
			return "", width, true // unusable group: expand to nothing
		}
		return strconv.FormatUint(v, 10), width, true
	}
	return "", 0, false
}

// parseArgs parses "(a,"b","c")" starting at the opening parenthesis. Quoted
// arguments are unquoted and unescaped with nmap's escape rules; bare ones are
// returned as written. It reports how many bytes it consumed.
func parseArgs(s string) ([]string, int, bool) {
	if s == "" || s[0] != '(' {
		return nil, 0, false
	}
	var (
		args []string
		cur  strings.Builder
		any  bool
	)
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			any = true
			body, rest, ok := scanDelim(s[i+1:], '"')
			if !ok {
				return nil, 0, false
			}
			cur.Write(unescape(body))
			i = len(s) - len(rest) - 1
		case ',':
			args = append(args, cur.String())
			cur.Reset()
			any = true
		case ')':
			if any || cur.Len() > 0 {
				args = append(args, cur.String())
			}
			return args, i + 1, true
		case ' ', '\t':
			// Ignore whitespace between arguments.
		default:
			cur.WriteByte(s[i])
		}
	}
	return nil, 0, false // unterminated argument list
}

// argIndex parses a helper's group-number argument.
func argIndex(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 9 {
		return 0, false
	}
	return n, true
}

// printableOnly drops every byte outside printable ASCII, which is what
// nmap's $P() does.
func printableOnly(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		}
	}
	return string(out)
}

// bytesToUint reads up to 8 bytes as an unsigned integer, little-endian for
// "<" and big-endian for ">".
func bytesToUint(b []byte, order string) (uint64, bool) {
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	var v uint64
	switch order {
	case "<":
		for i := len(b) - 1; i >= 0; i-- {
			v = v<<8 | uint64(b[i])
		}
	case ">":
		for _, c := range b {
			v = v<<8 | uint64(c)
		}
	default:
		return 0, false
	}
	return v, true
}

// cleanField makes a substituted version string safe to store and display: C0
// control bytes and DEL are dropped, and any byte that is not part of a valid
// UTF-8 sequence is re-encoded as the latin-1 character it stands for. A field
// that is already valid UTF-8 text is returned untouched.
func cleanField(s string) string {
	if s == "" {
		return ""
	}
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f || s[i] >= 0x80 {
			clean = false
			break
		}
	}
	if clean {
		return s
	}

	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		b = append(b, c)
	}
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	sb.Grow(len(b) + 8)
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size <= 1 {
			sb.WriteRune(rune(b[i]))
			i++
			continue
		}
		sb.Write(b[i : i+size])
		i += size
	}
	return sb.String()
}
