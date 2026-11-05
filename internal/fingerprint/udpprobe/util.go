package udpprobe

import (
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxExtraLen caps every value stored in Result.Extra. The values end up in
// model.Service.Extra and are rendered in the UI, so they must stay printable and small
// whatever the peer sent.
const maxExtraLen = 256

// maxJoined caps comma-joined lists before truncation.
const maxListItems = 64

// sanitize makes an arbitrary byte-derived string safe to store: invalid UTF-8 is
// dropped, control characters become spaces, runs of whitespace collapse and the result
// is truncated to maxExtraLen runes.
func sanitize(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	n := 0
	for i := 0; i < len(s) && n < maxExtraLen; {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			i++
			continue
		}
		i += size
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		if r == ' ' {
			if lastSpace || b.Len() == 0 {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimRight(b.String(), " ")
}

// printableASCII keeps only printable ASCII, used for banners carved out of binary
// payloads (vendor IDs, NetBIOS names).
func printableASCII(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		}
	}
	return strings.TrimSpace(sb.String())
}

// joinCapped joins at most maxListItems values with a comma and sanitises.
func joinCapped(items []string) string {
	if len(items) > maxListItems {
		items = items[:maxListItems]
	}
	return sanitize(strings.Join(items, ","))
}

// hexStr renders bytes as lowercase hex, bounded.
func hexStr(b []byte) string {
	if len(b) > maxExtraLen/2 {
		b = b[:maxExtraLen/2]
	}
	return hex.EncodeToString(b)
}

// reVersion matches a dotted numeric version, optionally with a patch suffix such as
// "4.2.8p15" or "1.6.9-1".
var reVersion = regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9]+)*(?:[pP][0-9]+)?)`)

// firstVersion returns the first dotted numeric version found in s.
func firstVersion(s string) string {
	m := reVersion.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// versionAfter looks for marker (case-insensitive) and returns the first dotted version
// appearing after it, within a bounded window.
func versionAfter(s, marker string) string {
	i := indexFold(s, marker)
	if i < 0 {
		return ""
	}
	rest := s[i+len(marker):]
	if len(rest) > 64 {
		rest = rest[:64]
	}
	return firstVersion(rest)
}

// indexFold is a case-insensitive strings.Index.
func indexFold(s, substr string) int {
	if substr == "" {
		return 0
	}
	if len(substr) > len(s) {
		return -1
	}
	ls, lsub := strings.ToLower(s), strings.ToLower(substr)
	return strings.Index(ls, lsub)
}

// containsFold reports whether s contains substr, ignoring case.
func containsFold(s, substr string) bool { return indexFold(s, substr) >= 0 }

// itoa is a tiny shorthand used all over the decoders.
func itoa(v int) string { return strconv.Itoa(v) }

// u32 reads a big-endian uint32 at off; ok is false when out of range.
func u32(b []byte, off int) (uint32, bool) {
	if off < 0 || off+4 > len(b) {
		return 0, false
	}
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3]), true
}

// u16 reads a big-endian uint16 at off; ok is false when out of range.
func u16(b []byte, off int) (uint16, bool) {
	if off < 0 || off+2 > len(b) {
		return 0, false
	}
	return uint16(b[off])<<8 | uint16(b[off+1]), true
}

// headerValues parses a CRLF (or LF) delimited "Key: value" block, lowercasing keys. It
// stops after maxHeaders lines and truncates oversized values. The first line is returned
// separately as the start line.
func headerValues(data []byte, maxHeaders int) (startLine string, hdrs map[string]string) {
	hdrs = make(map[string]string, 16)
	if len(data) > 64*1024 {
		data = data[:64*1024]
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return "", hdrs
	}
	startLine = sanitize(lines[0])
	n := 0
	for _, ln := range lines[1:] {
		if ln == "" {
			break // end of header block
		}
		if n >= maxHeaders {
			break
		}
		n++
		idx := strings.IndexByte(ln, ':')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(ln[:idx]))
		val := strings.TrimSpace(ln[idx+1:])
		if key == "" {
			continue
		}
		if _, dup := hdrs[key]; dup {
			continue // first occurrence wins
		}
		hdrs[key] = sanitize(val)
	}
	return startLine, hdrs
}
