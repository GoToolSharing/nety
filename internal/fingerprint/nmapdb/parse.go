package nmapdb

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

const (
	// maxFileSize caps how much of a probe file is read. The real
	// nmap-service-probes is a few MiB; anything past this is refused rather
	// than loaded into memory.
	maxFileSize = 32 << 20
	// maxLineLen caps a single line. Longer lines are skipped, not truncated,
	// so a half-read directive can never be mis-parsed.
	maxLineLen = 64 << 10
)

// Parse parses the nmap-service-probes format.
//
// Malformed directives, match lines with broken delimiters and over-long lines
// are skipped: a third-party database must never be able to abort a scan. An
// error is only returned for I/O failures, a file over maxFileSize, or a file
// that yielded no probe at all.
func Parse(r io.Reader) (*DB, error) {
	if r == nil {
		return nil, ErrNoProbes
	}
	db := &DB{}
	lr := &lineReader{br: bufio.NewReaderSize(r, 64<<10)}

	var cur *Probe
	for {
		raw, err := lr.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		line := strings.TrimRight(string(raw), "\r\n")
		line = strings.TrimLeft(line, " \t")
		if line == "" || line[0] == '#' {
			continue
		}

		key, rest := splitToken(line)
		switch key {
		case "Probe":
			if p := parseProbe(rest); p != nil {
				db.probes = append(db.probes, p)
				if p.Proto == "tcp" && p.Name == "NULL" && db.nullTCP == nil {
					db.nullTCP = p
				}
				cur = p
			} else {
				// A broken Probe line invalidates the directives that follow:
				// they would otherwise be attached to the previous probe.
				cur = nil
			}
		case "match", "softmatch":
			if cur == nil {
				continue
			}
			if ml := parseMatch(db, rest, key == "softmatch"); ml != nil {
				cur.matches = append(cur.matches, ml)
				db.nmatch++
			}
		case "ports":
			if cur != nil {
				cur.ports = append(cur.ports, parsePortRanges(rest)...).normalise()
			}
		case "sslports":
			if cur != nil {
				cur.sslPorts = append(cur.sslPorts, parsePortRanges(rest)...).normalise()
			}
		case "totalwaitms":
			if cur != nil {
				if ms, ok := parseUint(rest); ok {
					cur.TotalWait = time.Duration(ms) * time.Millisecond
				}
			}
		case "tcpwrappedms":
			if cur != nil {
				if ms, ok := parseUint(rest); ok {
					cur.TCPWrapped = time.Duration(ms) * time.Millisecond
				}
			}
		case "rarity":
			if cur != nil {
				if n, ok := parseUint(rest); ok && n >= 1 && n <= 9 {
					cur.Rarity = int(n)
				}
			}
		case "fallback":
			if cur != nil {
				for _, name := range strings.Split(firstField(rest), ",") {
					if name = strings.TrimSpace(name); name != "" {
						cur.fallbacks = append(cur.fallbacks, name)
					}
				}
			}
		case "Exclude":
			tcp, udp := parseExclude(rest)
			db.exclTCP = append(db.exclTCP, tcp...).normalise()
			db.exclUDP = append(db.exclUDP, udp...).normalise()
		default:
			// Unknown directive (future nmap versions, stray text): ignore.
		}
	}

	db.skipped = lr.skipped
	if len(db.probes) == 0 {
		return nil, ErrNoProbes
	}
	db.resolveFallbacks()
	return db, nil
}

// resolveFallbacks turns fallback names into probe pointers, appending the
// implicit TCP NULL fallback. Self-references and duplicates are dropped, so
// the chain is always finite.
func (db *DB) resolveFallbacks() {
	byName := make(map[string][]*Probe, len(db.probes))
	for _, p := range db.probes {
		byName[p.Name] = append(byName[p.Name], p)
	}
	lookup := func(name, proto string) *Probe {
		cands := byName[name]
		for _, p := range cands {
			if p.Proto == proto {
				return p
			}
		}
		if len(cands) > 0 {
			return cands[0]
		}
		return nil
	}

	for _, p := range db.probes {
		seen := map[*Probe]bool{p: true}
		for _, name := range p.fallbacks {
			fb := lookup(name, p.Proto)
			if fb == nil || seen[fb] {
				continue
			}
			seen[fb] = true
			p.chain = append(p.chain, fb)
		}
		if p.Proto == "tcp" && db.nullTCP != nil && !seen[db.nullTCP] {
			p.chain = append(p.chain, db.nullTCP)
		}
	}
}

// --- line reader ------------------------------------------------------------

// lineReader yields lines with a hard cap on both the total bytes read and the
// length of a single line.
type lineReader struct {
	br      *bufio.Reader
	n       int64
	skipped int
}

// next returns the next usable line. Over-long lines are counted and skipped.
// It returns io.EOF when the input is exhausted.
func (lr *lineReader) next() ([]byte, error) {
	for {
		var (
			buf     []byte
			tooLong bool
			eof     bool
		)
		for {
			chunk, err := lr.br.ReadSlice('\n')
			lr.n += int64(len(chunk))
			if lr.n > maxFileSize {
				return nil, ErrTooLarge
			}
			if err == bufio.ErrBufferFull {
				if tooLong || len(buf)+len(chunk) > maxLineLen {
					tooLong = true
					buf = nil
				} else {
					buf = append(buf, chunk...)
				}
				continue
			}
			if err == io.EOF {
				eof = true
			} else if err != nil {
				return nil, err
			}
			if tooLong || len(buf)+len(chunk) > maxLineLen {
				tooLong = true
				buf = nil
			} else {
				buf = append(buf, chunk...)
			}
			break
		}
		if tooLong {
			lr.skipped++
			if eof {
				return nil, io.EOF
			}
			continue
		}
		if len(buf) == 0 && eof {
			return nil, io.EOF
		}
		return buf, nil
	}
}

// --- directive parsers ------------------------------------------------------

// parseProbe parses the tail of a "Probe" line:
//
//	<TCP|UDP> <Name> q|<probestring>|
func parseProbe(s string) *Probe {
	proto, s := splitToken(s)
	proto = normProto(proto)
	if proto == "" {
		return nil
	}
	name, s := splitToken(s)
	if name == "" {
		return nil
	}
	s = strings.TrimLeft(s, " \t")
	if len(s) < 2 || s[0] != 'q' {
		return nil
	}
	delim := s[1]
	body, _, ok := scanDelim(s[2:], delim)
	if !ok {
		return nil
	}
	return &Probe{
		Proto:  proto,
		Name:   name,
		Data:   unescape(body),
		Rarity: 9, // nmap's default when the directive is absent
	}
}

// parseMatch parses the tail of a match/softmatch line:
//
//	<service> m/<pattern>/<flags> [p/../ v/../ i/../ h/../ o/../ d/../ cpe:/../]
func parseMatch(db *DB, s string, soft bool) *matchLine {
	service, s := splitToken(s)
	if service == "" {
		return nil
	}
	s = strings.TrimLeft(s, " \t")
	if len(s) < 2 || s[0] != 'm' {
		return nil
	}
	delim := s[1]
	// A letter or digit as a delimiter is almost certainly a malformed line
	// (nmap uses punctuation), and would swallow the rest of the file's line.
	if isAlnum(delim) {
		return nil
	}
	pattern, rest, ok := scanDelim(s[2:], delim)
	if !ok {
		return nil
	}

	var opts regexp2.RegexOptions
	i := 0
	for ; i < len(rest) && isAlpha(rest[i]); i++ {
		switch rest[i] {
		case 'i':
			opts |= regexp2.IgnoreCase
		case 's':
			opts |= regexp2.Singleline
		}
	}
	return &matchLine{
		db:      db,
		service: service,
		soft:    soft,
		pattern: pattern,
		opts:    opts,
		info:    parseVersionInfo(rest[i:]),
	}
}

// parseVersionInfo parses the trailing p//, v//, i//, h//, o//, d// and
// cpe:// fields of a match line. Anything it cannot make sense of is skipped.
func parseVersionInfo(s string) versionInfo {
	var vi versionInfo
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return vi
		}
		if strings.HasPrefix(s, "cpe:") && len(s) > 4 {
			delim := s[4]
			if isAlnum(delim) {
				_, s = splitToken(s)
				continue
			}
			body, rest, ok := scanDelim(s[5:], delim)
			if !ok {
				return vi
			}
			// nmap writes the CPE without its "cpe:/" prefix between the
			// delimiters; restore the canonical form whatever the delimiter.
			vi.cpes = append(vi.cpes, "cpe:/"+unescapeDelim(body, delim))
			// An optional trailing letter ("a") marks the CPE as auto-generated.
			_, s = splitToken(rest)
			continue
		}
		key := s[0]
		if len(s) < 2 || !strings.ContainsRune("pvihod", rune(key)) || isAlnum(s[1]) {
			_, s = splitToken(s) // unknown token: skip it, never loop forever
			continue
		}
		delim := s[1]
		body, rest, ok := scanDelim(s[2:], delim)
		if !ok {
			return vi
		}
		val := unescapeDelim(body, delim)
		switch key {
		case 'p':
			vi.product = val
		case 'v':
			vi.version = val
		case 'i':
			vi.info = val
		case 'h':
			vi.hostname = val
		case 'o':
			vi.ostype = val
		case 'd':
			vi.devicetype = val
		}
		s = rest
	}
}

// parseExclude parses an "Exclude" directive, e.g. "53,T:9100-9107,U:161".
// A T:/U: prefix applies to every following item until the other prefix.
func parseExclude(s string) (tcp, udp portSet) {
	proto := "both"
	for _, item := range strings.Split(firstField(s), ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		switch {
		case strings.HasPrefix(item, "T:"), strings.HasPrefix(item, "t:"):
			proto, item = "tcp", item[2:]
		case strings.HasPrefix(item, "U:"), strings.HasPrefix(item, "u:"):
			proto, item = "udp", item[2:]
		}
		r, ok := parseRange(item)
		if !ok {
			continue
		}
		if proto != "udp" {
			tcp = append(tcp, r)
		}
		if proto != "tcp" {
			udp = append(udp, r)
		}
	}
	return tcp, udp
}

// parsePortRanges parses "80,443,8000-8010".
func parsePortRanges(s string) portSet {
	var ps portSet
	for _, item := range strings.Split(firstField(s), ",") {
		if r, ok := parseRange(strings.TrimSpace(item)); ok {
			ps = append(ps, r)
		}
	}
	return ps
}

func parseRange(s string) (portRange, bool) {
	if s == "" {
		return portRange{}, false
	}
	lo, hi, found := strings.Cut(s, "-")
	a, ok := parsePort(lo)
	if !ok {
		return portRange{}, false
	}
	if !found {
		return portRange{a, a}, true
	}
	b, ok := parsePort(hi)
	if !ok {
		return portRange{}, false
	}
	if b < a {
		a, b = b, a
	}
	return portRange{a, b}, true
}

func parsePort(s string) (uint16, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

func parseUint(s string) (uint64, bool) {
	n, err := strconv.ParseUint(firstField(s), 10, 32)
	if err != nil {
		return 0, false
	}
	return n, true
}

// --- small string helpers ---------------------------------------------------

// splitToken returns the first whitespace-separated token of s and the rest.
func splitToken(s string) (tok, rest string) {
	s = strings.TrimLeft(s, " \t")
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

// firstField returns the first whitespace-separated token of s.
func firstField(s string) string {
	tok, _ := splitToken(s)
	return tok
}

// scanDelim returns the text of s up to the first unescaped delim, and what
// follows it. A backslash escapes the next byte, so "\|" does not close a
// |-delimited field.
func scanDelim(s string, delim byte) (body, rest string, ok bool) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ // skip the escaped byte (a trailing \ just ends the scan)
		case delim:
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// unescapeDelim turns "\<delim>" into the delimiter itself, leaving every
// other escape sequence for the version-template expander.
func unescapeDelim(s string, delim byte) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == delim {
			b.WriteByte(delim)
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unescape decodes nmap's probe-string escapes to raw bytes:
// \0 and octal \NNN, \a \b \f \n \r \t \v, \xHH, \\ and \<any other byte>.
func unescape(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		if i+1 >= len(s) {
			out = append(out, '\\') // trailing backslash: keep it literal
			break
		}
		i++
		switch e := s[i]; {
		case e == 'a':
			out = append(out, 0x07)
		case e == 'b':
			out = append(out, 0x08)
		case e == 'f':
			out = append(out, 0x0c)
		case e == 'n':
			out = append(out, 0x0a)
		case e == 'r':
			out = append(out, 0x0d)
		case e == 't':
			out = append(out, 0x09)
		case e == 'v':
			out = append(out, 0x0b)
		case e == 'x' || e == 'X':
			v, n := readHex(s[i+1:], 2)
			if n == 0 {
				out = append(out, e) // "\x" with no digits: literal x
				continue
			}
			out = append(out, byte(v))
			i += n
		case e >= '0' && e <= '7':
			v, n := readOctal(s[i:], 3)
			out = append(out, byte(v))
			i += n - 1
		default:
			out = append(out, e) // \\ , \| , \/ , anything else
		}
	}
	return out
}

func readHex(s string, max int) (v int, n int) {
	for n < max && n < len(s) {
		d, ok := hexDigit(s[n])
		if !ok {
			break
		}
		v = v<<4 | d
		n++
	}
	return v, n
}

func readOctal(s string, max int) (v int, n int) {
	for n < max && n < len(s) && s[n] >= '0' && s[n] <= '7' {
		v = v<<3 | int(s[n]-'0')
		n++
	}
	return v & 0xff, n
}

func hexDigit(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

func isAlpha(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isAlnum(c byte) bool {
	return isAlpha(c) || c >= '0' && c <= '9'
}
