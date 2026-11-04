package fingerprint

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dlclark/regexp2"

	"github.com/GoToolSharing/nety/internal/model"
)

// The nmap-service-probes database is loaded at runtime from the local nmap
// installation (it is NOT embedded: the file is distributed under the NPSL).
var nmapProbePaths = []string{
	"/usr/share/nmap/nmap-service-probes",
	"/usr/local/share/nmap/nmap-service-probes",
	"/opt/homebrew/share/nmap/nmap-service-probes",
}

// EnvNmapProbes overrides the location of nmap-service-probes.
const EnvNmapProbes = "NETY_NMAP_PROBES"

const (
	defaultProbeRarity = 5
	defaultTotalWait   = 5 * time.Second
	defaultTCPWrapped  = 3 * time.Second
	regexMatchTimeout  = 400 * time.Millisecond
)

// probeDB is a parsed nmap-service-probes file.
type probeDB struct {
	probes     []*nmapProbe
	byName     map[string]*nmapProbe // key: proto + "/" + name
	excludeTCP portList
	excludeUDP portList
	nullTCP    *nmapProbe
	nMatches   int
}

type nmapProbe struct {
	proto     model.Protocol
	name      string
	payload   []byte
	noPayload bool
	ports     portList
	sslports  portList
	rarity    int
	totalWait time.Duration
	tcpWrap   time.Duration
	fallback  []string
	fallbacks []*nmapProbe // resolved
	matches   []*nmapMatch
	services  map[string]bool
	line      int
}

type nmapMatch struct {
	service string
	soft    bool
	pattern string
	icase   bool
	dotall  bool
	tmpl    versionTemplate
	line    int

	once sync.Once
	re   *regexp2.Regexp
	err  error
}

type versionTemplate struct {
	product, version, info, hostname, ostype, devicetype string
	cpes                                                 []string
}

type portRange struct{ lo, hi uint16 }

type portList []portRange

func (pl portList) contains(p uint16) bool {
	for _, r := range pl {
		if p >= r.lo && p <= r.hi {
			return true
		}
	}
	return false
}

func (p *nmapProbe) key() string { return string(p.proto) + "/" + p.name }

// compiled returns the lazily compiled regular expression.
func (m *nmapMatch) compiled() (*regexp2.Regexp, error) {
	m.once.Do(func() {
		opt := regexp2.None
		if m.icase {
			opt |= regexp2.IgnoreCase
		}
		if m.dotall {
			opt |= regexp2.Singleline
		}
		m.re, m.err = regexp2.Compile(stripPossessive(m.pattern), opt)
		if m.re != nil {
			m.re.MatchTimeout = regexMatchTimeout
		}
	})
	return m.re, m.err
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

var (
	probeDBOnce   sync.Once
	probeDBGlobal *probeDB
)

// loadProbeDB loads and caches the nmap probe database (nil when absent).
func loadProbeDB(log *slog.Logger) *probeDB {
	probeDBOnce.Do(func() { probeDBGlobal = loadProbeDBFrom(log, probeSearchPaths()) })
	return probeDBGlobal
}

// probesOverride is set by SetProbesPath.
var probesOverride atomic.Pointer[string]

// SetProbesPath points the probe-match layer at an nmap-service-probes file,
// taking precedence over $NETY_NMAP_PROBES and the system locations. It is
// meant to be called once at start-up (cmd/nety wires it from the
// configuration) and has no effect once the file has been loaded, since the
// database is parsed at most once per process.
func SetProbesPath(path string) {
	if path == "" {
		probesOverride.Store(nil)
		return
	}
	probesOverride.Store(&path)
}

// probeSearchPaths lists where the nmap data file is looked for: the
// configured override, then $NETY_NMAP_PROBES, then the system locations.
func probeSearchPaths() []string {
	paths := nmapProbePaths
	if env := os.Getenv(EnvNmapProbes); env != "" {
		paths = append([]string{env}, paths...)
	}
	if p := probesOverride.Load(); p != nil {
		paths = append([]string{*p}, paths...)
	}
	return paths
}

// loadProbeDBFrom reads the first readable, parsable file in paths.
func loadProbeDBFrom(log *slog.Logger, paths []string) *probeDB {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		start := time.Now()
		db, err := parseProbeDB(f)
		_ = f.Close()
		if err != nil {
			log.Warn("fingerprint: cannot parse nmap-service-probes", "path", p, "err", err)
			continue
		}
		log.Info("fingerprint: loaded nmap-service-probes", "path", p,
			"probes", len(db.probes), "matches", db.nMatches, "took", time.Since(start))
		return db
	}
	log.Info("fingerprint: nmap-service-probes not found, probe-match layer disabled",
		"env", EnvNmapProbes)
	return nil
}

// parseProbeDB parses the nmap-service-probes format. Malformed match lines
// are skipped; a malformed Probe line is an error.
func parseProbeDB(r io.Reader) (*probeDB, error) {
	db := &probeDB{byName: map[string]*nmapProbe{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var cur *nmapProbe
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		trim := strings.TrimSpace(line)
		if trim == "" || trim[0] == '#' {
			continue
		}
		kw, rest, _ := strings.Cut(trim, " ")
		rest = strings.TrimSpace(rest)
		switch kw {
		case "Exclude":
			db.excludeTCP, db.excludeUDP = parseExclude(rest)
			continue
		case "Probe":
			p, err := parseProbeLine(rest)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
			p.line = lineNo
			cur = p
			db.probes = append(db.probes, p)
			db.byName[p.key()] = p
			if p.proto == model.TCP && p.name == "NULL" {
				db.nullTCP = p
			}
			continue
		}
		if cur == nil {
			continue
		}
		switch kw {
		case "match", "softmatch":
			m, err := parseMatchLine(rest, kw == "softmatch")
			if err != nil {
				continue // tolerate the odd unparsable line
			}
			m.line = lineNo
			cur.matches = append(cur.matches, m)
			cur.services[m.service] = true
			db.nMatches++
		case "ports":
			cur.ports = parsePortList(rest)
		case "sslports":
			cur.sslports = parsePortList(rest)
		case "rarity":
			if n, err := strconv.Atoi(rest); err == nil && n >= 1 && n <= 9 {
				cur.rarity = n
			}
		case "totalwaitms":
			if n, err := strconv.Atoi(rest); err == nil && n > 0 {
				cur.totalWait = time.Duration(n) * time.Millisecond
			}
		case "tcpwrappedms":
			if n, err := strconv.Atoi(rest); err == nil && n > 0 {
				cur.tcpWrap = time.Duration(n) * time.Millisecond
			}
		case "fallback":
			for f := range strings.SplitSeq(rest, ",") {
				if f = strings.TrimSpace(f); f != "" {
					cur.fallback = append(cur.fallback, f)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(db.probes) == 0 {
		return nil, fmt.Errorf("no Probe directive found")
	}
	for _, p := range db.probes {
		for _, name := range p.fallback {
			if fp, ok := db.byName[string(p.proto)+"/"+name]; ok && fp != p {
				p.fallbacks = append(p.fallbacks, fp)
			}
		}
	}
	return db, nil
}

func parseProbeLine(rest string) (*nmapProbe, error) {
	protoS, rest, ok := strings.Cut(rest, " ")
	if !ok {
		return nil, fmt.Errorf("malformed Probe line")
	}
	p := &nmapProbe{
		rarity:    defaultProbeRarity,
		totalWait: defaultTotalWait,
		tcpWrap:   defaultTCPWrapped,
		services:  map[string]bool{},
	}
	switch protoS {
	case "TCP":
		p.proto = model.TCP
	case "UDP":
		p.proto = model.UDP
	default:
		return nil, fmt.Errorf("unknown probe protocol %q", protoS)
	}
	name, rest, ok := strings.Cut(strings.TrimSpace(rest), " ")
	if !ok {
		return nil, fmt.Errorf("malformed Probe line")
	}
	p.name = name
	rest = strings.TrimSpace(rest)
	if len(rest) < 3 || rest[0] != 'q' {
		return nil, fmt.Errorf("probe %s: missing q|...| string", name)
	}
	delim := rest[1]
	end := strings.IndexByte(rest[2:], delim)
	if end < 0 {
		return nil, fmt.Errorf("probe %s: unterminated probe string", name)
	}
	p.payload = unescapeProbe(rest[2 : 2+end])
	if strings.Contains(rest[2+end+1:], "no-payload") {
		p.noPayload = true
	}
	return p, nil
}

// unescapeProbe decodes nmap C-style escapes (\0 \r \n \t \xHH \\ ...).
func unescapeProbe(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			out = append(out, c)
			continue
		}
		i++
		switch s[i] {
		case '0':
			out = append(out, 0)
		case 'a':
			out = append(out, 7)
		case 'b':
			out = append(out, 8)
		case 'f':
			out = append(out, 12)
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'v':
			out = append(out, 11)
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					out = append(out, byte(v))
					i += 2
					continue
				}
			}
			out = append(out, 'x')
		default:
			out = append(out, s[i])
		}
	}
	return out
}

// parseMatchLine parses "<service> m<d>regex<d>[flags] [templates...]".
func parseMatchLine(rest string, soft bool) (*nmapMatch, error) {
	svc, rest, ok := strings.Cut(rest, " ")
	if !ok {
		return nil, fmt.Errorf("malformed match")
	}
	rest = strings.TrimLeft(rest, " ")
	if len(rest) < 3 || rest[0] != 'm' {
		return nil, fmt.Errorf("malformed match pattern")
	}
	delim := rest[1]
	end := strings.IndexByte(rest[2:], delim)
	if end < 0 {
		return nil, fmt.Errorf("unterminated match pattern")
	}
	m := &nmapMatch{service: svc, soft: soft, pattern: latin1Pattern(rest[2 : 2+end])}
	rest = rest[2+end+1:]
	for len(rest) > 0 && rest[0] != ' ' {
		switch rest[0] {
		case 'i':
			m.icase = true
		case 's':
			m.dotall = true
		}
		rest = rest[1:]
	}
	if err := parseTemplates(rest, &m.tmpl); err != nil {
		return nil, err
	}
	return m, nil
}

// latin1Pattern turns raw non-ASCII bytes of a pattern into the runes they
// represent when the subject is decoded byte-per-rune.
func latin1Pattern(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return string(bytesToRunes([]byte(s)))
		}
	}
	return s
}

func parseTemplates(s string, t *versionTemplate) error {
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return nil
		}
		if strings.HasPrefix(s, "cpe:") {
			if len(s) < 5 {
				return fmt.Errorf("truncated cpe")
			}
			d := s[4]
			end := strings.IndexByte(s[5:], d)
			if end < 0 {
				return fmt.Errorf("unterminated cpe")
			}
			t.cpes = append(t.cpes, "cpe:/"+s[5:5+end])
			s = s[5+end+1:]
			if strings.HasPrefix(s, "a") {
				s = s[1:]
			}
			continue
		}
		if len(s) < 2 {
			return fmt.Errorf("truncated template")
		}
		field, d := s[0], s[1]
		end := strings.IndexByte(s[2:], d)
		if end < 0 {
			return fmt.Errorf("unterminated template %c", field)
		}
		val := s[2 : 2+end]
		s = s[2+end+1:]
		switch field {
		case 'p':
			t.product = val
		case 'v':
			t.version = val
		case 'i':
			t.info = val
		case 'h':
			t.hostname = val
		case 'o':
			t.ostype = val
		case 'd':
			t.devicetype = val
		}
	}
}

func parsePortList(s string) portList {
	var pl portList
	for tok := range strings.SplitSeq(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(tok, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 || a > 65535 {
			continue
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a || b > 65535 {
				continue
			}
		}
		pl = append(pl, portRange{uint16(a), uint16(b)})
	}
	return pl
}

// parseExclude parses "Exclude T:9100-9107,U:30000" (no prefix = both).
func parseExclude(s string) (tcp, udp portList) {
	mode := byte(0)
	for tok := range strings.SplitSeq(s, ",") {
		tok = strings.TrimSpace(tok)
		if len(tok) > 2 && tok[1] == ':' {
			mode = tok[0] | 0x20
			tok = tok[2:]
		}
		pl := parsePortList(tok)
		switch mode {
		case 't':
			tcp = append(tcp, pl...)
		case 'u':
			udp = append(udp, pl...)
		default:
			tcp = append(tcp, pl...)
			udp = append(udp, pl...)
		}
	}
	return tcp, udp
}

func bytesToRunes(b []byte) []rune {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return r
}

func runesToBytes(r []rune) []byte {
	var b bytes.Buffer
	b.Grow(len(r))
	for _, c := range r {
		if c < 256 {
			b.WriteByte(byte(c))
		} else {
			b.WriteRune(c)
		}
	}
	return b.Bytes()
}

// stripPossessive rewrites PCRE possessive quantifiers ("a++", "a*+", "a?+",
// "a{2,3}+") into their greedy equivalents. regexp2 implements .NET syntax,
// which has no possessive form; nmap's database uses it in a few dozen
// patterns. Dropping the possessive marker only makes the match backtrack
// where PCRE would not, and the compiled regexps carry a match timeout, so
// the worst case stays bounded.
//
// A quantifier is only recognised at a position where one is legal: an
// escaped "\+" or a "+" inside a character class is left untouched.
func stripPossessive(pat string) string {
	var b strings.Builder
	b.Grow(len(pat))
	inClass, quantifiable := false, false
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		switch {
		case c == '\\':
			b.WriteByte(c)
			if i+1 < len(pat) {
				i++
				b.WriteByte(pat[i])
			}
			quantifiable = !inClass
			continue
		case inClass:
			b.WriteByte(c)
			if c == ']' {
				inClass = false
				quantifiable = true
			}
			continue
		case c == '[':
			b.WriteByte(c)
			inClass = true
			// "[]abc]" and "[^]abc]": a leading ] is a literal.
			if i+1 < len(pat) && pat[i+1] == '^' {
				i++
				b.WriteByte(pat[i])
			}
			if i+1 < len(pat) && pat[i+1] == ']' {
				i++
				b.WriteByte(pat[i])
			}
			continue
		}

		isQuant := false
		switch c {
		case '*', '+', '?':
			isQuant = quantifiable
		case '{':
			if n, ok := braceQuantifier(pat[i:]); ok && quantifiable {
				b.WriteString(pat[i : i+n])
				i += n - 1
				isQuant = true
				c = 0 // already written
			}
		}
		if c != 0 {
			b.WriteByte(c)
		}
		if !isQuant {
			// A group opener or an alternation cannot be quantified; anything
			// else (a literal, a class, a closing paren) can.
			quantifiable = c != '(' && c != '|' && c != 0
			if c == 0 {
				quantifiable = true
			}
			continue
		}
		// Consume the quantifier's modifier: "?" is lazy (kept), "+" is
		// possessive (dropped).
		if i+1 < len(pat) {
			switch pat[i+1] {
			case '+':
				i++ // drop it
			case '?':
				i++
				b.WriteByte('?')
			}
		}
		quantifiable = false
	}
	return b.String()
}

// braceQuantifier reports the length of a leading "{n}", "{n,}" or "{n,m}".
func braceQuantifier(s string) (int, bool) {
	if len(s) < 3 || s[0] != '{' {
		return 0, false
	}
	digits, comma := 0, false
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
			digits++
		case s[i] == ',' && !comma && digits > 0:
			comma = true
		case s[i] == '}':
			if digits == 0 {
				return 0, false
			}
			return i + 1, true
		default:
			return 0, false
		}
		if i > 16 {
			return 0, false
		}
	}
	return 0, false
}
