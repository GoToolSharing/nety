// Package nmapdb parses and matches nmap's service-probes file format.
//
// The probe database itself is never embedded in NETY: nmap's
// nmap-service-probes file is covered by the Nmap Public Source License and
// stays on the operator's disk. [Load] reads it at runtime; the only file
// shipped with this package is testdata/synthetic-service-probes, which is
// hand-written test data.
//
// # Byte handling
//
// Responses from a service are arbitrary bytes, and so are the patterns in the
// probe file. Both are mapped to runes latin-1 style (byte b becomes rune(b))
// before being handed to the regex engine, and capture groups are mapped back
// the same way. That keeps the engine's rune offsets equal to byte offsets and
// makes \xNN patterns behave exactly as written, with no UTF-8 decoding in the
// middle that could merge or drop bytes.
//
// Version-template results are run through a final cleanup that drops C0/DEL
// control bytes and re-encodes any remaining invalid UTF-8 as latin-1, so the
// strings in a [Result] are always valid UTF-8 and safe to store or serialise.
package nmapdb

import (
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dlclark/regexp2"
)

// matchTimeout bounds a single regex execution. nmap's patterns include
// constructs that can backtrack catastrophically on hostile input; a timeout
// is reported as "no match" rather than hanging the scanner.
const matchTimeout = 250 * time.Millisecond

// Errors returned by [Parse] and [Load].
var (
	// ErrTooLarge is returned when the probe file exceeds maxFileSize.
	ErrTooLarge = errors.New("nmapdb: probe file too large")
	// ErrNoProbes is returned when a file parsed without yielding a probe.
	ErrNoProbes = errors.New("nmapdb: no probes found")
	// ErrNotFound is returned by Load when no probe file could be located.
	ErrNotFound = errors.New("nmapdb: no nmap-service-probes file found")
)

// Result is what a match line says about a service.
type Result struct {
	Service    string   // match line's service name, e.g. "http"
	Soft       bool     // true for a softmatch
	Product    string   // p//
	Version    string   // v//
	Info       string   // i//
	Hostname   string   // h//
	OSType     string   // o//
	DeviceType string   // d//
	CPEs       []string // cpe:/...
}

// Probe is one Probe directive of the file with its scoped directives.
type Probe struct {
	Proto      string        // "tcp" | "udp"
	Name       string        // e.g. "NULL", "GenericLines", "GetRequest"
	Data       []byte        // decoded probe payload to send (empty for NULL)
	Rarity     int           // 1..9, default 9 when absent
	TotalWait  time.Duration // totalwaitms, 0 when absent
	TCPWrapped time.Duration // tcpwrappedms, 0 when absent

	ports     portSet
	sslPorts  portSet
	matches   []*matchLine
	fallbacks []string // names, as written
	chain     []*Probe // resolved fallbacks, including the implicit TCP NULL
}

// matchLine is one match/softmatch line. Its pattern is compiled on first use
// and cached: compiling the ~12k patterns of a real probe file up front costs
// seconds, while a scan only ever touches a handful of them.
type matchLine struct {
	db      *DB
	service string
	soft    bool
	pattern string // raw bytes of the pattern, delimiters stripped
	opts    regexp2.RegexOptions
	info    versionInfo

	once sync.Once
	re   *regexp2.Regexp // nil when the pattern failed to compile
}

// versionInfo holds the un-substituted version templates of a match line.
type versionInfo struct {
	product    string
	version    string
	info       string
	hostname   string
	ostype     string
	devicetype string
	cpes       []string
}

// empty reports whether the match line carries no version information.
func (v versionInfo) empty() bool {
	return v.product == "" && v.version == "" && v.info == "" && v.hostname == "" &&
		v.ostype == "" && v.devicetype == "" && len(v.cpes) == 0
}

// DB is a parsed probe database. It is safe for concurrent use.
type DB struct {
	probes  []*Probe
	nullTCP *Probe
	nmatch  int

	exclTCP portSet
	exclUDP portSet

	badRegex atomic.Int64 // patterns that failed to compile
	skipped  int          // over-long lines skipped by the reader
}

// Stats reports how much was parsed (for logging).
func (db *DB) Stats() (probes, matches int) {
	if db == nil {
		return 0, 0
	}
	return len(db.probes), db.nmatch
}

// Probes returns the parsed probes in file order. The slice must not be
// modified.
func (db *DB) Probes() []*Probe {
	if db == nil {
		return nil
	}
	return db.probes
}

// excluded reports whether port is covered by a file-level Exclude directive.
// Exclude is advisory for NETY (the operator decides what to scan), so it is
// parsed and exposed but never applied by this package.
func (db *DB) excluded(proto string, port uint16) bool {
	if db == nil {
		return false
	}
	switch normProto(proto) {
	case "tcp":
		return db.exclTCP.contains(port)
	case "udp":
		return db.exclUDP.contains(port)
	}
	return false
}

// Select returns the probes worth sending to proto/port, best first.
//
// NULL comes first for TCP: nmap always reads the banner of a TCP service
// before sending anything, so the TCP NULL probe is always included whatever
// the intensity. Every other probe is selected when its rarity <= intensity or
// when port is listed in its ports directive (its sslports directive when ssl
// is true). The remaining probes keep their file order, which is the order
// nmap intends them to be tried in.
func (db *DB) Select(proto string, port uint16, ssl bool, intensity int) []*Probe {
	if db == nil {
		return nil
	}
	proto = normProto(proto)
	if proto == "" {
		return nil
	}
	if intensity < 0 {
		intensity = 0
	}
	if intensity > 9 {
		intensity = 9
	}

	out := make([]*Probe, 0, 8)
	if proto == "tcp" && db.nullTCP != nil {
		out = append(out, db.nullTCP)
	}
	for _, p := range db.probes {
		if p.Proto != proto || p == db.nullTCP {
			continue
		}
		set := p.ports
		if ssl {
			set = p.sslPorts
		}
		if p.Rarity <= intensity || set.contains(port) {
			out = append(out, p)
		}
	}
	return out
}

// Match tries p's match/softmatch lines against resp, then the lines of p's
// fallback probes (fallback directive, plus the implicit NULL fallback for
// TCP). It returns the first hard match; if only softmatches are found it
// returns the first one with Soft=true. ok is false when nothing matched.
func (db *DB) Match(p *Probe, resp []byte) (res *Result, ok bool) {
	if db == nil || p == nil || len(resp) == 0 {
		return nil, false
	}
	runes := latin1Runes(resp)

	var soft *Result
	for i := -1; i < len(p.chain); i++ {
		pr := p
		if i >= 0 {
			pr = p.chain[i]
		}
		if pr == nil {
			continue
		}
		for _, ml := range pr.matches {
			if ml.soft && soft != nil {
				continue // we already have the first softmatch
			}
			m := ml.exec(runes)
			if m == nil {
				continue
			}
			r := ml.result(m)
			if !ml.soft {
				return r, true
			}
			soft = r
		}
	}
	if soft != nil {
		return soft, true
	}
	return nil, false
}

// compile compiles the match line's pattern once. It returns nil when the
// pattern is not usable; such patterns are counted and silently dropped, as a
// single bad line in a third-party database must never break a scan.
func (ml *matchLine) compile() *regexp2.Regexp {
	ml.once.Do(func() {
		re, err := regexp2.Compile(latin1String(ml.pattern), ml.opts)
		if err != nil {
			if ml.db != nil {
				ml.db.badRegex.Add(1)
			}
			return
		}
		re.MatchTimeout = matchTimeout
		ml.re = re
	})
	return ml.re
}

// exec runs the match line against the latin-1 runes of a response. A regex
// timeout (or any other engine error) counts as "no match".
func (ml *matchLine) exec(runes []rune) *regexp2.Match {
	re := ml.compile()
	if re == nil {
		return nil
	}
	m, err := re.FindRunesMatch(runes)
	if err != nil {
		return nil
	}
	return m
}

// result builds a Result from a successful match, substituting the version
// templates with the match's capture groups.
func (ml *matchLine) result(m *regexp2.Match) *Result {
	res := &Result{Service: ml.service, Soft: ml.soft}
	if ml.info.empty() {
		return res
	}
	groups := captureBytes(m)
	res.Product = cleanField(expandTemplate(ml.info.product, groups))
	res.Version = cleanField(expandTemplate(ml.info.version, groups))
	res.Info = cleanField(expandTemplate(ml.info.info, groups))
	res.Hostname = cleanField(expandTemplate(ml.info.hostname, groups))
	res.OSType = cleanField(expandTemplate(ml.info.ostype, groups))
	res.DeviceType = cleanField(expandTemplate(ml.info.devicetype, groups))
	for _, c := range ml.info.cpes {
		if s := cleanField(expandTemplate(c, groups)); s != "" {
			res.CPEs = append(res.CPEs, s)
		}
	}
	return res
}

// captureBytes extracts groups 0..9 of a match as raw bytes.
func captureBytes(m *regexp2.Match) [][]byte {
	groups := make([][]byte, 10)
	if m == nil {
		return groups
	}
	for i := range groups {
		g := m.GroupByNumber(i)
		if g == nil {
			continue
		}
		groups[i] = unlatin1(g.Runes())
	}
	return groups
}

// --- probe-file location & caching -----------------------------------------

// probePaths are the well-known locations tried by Load, in order, after
// $NETY_NMAP_PROBES.
var probePaths = []string{
	"/usr/share/nmap/nmap-service-probes",
	"/usr/local/share/nmap/nmap-service-probes",
}

var (
	loadOnce   = sync.OnceValues(loadDefault)
	loadedPath atomic.Value // string
)

// Load locates and parses the probe file, trying in order:
//
//	$NETY_NMAP_PROBES, /usr/share/nmap/nmap-service-probes,
//	/usr/local/share/nmap/nmap-service-probes
//
// The result (DB and error) is cached with sync.OnceValues so repeated calls
// are free. Returns (nil, err) when no file is found or it fails to parse.
func Load() (*DB, error) { return loadOnce() }

// Path reports the file Load() actually read, "" when none.
func Path() string {
	s, _ := loadedPath.Load().(string)
	return s
}

func loadDefault() (*DB, error) {
	var candidates []string
	if p := strings.TrimSpace(os.Getenv("NETY_NMAP_PROBES")); p != "" {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, probePaths...)

	var firstErr error
	for _, p := range candidates {
		db, err := load(p)
		if err == nil {
			loadedPath.Store(p)
			return db, nil
		}
		if !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, ErrNotFound
}

// load reads and parses a single probe file. It is the testable half of Load.
func load(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// --- port ranges ------------------------------------------------------------

type portRange struct{ lo, hi uint16 }

// portSet is a sorted, non-overlapping set of port ranges.
type portSet []portRange

func (ps portSet) contains(p uint16) bool {
	i := sort.Search(len(ps), func(i int) bool { return ps[i].hi >= p })
	return i < len(ps) && ps[i].lo <= p
}

// normalise sorts and merges the ranges so contains can binary-search.
func (ps portSet) normalise() portSet {
	if len(ps) < 2 {
		return ps
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].lo != ps[j].lo {
			return ps[i].lo < ps[j].lo
		}
		return ps[i].hi < ps[j].hi
	})
	out := ps[:1]
	for _, r := range ps[1:] {
		last := &out[len(out)-1]
		if r.lo <= last.hi || (last.hi < 65535 && r.lo == last.hi+1) {
			if r.hi > last.hi {
				last.hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// --- byte/rune helpers ------------------------------------------------------

// latin1Runes maps each byte to the rune of the same value.
func latin1Runes(b []byte) []rune {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return r
}

// latin1String is latin1Runes for a raw byte string.
func latin1String(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	return string(latin1Runes([]byte(s)))
}

// unlatin1 maps runes back to the bytes they stand for.
func unlatin1(r []rune) []byte {
	b := make([]byte, len(r))
	for i, c := range r {
		b[i] = byte(c)
	}
	return b
}

func normProto(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	}
	return ""
}
