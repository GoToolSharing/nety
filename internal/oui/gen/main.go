//go:build ignore

// Command gen builds the MAC-vendor database embedded by package oui.
//
// It downloads the IEEE MA-L / MA-M / MA-S registries (CSV) and, when they are
// unreachable, falls back to Wireshark's tab-separated "manuf" file. The result is
// written as a gzip-compressed binary blob (see "Wire format" below) that package oui
// embeds and decodes lazily.
//
// Usage, from the repository root:
//
//	go run internal/oui/gen/main.go [-out internal/oui/oui.bin.gz] [-source auto]
//
// Flags:
//
//	-out     output file (default internal/oui/oui.bin.gz)
//	-source  auto | ieee | wireshark (default auto)
//
// # Wire format (after gunzip)
//
//	magic    8 bytes  "NETYOUI2"
//	version  1 byte   0x01
//	uvarint  number of distinct vendor names (N)
//	uvarint  xN       length in bytes of each name, in index order
//	bytes             the names, concatenated, no separators
//	then three sections, in this order: MA-L (24 bit), MA-M (28 bit),
//	MA-S (36 bit); each one is
//	    uvarint  number of entries (C)
//	    uvarint  xC  prefix keys, ascending, delta-encoded (first is absolute)
//	    uvarint  xC  index into the name table, in the same order
//
// A key is the prefix's hex digits read as a big-endian integer: 0x00505 6 for the MA-L
// 00:50:56, 0x0055DA1 for the MA-M 00:55:DA:1, and so on.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	magic      = "NETYOUI2"
	version    = 1
	maxBody    = 64 << 20 // response size cap
	httpTotal  = 3 * time.Minute
	httpSingle = 90 * time.Second
	userAgent  = "nety-oui-gen/1.0 (+https://github.com/GoToolSharing/nety)"
)

// ieeeSources are the three public IEEE registry exports. oui.csv is the only mandatory
// one: without it we consider the IEEE source failed.
var ieeeSources = []struct {
	url      string
	required bool
}{
	{"https://standards-oui.ieee.org/oui/oui.csv", true},      // MA-L, 24 bits
	{"https://standards-oui.ieee.org/oui28/mam.csv", false},   // MA-M, 28 bits
	{"https://standards-oui.ieee.org/oui36/oui36.csv", false}, // MA-S, 36 bits
	{"https://standards-oui.ieee.org/iab/iab.csv", false},     // IAB (legacy), 36 bits
}

const manufURL = "https://www.wireshark.org/download/automated/data/manuf"

// placeholders are registry entries that name the block administrator rather than a real
// vendor. Keeping them would shadow the more specific MA-M / MA-S assignments carved out
// of the same MA-L range, so they are dropped.
var placeholders = map[string]bool{
	"ieee registration authority":     true,
	"private":                         true,
	"ieee registration authority(ra)": true,
}

func main() {
	out := flag.String("out", "internal/oui/oui.bin.gz", "output file")
	source := flag.String("source", "auto", "data source: auto, ieee or wireshark")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, cancel := context.WithTimeout(context.Background(), httpTotal)
	defer cancel()

	entries := make(map[string]string, 64<<10)
	used := ""

	if *source == "auto" || *source == "ieee" {
		if ok := loadIEEE(ctx, log, entries); ok {
			used = "ieee"
		} else if *source == "ieee" {
			log.Error("IEEE registries unavailable and -source=ieee")
			os.Exit(1)
		} else {
			log.Warn("IEEE registries unavailable, falling back to Wireshark manuf")
		}
	}
	if used == "" {
		body, err := fetch(ctx, manufURL)
		if err != nil {
			log.Error("manuf download failed", "err", err)
			os.Exit(1)
		}
		n := parseManuf(body, entries)
		log.Info("parsed", "url", manufURL, "entries", n)
		used = "wireshark"
	}

	var l, m, s int
	for k := range entries {
		switch len(k) {
		case 6:
			l++
		case 7:
			m++
		case 9:
			s++
		}
	}
	if l < 5000 {
		log.Error("refusing to write: too few MA-L entries", "entries", l)
		os.Exit(1)
	}

	blob, names, err := encode(entries)
	if err != nil {
		log.Error("encode failed", "err", err)
		os.Exit(1)
	}
	if err := writeFile(*out, blob); err != nil {
		log.Error("write failed", "err", err)
		os.Exit(1)
	}
	log.Info("wrote database",
		"file", *out, "source", used,
		"mal", l, "mam", m, "mas", s, "total", l+m+s,
		"names", names, "gzip_bytes", len(blob))
}

// loadIEEE fills entries from the IEEE CSV registries. It reports whether the mandatory
// MA-L export was retrieved and parsed.
func loadIEEE(ctx context.Context, log *slog.Logger, entries map[string]string) bool {
	ok := false
	for _, src := range ieeeSources {
		body, err := fetch(ctx, src.url)
		if err != nil {
			log.Warn("download failed", "url", src.url, "err", err)
			continue
		}
		n, err := parseIEEECSV(body, entries)
		if err != nil {
			log.Warn("parse failed", "url", src.url, "err", err, "entries", n)
			continue
		}
		log.Info("parsed", "url", src.url, "entries", n)
		if src.required && n > 5000 {
			ok = true
		}
	}
	return ok
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, httpSingle)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// standards-oui.ieee.org rejects requests without a browser-ish UA.
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := (&http.Client{Timeout: httpSingle}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if len(body) == maxBody {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBody)
	}
	return body, nil
}

// parseIEEECSV parses an IEEE registry export, whose columns are Registry, Assignment,
// Organization Name, Organization Address.
func parseIEEECSV(body []byte, entries map[string]string) (int, error) {
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.ReuseRecord = true

	n := 0
	first := true
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return n, err
		}
		if first {
			first = false
			continue // header
		}
		if len(rec) < 3 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(rec[0]), "CID") {
			continue // company IDs are not MAC assignments
		}
		key, ok := normPrefix(rec[1])
		if !ok {
			continue
		}
		name := cleanVendor(rec[2])
		if name == "" || placeholders[strings.ToLower(name)] {
			continue
		}
		entries[key] = name
		n++
	}
	return n, nil
}

// parseManuf parses Wireshark's manuf file. Lines are tab-separated:
//
//	00:00:0C<TAB>Cisco<TAB>Cisco Systems, Inc
//	00:1B:C5:00:00:00/36<TAB>Converging<TAB>Converging Systems Inc.
//
// The third column (long name) is preferred; the short name is used when the long one is
// absent.
func parseManuf(body []byte, entries map[string]string) int {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		// The prefix column is space-padded to a fixed width, so both halves of
		// "00:55:DA:00/28 " need trimming.
		prefix, bits := strings.TrimSpace(f[0]), 24
		if i := strings.IndexByte(prefix, '/'); i >= 0 {
			v, err := strconv.Atoi(strings.TrimSpace(prefix[i+1:]))
			if err != nil {
				continue
			}
			bits, prefix = v, strings.TrimSpace(prefix[:i])
		}
		if bits != 24 && bits != 28 && bits != 36 {
			continue
		}
		hex := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(prefix))
		if len(hex) < bits/4 {
			continue
		}
		key, ok := normPrefix(hex[:bits/4])
		if !ok {
			continue
		}
		name := ""
		for _, c := range f[1:] {
			if c = cleanVendor(c); c != "" {
				name = c // last non-empty column wins (the long name)
			}
		}
		if name == "" || placeholders[strings.ToLower(name)] {
			continue
		}
		entries[key] = name
		n++
	}
	return n
}

// normPrefix validates an assignment string and returns it as uppercase hex of 6, 7 or 9
// digits (24, 28 or 36 bits).
func normPrefix(s string) (string, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(s)
	if len(s) != 6 && len(s) != 7 && len(s) != 9 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return "", false
		}
	}
	return s, true
}

// cleanVendor collapses whitespace, drops control characters and strips the quoting some
// registry rows carry. Names are otherwise kept verbatim so they stay recognisable.
func cleanVendor(v string) string {
	v = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
	v = strings.Join(strings.Fields(v), " ")
	v = strings.Trim(v, `"'`)
	v = strings.Join(strings.Fields(v), " ")
	if strings.EqualFold(v, "n/a") || strings.EqualFold(v, "none") {
		return ""
	}
	return v
}

type entry struct {
	key  uint64
	name uint32
}

// encode serialises entries into the gzip'd wire format and reports the number of
// distinct vendor names.
func encode(entries map[string]string) (blob []byte, names int, err error) {
	// Intern vendor names, most frequent first so the common ones get small varint
	// indices.
	count := map[string]int{}
	for _, v := range entries {
		count[v]++
	}
	order := make([]string, 0, len(count))
	for v := range count {
		order = append(order, v)
	}
	slices.SortFunc(order, func(a, b string) int {
		if d := count[b] - count[a]; d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	idx := make(map[string]uint32, len(order))
	for i, v := range order {
		idx[v] = uint32(i)
	}

	var sections [3][]entry // 0: MA-L, 1: MA-M, 2: MA-S
	for k, v := range entries {
		n, perr := strconv.ParseUint(k, 16, 64)
		if perr != nil {
			continue
		}
		var sec int
		switch len(k) {
		case 6:
			sec = 0
		case 7:
			sec = 1
		case 9:
			sec = 2
		default:
			continue
		}
		sections[sec] = append(sections[sec], entry{key: n, name: idx[v]})
	}

	buf := make([]byte, 0, 4<<20)
	buf = append(buf, magic...)
	buf = append(buf, version)

	buf = binary.AppendUvarint(buf, uint64(len(order)))
	for _, v := range order {
		buf = binary.AppendUvarint(buf, uint64(len(v)))
	}
	for _, v := range order {
		buf = append(buf, v...)
	}

	for _, sec := range sections {
		slices.SortFunc(sec, func(a, b entry) int {
			switch {
			case a.key < b.key:
				return -1
			case a.key > b.key:
				return 1
			}
			return 0
		})
		buf = binary.AppendUvarint(buf, uint64(len(sec)))
		var prev uint64
		for _, e := range sec {
			buf = binary.AppendUvarint(buf, e.key-prev)
			prev = e.key
		}
		for _, e := range sec {
			buf = binary.AppendUvarint(buf, uint64(e.name))
		}
	}

	var gz bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if err != nil {
		return nil, 0, err
	}
	zw.ModTime = time.Time{} // reproducible output
	zw.OS = 255
	if _, err := zw.Write(buf); err != nil {
		return nil, 0, err
	}
	if err := zw.Close(); err != nil {
		return nil, 0, err
	}
	return gz.Bytes(), len(order), nil
}

func writeFile(path string, blob []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
