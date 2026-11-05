package fingerprint

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/GoToolSharing/nety/internal/model"
)

// matchResult is a successful match line with its version template expanded.
type matchResult struct {
	service    string
	soft       bool
	product    string
	version    string
	info       string
	hostname   string
	ostype     string
	devicetype string
	cpes       []string
	probe      string
}

// try runs the match against a byte-per-rune decoded response.
func (m *nmapMatch) try(resp []rune) *matchResult {
	re, err := m.compiled()
	if err != nil || re == nil {
		return nil
	}
	mt, err := re.FindRunesMatch(resp)
	if err != nil || mt == nil {
		return nil
	}
	group := func(n int) ([]byte, bool) {
		g := mt.GroupByNumber(n)
		if g == nil || len(g.Captures) == 0 {
			return nil, false
		}
		return runesToBytes(g.Runes()), true
	}
	r := &matchResult{
		service:    m.service,
		soft:       m.soft,
		product:    expandTemplate(m.tmpl.product, group),
		version:    expandTemplate(m.tmpl.version, group),
		info:       expandTemplate(m.tmpl.info, group),
		hostname:   expandTemplate(m.tmpl.hostname, group),
		ostype:     expandTemplate(m.tmpl.ostype, group),
		devicetype: expandTemplate(m.tmpl.devicetype, group),
	}
	for _, c := range m.tmpl.cpes {
		if v := expandTemplate(c, group); v != "" {
			r.cpes = append(r.cpes, strings.ReplaceAll(v, " ", "_"))
		}
	}
	return r
}

// expandTemplate substitutes $N, $P(N), $SUBST(N,"a","b") and $I(N,"<"|">") in an nmap
// version template.
func expandTemplate(t string, group func(int) ([]byte, bool)) string {
	if t == "" {
		return ""
	}
	if !strings.Contains(t, "$") {
		return cleanText(t)
	}
	var out []byte
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c != '$' || i+1 >= len(t) {
			out = append(out, c)
			continue
		}
		rest := t[i+1:]
		switch {
		case rest[0] >= '0' && rest[0] <= '9':
			g, _ := group(int(rest[0] - '0'))
			out = append(out, g...)
			i++
		case strings.HasPrefix(rest, "P("):
			args, n, ok := templateArgs(rest[1:])
			if !ok || len(args) != 1 {
				out = append(out, c)
				continue
			}
			g, _ := group(atoiSafe(args[0]))
			for _, b := range g {
				if b >= 0x20 && b < 0x7f {
					out = append(out, b)
				}
			}
			i += 1 + n
		case strings.HasPrefix(rest, "SUBST("):
			args, n, ok := templateArgs(rest[5:])
			if !ok || len(args) != 3 {
				out = append(out, c)
				continue
			}
			g, _ := group(atoiSafe(args[0]))
			out = append(out, strings.ReplaceAll(string(g), unquote(args[1]), unquote(args[2]))...)
			i += 5 + n
		case strings.HasPrefix(rest, "I("):
			args, n, ok := templateArgs(rest[1:])
			if !ok || len(args) != 2 {
				out = append(out, c)
				continue
			}
			g, _ := group(atoiSafe(args[0]))
			if len(g) > 0 && len(g) <= 8 {
				var buf [8]byte
				var v uint64
				if unquote(args[1]) == "<" {
					copy(buf[:], g)
					v = binary.LittleEndian.Uint64(buf[:])
				} else {
					copy(buf[8-len(g):], g)
					v = binary.BigEndian.Uint64(buf[:])
				}
				out = strconv.AppendUint(out, v, 10)
			}
			i += 1 + n
		default:
			out = append(out, c)
		}
	}
	s := string(out)
	if !utf8.ValidString(s) {
		s = latin1ToUTF8(out)
	}
	return cleanText(s)
}

// templateArgs parses "(a,"b,c",d)" at the start of s, returning the args and the number
// of bytes consumed (including parentheses).
func templateArgs(s string) ([]string, int, bool) {
	if len(s) == 0 || s[0] != '(' {
		return nil, 0, false
	}
	var args []string
	var cur strings.Builder
	inQ := false
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQ = !inQ
			cur.WriteByte(c)
		case c == ',' && !inQ:
			args = append(args, strings.TrimSpace(cur.String()))
			cur.Reset()
		case c == ')' && !inQ:
			args = append(args, strings.TrimSpace(cur.String()))
			return args, i + 1, true
		default:
			cur.WriteByte(c)
		}
	}
	return nil, 0, false
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return string(unescapeProbe(s[1 : len(s)-1]))
	}
	return s
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// matchResponse tries the probe's matches, then its fallbacks', then (TCP) the NULL
// probe's ones, like nmap.
func (db *probeDB) matchResponse(p *nmapProbe, resp []byte) (hard, soft *matchResult) {
	if len(resp) == 0 {
		return nil, nil
	}
	rs := bytesToRunes(resp)
	sets := []*nmapProbe{p}
	sets = append(sets, p.fallbacks...)
	if p.proto == model.TCP && db.nullTCP != nil && p != db.nullTCP {
		sets = append(sets, db.nullTCP)
	}
	seen := map[*nmapProbe]bool{}
	for _, set := range sets {
		if seen[set] {
			continue
		}
		seen[set] = true
		for _, m := range set.matches {
			if soft != nil && m.soft {
				continue
			}
			if soft != nil && m.service != soft.service {
				// once soft-matched, only hard matches of the same service count
				continue
			}
			r := m.try(rs)
			if r == nil {
				continue
			}
			r.probe = p.name
			if !r.soft {
				return r, soft
			}
			soft = r
		}
	}
	return nil, soft
}

// probeOutcome is the result of running the probe engine against a port.
type probeOutcome struct {
	hard      *matchResult
	soft      *matchResult
	banner    []byte // first non-empty response
	probeName string // probe that produced banner
	wrapped   bool   // every connection was closed without data
}

// tcpCandidates orders probes like nmap: probes listing the port first, then the other
// probes allowed by intensity (rarity), in file order.
func (db *probeDB) tcpCandidates(proto model.Protocol, port uint16, ssl bool, intensity int) []*nmapProbe {
	var first, rest []*nmapProbe
	for _, p := range db.probes {
		if p.proto != proto || (proto == model.TCP && p == db.nullTCP) || (p.name == "NULL") {
			continue
		}
		listed := p.ports.contains(port) || (ssl && p.sslports.contains(port))
		switch {
		case listed:
			first = append(first, p)
		case p.rarity <= intensity:
			rest = append(rest, p)
		}
	}
	return append(first, rest...)
}

// runTCP drives the TCP probes. nullResp is the banner already read on a fresh connection
// (NULL probe). deadline bounds the whole phase.
func (db *probeDB) runTCP(ctx context.Context, log *slog.Logger, dial func(context.Context) (net.Conn, error),
	port uint16, ssl bool, intensity int, nullResp []byte, timeout time.Duration, deadline time.Time) *probeOutcome {
	out := &probeOutcome{wrapped: true}
	if len(nullResp) > 0 {
		out.wrapped = false
		out.banner, out.probeName = nullResp, "NULL"
		if db.nullTCP != nil {
			hard, soft := db.matchResponse(db.nullTCP, nullResp)
			if hard != nil {
				out.hard = hard
				return out
			}
			out.soft = soft
		}
	}
	if db.excludeTCP.contains(port) {
		return out
	}
	failures := 0
	for _, p := range db.tcpCandidates(model.TCP, port, ssl, intensity) {
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		if out.soft != nil && !p.services[out.soft.service] {
			continue
		}
		resp, closed, err := sendProbe(ctx, dial, p, timeout, deadline)
		if err != nil {
			failures++
			log.Debug("fingerprint: probe failed", "probe", p.name, "err", err)
			if failures >= 3 {
				break
			}
			continue
		}
		failures = 0
		if len(resp) == 0 {
			if !closed {
				out.wrapped = false
			}
			continue
		}
		out.wrapped = false
		if out.banner == nil {
			out.banner, out.probeName = resp, p.name
		}
		hard, soft := db.matchResponse(p, resp)
		if hard != nil {
			out.hard = hard
			out.banner, out.probeName = resp, p.name
			return out
		}
		if soft != nil && out.soft == nil {
			out.soft = soft
		}
	}
	return out
}

// runTCPFiltered runs only the named probes (used when the service is already known, e.g.
// HTTP, to refine product/version cheaply).
func (db *probeDB) runTCPFiltered(ctx context.Context, log *slog.Logger, dial func(context.Context) (net.Conn, error),
	port uint16, ssl bool, nullResp []byte, timeout time.Duration, deadline time.Time, names []string) *probeOutcome {
	out := &probeOutcome{}
	if len(nullResp) > 0 && db.nullTCP != nil && !bytes.HasPrefix(nullResp, []byte("HTTP/")) {
		if hard, soft := db.matchResponse(db.nullTCP, nullResp); hard != nil {
			out.hard = hard
			return out
		} else {
			out.soft = soft
		}
	}
	for _, name := range names {
		p := db.byName[string(model.TCP)+"/"+name]
		if p == nil || ctx.Err() != nil || time.Now().After(deadline) {
			continue
		}
		resp, _, err := sendProbe(ctx, dial, p, timeout, deadline)
		if err != nil || len(resp) == 0 {
			log.Debug("fingerprint: probe without answer", "probe", name, "err", err)
			continue
		}
		if out.banner == nil {
			out.banner, out.probeName = resp, p.name
		}
		hard, soft := db.matchResponse(p, resp)
		if hard != nil {
			out.hard = hard
			return out
		}
		if soft != nil && out.soft == nil {
			out.soft = soft
		}
	}
	return out
}

func sendProbe(ctx context.Context, dial func(context.Context) (net.Conn, error), p *nmapProbe,
	timeout time.Duration, deadline time.Time) ([]byte, bool, error) {
	c, err := dial(ctx)
	if err != nil {
		return nil, false, err
	}
	defer c.Close()
	if len(p.payload) > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := c.Write(p.payload); err != nil {
			return nil, true, nil
		}
	}
	wait := min(p.totalWait, timeout)
	if rem := time.Until(deadline); rem < wait {
		wait = rem
	}
	if wait <= 0 {
		return nil, false, errors.New("probe budget exhausted")
	}
	data, closed, err := readResponse(c, wait, 750*time.Millisecond, nil)
	if err != nil && len(data) == 0 {
		return nil, closed, err
	}
	return data, closed, nil
}

// runUDP sends the UDP probes listing the port (and the most common generic ones) and
// matches the first datagram received.
func (db *probeDB) runUDP(ctx context.Context, dial func(context.Context) (net.Conn, error),
	port uint16, intensity int, timeout time.Duration, deadline time.Time) *probeOutcome {
	out := &probeOutcome{}
	if db.excludeUDP.contains(port) {
		return out
	}
	for _, p := range db.tcpCandidates(model.UDP, port, false, min(intensity, 1)) {
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		if out.soft != nil && !p.services[out.soft.service] {
			continue
		}
		resp := udpExchange(ctx, dial, p.payload, min(p.totalWait, timeout), 2)
		if len(resp) == 0 {
			continue
		}
		if out.banner == nil {
			out.banner, out.probeName = resp, p.name
		}
		hard, soft := db.matchResponse(p, resp)
		if hard != nil {
			out.hard = hard
			out.banner, out.probeName = resp, p.name
			return out
		}
		if soft != nil && out.soft == nil {
			out.soft = soft
		}
	}
	return out
}
