package checks

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/identity/ntlm"
	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("ldap-anonymous-bind", "LDAP directory readable anonymously", model.SevMedium,
			[]string{"ldap", "ldaps", "globalcatln", "globalcatldap", "globalcatldapssl"},
			"The LDAP server accepts anonymous binds and returns directory entries below the naming context to unauthenticated clients. Attackers can enumerate users, groups, computers and attributes (sometimes including passwords in description fields) without credentials."),
		Remediation: "Disable anonymous read access to the directory: on Active Directory keep dsHeuristics without the anonymous flag (7th char) and remove ANONYMOUS LOGON ACEs; on OpenLDAP use 'disallow bind_anon' and restrict 'access to * by anonymous auth'.",
		References:  []string{"https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-anonymous-queries-to-ad"},
		Applies:     ldapApplies,
		Run:         runLDAPAnon,
	})
}

func ldapApplies(t *Target) bool {
	s := t.Service
	n := strings.ToLower(s.Name)
	if s.Protocol != model.TCP {
		return false
	}
	if strings.HasPrefix(n, "ldap") || strings.HasPrefix(n, "globalcat") {
		return true
	}
	return svcIs(s, model.TCP, nil, 389, 636, 3268, 3269)
}

func ldapUseTLS(s model.Service) bool {
	return isTLS(s) || s.Port == 636 || s.Port == 3269 || strings.EqualFold(s.Name, "ldaps")
}

// ---------------------------------------------------------------------------
// Minimal BER / LDAPv3 encoding
// ---------------------------------------------------------------------------

func ldapInt(tag byte, v int) []byte {
	var b []byte
	switch {
	case v >= 0 && v < 0x80:
		b = []byte{byte(v)}
	case v >= 0 && v < 0x8000:
		b = []byte{byte(v >> 8), byte(v)}
	default:
		b = []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return ntlm.DER(tag, b)
}

func ldapStr(tag byte, s string) []byte { return ntlm.DER(tag, []byte(s)) }

func ldapMessage(id int, op []byte) []byte { return ntlm.DER(0x30, ldapInt(0x02, id), op) }

// ldapBindRequest builds an anonymous simple bind.
func ldapBindRequest(id int) []byte {
	return ldapMessage(id, ntlm.DER(0x60, ldapInt(0x02, 3), ldapStr(0x04, ""), ldapStr(0x80, "")))
}

// ldapSearchRequest builds a search with filter (objectClass=*) (present).
func ldapSearchRequest(id int, base string, scope, sizeLimit int, attrs []string) []byte {
	var al []byte
	for _, a := range attrs {
		al = append(al, ldapStr(0x04, a)...)
	}
	return ldapMessage(id, ntlm.DER(0x63,
		ldapStr(0x04, base),
		ldapInt(0x0a, scope),
		ldapInt(0x0a, 0), // neverDerefAliases
		ldapInt(0x02, sizeLimit),
		ldapInt(0x02, 10), // time limit (s)
		[]byte{0x01, 0x01, 0x00},
		ldapStr(0x87, "objectClass"),
		ntlm.DER(0x30, al),
	))
}

func ldapUnbind(id int) []byte { return ldapMessage(id, []byte{0x42, 0x00}) }

// ldapMsg is a decoded LDAPMessage.
type ldapMsg struct {
	ID     int
	Op     byte
	Result int    // for *Response / SearchResultDone
	DN     string // SearchResultEntry objectName
	Attrs  map[string][]string
	Diag   string
}

var errLDAPMalformed = errors.New("ldap: malformed message")

func berInt(v []byte) int {
	if len(v) == 0 || len(v) > 4 {
		return -1
	}
	n := 0
	for _, x := range v {
		n = n<<8 | int(x)
	}
	return n
}

// ldapParseMessage decodes one complete LDAPMessage.
func ldapParseMessage(b []byte) (*ldapMsg, error) {
	tag, seq, _, err := ntlm.ReadTLV(b)
	if err != nil || tag != 0x30 {
		return nil, errLDAPMalformed
	}
	tag, idv, rest, err := ntlm.ReadTLV(seq)
	if err != nil || tag != 0x02 {
		return nil, errLDAPMalformed
	}
	m := &ldapMsg{ID: berInt(idv)}
	op, body, _, err := ntlm.ReadTLV(rest)
	if err != nil {
		return nil, errLDAPMalformed
	}
	m.Op = op
	switch op {
	case 0x61, 0x65, 0x67, 0x69, 0x6b, 0x6d, 0x6f, 0x78: // LDAPResult based responses
		t, v, r, err := ntlm.ReadTLV(body)
		if err != nil || t != 0x0a {
			return nil, errLDAPMalformed
		}
		m.Result = berInt(v)
		if _, _, r2, err := ntlm.ReadTLV(r); err == nil { // matchedDN
			if t, v, _, err := ntlm.ReadTLV(r2); err == nil && t == 0x04 {
				m.Diag = partASanitize(string(v))
			}
		}
	case 0x64: // SearchResultEntry
		t, v, r, err := ntlm.ReadTLV(body)
		if err != nil || t != 0x04 {
			return nil, errLDAPMalformed
		}
		m.DN = partASanitize(string(v))
		m.Attrs = map[string][]string{}
		t, attrs, _, err := ntlm.ReadTLV(r)
		if err != nil || t != 0x30 {
			return m, nil
		}
		for n := 0; len(attrs) > 0 && n < 256; n++ {
			var pa []byte
			t, pa, attrs, err = ntlm.ReadTLV(attrs)
			if err != nil || t != 0x30 {
				break
			}
			t, name, vals, err := ntlm.ReadTLV(pa)
			if err != nil || t != 0x04 {
				break
			}
			_, set, _, err := ntlm.ReadTLV(vals)
			if err != nil {
				break
			}
			key := strings.ToLower(partASanitize(string(name)))
			for k := 0; len(set) > 0 && k < 64; k++ {
				var v []byte
				_, v, set, err = ntlm.ReadTLV(set)
				if err != nil {
					break
				}
				m.Attrs[key] = append(m.Attrs[key], truncate(partASanitize(string(v)), 256))
			}
		}
	}
	return m, nil
}

// ldapConn reads LDAP messages from a stream.
type ldapConn struct {
	c       net.Conn
	timeout time.Duration
}

const ldapMaxMsg = 1 << 20

func (l *ldapConn) send(b []byte) error {
	_ = l.c.SetDeadline(time.Now().Add(l.timeout))
	_, err := l.c.Write(b)
	return err
}

func (l *ldapConn) recv() (*ldapMsg, error) {
	_ = l.c.SetDeadline(time.Now().Add(l.timeout))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(l.c, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x30 {
		return nil, errLDAPMalformed
	}
	n := int(hdr[1])
	lenBytes := []byte{}
	if n&0x80 != 0 {
		nb := n & 0x7f
		if nb == 0 || nb > 4 {
			return nil, errLDAPMalformed
		}
		lenBytes = make([]byte, nb)
		if _, err := io.ReadFull(l.c, lenBytes); err != nil {
			return nil, err
		}
		n = 0
		for _, x := range lenBytes {
			n = n<<8 | int(x)
		}
	}
	if n < 0 || n > ldapMaxMsg {
		return nil, errLDAPMalformed
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(l.c, body); err != nil {
		return nil, err
	}
	full := append(append(hdr, lenBytes...), body...)
	return ldapParseMessage(full)
}

// ldapSearch runs a search and collects entries until SearchResultDone.
func (l *ldapConn) search(id int, base string, scope, size int, attrs []string) ([]*ldapMsg, int, error) {
	if err := l.send(ldapSearchRequest(id, base, scope, size, attrs)); err != nil {
		return nil, -1, err
	}
	var entries []*ldapMsg
	for i := 0; i < 1000; i++ {
		m, err := l.recv()
		if err != nil {
			return entries, -1, err
		}
		if m.ID != id {
			continue
		}
		switch m.Op {
		case 0x64:
			entries = append(entries, m)
		case 0x65:
			return entries, m.Result, nil
		case 0x73: // reference
		default:
			return entries, -1, fmt.Errorf("ldap: unexpected op 0x%02x", m.Op)
		}
	}
	return entries, -1, errors.New("ldap: too many messages")
}

func runLDAPAnon(ctx context.Context, t *Target) []model.Finding {
	raw, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer raw.Close()
	var conn net.Conn = raw
	if ldapUseTLS(t.Service) {
		tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // scanner
		_ = tc.SetDeadline(time.Now().Add(t.Timeout))
		if err := tc.HandshakeContext(ctx); err != nil {
			t.Log.Debug("ldaps handshake", "err", err)
			return nil
		}
		conn = tc
	}
	l := &ldapConn{c: conn, timeout: t.Timeout}
	return ldapAnonProbe(l, t)
}

func ldapAnonProbe(l *ldapConn, t *Target) []model.Finding {
	defer func() { _ = l.send(ldapUnbind(9)) }()
	if err := l.send(ldapBindRequest(1)); err != nil {
		return nil
	}
	m, err := l.recv()
	if err != nil || m.Op != 0x61 || m.Result != 0 {
		return nil
	}
	root, _, err := l.search(2, "", 0, 1, []string{"namingContexts", "defaultNamingContext", "dnsHostName", "supportedLDAPVersion", "serverName"})
	if err != nil || len(root) == 0 {
		return nil
	}
	ra := root[0].Attrs
	var bases []string
	if d := ra["defaultnamingcontext"]; len(d) > 0 && d[0] != "" {
		bases = append(bases, d[0])
	}
	for _, nc := range ra["namingcontexts"] {
		if nc != "" && !ldapContainsFold(bases, nc) && !strings.HasPrefix(strings.ToLower(nc), "cn=schema") &&
			!strings.HasPrefix(strings.ToLower(nc), "cn=configuration") && len(bases) < 3 {
			bases = append(bases, nc)
		}
	}
	id := 3
	for _, base := range bases {
		entries, code, err := l.search(id, base, 2, 5, []string{"1.1"})
		id++
		if err != nil {
			t.Log.Debug("ldap anonymous search", "base", base, "err", err)
			continue
		}
		// 0 success, 4 sizeLimitExceeded: both mean data is readable.
		if len(entries) == 0 || (code != 0 && code != 4) {
			continue
		}
		var dns []string
		for _, e := range entries {
			if e.DN != "" {
				dns = append(dns, e.DN)
			}
		}
		if len(dns) == 0 {
			continue
		}
		sort.Strings(dns)
		var ev strings.Builder
		fmt.Fprintf(&ev, "Anonymous bind accepted; subtree search of %q (objectClass=*) returned entries without authentication (size limit 5):\n", base)
		for _, d := range dns {
			fmt.Fprintf(&ev, "  %s\n", d)
		}
		if h := ra["dnshostname"]; len(h) > 0 {
			fmt.Fprintf(&ev, "rootDSE dnsHostName: %s\n", h[0])
		}
		return []model.Finding{t.Finding(ev.String())}
	}
	return nil
}

func ldapContainsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
