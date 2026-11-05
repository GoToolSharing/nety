package checks

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/identity/ntlm"
	"github.com/GoToolSharing/nety/internal/model"
)

// --------------------------------------------------------------------------- LDAP
// anonymous bind
// ---------------------------------------------------------------------------

// ldapEnum encodes an ENUMERATED result code.
func ldapEnum(v int) []byte { return ntlm.DER(0x0a, []byte{byte(v)}) }

// ldapBindResponse builds a BindResponse ([APPLICATION 1]).
func ldapBindResponse(id, code int) []byte {
	return ldapMessage(id, ntlm.DER(0x61, ldapEnum(code), ntlm.DER(0x04), ntlm.DER(0x04)))
}

// ldapSearchEntry builds a SearchResultEntry ([APPLICATION 4]).
func ldapSearchEntry(id int, dn string, attrs map[string][]string) []byte {
	var attrSeq [][]byte
	// Deterministic order: the parser lowercases the names anyway.
	for _, name := range sortedKeys(attrs) {
		var vals [][]byte
		for _, v := range attrs[name] {
			vals = append(vals, ntlm.DER(0x04, []byte(v)))
		}
		attrSeq = append(attrSeq, ntlm.DER(0x30, ntlm.DER(0x04, []byte(name)), ntlm.DER(0x31, vals...)))
	}
	return ldapMessage(id, ntlm.DER(0x64, ntlm.DER(0x04, []byte(dn)), ntlm.DER(0x30, attrSeq...)))
}

// ldapSearchDone builds a SearchResultDone ([APPLICATION 5]).
func ldapSearchDone(id, code int) []byte {
	return ldapMessage(id, ntlm.DER(0x65, ldapEnum(code), ntlm.DER(0x04), ntlm.DER(0x04)))
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// readLDAPMessage reads one complete LDAPMessage from the wire.
func readLDAPMessage(c net.Conn) (*ldapMsg, error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for len(buf) < 64*1024 {
		n, err := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if m, perr := ldapParseMessage(buf); perr == nil {
				return m, nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, io.ErrUnexpectedEOF
}

// ldapServer answers an anonymous bind and serves a rootDSE plus one subtree. bindCode !=
// 0 makes it refuse the anonymous bind.
func ldapServer(t *testing.T, bindCode int, entries []string) int {
	return fakeServer(t, func(c net.Conn) {
		bind, err := readLDAPMessage(c)
		if err != nil {
			return
		}
		if bind.Op != 0x60 {
			t.Errorf("first LDAP operation is 0x%02x, want a BindRequest (0x60)", bind.Op)
			return
		}
		if _, err := c.Write(ldapBindResponse(bind.ID, bindCode)); err != nil || bindCode != 0 {
			return
		}
		for i := 0; i < 6; i++ {
			m, err := readLDAPMessage(c)
			if err != nil {
				return
			}
			if m.Op == 0x42 { // UnbindRequest
				return
			}
			if m.Op != 0x63 {
				continue
			}
			if i == 0 {
				// rootDSE
				root := ldapSearchEntry(m.ID, "", map[string][]string{
					"defaultNamingContext": {"DC=corp,DC=local"},
					"dnsHostName":          {"dc01.corp.local"},
					"namingContexts":       {"DC=corp,DC=local", "CN=Configuration,DC=corp,DC=local"},
				})
				if _, err := c.Write(append(root, ldapSearchDone(m.ID, 0)...)); err != nil {
					return
				}
				continue
			}
			var out []byte
			for _, dn := range entries {
				out = append(out, ldapSearchEntry(m.ID, dn, nil)...)
			}
			out = append(out, ldapSearchDone(m.ID, 0)...)
			if _, err := c.Write(out); err != nil {
				return
			}
		}
	})
}

func TestLDAPAnonymousBind(t *testing.T) {
	t.Run("directory readable", func(t *testing.T) {
		port := ldapServer(t, 0, []string{"DC=corp,DC=local", "CN=Users,DC=corp,DC=local"})
		fs := probe(t, "ldap-anonymous-bind", tcpSvc("ldap", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		for _, want := range []string{"DC=corp,DC=local", "CN=Users,DC=corp,DC=local", "dc01.corp.local"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
	})

	t.Run("anonymous bind refused", func(t *testing.T) {
		// 48 = inappropriateAuthentication, what a hardened AD returns.
		port := ldapServer(t, 48, nil)
		if fs := probe(t, "ldap-anonymous-bind", tcpSvc("ldap", port)); len(fs) != 0 {
			t.Fatalf("refused bind reported: %+v", fs)
		}
	})

	t.Run("bind accepted but directory empty", func(t *testing.T) {
		port := ldapServer(t, 0, nil)
		if fs := probe(t, "ldap-anonymous-bind", tcpSvc("ldap", port)); len(fs) != 0 {
			t.Fatalf("reported without readable entries: %+v", fs)
		}
	})
}

func TestLDAPParseMessageHostileInput(t *testing.T) {
	good := ldapSearchEntry(1, "DC=x", map[string][]string{"a": {"b"}})
	for i := 0; i < len(good); i++ {
		if _, err := ldapParseMessage(good[:i]); err == nil && i < len(good) {
			continue // a prefix may parse; the requirement is no panic
		}
	}
	for _, junk := range [][]byte{nil, {}, {0x30}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, {0x30, 0x02, 0x02, 0x7f}} {
		_, _ = ldapParseMessage(junk)
	}
}

// --------------------------------------------------------------------------- SNMP
// default community
// ---------------------------------------------------------------------------

// berLen encodes a definite BER length.
func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

func berTLV(tag byte, content ...[]byte) []byte {
	var body []byte
	for _, c := range content {
		body = append(body, c...)
	}
	out := append([]byte{tag}, berLen(len(body))...)
	return append(out, body...)
}

func berIntBytes(v int) []byte {
	if v == 0 {
		return berTLV(0x02, []byte{0})
	}
	var b []byte
	for x := v; x > 0; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return berTLV(0x02, b)
}

// berOID encodes a dotted OID.
func berOID(dotted string) []byte {
	parts := strings.Split(strings.TrimPrefix(dotted, "."), ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		nums = append(nums, n)
	}
	if len(nums) < 2 {
		return berTLV(0x06)
	}
	body := []byte{byte(nums[0]*40 + nums[1])}
	for _, n := range nums[2:] {
		var enc []byte
		for {
			enc = append([]byte{byte(n & 0x7f)}, enc...)
			n >>= 7
			if n == 0 {
				break
			}
		}
		for i := 0; i < len(enc)-1; i++ {
			enc[i] |= 0x80
		}
		body = append(body, enc...)
	}
	return berTLV(0x06, body)
}

// snmpParseRequest pulls the community and request id out of a v1/v2c GetRequest, using
// only bounds-checked TLV reads.
func snmpParseRequest(b []byte) (version int, community string, reqID []byte, ok bool) {
	tag, seq, _, err := ntlm.ReadTLV(b)
	if err != nil || tag != 0x30 {
		return 0, "", nil, false
	}
	tag, ver, rest, err := ntlm.ReadTLV(seq)
	if err != nil || tag != 0x02 || len(ver) != 1 {
		return 0, "", nil, false
	}
	tag, comm, rest, err := ntlm.ReadTLV(rest)
	if err != nil || tag != 0x04 {
		return 0, "", nil, false
	}
	tag, pdu, _, err := ntlm.ReadTLV(rest)
	if err != nil || tag != 0xa0 {
		return 0, "", nil, false
	}
	tag, rid, _, err := ntlm.ReadTLV(pdu)
	if err != nil || tag != 0x02 {
		return 0, "", nil, false
	}
	return int(ver[0]), string(comm), rid, true
}

// snmpAgent answers GetRequests carrying one of the accepted communities.
func snmpAgent(t *testing.T, accepted map[string]bool, values map[string]string) int {
	return fakeUDPServer(t, func(req []byte) []byte {
		ver, comm, reqID, ok := snmpParseRequest(req)
		if !ok {
			return nil
		}
		if !accepted[comm] {
			return nil // a real agent stays silent on a bad community
		}
		var vbs [][]byte
		for _, oid := range []string{oidSysDescr, oidSysObjectID, oidSysName, oidSysLocation} {
			v, present := values[oid]
			val := berTLV(0x05) // NULL
			if present {
				val = berTLV(0x04, []byte(v))
			}
			vbs = append(vbs, berTLV(0x30, berOID(oid), val))
		}
		pdu := berTLV(0xa2, berTLV(0x02, reqID), berIntBytes(0), berIntBytes(0), berTLV(0x30, vbs...))
		return berTLV(0x30, berIntBytes(ver), berTLV(0x04, []byte(comm)), pdu)
	})
}

func TestSNMPDefaultCommunity(t *testing.T) {
	values := map[string]string{
		oidSysDescr: "Cisco IOS Software, C2960 Software",
		oidSysName:  "sw-access-01",
	}

	t.Run("public only", func(t *testing.T) {
		port := snmpAgent(t, map[string]bool{"public": true}, values)
		fs := probe(t, "snmp-default-community", udpSvc("snmp", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevMedium {
			t.Errorf("read-only community severity = %s, want medium", fs[0].Severity)
		}
		for _, want := range []string{`"public"`, "sw-access-01", "Cisco IOS"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
		if strings.Contains(fs[0].Evidence, "private") {
			t.Errorf("reported a community the agent rejected: %q", fs[0].Evidence)
		}
	})

	t.Run("read-write community escalates", func(t *testing.T) {
		port := snmpAgent(t, map[string]bool{"public": true, "private": true}, values)
		fs := probe(t, "snmp-default-community", udpSvc("snmp", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevHigh {
			t.Errorf("read-write community severity = %s, want high", fs[0].Severity)
		}
		if !strings.Contains(fs[0].Evidence, `"private"`) {
			t.Errorf("evidence: %q", fs[0].Evidence)
		}
	})

	t.Run("hardened agent", func(t *testing.T) {
		port := snmpAgent(t, map[string]bool{"s3cr3t-ro": true}, values)
		if fs := probeTimeout(t, "snmp-default-community", 400*time.Millisecond, udpSvc("snmp", port)); len(fs) != 0 {
			t.Fatalf("agent with custom communities reported: %+v", fs)
		}
	})

	t.Run("agent answers but hides the system group", func(t *testing.T) {
		port := snmpAgent(t, map[string]bool{"public": true}, nil)
		if fs := probe(t, "snmp-default-community", udpSvc("snmp", port)); len(fs) != 0 {
			t.Fatalf("empty system group reported as readable: %+v", fs)
		}
	})
}

// TestSNMPCommunityListStaysTiny guards the promise made to the client: NETY does not
// spray community strings on a live network.
func TestSNMPCommunityListStaysTiny(t *testing.T) {
	if len(snmpDefaultCommunities) > 3 {
		t.Fatalf("%d default communities tried; the check must stay a spot check", len(snmpDefaultCommunities))
	}
	for _, c := range snmpDefaultCommunities {
		switch c.name {
		case "public", "private":
		default:
			t.Errorf("community %q is not a universal vendor default", c.name)
		}
	}
}
