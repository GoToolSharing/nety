package checks

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("snmp-default-community", "SNMP answers to a default community string", model.SevMedium,
			[]string{"snmp"},
			"The SNMP agent answers SNMPv1/v2c requests authenticated only by a well-known default community string. Community strings travel in cleartext and act as a password: an unauthenticated attacker can read the full device configuration (interfaces, routing and ARP tables, running processes, and on network equipment sometimes the configuration file itself). A read-write community additionally allows reconfiguring the device."),
		Remediation: "Replace the default community strings with long random values, or migrate to SNMPv3 with authPriv (SHA/AES). Restrict SNMP to the management network with an ACL on the agent, and disable read-write access unless it is genuinely required.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/1188.html",
			"https://datatracker.ietf.org/doc/html/rfc3414",
		},
		Applies: snmpApplies,
		Run:     runSNMPDefaultCommunity,
	})
}

func snmpApplies(t *Target) bool {
	return svcIs(t.Service, model.UDP, []string{"snmp"}, 161)
}

// snmpDefaultCommunities is deliberately tiny: these are the two strings every
// vendor ships with. Community strings are not accounts and cannot be locked
// out, but there is still no reason to enumerate a wordlist on a live network.
// "private" is conventionally read-write, which is why finding it is worse.
var snmpDefaultCommunities = []struct {
	name  string
	write bool
}{
	{"public", false},
	{"private", true},
}

const (
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID = ".1.3.6.1.2.1.1.2.0"
	oidSysName     = ".1.3.6.1.2.1.1.5.0"
	oidSysLocation = ".1.3.6.1.2.1.1.6.0"
)

// snmpHit is one community/version pair the agent accepted.
type snmpHit struct {
	community string
	version   string
	write     bool
	sysName   string
	sysDescr  string
}

// runSNMPDefaultCommunity tries the two default community strings with
// SNMPv2c then SNMPv1. Only GET requests are issued: NETY never sends a SET,
// so a read-write community is reported but never exercised.
func runSNMPDefaultCommunity(ctx context.Context, t *Target) []model.Finding {
	var hits []snmpHit
	for _, comm := range snmpDefaultCommunities {
		if ctx.Err() != nil {
			break
		}
		hit, err := snmpTryCommunity(ctx, t, comm.name)
		if err != nil {
			t.Log.Debug("snmp community rejected", "community", comm.name, "err", err)
			continue
		}
		hit.write = comm.write
		hits = append(hits, *hit)
	}
	if len(hits) == 0 {
		return nil
	}

	var lines []string
	rw := false
	for _, h := range hits {
		rw = rw || h.write
		line := fmt.Sprintf("community %q accepted over %s", h.community, h.version)
		if h.sysName != "" {
			line += fmt.Sprintf(", sysName=%q", h.sysName)
		}
		if h.sysDescr != "" {
			line += fmt.Sprintf(", sysDescr=%q", truncate(h.sysDescr, 200))
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)

	f := t.Finding(strings.Join(lines, "\n"))
	if rw {
		// "private" is the read-write community on virtually every stack:
		// reconfiguring the device is one SET away.
		f.Severity = model.SevHigh
		f.Title = "SNMP answers to the default read-write community string"
	}
	return []model.Finding{f}
}

// snmpTryCommunity issues one GET of the system group per SNMP version and
// returns the first version that answered.
func snmpTryCommunity(ctx context.Context, t *Target, community string) (*snmpHit, error) {
	var errs []error
	for _, v := range []gosnmp.SnmpVersion{gosnmp.Version2c, gosnmp.Version1} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		g := &gosnmp.GoSNMP{
			Target:    t.IP,
			Port:      uint16(t.Service.Port),
			Community: community,
			Version:   v,
			Timeout:   t.Timeout,
			Retries:   0,
			MaxOids:   4,
			Context:   ctx,
		}
		if err := g.Connect(); err != nil {
			return nil, err
		}
		pkt, err := g.Get([]string{oidSysDescr, oidSysObjectID, oidSysName, oidSysLocation})
		if g.Conn != nil {
			_ = g.Conn.Close()
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if pkt == nil || pkt.Error != gosnmp.NoError {
			errs = append(errs, errors.New("snmp: agent returned an error status"))
			continue
		}
		vals := snmpValues(pkt)
		// An agent that rejects the community simply does not answer; a reply
		// with no usable value means the system group is restricted.
		if vals[oidSysDescr] == "" && vals[oidSysName] == "" && vals[oidSysObjectID] == "" {
			errs = append(errs, errors.New("snmp: empty system group"))
			continue
		}
		return &snmpHit{
			community: community,
			version:   v.String(),
			sysName:   vals[oidSysName],
			sysDescr:  vals[oidSysDescr],
		}, nil
	}
	return nil, errors.Join(errs...)
}

// snmpValues extracts printable varbind values keyed by OID. Values come from
// an untrusted agent: they are sanitized and capped.
func snmpValues(pkt *gosnmp.SnmpPacket) map[string]string {
	out := map[string]string{}
	if pkt == nil {
		return out
	}
	for i, vb := range pkt.Variables {
		if i >= 16 {
			break
		}
		var s string
		switch x := vb.Value.(type) {
		case []byte:
			s = string(x)
		case string:
			s = x
		case nil:
			continue
		default:
			s = fmt.Sprint(x)
		}
		s = strings.TrimSpace(strings.Map(func(r rune) rune {
			switch {
			case r == '\n' || r == '\r' || r == '\t':
				return ' '
			case r < 0x20 || r == 0x7f:
				return -1
			}
			return r
		}, s))
		if len(s) > 512 {
			s = s[:512]
		}
		if s == "" {
			continue
		}
		out["."+strings.TrimPrefix(vb.Name, ".")] = s
	}
	return out
}
