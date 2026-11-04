package identity

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/GoToolSharing/nety/internal/identity/ntlm"
	"github.com/GoToolSharing/nety/internal/model"
)

const (
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID = ".1.3.6.1.2.1.1.2.0"
	oidSysName     = ".1.3.6.1.2.1.1.5.0"
	oidSysLocation = ".1.3.6.1.2.1.1.6.0"
)

// snmpEnterprises maps common IANA enterprise numbers (engine ID prefix).
var snmpEnterprises = map[uint32]string{
	9: "cisco", 11: "hp", 43: "3com", 311: "microsoft", 674: "dell", 1916: "extreme",
	2011: "huawei", 2021: "ucd", 2636: "juniper", 3375: "f5", 4526: "netgear", 6527: "nokia",
	6876: "vmware", 8072: "net-snmp", 9148: "acme", 12356: "fortinet", 14823: "aruba",
	14988: "mikrotik", 25461: "paloalto", 25506: "h3c", 30065: "arista", 41112: "ubiquiti",
	6574: "synology", 24681: "qnap", 1981: "emc", 789: "netapp", 2620: "checkpoint", 3076: "cisco-altiga",
}

// buildSNMPv3Discovery builds an unauthenticated SNMPv3 GetRequest used for
// engine ID discovery (RFC 3414 4.).
func buildSNMPv3Discovery(msgID, reqID uint32) []byte {
	i32 := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v&0x7fffffff)
		for len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
			b = b[1:]
		}
		return ntlm.DER(0x02, b)
	}
	empty := ntlm.DER(0x04)
	global := ntlm.DER(0x30, i32(msgID), i32(65507), ntlm.DER(0x04, []byte{0x04}), i32(3))
	usm := ntlm.DER(0x30, empty, i32(0), i32(0), empty, empty, empty)
	pdu := ntlm.DER(0xa0, i32(reqID), i32(0), i32(0), ntlm.DER(0x30))
	scoped := ntlm.DER(0x30, empty, empty, pdu)
	return ntlm.DER(0x30, i32(3), global, ntlm.DER(0x04, usm), scoped)
}

// snmpEngine is decoded from a REPORT response.
type snmpEngine struct {
	ID    []byte
	Boots int64
	Time  int64
}

func derInt(v []byte) int64 {
	if len(v) == 0 || len(v) > 8 {
		return 0
	}
	var n int64
	if v[0]&0x80 != 0 {
		n = -1
	}
	for _, b := range v {
		n = n<<8 | int64(b)
	}
	return n
}

// parseSNMPv3Report extracts msgAuthoritativeEngineID/Boots/Time.
func parseSNMPv3Report(b []byte) (*snmpEngine, error) {
	bad := errors.New("snmp: malformed v3 message")
	tag, msg, _, err := ntlm.ReadTLV(b)
	if err != nil || tag != 0x30 {
		return nil, bad
	}
	tag, ver, rest, err := ntlm.ReadTLV(msg)
	if err != nil || tag != 0x02 || derInt(ver) != 3 {
		return nil, errors.New("snmp: not SNMPv3")
	}
	tag, _, rest, err = ntlm.ReadTLV(rest) // global data
	if err != nil || tag != 0x30 {
		return nil, bad
	}
	tag, sp, _, err := ntlm.ReadTLV(rest)
	if err != nil || tag != 0x04 {
		return nil, bad
	}
	tag, usm, _, err := ntlm.ReadTLV(sp)
	if err != nil || tag != 0x30 {
		return nil, bad
	}
	tag, id, usm, err := ntlm.ReadTLV(usm)
	if err != nil || tag != 0x04 {
		return nil, bad
	}
	e := &snmpEngine{ID: append([]byte(nil), id...)}
	if tag, v, r2, err := ntlm.ReadTLV(usm); err == nil && tag == 0x02 {
		e.Boots = derInt(v)
		if tag, v, _, err := ntlm.ReadTLV(r2); err == nil && tag == 0x02 {
			e.Time = derInt(v)
		}
	}
	if len(e.ID) == 0 {
		return nil, errors.New("snmp: empty engine ID")
	}
	return e, nil
}

// engineIDAttrs decodes the RFC 3411 SnmpEngineID format.
func engineIDAttrs(id []byte) map[string]string {
	a := map[string]string{}
	if len(id) < 5 {
		return a
	}
	ent := binary.BigEndian.Uint32(id) &^ 0x80000000
	a["enterprise"] = strconv.FormatUint(uint64(ent), 10)
	if n, ok := snmpEnterprises[ent]; ok {
		a["enterprise_name"] = n
	}
	if id[0]&0x80 == 0 { // pre-RFC3411 format: 12 octets, no format byte
		return a
	}
	data := id[5:]
	switch id[4] {
	case 1:
		if len(data) == 4 {
			a["format"] = "ipv4"
			a["ip"] = net.IP(data).String()
		}
	case 2:
		if len(data) == 16 {
			a["format"] = "ipv6"
			a["ip"] = net.IP(data).String()
		}
	case 3:
		if len(data) == 6 {
			a["format"] = "mac"
			a["mac"] = net.HardwareAddr(data).String()
		}
	case 4:
		a["format"] = "text"
		a["text"] = strings.Map(func(r rune) rune {
			if r < 0x20 || r >= 0x7f {
				return -1
			}
			return r
		}, string(data))
	default:
		a["format"] = "octets"
	}
	return a
}

// usableEngineID rejects trivially non-unique engine IDs.
func usableEngineID(id []byte) bool {
	if len(id) < 5 || len(id) > 32 {
		return false
	}
	if id[0]&0x80 != 0 && len(id) <= 5 {
		return false
	}
	nz := 0
	for _, b := range id[4:] {
		if b != 0 && b != 0xff {
			nz++
		}
	}
	return nz > 0
}

// probeSNMP runs v2c/v1 "public" system queries and SNMPv3 engine discovery.
func (c *collector) probeSNMP(ctx context.Context, sink *evidenceSink, ip string, port int) error {
	src := "snmp/" + strconv.Itoa(port)
	var errs []error
	// SNMPv3 engine ID discovery (unauthenticated, read-only).
	var ids [8]byte
	_, _ = rand.Read(ids[:])
	req := buildSNMPv3Discovery(binary.BigEndian.Uint32(ids[:4]), binary.BigEndian.Uint32(ids[4:]))
	if resp, err := udpExchange(ctx, net.JoinHostPort(ip, strconv.Itoa(port)), req, c.ioTimeout); err != nil {
		errs = append(errs, err)
	} else if e, err := parseSNMPv3Report(resp); err != nil {
		errs = append(errs, err)
	} else if usableEngineID(e.ID) {
		attrs := engineIDAttrs(e.ID)
		attrs["engine_boots"] = strconv.FormatInt(e.Boots, 10)
		attrs["engine_time"] = strconv.FormatInt(e.Time, 10)
		sink.add(model.EvSNMPEngineID, hex.EncodeToString(e.ID), src, 95, attrs)
	}
	// v2c then v1 with community "public".
	for _, v := range []gosnmp.SnmpVersion{gosnmp.Version2c, gosnmp.Version1} {
		if ctx.Err() != nil {
			break
		}
		g := &gosnmp.GoSNMP{
			Target: ip, Port: uint16(port), Community: "public", Version: v,
			Timeout: c.ioTimeout, Retries: 0, Context: ctx, MaxOids: 4,
		}
		if err := g.Connect(); err != nil {
			errs = append(errs, err)
			break
		}
		pkt, err := g.Get([]string{oidSysDescr, oidSysObjectID, oidSysName, oidSysLocation})
		_ = g.Conn.Close()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if pkt.Error != gosnmp.NoError {
			errs = append(errs, errors.New("snmp: "+pkt.Error.String()))
			continue
		}
		vals := map[string]string{}
		for _, vb := range pkt.Variables {
			var s string
			switch x := vb.Value.(type) {
			case []byte:
				s = string(x)
			case string:
				s = x
			}
			s = strings.TrimSpace(strings.Map(func(r rune) rune {
				if r == '\n' || r == '\r' || r == '\t' {
					return ' '
				}
				if r < 0x20 || r == 0x7f {
					return -1
				}
				return r
			}, s))
			if len(s) > 512 {
				s = s[:512]
			}
			vals["."+strings.TrimPrefix(vb.Name, ".")] = s
		}
		attrs := map[string]string{
			"sysdescr":    vals[oidSysDescr],
			"sysobjectid": vals[oidSysObjectID],
			"syslocation": vals[oidSysLocation],
			"community":   "public",
			"version":     v.String(),
			"source":      "snmp",
		}
		name := vals[oidSysName]
		if name == "" && attrs["sysdescr"] == "" {
			continue
		}
		if name == "" {
			// No sysName: still carry sysDescr for OS / kind inference.
			d := attrs["sysdescr"]
			if len(d) > 128 {
				d = d[:128]
			}
			sink.add(model.EvOSVersion, d, src, 30, attrs)
			return nil
		}
		sink.add(model.EvSNMPSysName, name, src, 80, attrs)
		if validHostname(strings.ToLower(name)) {
			n := strings.ToLower(name)
			if strings.Contains(n, ".") {
				sink.add(model.EvFQDN, n, src, 55, nil)
			}
			sink.add(model.EvHostname, shortLabel(n), src, 55, nil)
		}
		return nil
	}
	return errors.Join(errs...)
}
