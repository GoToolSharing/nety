package udpprobe

import (
	"strconv"
	"strings"
)

// Fixed, synthetic SNMP identifiers, verified by the decoders.
const (
	snmpReqIDv1  int64 = 0x4e450101
	snmpReqIDv2c int64 = 0x4e450201
	snmpReqIDv3  int64 = 0x4e450301
	snmpMsgIDv3  int64 = 0x4e450302

	snmpCommunity = "public"
)

// oidSysDescr is 1.3.6.1.2.1.1.1.0 (SNMPv2-MIB::sysDescr.0).
var oidSysDescr = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

const (
	oidSysDescrStr = "1.3.6.1.2.1.1.1.0"
	maxVarbinds    = 64
)

func snmpGetPayload(version int64, community string, reqID int64, oid []byte) []byte {
	varbind := encSeq(enc(tagOID, oid), enc(tagNull, nil))
	pdu := enc(0xa0, concat( // [0] GetRequest-PDU
		encInt(reqID),
		encInt(0), // error-status
		encInt(0), // error-index
		encSeq(varbind),
	))
	return encSeq(encInt(version), enc(tagOctetStr, []byte(community)), pdu)
}

// snmpV2cPayload is an SNMPv2c GET of sysDescr.0 with community "public".
func snmpV2cPayload() []byte { return snmpGetPayload(1, snmpCommunity, snmpReqIDv2c, oidSysDescr) }

// snmpV1Payload is the same GET in SNMPv1. Plenty of embedded agents, printers
// and PDUs still speak v1 only and drop v2c messages silently.
func snmpV1Payload() []byte { return snmpGetPayload(0, snmpCommunity, snmpReqIDv1, oidSysDescr) }

// snmpV3Payload is an SNMPv3 discovery message: USM with an empty engine ID,
// empty user and no auth/priv, reportable flag set. Any v3 agent answers with a
// Report PDU carrying its authoritative engine ID, boots and time - regardless
// of credentials. The engine ID is a very stable asset identity key.
func snmpV3Payload() []byte {
	globals := encSeq(
		encInt(snmpMsgIDv3),
		encInt(65507),                  // msgMaxSize
		enc(tagOctetStr, []byte{0x04}), // msgFlags: reportable, no auth, no priv
		encInt(3),                      // msgSecurityModel: USM
	)
	usm := encSeq(
		enc(tagOctetStr, nil), // msgAuthoritativeEngineID
		encInt(0),             // msgAuthoritativeEngineBoots
		encInt(0),             // msgAuthoritativeEngineTime
		enc(tagOctetStr, nil), // msgUserName
		enc(tagOctetStr, nil), // msgAuthenticationParameters
		enc(tagOctetStr, nil), // msgPrivacyParameters
	)
	pdu := enc(0xa0, concat(
		encInt(snmpReqIDv3),
		encInt(0),
		encInt(0),
		encSeq(),
	))
	scoped := encSeq(
		enc(tagOctetStr, nil), // contextEngineID
		enc(tagOctetStr, nil), // contextName
		pdu,
	)
	return encSeq(encInt(3), globals, enc(tagOctetStr, usm), scoped)
}

func decodeSNMPv1(resp []byte) *Result  { return decodeSNMPCommunity(resp, 0, snmpReqIDv1) }
func decodeSNMPv2c(resp []byte) *Result { return decodeSNMPCommunity(resp, 1, snmpReqIDv2c) }

var snmpErrorStatus = map[int64]string{
	0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly",
	5: "genErr", 6: "noAccess", 7: "wrongType", 8: "wrongLength",
	9: "wrongEncoding", 10: "wrongValue", 11: "noCreation", 12: "inconsistentValue",
	13: "resourceUnavailable", 14: "commitFailed", 15: "undoFailed",
	16: "authorizationError", 17: "notWritable", 18: "inconsistentName",
}

func snmpVersionName(v int64) string {
	switch v {
	case 0:
		return "v1"
	case 1:
		return "v2c"
	case 3:
		return "v3"
	default:
		return "v" + strconv.FormatInt(v, 10)
	}
}

// decodeSNMPCommunity decodes a v1/v2c response.
func decodeSNMPCommunity(resp []byte, wantVersion, wantReqID int64) *Result {
	body, ok := parseSeq(resp, tagSequence)
	if !ok {
		return nil
	}
	t, rest, ok := parseTLV(body)
	if !ok || t.tag != tagInteger {
		return nil
	}
	version, ok := berInt(t.content)
	if !ok || version < 0 || version > 1 {
		return nil
	}
	t, rest, ok = parseTLV(rest)
	if !ok || t.tag != tagOctetStr || len(t.content) > 128 {
		return nil
	}
	community := printableASCII(t.content)

	pdu, _, ok := parseTLV(rest)
	if !ok || pdu.tag&0xe0 != 0xa0 {
		return nil // not a context-specific constructed PDU
	}
	pduType := pdu.tag & 0x1f
	// 2 = GetResponse, 8 = Report (v2 trap/report seen over a v2c header).
	if pduType != 2 && pduType != 8 {
		return nil
	}

	t, rest, ok = parseTLV(pdu.content)
	if !ok || t.tag != tagInteger {
		return nil
	}
	reqID, ok := berInt(t.content)
	if !ok {
		return nil
	}
	t, rest, ok = parseTLV(rest)
	if !ok || t.tag != tagInteger {
		return nil
	}
	errStatus, _ := berInt(t.content)
	t, rest, ok = parseTLV(rest)
	if !ok || t.tag != tagInteger {
		return nil
	}
	errIndex, _ := berInt(t.content)
	vbList, ok := parseSeq(rest, tagSequence)
	if !ok {
		return nil
	}

	r := newResult("snmp", 60)
	if reqID == wantReqID {
		r.Confidence = 90
	} else {
		// Structurally a GetResponse but not ours: could be a stray datagram.
		r.Confidence = 60
	}
	if version != wantVersion {
		r.Confidence -= 10
	}
	r.set("snmp.version", snmpVersionName(version))
	r.set("snmp.community", community)
	if name, okName := snmpErrorStatus[errStatus]; okName && errStatus != 0 {
		r.set("snmp.error_status", name)
		r.set("snmp.error_index", strconv.FormatInt(errIndex, 10))
	}

	sysDescr := ""
	vbCount := 0
	for len(vbList) > 0 && vbCount < maxVarbinds {
		vb, next, okVB := parseTLV(vbList)
		if !okVB {
			break
		}
		vbList = next
		vbCount++
		if vb.tag != tagSequence {
			continue
		}
		oidTLV, valRest, okOID := parseTLV(vb.content)
		if !okOID || oidTLV.tag != tagOID {
			continue
		}
		oid := decodeOID(oidTLV.content)
		val, _, okVal := parseTLV(valRest)
		if !okVal {
			continue
		}
		if oid == oidSysDescrStr {
			switch val.tag {
			case tagOctetStr:
				sysDescr = sanitize(string(val.content))
			case 0x80, 0x81, 0x82:
				r.set("snmp.sysdescr_error", "noSuchObject")
			}
		}
	}
	r.set("snmp.varbinds", itoa(vbCount))

	if sysDescr != "" {
		r.set("snmp.sysdescr", sysDescr)
		r.ExtraInfo = sysDescr
		snmpFingerprint(sysDescr, r)
		return r
	}

	switch errStatus {
	case 16, 5, 6: // authorizationError, genErr, noAccess
		r.ExtraInfo = "SNMP agent present, community \"" + snmpCommunity + "\" rejected"
		r.set("snmp.access", "denied")
	case 2: // noSuchName - v1 agent that does not expose sysDescr
		r.ExtraInfo = "SNMP agent present, sysDescr not readable"
		r.set("snmp.access", "limited")
	default:
		if errStatus != 0 {
			r.ExtraInfo = "SNMP agent present"
		}
	}
	return r
}

// decodeSNMPv3 decodes an SNMPv3 Report answering the discovery message.
func decodeSNMPv3(resp []byte) *Result {
	body, ok := parseSeq(resp, tagSequence)
	if !ok {
		return nil
	}
	t, rest, ok := parseTLV(body)
	if !ok || t.tag != tagInteger {
		return nil
	}
	version, ok := berInt(t.content)
	if !ok || version != 3 {
		return nil
	}

	globals, rest, ok := parseTLV(rest)
	if !ok || globals.tag != tagSequence {
		return nil
	}
	gt, grest, ok := parseTLV(globals.content)
	if !ok || gt.tag != tagInteger {
		return nil
	}
	msgID, _ := berInt(gt.content)
	// msgMaxSize, msgFlags, msgSecurityModel follow; we only want the flags.
	var flags byte
	var secModel int64
	if gt2, g2, ok2 := parseTLV(grest); ok2 && gt2.tag == tagInteger {
		if gt3, g3, ok3 := parseTLV(g2); ok3 && gt3.tag == tagOctetStr && len(gt3.content) == 1 {
			flags = gt3.content[0]
			if gt4, _, ok4 := parseTLV(g3); ok4 && gt4.tag == tagInteger {
				secModel, _ = berInt(gt4.content)
			}
		}
	}

	secParams, rest, ok := parseTLV(rest)
	if !ok || secParams.tag != tagOctetStr {
		return nil
	}

	r := newResult("snmp", 75)
	r.set("snmp.version", "v3")
	if msgID == snmpMsgIDv3 {
		r.Confidence = 90
	}
	if secModel != 0 {
		r.set("snmp.security_model", strconv.FormatInt(secModel, 10))
	}
	r.setBool("snmp.auth", flags&0x01 != 0)
	r.setBool("snmp.priv", flags&0x02 != 0)

	// USM security parameters: SEQUENCE { engineID, boots, time, user, ... }
	if usm, okUSM := parseSeq(secParams.content, tagSequence); okUSM {
		if et, erest, okE := parseTLV(usm); okE && et.tag == tagOctetStr {
			if len(et.content) > 0 && len(et.content) <= 64 {
				r.set("snmp.engine_id", hexStr(et.content))
				snmpEngineIDFacts(et.content, r)
			}
			if bt, brest, okB := parseTLV(erest); okB && bt.tag == tagInteger {
				if boots, okI := berInt(bt.content); okI && boots >= 0 {
					r.set("snmp.engine_boots", strconv.FormatInt(boots, 10))
				}
				if tt, trest, okT := parseTLV(brest); okT && tt.tag == tagInteger {
					if etime, okI := berInt(tt.content); okI && etime >= 0 {
						r.set("snmp.engine_time", strconv.FormatInt(etime, 10))
					}
					if ut, _, okU := parseTLV(trest); okU && ut.tag == tagOctetStr && len(ut.content) > 0 {
						r.set("snmp.engine_user", printableASCII(ut.content))
					}
				}
			}
		}
	}

	// scopedPDU: readable only when privacy is off (flags bit 1 clear).
	if scoped, okS := parseSeq(rest, tagSequence); okS {
		if ct, crest, okC := parseTLV(scoped); okC && ct.tag == tagOctetStr {
			if nt, nrest, okN := parseTLV(crest); okN && nt.tag == tagOctetStr {
				if len(nt.content) > 0 {
					r.set("snmp.context_name", printableASCII(nt.content))
				}
				if pdu, _, okP := parseTLV(nrest); okP && pdu.tag&0xe0 == 0xa0 {
					if pdu.tag&0x1f == 8 {
						r.set("snmp.pdu", "report")
					}
					snmpReportOID(pdu.content, r)
				}
			}
		}
	}

	if _, has := r.Extra["snmp.engine_id"]; !has && r.Confidence < 90 {
		// Nothing identifying at all: do not claim a match.
		if msgID != snmpMsgIDv3 {
			return nil
		}
	}
	if r.ExtraInfo == "" {
		r.ExtraInfo = "SNMPv3 agent"
	}
	return r
}

// snmpReportOID pulls the first varbind OID out of a Report PDU; it tells us
// why the agent rejected us (unknown engine id, unknown user, ...).
func snmpReportOID(pduBody []byte, r *Result) {
	t, rest, ok := parseTLV(pduBody) // request-id
	if !ok || t.tag != tagInteger {
		return
	}
	if t, rest, ok = parseTLV(rest); !ok || t.tag != tagInteger { // error-status
		return
	}
	if t, rest, ok = parseTLV(rest); !ok || t.tag != tagInteger { // error-index
		return
	}
	vbList, ok := parseSeq(rest, tagSequence)
	if !ok {
		return
	}
	vb, _, ok := parseTLV(vbList)
	if !ok || vb.tag != tagSequence {
		return
	}
	oidTLV, valRest, ok := parseTLV(vb.content)
	if !ok || oidTLV.tag != tagOID {
		return
	}
	oid := decodeOID(oidTLV.content)
	r.set("snmp.report_oid", oid)
	if name, okName := snmpReportNames[oid]; okName {
		r.set("snmp.report", name)
	}
	if val, _, okV := parseTLV(valRest); okV {
		if n, okU := berUint(val.content); okU && val.tag == tagCounter32 {
			r.set("snmp.report_count", strconv.FormatUint(n, 10))
		}
	}
}

var snmpReportNames = map[string]string{
	"1.3.6.1.6.3.11.2.1.1.0": "snmpUnknownSecurityModels",
	"1.3.6.1.6.3.11.2.1.2.0": "snmpInvalidMsgs",
	"1.3.6.1.6.3.11.2.1.3.0": "snmpUnknownPDUHandlers",
	"1.3.6.1.6.3.15.1.1.1.0": "usmStatsUnsupportedSecLevels",
	"1.3.6.1.6.3.15.1.1.2.0": "usmStatsNotInTimeWindows",
	"1.3.6.1.6.3.15.1.1.3.0": "usmStatsUnknownUserNames",
	"1.3.6.1.6.3.15.1.1.4.0": "usmStatsUnknownEngineIDs",
	"1.3.6.1.6.3.15.1.1.5.0": "usmStatsWrongDigests",
	"1.3.6.1.6.3.15.1.1.6.0": "usmStatsDecryptionErrors",
}

// snmpEnterprises maps the IANA private-enterprise numbers we care about.
var snmpEnterprises = map[uint32]string{
	2: "IBM", 9: "Cisco", 11: "Hewlett-Packard", 23: "Novell", 42: "Sun/Oracle",
	43: "3Com", 171: "D-Link", 232: "HP/Compaq", 236: "Samsung", 253: "Xerox",
	311: "Microsoft", 318: "APC", 332: "Lexmark", 367: "Ricoh", 674: "Dell",
	789: "NetApp", 1588: "Brocade", 1602: "Canon", 1751: "Alcatel-Lucent",
	1991: "Foundry/Brocade", 2011: "Huawei", 2021: "UCD-SNMP", 2435: "Brother",
	2636: "Juniper", 3224: "Netscreen", 4413: "Broadcom", 4874: "Alcatel",
	5003: "Zebra", 6027: "Dell Force10", 6486: "Alcatel-Lucent",
	6876: "VMware", 7244: "Quanta", 8072: "Net-SNMP", 9303: "Siemens",
	10876: "Super Micro", 12356: "Fortinet", 14823: "Aruba", 20301: "Lenovo",
	25506: "H3C", 30065: "Arista", 34592: "Kyocera", 41112: "Ubiquiti",
}

// snmpEngineIDFacts decodes the RFC 3411 engine-ID layout.
func snmpEngineIDFacts(id []byte, r *Result) {
	if len(id) < 5 {
		return
	}
	if id[0]&0x80 == 0 {
		return // legacy 12-byte RFC 1910 format, nothing structured to read
	}
	ent := (uint32(id[0]&0x7f) << 24) | uint32(id[1])<<16 | uint32(id[2])<<8 | uint32(id[3])
	r.set("snmp.engine_enterprise", strconv.FormatUint(uint64(ent), 10))
	if name, ok := snmpEnterprises[ent]; ok {
		r.set("snmp.engine_vendor", name)
		if r.Product == "" {
			r.Product = name + " SNMP agent"
		}
	}
	format := id[4]
	rest := id[5:]
	switch format {
	case 1: // IPv4 address
		if len(rest) >= 4 {
			r.set("snmp.engine_addr", itoa(int(rest[0]))+"."+itoa(int(rest[1]))+"."+itoa(int(rest[2]))+"."+itoa(int(rest[3])))
		}
	case 3: // MAC address
		if len(rest) >= 6 {
			r.set("snmp.engine_mac", formatMAC(rest[:6]))
		}
	case 4: // administratively assigned text
		if s := printableASCII(rest); s != "" {
			r.set("snmp.engine_text", s)
		}
	}
}

// snmpFingerprint maps a sysDescr banner onto product/version/OS.
func snmpFingerprint(d string, r *Result) {
	switch {
	case containsFold(d, "Cisco NX-OS"):
		r.Product = "Cisco NX-OS"
		r.OSType = "NX-OS"
		r.Version = versionAfter(d, "Version")
		r.addCPE("cpe:/o:cisco:nx-os")
	case containsFold(d, "Cisco Adaptive Security Appliance"):
		r.Product = "Cisco ASA"
		r.OSType = "ASA"
		r.Version = versionAfter(d, "Version")
		r.addCPE("cpe:/o:cisco:asa")
	case containsFold(d, "Cisco IOS XE"):
		r.Product = "Cisco IOS XE"
		r.OSType = "IOS XE"
		r.Version = versionAfter(d, "Version")
		r.addCPE("cpe:/o:cisco:ios_xe")
	case containsFold(d, "Cisco IOS") || containsFold(d, "Cisco Internetwork Operating System"):
		r.Product = "Cisco IOS"
		r.OSType = "IOS"
		r.Version = versionAfter(d, "Version")
		r.addCPE("cpe:/o:cisco:ios")
	case containsFold(d, "Cisco"):
		r.Product = "Cisco device"
		r.Version = versionAfter(d, "Version")
	case containsFold(d, "JUNOS") || containsFold(d, "Juniper Networks"):
		r.Product = "Juniper JUNOS"
		r.OSType = "JUNOS"
		r.Version = versionAfter(d, "JUNOS")
		r.addCPE("cpe:/o:juniper:junos")
	case containsFold(d, "FortiGate") || containsFold(d, "FortiOS") || containsFold(d, "Fortinet"):
		r.Product = "Fortinet FortiGate"
		r.OSType = "FortiOS"
		r.Version = versionAfter(d, "v")
		r.addCPE("cpe:/o:fortinet:fortios")
	case containsFold(d, "VMware ESXi") || containsFold(d, "VMware ESX"):
		r.Product = "VMware ESXi"
		r.OSType = "ESXi"
		r.Version = firstVersion(d)
		r.addCPE("cpe:/o:vmware:esxi")
	case containsFold(d, "Hardware:") && containsFold(d, "Windows"):
		r.Product = "Microsoft Windows"
		r.OSType = "Windows"
		r.Version = versionAfter(d, "Version")
		r.addCPE("cpe:/o:microsoft:windows")
	case containsFold(d, "Windows"):
		r.Product = "Microsoft Windows"
		r.OSType = "Windows"
		r.addCPE("cpe:/o:microsoft:windows")
	case strings.HasPrefix(d, "Linux") || containsFold(d, "Linux "):
		r.OSType = "Linux"
		r.Product = "Linux"
		r.Version = linuxKernelVersion(d)
		r.addCPE("cpe:/o:linux:linux_kernel")
		if containsFold(d, "Synology") {
			r.Product = "Synology DSM"
		} else if containsFold(d, "QNAP") {
			r.Product = "QNAP NAS"
		}
	case containsFold(d, "APC Web/SNMP Management Card") || containsFold(d, "APC "):
		r.Product = "APC management card"
		r.OSType = "embedded"
		r.Version = versionAfter(d, "AOS")
	case containsFold(d, "Aruba") || containsFold(d, "ArubaOS"):
		r.Product = "Aruba ArubaOS"
		r.OSType = "ArubaOS"
		r.Version = versionAfter(d, "Version")
	case containsFold(d, "FreeBSD"):
		r.Product = "FreeBSD"
		r.OSType = "FreeBSD"
		r.Version = versionAfter(d, "FreeBSD")
	default:
		if p, os := snmpPrinter(d); p != "" {
			r.Product = p
			r.OSType = os
			r.Version = firstVersion(d)
		}
	}
	if r.Version == "" {
		r.Version = firstVersion(d)
	}
	if r.Product == "" {
		if p, os := snmpPrinter(d); p != "" {
			r.Product = p
			r.OSType = os
		}
	}
}

// snmpPrinter recognises the usual network-printer sysDescr shapes.
func snmpPrinter(d string) (product, osType string) {
	switch {
	case containsFold(d, "JETDIRECT") || containsFold(d, "HP ETHERNET MULTI-ENVIRONMENT") ||
		(containsFold(d, "HP ") && containsFold(d, "LaserJet")):
		return "HP JetDirect printer", "embedded"
	case containsFold(d, "RICOH"):
		return "Ricoh printer", "embedded"
	case containsFold(d, "KYOCERA"):
		return "Kyocera printer", "embedded"
	case containsFold(d, "Lexmark"):
		return "Lexmark printer", "embedded"
	case containsFold(d, "Xerox") || containsFold(d, "WorkCentre") || containsFold(d, "Phaser"):
		return "Xerox printer", "embedded"
	case containsFold(d, "Brother"):
		return "Brother printer", "embedded"
	case containsFold(d, "Canon"):
		return "Canon printer", "embedded"
	case containsFold(d, "EPSON"):
		return "Epson printer", "embedded"
	case containsFold(d, "Konica") || containsFold(d, "bizhub"):
		return "Konica Minolta printer", "embedded"
	case containsFold(d, "SHARP"):
		return "Sharp printer", "embedded"
	case containsFold(d, "Zebra") || containsFold(d, "ZTC "):
		return "Zebra printer", "embedded"
	}
	return "", ""
}

// linuxKernelVersion picks the kernel release out of a uname-style sysDescr:
// "Linux host 3.10.0-693.el7.x86_64 #1 SMP ... x86_64".
func linuxKernelVersion(d string) string {
	fields := strings.Fields(d)
	if len(fields) > 16 {
		fields = fields[:16]
	}
	for _, f := range fields {
		if len(f) > 0 && f[0] >= '0' && f[0] <= '9' && strings.Contains(f, ".") {
			return sanitize(f)
		}
	}
	return ""
}

func formatMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i := 0; i < 6; i++ {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexDigits[b[i]>>4], hexDigits[b[i]&0x0f])
	}
	return string(out)
}
