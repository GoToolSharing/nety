package portscan

import (
	"encoding/binary"
	"strings"
)

// UDPPayloads returns the protocol-specific probe payloads sent to a UDP port, in sending
// order. Ports without a dedicated probe get a single empty datagram. The returned slices
// must not be modified.
func UDPPayloads(port uint16) [][]byte {
	if p, ok := udpPayloads[port]; ok {
		return p
	}
	return genericPayload
}

// HasUDPPayload reports whether port has a protocol-specific probe.
func HasUDPPayload(port uint16) bool {
	_, ok := udpPayloads[port]
	return ok
}

var genericPayload = [][]byte{{}}

var udpPayloads = buildUDPPayloads()

func buildUDPPayloads() map[uint16][][]byte {
	dns := dnsQuery(0x6e74, "version.bind", 16 /*TXT*/, 3 /*CH*/, true)
	snmpV2 := snmpGetSysDescr(1)
	snmpV1 := snmpGetSysDescr(0)
	ike := ikeV1MainMode()
	rpcNull := func(prog, vers uint32) []byte {
		b := make([]byte, 40)
		binary.BigEndian.PutUint32(b[0:], 0x6e657479) // xid
		binary.BigEndian.PutUint32(b[4:], 0)          // call
		binary.BigEndian.PutUint32(b[8:], 2)          // rpc version
		binary.BigEndian.PutUint32(b[12:], prog)
		binary.BigEndian.PutUint32(b[16:], vers)
		binary.BigEndian.PutUint32(b[20:], 0) // NULL procedure
		// AUTH_NULL credentials + verifier (all zero)
		return b
	}
	sip := []byte(strings.Join([]string{
		"OPTIONS sip:nm SIP/2.0",
		"Via: SIP/2.0/UDP nm;branch=z9hG4bK-nety;rport",
		"From: <sip:nm@nm>;tag=6e657479",
		"To: <sip:nm2@nm2>",
		"Call-ID: 6e657479@nm",
		"CSeq: 42 OPTIONS",
		"Max-Forwards: 70",
		"Contact: <sip:nm@nm>",
		"Accept: application/sdp",
		"Content-Length: 0",
		"", "",
	}, "\r\n"))
	ssdp := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
	stun := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 'n', 'e', 't', 'y', 0x6e, 0x65, 0x74, 0x79, 0x01, 0x02, 0x03, 0x04}
	coap := append([]byte{0x40, 0x01, 0x6e, 0x74, 0xbb}, append([]byte(".well-known"), append([]byte{0x04}, []byte("core")...)...)...)
	citrix := make([]byte, 30)
	copy(citrix, []byte{0x1e, 0x00, 0x01, 0x30, 0x02, 0xfd, 0xa8, 0xe3})
	wsd := []byte(`<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:6e657479-0000-4000-8000-000000000001</wsa:MessageID></soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>`)

	return map[uint16][][]byte{
		7:     {[]byte("nety\r\n")},
		53:    {dns},
		69:    {append(append([]byte{0x00, 0x01}, []byte("nety-probe.txt\x00")...), []byte("octet\x00")...)},
		88:    {kerberosASReq()},
		111:   {rpcNull(100000, 2)},
		123:   {ntpClient()},
		137:   {nbstatQuery()},
		161:   {snmpV2, snmpV1},
		177:   {{0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00}},
		389:   {cldapRootDSE()},
		500:   {ike},
		520:   {append([]byte{0x01, 0x02, 0x00, 0x00}, append(make([]byte, 16), 0x00, 0x00, 0x00, 0x10)...)},
		623:   {{0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5}},
		1194:  {{0x38, 0x6e, 0x65, 0x74, 0x79, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}},
		1434:  {{0x02}},
		1604:  {citrix},
		1900:  {ssdp},
		2049:  {rpcNull(100003, 3)},
		3478:  {stun},
		3702:  {wsd},
		4500:  {append([]byte{0x00, 0x00, 0x00, 0x00}, ike...)}, // non-ESP marker + IKE
		5060:  {sip},
		5351:  {{0x00, 0x00}},
		5353:  {dnsQuery(0, "_services._dns-sd._udp.local", 12 /*PTR*/, 1, false)},
		5355:  {dnsQuery(0x6e74, "wpad", 1 /*A*/, 1, false)},
		5683:  {coap},
		10001: {{0x01, 0x00, 0x00, 0x00}},
		11211: {append([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}, []byte("version\r\n")...)},
		27015: {append([]byte{0xff, 0xff, 0xff, 0xff}, []byte("TSource Engine Query\x00")...)},
		47808: {{0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x01, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19, 0x4b}},
	}
}

// dnsQuery builds a single-question DNS query.
func dnsQuery(id uint16, name string, qtype, qclass uint16, rd bool) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	if rd {
		b[2] = 0x01
	}
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, qclass)
	return b
}

// ntpClient is an NTPv4 client-mode request (48 bytes).
func ntpClient() []byte {
	b := make([]byte, 48)
	b[0] = 0xe3                                    // LI=3 (unsynchronised), VN=4, mode=3 (client)
	b[2] = 0x04                                    // poll
	b[3] = 0xfa                                    // precision
	binary.BigEndian.PutUint32(b[40:], 0x6e657479) // transmit timestamp (arbitrary)
	return b
}

// nbstatQuery is a NetBIOS Node Status (NBSTAT) request for the wildcard name.
func nbstatQuery() []byte {
	b := []byte{0x6e, 0x74, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 'C', 'K'}
	b = append(b, []byte(strings.Repeat("A", 30))...)
	return append(b, 0x00, 0x00, 0x21, 0x00, 0x01)
}

// snmpGetSysDescr builds an SNMP GetRequest for sysDescr.0 with community "public"
// (version 0 = v1, 1 = v2c).
func snmpGetSysDescr(version byte) []byte {
	oid := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	varbind := ber(0x30, append(oid, 0x05, 0x00))
	vbl := ber(0x30, varbind)
	pdu := ber(0xa0, concat(
		[]byte{0x02, 0x04, 0x6e, 0x65, 0x74, 0x79}, // request-id
		[]byte{0x02, 0x01, 0x00},                   // error-status
		[]byte{0x02, 0x01, 0x00},                   // error-index
		vbl,
	))
	return ber(0x30, concat([]byte{0x02, 0x01, version}, ber(0x04, []byte("public")), pdu))
}

// cldapRootDSE is a connectionless LDAP search of the root DSE.
func cldapRootDSE() []byte {
	search := ber(0x63, concat(
		ber(0x04, nil),           // baseObject ""
		[]byte{0x0a, 0x01, 0x00}, // scope baseObject
		[]byte{0x0a, 0x01, 0x00}, // derefAliases never
		[]byte{0x02, 0x01, 0x00}, // sizeLimit
		[]byte{0x02, 0x01, 0x00}, // timeLimit
		[]byte{0x01, 0x01, 0x00}, // typesOnly false
		ber(0x87, []byte("objectClass")),
		ber(0x30, nil),
	))
	return ber(0x30, concat([]byte{0x02, 0x01, 0x01}, search))
}

// kerberosASReq builds a minimal AS-REQ for an unlikely principal; KDCs answer with a
// KRB-ERROR (which proves the service and leaks the realm).
func kerberosASReq() []byte {
	gs := func(s string) []byte { return ber(0x1b, []byte(s)) }
	integer := func(v int) []byte {
		if v < 0x80 {
			return []byte{0x02, 0x01, byte(v)}
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v))
		i := 0
		for i < 3 && b[i] == 0 && b[i+1]&0x80 == 0 {
			i++
		}
		return ber(0x02, b[i:])
	}
	principal := func(nameType int, parts ...string) []byte {
		var seq []byte
		for _, p := range parts {
			seq = append(seq, gs(p)...)
		}
		return ber(0x30, concat(ber(0xa0, integer(nameType)), ber(0xa1, ber(0x30, seq))))
	}
	body := ber(0x30, concat(
		ber(0xa0, []byte{0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x10}), // forwardable, renewable, canonicalize, renewable-ok
		ber(0xa1, principal(1, "nety")),
		ber(0xa2, gs("NETY")),
		ber(0xa3, principal(2, "krbtgt", "NETY")),
		ber(0xa5, ber(0x18, []byte("20370913024805Z"))),
		ber(0xa7, integer(0x6e657479)),
		ber(0xa8, ber(0x30, concat(integer(18), integer(17), integer(23)))),
	))
	req := ber(0x30, concat(
		ber(0xa1, integer(5)),
		ber(0xa2, integer(10)),
		ber(0xa4, body),
	))
	return ber(0x6a, req)
}

// ikeV1MainMode builds an ISAKMP (IKEv1) Main Mode SA proposal (3DES/SHA1/PSK/MODP1024),
// which any IKEv1 responder answers.
func ikeV1MainMode() []byte {
	attrs := []byte{
		0x80, 0x01, 0x00, 0x05, // encryption 3DES-CBC
		0x80, 0x02, 0x00, 0x02, // hash SHA1
		0x80, 0x03, 0x00, 0x01, // auth pre-shared key
		0x80, 0x04, 0x00, 0x02, // group MODP 1024
		0x80, 0x0b, 0x00, 0x01, // life type seconds
		0x00, 0x0c, 0x00, 0x04, 0x00, 0x00, 0x70, 0x80, // life duration 28800
	}
	transform := concat([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00}, attrs)
	binary.BigEndian.PutUint16(transform[2:], uint16(len(transform)))
	proposal := concat([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01}, transform)
	binary.BigEndian.PutUint16(proposal[2:], uint16(len(proposal)))
	sa := concat([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}, proposal)
	binary.BigEndian.PutUint16(sa[2:], uint16(len(sa)))
	hdr := []byte{
		0x6e, 0x65, 0x74, 0x79, 0x6e, 0x65, 0x74, 0x79, // initiator cookie
		0, 0, 0, 0, 0, 0, 0, 0, // responder cookie
		0x01,       // next payload: SA
		0x10,       // version 1.0
		0x02,       // exchange: identity protection (main mode)
		0x00,       // flags
		0, 0, 0, 0, // message id
		0, 0, 0, 0, // length
	}
	msg := concat(hdr, sa)
	binary.BigEndian.PutUint32(msg[24:], uint32(len(msg)))
	return msg
}

// ber encodes a definite-length BER TLV.
func ber(tag byte, content []byte) []byte {
	n := len(content)
	var out []byte
	switch {
	case n < 0x80:
		out = append(make([]byte, 0, n+2), tag, byte(n))
	case n < 0x100:
		out = append(make([]byte, 0, n+3), tag, 0x81, byte(n))
	default:
		out = append(make([]byte, 0, n+4), tag, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
