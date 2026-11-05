package udpprobe

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Response fixtures. The binary ones are handcrafted packets written as annotated hex;
// the text ones are literal protocol responses. Nothing here touches the network.

// mustHex decodes a hex fixture, ignoring whitespace and "//" comments so the fixtures
// can be annotated inline.
func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	var sb strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		for _, r := range line {
			if r != ' ' && r != '\t' && r != '\r' {
				sb.WriteRune(r)
			}
		}
	}
	b, err := hex.DecodeString(sb.String())
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

const (
	// DNS: version.bind. CH TXT answer "9.11.3-1ubuntu1.17-Ubuntu".
	fxDNSBind = `
		4e01 8400 0001 0001 0000 0000               // id, QR|AA, qd=1 an=1
		07 76657273696f6e 04 62696e64 00 0010 0003  // version.bind. TXT CH
		c00c 0010 0003 00000000 001a                // answer: TXT CH, rdlen 26
		19 392e31312e332d317562756e7475312e31372d5562756e7475`

	// Same, but the banner is a dnsmasq one.
	fxDNSDnsmasq = `
		4e01 8400 0001 0001 0000 0000
		07 76657273696f6e 04 62696e64 00 0010 0003
		c00c 0010 0003 00000000 000d
		0c 646e736d6173712d322e3830                 // "dnsmasq-2.80"`

	// The server refuses the CHAOS query (rcode 5).
	fxDNSRefused = `
		4e01 8405 0001 0000 0000 0000
		07 76657273696f6e 04 62696e64 00 0010 0003`

	// Right shape, wrong transaction id.
	fxDNSWrongID = `
		1234 8400 0001 0001 0000 0000
		07 76657273696f6e 04 62696e64 00 0010 0003
		c00c 0010 0003 00000000 001a
		19 392e31312e332d317562756e7475312e31372d5562756e7475`

	// dns-status: NOERROR, recursion available.
	fxDNSStatus = `4e02 8180 0001 0000 0000 0000 00 0006 0001`

	// mDNS: two PTR answers plus an A record for printer.local.
	fxMDNS = `
		0000 8400 0000 0002 0000 0001
		095f7365727669636573075f646e732d7364045f756470056c6f63616c00  // _services._dns-sd._udp.local.
		000c 0001 00001194 0011
		045f697070045f746370056c6f63616c00                            // _ipp._tcp.local.
		095f7365727669636573075f646e732d7364045f756470056c6f63616c00
		000c 0001 00001194 0015
		085f7072696e746572045f746370056c6f63616c00                    // _printer._tcp.local.
		077072696e746572056c6f63616c00                                // printer.local.
		0001 8001 00000078 0004 c0000232                             // A 192.0.2.50, cache-flush`

	// SNMPv2c GetResponse carrying a Cisco IOS sysDescr.
	fxSNMPCisco = `
		30818c 020101 0406 7075626c6963                 // SEQ, version v2c, "public"
		a27f 0204 4e450201 020100 020100                // GetResponse, our request id
		3071 306f 0608 2b06010201010100                 // varbinds, sysDescr.0
		0463 436973636f20494f5320536f6674776172652c20433239363020536f667477
		617265202843323936302d4c414e424153454b392d4d292c2056657273696f6e20
		31352e30283229534531312c2052454c4541534520534f4654574152452028666333 29`

	// SNMPv2c GetResponse carrying a Linux sysDescr.
	fxSNMPLinux = `
		3062 020101 0406 7075626c6963
		a255 0204 4e450201 020100 020100
		3047 3045 0608 2b06010201010100
		0439 4c696e757820737276303120352e31302e302d382d616d64363420233120
		534d502044656269616e20352e31302e34362d34207838365f3634`

	// SNMPv2c agent that answers but rejects the community (authorizationError).
	fxSNMPAuthErr = `
		3029 020101 0406 7075626c6963
		a21c 0204 4e450201 020110 020101          // error-status 16
		300e 300c 0608 2b06010201010100 0500`

	// SNMPv1 agent that does not expose sysDescr (noSuchName).
	fxSNMPv1NoSuchName = `
		3029 020100 0406 7075626c6963
		a21c 0204 4e450101 020102 020101
		300e 300c 0608 2b06010201010100 0500`

	// Structurally valid SNMPv2c response with somebody else's request id.
	fxSNMPWrongID = `
		3062 020101 0406 7075626c6963
		a255 0204 11223344 020100 020100
		3047 3045 0608 2b06010201010100
		0439 4c696e757820737276303120352e31302e302d382d616d64363420233120
		534d502044656269616e20352e31302e34362d34207838365f3634`

	// SNMPv3 Report: Net-SNMP engine id, boots 5, usmStatsUnknownEngineIDs.
	fxSNMPv3 = `
		3067 020103
		3011 0204 4e450302 0203 00ffe3 040100 020103     // globals
		041d 301b 040b 80001f8803005056abcdef             // USM: engine id
		020105 0203 0a1b2c 0400 0400 0400                 // boots, time, user
		3030 040b 80001f8803005056abcdef 0400             // scoped PDU
		a81f 0204 4e450301 020100 020100
		3011 300f 060a 2b060106030f01010400 410101`

	// NTP mode-4 server reply, stratum 2, originate echoes our transmit stamp.
	fxNTPServer = `
		24 02 06 e9 00001234 00004567 c0a80101
		e46ba140 00000000                                  // reference
		e46ba150 4e455459                                  // originate == our xmt
		e46ba151 11111111 e46ba151 22222222`

	// Same, but the originate timestamp is zeroed (no echo to verify).
	fxNTPNoEcho = `
		24 02 06 e9 00001234 00004567 c0a80101
		e46ba140 00000000 00000000 00000000
		e46ba151 11111111 e46ba151 22222222`

	// NTP mode-6 READVAR response with ntpd system variables.
	fxNTPReadvar = `
		16 82 4e45 0615 0000 0000 00be
		76657273696f6e3d226e74706420342e322e3870313540312e333732382d6f2057
		6564205365702032332031313a34363a333820555443203230323020283129222c
		2070726f636573736f723d227838365f3634222c2073797374656d3d224c696e75
		782f352e342e302d37342d67656e65726963222c206c6561703d30302c20737472
		6174756d3d332c20707265636973696f6e3d2d32342c20726f6f7464656c61793d
		31322e3334352c2072656669643d3139322e3136382e312e31`

	// NetBIOS node status: WORKSTATION01 in WORKGROUP, MAC 00:0c:29:ab:cd:ef.
	fxNBNS = `
		4e03 8400 0001 0001 0000 0000
		20 434b414141414141414141414141414141414141414141414141414141414141 00
		0021 0001
		c00c 0021 0001 00000000 0065
		03                                                     // 3 names
		574f524b53544154494f4e3031 2020 00  0400               // WORKSTATION01<00> unique
		574f524b47524f5550 202020202020 00  8400               // WORKGROUP<00> group
		574f524b53544154494f4e3031 2020 20  0400               // WORKSTATION01<20> unique
		000c29abcdef                                           // adapter MAC
		00000000000000000000000000000000000000000000000000000000000000000000000000000000`

	fxNBNSWrongID = `
		1111 8400 0001 0001 0000 0000
		20 434b414141414141414141414141414141414141414141414141414141414141 00
		0021 0001
		c00c 0021 0001 00000000 0065
		03
		574f524b53544154494f4e3031202000 0400
		574f524b47524f555020202020202000 8400
		574f524b53544154494f4e3031202020 0400
		000c29abcdef
		00000000000000000000000000000000000000000000000000000000000000000000000000000000`

	// IKEv1 Main Mode response: accepted transform + DPD and Cisco vendor ids.
	fxIKEv1 = `
		4e45545901000001 1122334455667788                   // echoed initiator cookie
		01 10 02 00 00000000 00000080                       // next=SA, v1.0, main mode, len
		0d 00 003c 00000001 00000001                        // SA payload, DOI 1, situation 1
		00 00 0030 01 01 00 01                              // proposal: ISAKMP, 1 transform
		00 00 0028 01 01 0000                               // transform 1, KEY_IKE
		80010007 800e0080 80020002 80030001 80040002        // AES/128, SHA1, PSK, modp1024
		800b0001 000c000400007080                           // lifetime 28800 s
		0d 00 0014 afcad71368a1f1c96b8696fc77570100         // VID: Dead Peer Detection
		00 00 0014 4048b7d56ebce88525e7de7f00d6c2d3         // VID: Cisco fragmentation`

	// Same packet with a different initiator cookie.
	fxIKEv1WrongCookie = `
		ff45545901000001 1122334455667788
		01 10 02 00 00000000 00000080
		0d 00 003c 00000001 00000001
		00 00 0030 01 01 00 01
		00 00 0028 01 01 0000
		80010007 800e0080 80020002 80030001 80040002
		800b0001 000c000400007080
		0d 00 0014 afcad71368a1f1c96b8696fc77570100
		00 00 0014 4048b7d56ebce88525e7de7f00d6c2d3`

	// IKEv2 IKE_SA_INIT response.
	fxIKEv2 = `
		4e45545902000002 aabbccddeeff0011                   // echoed initiator SPI
		21 20 22 20 00000000 00000068                       // next=SA, v2.0, IKE_SA_INIT, response
		22 00 0030 00 00 002c 01 01 00 04                   // SA, proposal with 4 transforms
		03 00 000c 01 00 000c 800e0080                      // ENCR_AES_CBC 128
		03 00 0008 02 00 0002                               // PRF_HMAC_SHA1
		03 00 0008 03 00 0002                               // AUTH_HMAC_SHA1_96
		00 00 0008 04 00 000e                               // DH modp2048
		28 00 0010 000e 0000 0011223344556677                // KE
		00 00 000c 8899aabbccddeeff                          // Nonce`

	// IPMI Get Channel Authentication Capabilities response, Dell BMC.
	fxIPMI = `
		06 00 ff 07                                         // RMCP
		00 00000000 00000000 10                             // auth NONE, session 0, msg len 16
		81 1c 63 20 54 38 00                                // rqAddr, netFn 0x07, rqSeq 0x15, cmd 0x38, cc 0
		01 16 0a 03 a2 02 00 00 8c                          // channel, auth types, status, ext, OEM 674`

	// Same, with a sequence number that is not ours.
	fxIPMIWrongSeq = `
		06 00 ff 07
		00 00000000 00000000 10
		81 1c 63 20 08 38 00
		01 16 0a 03 a2 02 00 00 d8`

	// Portmapper DUMP reply: portmapper on 111 tcp+udp, NFSv3 on 2049/tcp.
	fxRPC = `
		4e455459 00000001 00000000                          // xid, REPLY, MSG_ACCEPTED
		00000000 00000000                                   // verifier AUTH_NULL
		00000000                                            // accept stat SUCCESS
		00000001 000186a0 00000002 00000011 0000006f
		00000001 000186a0 00000002 00000006 0000006f
		00000001 000186a3 00000003 00000006 00000801
		00000000`

	fxRPCWrongXID = `11111111 00000001 00000000 00000000 00000000 00000000 00000000`

	// memcached ASCII "stats" reply behind the 8-byte UDP frame header.
	fxMemcachedStats = `
		4e45 0000 0001 0000                                 // UDP frame: our request id
		535441542070696420313233340d0a
		5354415420757074696d652039383736350d0a
		535441542076657273696f6e20312e362e390d0a
		5354415420706f696e7465725f73697a652036340d0a
		5354415420637572725f636f6e6e656374696f6e732031300d0a
		53544154207468726561647320340d0a
		454e440d0a`

	// memcached binary VERSION reply.
	fxMemcachedBin = `
		4e45 0000 0001 0000
		81 0b 0000 00 00 0000 00000005 4e455459 0000000000000000
		312e362e39                                          // "1.6.9"`

	fxMemcachedBinWrongOpaque = `
		4e45 0000 0001 0000
		81 0b 0000 00 00 0000 00000005 11223344 0000000000000000
		312e362e39`
)

// Text protocol fixtures.
const (
	fxSSDP = "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"DATE: Tue, 04 Nov 2025 10:00:00 GMT\r\n" +
		"EXT:\r\n" +
		"LOCATION: http://192.0.2.10:49152/rootDesc.xml\r\n" +
		"SERVER: Linux/3.14.0 UPnP/1.0 MiniUPnPd/1.9\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"USN: uuid:fc4ec57e-b051-11db-88f8-0060085db3f6::upnp:rootdevice\r\n" +
		"\r\n"

	fxSSDPNotUPnP = "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 2\r\n" +
		"\r\n" +
		"ok"

	fxSIP = "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP probe.invalid:5060;branch=" + sipBranch + ";rport=5060\r\n" +
		"From: \"NETY Probe\" <" + sipURI + ">;tag=" + sipTag + "\r\n" +
		"To: <" + sipURI + ">;tag=as1b2c3d4e\r\n" +
		"Call-ID: " + sipCallID + "\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Server: Asterisk PBX 16.2.1~dfsg-1ubuntu1\r\n" +
		"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO\r\n" +
		"Supported: replaces, timer\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"

	fxSIPOtherCallID = "SIP/2.0 404 Not Found\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKsomethingelse\r\n" +
		"Call-ID: 9f8e7d6c5b4a@192.0.2.1\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Server: kamailio (5.5.2 (x86_64/linux))\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
)
