package udpprobe

import (
	"strconv"
	"strings"
)

// Fixed, synthetic initiator cookies / SPIs. A responder echoes the initiator
// cookie verbatim, so verifying it is what earns confidence 90.
var (
	ikeV1Cookie = [8]byte{0x4e, 0x45, 0x54, 0x59, 0x01, 0x00, 0x00, 0x01}
	ikeV2SPI    = [8]byte{0x4e, 0x45, 0x54, 0x59, 0x02, 0x00, 0x00, 0x02}
)

const (
	ikeHdrLen      = 28
	maxIKEPayloads = 64
	maxIKEVendor   = 16
)

// --- payload construction -------------------------------------------------

// ikeAttrBasic encodes a basic (TV) ISAKMP attribute.
func ikeAttrBasic(typ, val uint16) []byte {
	t := typ | 0x8000
	return []byte{byte(t >> 8), byte(t), byte(val >> 8), byte(val)}
}

// ikeAttrVar encodes a variable-length (TLV) ISAKMP attribute.
func ikeAttrVar(typ uint16, val []byte) []byte {
	out := []byte{byte(typ >> 8), byte(typ), byte(len(val) >> 8), byte(len(val))}
	return append(out, val...)
}

// ikeV1Transform builds one IKEv1 transform payload (KEY_IKE).
func ikeV1Transform(num byte, last bool, attrs []byte) []byte {
	next := byte(3) // Transform
	if last {
		next = 0
	}
	l := 8 + len(attrs)
	out := []byte{next, 0, byte(l >> 8), byte(l), num, 1 /* KEY_IKE */, 0, 0}
	return append(out, attrs...)
}

// ikeV1Payload is an IKEv1 Main Mode SA proposal offering the eight classic
// transforms (AES-256/AES-128/3DES/DES x SHA1/MD5, PSK, DH group 2). Almost
// every IKEv1 responder on the planet accepts at least one of them, and the one
// it picks is itself a fingerprint.
func ikeV1Payload() []byte {
	type combo struct {
		enc, keyLen, hash uint16
	}
	combos := []combo{
		{7, 256, 2}, {7, 256, 1}, {7, 128, 2}, {7, 128, 1},
		{5, 0, 2}, {5, 0, 1}, {1, 0, 2}, {1, 0, 1},
	}
	var transforms []byte
	for i, c := range combos {
		attrs := ikeAttrBasic(1, c.enc) // Encryption Algorithm
		if c.keyLen != 0 {
			attrs = append(attrs, ikeAttrBasic(14, c.keyLen)...) // Key Length
		}
		attrs = append(attrs, ikeAttrBasic(2, c.hash)...)                        // Hash Algorithm
		attrs = append(attrs, ikeAttrBasic(3, 1)...)                             // Authentication Method: PSK
		attrs = append(attrs, ikeAttrBasic(4, 2)...)                             // Group Description: modp1024
		attrs = append(attrs, ikeAttrBasic(11, 1)...)                            // Life Type: seconds
		attrs = append(attrs, ikeAttrVar(12, []byte{0x00, 0x00, 0x70, 0x80})...) // Life Duration: 28800
		transforms = append(transforms, ikeV1Transform(byte(i+1), i == len(combos)-1, attrs)...)
	}

	// Proposal payload: #1, protocol ISAKMP, no SPI, N transforms.
	propLen := 8 + len(transforms)
	proposal := []byte{0, 0, byte(propLen >> 8), byte(propLen), 1, 1, 0, byte(len(combos))}
	proposal = append(proposal, transforms...)

	// SA payload: DOI = IPSEC(1), situation = SIT_IDENTITY_ONLY(1).
	saLen := 12 + len(proposal)
	sa := []byte{0, 0, byte(saLen >> 8), byte(saLen), 0, 0, 0, 1, 0, 0, 0, 1}
	sa = append(sa, proposal...)

	total := ikeHdrLen + len(sa)
	out := make([]byte, 0, total)
	out = append(out, ikeV1Cookie[:]...)
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // responder cookie
	out = append(out, 1)                      // next payload: SA
	out = append(out, 0x10)                   // version 1.0
	out = append(out, 2)                      // exchange type: Identity Protection (Main Mode)
	out = append(out, 0)                      // flags
	out = append(out, 0, 0, 0, 0)             // message id
	out = append(out, byte(total>>24), byte(total>>16), byte(total>>8), byte(total))
	out = append(out, sa...)
	return out
}

// ikeSynthetic fills n bytes with a deterministic, obviously synthetic pattern.
// Used for the IKEv2 key-exchange value and nonce: we never complete the
// handshake, so no real entropy is needed - and a fixed pattern keeps the probe
// reproducible and auditable.
func ikeSynthetic(n int, seed uint32) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, n)
	x := seed
	for i := range out {
		x = x*1664525 + 1013904223
		out[i] = byte(x >> 24)
	}
	out[0] |= 0x80 // keep the value in the upper half of the group, as a real one would be
	return out
}

// ikeV2Transform builds one IKEv2 transform substructure.
func ikeV2Transform(last bool, typ byte, id uint16, attrs []byte) []byte {
	next := byte(3)
	if last {
		next = 0
	}
	l := 8 + len(attrs)
	out := []byte{next, 0, byte(l >> 8), byte(l), typ, 0, byte(id >> 8), byte(id)}
	return append(out, attrs...)
}

// ikeV2Payload is an IKEv2 IKE_SA_INIT offering AES-CBC-128 / HMAC-SHA1 /
// modp2048.
func ikeV2Payload() []byte {
	transforms := concat(
		ikeV2Transform(false, 1, 12, ikeAttrBasic(14, 128)), // ENCR_AES_CBC, 128 bit
		ikeV2Transform(false, 2, 2, nil),                    // PRF_HMAC_SHA1
		ikeV2Transform(false, 3, 2, nil),                    // AUTH_HMAC_SHA1_96
		ikeV2Transform(true, 4, 14, nil),                    // DH group 14 (modp2048)
	)
	propLen := 8 + len(transforms)
	proposal := []byte{0, 0, byte(propLen >> 8), byte(propLen), 1, 1, 0, 4}
	proposal = append(proposal, transforms...)

	saLen := 4 + len(proposal)
	sa := []byte{34 /* next: KE */, 0, byte(saLen >> 8), byte(saLen)}
	sa = append(sa, proposal...)

	ke := ikeSynthetic(256, 0x4e455459)
	keLen := 8 + len(ke)
	kePayload := []byte{40 /* next: Nonce */, 0, byte(keLen >> 8), byte(keLen), 0, 14, 0, 0}
	kePayload = append(kePayload, ke...)

	nonce := ikeSynthetic(32, 0x4e4f4e43)
	nLen := 4 + len(nonce)
	noncePayload := []byte{0, 0, byte(nLen >> 8), byte(nLen)}
	noncePayload = append(noncePayload, nonce...)

	body := concat(sa, kePayload, noncePayload)
	total := ikeHdrLen + len(body)
	out := make([]byte, 0, total)
	out = append(out, ikeV2SPI[:]...)
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // responder SPI
	out = append(out, 33)                     // next payload: SA
	out = append(out, 0x20)                   // version 2.0
	out = append(out, 34)                     // exchange type: IKE_SA_INIT
	out = append(out, 0x08)                   // flags: initiator
	out = append(out, 0, 0, 0, 0)             // message id
	out = append(out, byte(total>>24), byte(total>>16), byte(total>>8), byte(total))
	out = append(out, body...)
	return out
}

// --- decoding -------------------------------------------------------------

func decodeIKEv1(resp []byte) *Result { return decodeIKE(resp, ikeV1Cookie) }
func decodeIKEv2(resp []byte) *Result { return decodeIKE(resp, ikeV2SPI) }

var ikeExchangeV1 = map[byte]string{
	0: "none", 1: "base", 2: "identity-protection", 3: "authentication-only",
	4: "aggressive", 5: "informational", 32: "quick-mode", 33: "new-group-mode",
}

var ikeExchangeV2 = map[byte]string{
	34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
}

func decodeIKE(resp []byte, wantCookie [8]byte) *Result {
	if len(resp) < ikeHdrLen {
		return nil
	}
	if string(resp[0:8]) != string(wantCookie[:]) {
		return nil
	}
	verByte := resp[17]
	major := verByte >> 4
	if major != 1 && major != 2 {
		return nil
	}
	exch := resp[18]
	declared, _ := u32(resp, 24)

	r := newResult("isakmp", 90)
	r.set("ike.version", itoa(int(major))+"."+itoa(int(verByte&0x0f)))
	if major == 2 {
		if name, ok := ikeExchangeV2[exch]; ok {
			r.set("ike.exchange", name)
		} else {
			r.set("ike.exchange", itoa(int(exch)))
		}
	} else {
		if name, ok := ikeExchangeV1[exch]; ok {
			r.set("ike.exchange", name)
		} else {
			r.set("ike.exchange", itoa(int(exch)))
		}
	}
	r.set("ike.responder_spi", hexStr(resp[8:16]))
	r.setBool("ike.encrypted", resp[19]&0x01 != 0)

	body := resp[ikeHdrLen:]
	if int(declared) >= ikeHdrLen && int(declared) <= len(resp) {
		body = resp[ikeHdrLen:declared]
	}

	var vendorIDs []string
	var vendorNames []string
	nextPayload := resp[16]
	count := 0
	for len(body) >= 4 && nextPayload != 0 && count < maxIKEPayloads {
		count++
		plen := int(body[2])<<8 | int(body[3])
		if plen < 4 || plen > len(body) {
			break
		}
		content := body[4:plen]
		switch {
		case (major == 1 && nextPayload == 1) || (major == 2 && nextPayload == 33):
			decodeIKESA(content, major, r)
		case (major == 1 && nextPayload == 13) || (major == 2 && nextPayload == 43):
			if len(vendorIDs) < maxIKEVendor {
				h := hexStr(content)
				vendorIDs = append(vendorIDs, h)
				if name := ikeVendorName(h, content); name != "" {
					vendorNames = append(vendorNames, name)
					ikeVendorProduct(name, r)
				}
			}
		case (major == 1 && nextPayload == 11) || (major == 2 && nextPayload == 41):
			decodeIKENotify(content, major, r)
		}
		nextPayload = body[0]
		body = body[plen:]
	}
	r.set("ike.payloads", itoa(count))
	if len(vendorIDs) > 0 {
		r.set("ike.vendor_ids", joinCapped(vendorIDs))
	}
	if len(vendorNames) > 0 {
		r.set("ike.vendors", joinCapped(vendorNames))
		if r.ExtraInfo == "" {
			r.ExtraInfo = joinCapped(vendorNames)
		}
	}
	if r.Product == "" {
		if major == 2 {
			r.Product = "IKEv2 VPN gateway"
		} else {
			r.Product = "IKEv1 VPN gateway"
		}
	}
	return r
}

// decodeIKENotify records an ISAKMP notification (e.g. NO-PROPOSAL-CHOSEN,
// INVALID-KE-PAYLOAD): proof of a live IKE responder even when it rejects us.
func decodeIKENotify(content []byte, major byte, r *Result) {
	var msgType uint16
	if major == 1 {
		// DOI(4) protocol(1) spiSize(1) msgType(2)
		if len(content) < 8 {
			return
		}
		msgType = uint16(content[6])<<8 | uint16(content[7])
	} else {
		// protocol(1) spiSize(1) msgType(2)
		if len(content) < 4 {
			return
		}
		msgType = uint16(content[2])<<8 | uint16(content[3])
	}
	if name, ok := ikeNotifyNames[msgType]; ok {
		r.set("ike.notify", name)
	} else {
		r.set("ike.notify", itoa(int(msgType)))
	}
}

var ikeNotifyNames = map[uint16]string{
	1: "INVALID-PAYLOAD-TYPE", 7: "INVALID-SPI", 14: "NO-PROPOSAL-CHOSEN",
	17: "INVALID-KE-PAYLOAD", 24: "AUTHENTICATION-FAILED", 29: "INVALID-SYNTAX",
	9: "INVALID-MAJOR-VERSION", 39: "SINGLE-PAIR-REQUIRED",
	16384: "INITIAL-CONTACT", 16388: "NAT-DETECTION-SOURCE-IP",
	16389: "NAT-DETECTION-DESTINATION-IP", 16430: "DEAD-PEER-DETECTION",
}

// decodeIKESA parses the accepted transform out of an SA payload.
func decodeIKESA(content []byte, major byte, r *Result) {
	if major == 1 {
		if len(content) < 8 {
			return
		}
		doi := uint32(content[0])<<24 | uint32(content[1])<<16 | uint32(content[2])<<8 | uint32(content[3])
		r.set("ike.doi", strconv.FormatUint(uint64(doi), 10))
		content = content[8:] // skip DOI + situation
	}
	// Proposal payload header: next(1) res(1) len(2) num(1) protocol(1)
	// spiSize(1) numTransforms(1)
	if len(content) < 8 {
		return
	}
	plen := int(content[2])<<8 | int(content[3])
	if plen < 8 || plen > len(content) {
		plen = len(content)
	}
	spiSize := int(content[6])
	numT := int(content[7])
	if numT > 32 {
		numT = 32
	}
	off := 8 + spiSize
	if off > plen {
		return
	}
	trans := content[off:plen]
	// Only the first (accepted) transform matters: a responder returns exactly
	// the one it chose.
	if len(trans) < 8 {
		return
	}
	tlen := int(trans[2])<<8 | int(trans[3])
	if tlen < 8 || tlen > len(trans) {
		tlen = len(trans)
	}
	if major == 2 {
		ikeV2TransformFacts(trans[:tlen], r)
		// Walk the remaining transforms too: IKEv2 returns one per type.
		rest := trans[tlen:]
		for i := 0; i < numT && len(rest) >= 8; i++ {
			l := int(rest[2])<<8 | int(rest[3])
			if l < 8 || l > len(rest) {
				break
			}
			ikeV2TransformFacts(rest[:l], r)
			rest = rest[l:]
		}
		return
	}
	ikeV1Attributes(trans[8:tlen], r)
}

func ikeV2TransformFacts(t []byte, r *Result) {
	if len(t) < 8 {
		return
	}
	typ := t[4]
	id := uint16(t[6])<<8 | uint16(t[7])
	switch typ {
	case 1:
		r.set("ike.encryption", ikev2Encr[id])
		// Key length attribute, if present.
		if len(t) >= 12 && t[8] == 0x80 && t[9] == 0x0e {
			r.set("ike.key_length", itoa(int(uint16(t[10])<<8|uint16(t[11]))))
		}
	case 2:
		r.set("ike.prf", ikev2PRF[id])
	case 3:
		r.set("ike.integrity", ikev2Integ[id])
	case 4:
		r.set("ike.dh_group", ikeDHName(id))
	}
}

var ikev2Encr = map[uint16]string{
	1: "DES-IV64", 2: "DES-CBC", 3: "3DES-CBC", 4: "RC5", 5: "IDEA", 6: "CAST",
	7: "Blowfish", 11: "NULL", 12: "AES-CBC", 13: "AES-CTR", 14: "AES-CCM-8",
	15: "AES-CCM-12", 16: "AES-CCM-16", 18: "AES-GCM-8", 19: "AES-GCM-12",
	20: "AES-GCM-16", 23: "CAMELLIA-CBC", 28: "CHACHA20-POLY1305",
}

var ikev2PRF = map[uint16]string{
	1: "HMAC-MD5", 2: "HMAC-SHA1", 4: "AES128-XCBC", 5: "HMAC-SHA2-256",
	6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512", 8: "AES128-CMAC",
}

var ikev2Integ = map[uint16]string{
	0: "NONE", 1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 5: "AES-XCBC-96",
	12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256",
}

var ikeV1Encr = map[uint16]string{
	1: "DES-CBC", 2: "IDEA-CBC", 3: "Blowfish-CBC", 4: "RC5", 5: "3DES-CBC",
	6: "CAST-CBC", 7: "AES-CBC", 8: "CAMELLIA-CBC",
}

var ikeV1Hash = map[uint16]string{
	1: "MD5", 2: "SHA1", 3: "Tiger", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512",
}

var ikeV1Auth = map[uint16]string{
	1: "pre-shared-key", 2: "DSS-signature", 3: "RSA-signature",
	4: "RSA-encryption", 5: "revised-RSA-encryption",
	64221: "hybrid-RSA", 65001: "XAUTHInitPreShared", 65003: "XAUTHInitRSA",
}

func ikeDHName(id uint16) string {
	switch id {
	case 1:
		return "modp768"
	case 2:
		return "modp1024"
	case 5:
		return "modp1536"
	case 14:
		return "modp2048"
	case 15:
		return "modp3072"
	case 16:
		return "modp4096"
	case 19:
		return "ecp256"
	case 20:
		return "ecp384"
	case 21:
		return "ecp521"
	case 31:
		return "curve25519"
	default:
		return itoa(int(id))
	}
}

// ikeV1Attributes walks the attribute list of an IKEv1 transform.
func ikeV1Attributes(attrs []byte, r *Result) {
	var keyLen uint16
	var lifeType uint16
	for i := 0; i < 32 && len(attrs) >= 4; i++ {
		typ := uint16(attrs[0])<<8 | uint16(attrs[1])
		basic := typ&0x8000 != 0
		typ &= 0x7fff
		var val uint64
		var consumed int
		if basic {
			val = uint64(attrs[2])<<8 | uint64(attrs[3])
			consumed = 4
		} else {
			l := int(attrs[2])<<8 | int(attrs[3])
			if l < 0 || 4+l > len(attrs) || l > 8 {
				return
			}
			for _, c := range attrs[4 : 4+l] {
				val = val<<8 | uint64(c)
			}
			consumed = 4 + l
		}
		switch typ {
		case 1:
			r.set("ike.encryption", ikeV1Encr[uint16(val)])
		case 2:
			r.set("ike.hash", ikeV1Hash[uint16(val)])
		case 3:
			if name, ok := ikeV1Auth[uint16(val)]; ok {
				r.set("ike.auth", name)
			} else {
				r.set("ike.auth", strconv.FormatUint(val, 10))
			}
		case 4:
			r.set("ike.dh_group", ikeDHName(uint16(val)))
		case 11:
			lifeType = uint16(val)
		case 12:
			unit := "s"
			if lifeType == 2 {
				unit = "KB"
			}
			r.set("ike.lifetime", strconv.FormatUint(val, 10)+unit)
		case 14:
			keyLen = uint16(val)
		}
		attrs = attrs[consumed:]
	}
	if keyLen != 0 {
		r.set("ike.key_length", itoa(int(keyLen)))
	}
}

// ikeVendorIDs maps well-known vendor-ID prefixes (lowercase hex) to a label.
var ikeVendorIDs = []struct{ prefix, name string }{
	{"4048b7d56ebce88525e7de7f00d6c2d3", "Cisco IKE Fragmentation"},
	{"12f5f28c457168a9702d9fe274cc0100", "Cisco Unity"},
	{"4df37928e9fc4fd1b3262170d515c662", "Cisco VPN 3000 Concentrator"},
	{"1f07f70eaa6514d3b0fa96542a500100", "Fortinet FortiGate"},
	{"1f07f70eaa6514d3b0fa96542a500300", "Fortinet FortiGate"},
	{"8f9cc94e01248ecdf147594c284b213b", "Microsoft Windows (MS NT5 ISAKMPOAKLEY)"},
	{"1e2b516905991c7d7c96fcbfb587e461", "draft-ietf-ipsec-nat-t-ike-00 (Microsoft)"},
	{"4865617274426561745f4e6f74696679", "Check Point HeartBeat_Notify"},
	{"f4ed19e0c114eb516faaac0ee37daf28", "strongSwan"},
	{"afcad71368a1f1c96b8696fc77570100", "Dead Peer Detection v1.0"},
	{"4a131c81070358455c5728f20e95452f", "RFC 3947 NAT-T"},
	{"90cb80913ebb696e086381b5ec427b1f", "draft-ietf-ipsec-nat-t-ike-02"},
	{"7d9419a65310ca6f2c179d9215529d56", "draft-ietf-ipsec-nat-t-ike-03"},
	{"4485152d18b6bbcd0be8a8469579ddcc", "draft-ietf-ipsec-nat-t-ike-00"},
	{"cd60464335df21f87cfdb2fc68b6a448", "draft-ietf-ipsec-nat-t-ike-02\\n"},
	{"09002689dfd6b712", "XAUTH"},
	{"afcad71368a1f1c9", "Dead Peer Detection"},
	{"4a131c8107035845", "RFC 3947 NAT-T"},
}

func ikeVendorName(h string, raw []byte) string {
	for _, v := range ikeVendorIDs {
		if strings.HasPrefix(h, v.prefix) {
			return v.name
		}
	}
	// Some implementations put a readable string in the vendor ID (Check Point
	// "HeartBeat_Notify", SonicWALL, Juniper and others).
	if s := printableASCII(raw); len(s) >= 6 {
		return s
	}
	return ""
}

func ikeVendorProduct(name string, r *Result) {
	switch {
	case strings.HasPrefix(name, "Cisco"):
		r.Product = "Cisco VPN"
	case strings.HasPrefix(name, "Fortinet"):
		r.Product = "Fortinet FortiGate"
		r.OSType = "FortiOS"
	case strings.HasPrefix(name, "Microsoft") || containsFold(name, "MS NT5"):
		r.Product = "Microsoft Windows IKE"
		r.OSType = "Windows"
	case strings.HasPrefix(name, "Check Point") || containsFold(name, "HeartBeat_Notify"):
		r.Product = "Check Point FireWall-1"
	case strings.HasPrefix(name, "strongSwan"):
		r.Product = "strongSwan"
		r.OSType = "Linux"
	case containsFold(name, "SonicWALL"):
		r.Product = "SonicWALL"
	case containsFold(name, "Juniper") || containsFold(name, "Netscreen"):
		r.Product = "Juniper/Netscreen VPN"
	}
}
