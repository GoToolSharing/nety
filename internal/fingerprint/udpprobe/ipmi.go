package udpprobe

import "strconv"

// ipmiRqSeq is the fixed, synthetic requester sequence number; a BMC echoes it in the
// response, which is what we verify.
const ipmiRqSeq byte = 0x15

const (
	ipmiCmdGetChannelAuthCap byte = 0x38
	ipmiNetFnApp             byte = 0x06
)

// ipmiChecksum returns the IPMI two's-complement checksum of b.
func ipmiChecksum(b []byte) byte {
	var sum byte
	for _, c := range b {
		sum += c
	}
	return -sum
}

// ipmiPayload is a Get Channel Authentication Capabilities request for the current
// channel at ADMINISTRATOR privilege, inside an unauthenticated IPMI v1.5 session. Both
// 1.5 and 2.0 BMCs answer it, and a 2.0 BMC advertises its v2.0 support in the
// extended-capabilities byte, so one probe covers both. This is the request ipmitool and
// ipmi-version use.
func ipmiPayload() []byte {
	msg := []byte{
		0x20,                     // rsAddr: BMC
		ipmiNetFnApp<<2 | 0x00,   // netFn (App) / rsLUN
		0,                        // header checksum, filled below
		0x81,                     // rqAddr: remote console
		ipmiRqSeq << 2,           // rqSeq / rqLUN
		ipmiCmdGetChannelAuthCap, // command
		0x0e,                     // channel number: current channel
		0x04,                     // requested privilege: ADMINISTRATOR
		0,                        // data checksum, filled below
	}
	msg[2] = ipmiChecksum(msg[0:2])
	msg[8] = ipmiChecksum(msg[3:8])

	out := make([]byte, 0, 14+len(msg))
	out = append(out, 0x06, 0x00, 0xff, 0x07) // RMCP: version 1.0, seq 255 (no ack), class IPMI
	out = append(out, 0x00)                   // auth type: NONE
	out = append(out, 0, 0, 0, 0)             // session sequence number
	out = append(out, 0, 0, 0, 0)             // session id
	out = append(out, byte(len(msg)))         // IPMI message length
	return append(out, msg...)
}

var ipmiOEM = map[uint32]string{
	2: "IBM", 9: "Cisco", 11: "Hewlett-Packard", 42: "Sun/Oracle",
	343: "Intel", 674: "Dell", 689: "NEC", 2011: "Huawei", 2606: "Fujitsu-Siemens",
	4337: "Radisys", 5771: "Cisco UCS", 6876: "VMware", 7244: "Quanta",
	10368: "Fujitsu", 10876: "Super Micro", 11129: "Google", 15370: "Inspur",
	19046: "Lenovo", 20301: "Lenovo", 24681: "Tyan", 30154: "Nuvoton",
	40092: "ASRock Rack", 47488: "Gigabyte",
}

var ipmiOEMProduct = map[string]string{
	"Dell":            "Dell iDRAC",
	"Hewlett-Packard": "HP iLO",
	"IBM":             "IBM IMM",
	"Lenovo":          "Lenovo XClarity Controller",
	"Super Micro":     "Supermicro BMC",
	"Cisco":           "Cisco CIMC",
	"Cisco UCS":       "Cisco CIMC",
	"Fujitsu":         "Fujitsu iRMC",
	"Intel":           "Intel BMC",
	"Quanta":          "Quanta BMC",
	"Huawei":          "Huawei iBMC",
	"Inspur":          "Inspur BMC",
	"ASRock Rack":     "ASRock Rack BMC",
	"Gigabyte":        "Gigabyte BMC",
	"Tyan":            "Tyan BMC",
}

// decodeIPMI reads a Get Channel Authentication Capabilities response.
func decodeIPMI(resp []byte) *Result {
	if len(resp) < 8 {
		return nil
	}
	if resp[0] != 0x06 || resp[3] != 0x07 { // RMCP version 1.0, class IPMI
		return nil
	}
	authType := resp[4]

	var msg []byte
	switch {
	case authType == 0x00:
		if len(resp) < 14 {
			return nil
		}
		mlen := int(resp[13])
		if mlen < 7 || 14+mlen > len(resp) {
			if 14 >= len(resp) {
				return nil
			}
			msg = resp[14:]
		} else {
			msg = resp[14 : 14+mlen]
		}
	case authType >= 0x01 && authType <= 0x05:
		// Authenticated v1.5 session: a 16-byte auth code precedes the length.
		if len(resp) < 30 {
			return nil
		}
		mlen := int(resp[29])
		if mlen < 7 || 30+mlen > len(resp) {
			msg = resp[30:]
		} else {
			msg = resp[30 : 30+mlen]
		}
	case authType == 0x06:
		// RMCP+ (IPMI 2.0) framing.
		if len(resp) < 16 {
			return nil
		}
		plen := int(resp[14]) | int(resp[15])<<8
		if plen < 7 || 16+plen > len(resp) {
			msg = resp[16:]
		} else {
			msg = resp[16 : 16+plen]
		}
	default:
		return nil
	}
	if len(msg) < 7 {
		return nil
	}

	// rqAddr, netFn/lun, chk1, rsAddr, rqSeq/lun, cmd, completion code, data...
	netFn := msg[1] >> 2
	rqSeq := msg[4] >> 2
	cmd := msg[5]
	cc := msg[6]
	if cmd != ipmiCmdGetChannelAuthCap {
		return nil
	}
	// Response net function is the request's net function with the low bit set.
	if netFn != ipmiNetFnApp|0x01 {
		return nil
	}

	r := newResult("ipmi", 65)
	if rqSeq == ipmiRqSeq {
		r.Confidence = 90
	}
	r.Product = "IPMI BMC"
	r.OSType = "embedded"

	if cc != 0 {
		r.Confidence = min(r.Confidence, 80)
		r.set("ipmi.completion_code", "0x"+hexByte(cc))
		r.ExtraInfo = "BMC present, Get Channel Authentication Capabilities rejected"
		return r
	}

	data := msg[7:]
	if len(data) < 8 {
		r.Confidence = min(r.Confidence, 75)
		r.ExtraInfo = "BMC present (short capabilities response)"
		return r
	}

	channel := data[0] & 0x0f
	authSupport := data[1]
	authStatus := data[2]
	extCap := data[3]
	oem := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16

	r.set("ipmi.channel", itoa(int(channel)))

	switch {
	case extCap&0x02 != 0:
		r.set("ipmi.version", "2.0")
		r.Version = "2.0"
	case authSupport&0x80 != 0:
		// Bit 7 of the auth-type byte also flags "IPMI v2.0 extended data".
		r.set("ipmi.version", "2.0")
		r.Version = "2.0"
	default:
		r.set("ipmi.version", "1.5")
		r.Version = "1.5"
	}
	r.setBool("ipmi.v15_supported", extCap&0x01 != 0)
	r.setBool("ipmi.v20_supported", extCap&0x02 != 0)

	var auths []string
	if authSupport&0x01 != 0 {
		auths = append(auths, "none")
	}
	if authSupport&0x02 != 0 {
		auths = append(auths, "md2")
	}
	if authSupport&0x04 != 0 {
		auths = append(auths, "md5")
	}
	if authSupport&0x10 != 0 {
		auths = append(auths, "password")
	}
	if authSupport&0x20 != 0 {
		auths = append(auths, "oem")
	}
	if len(auths) == 0 {
		auths = append(auths, "none-advertised")
	}
	r.set("ipmi.auth_types", joinCapped(auths))

	// Authentication status byte.
	r.setBool("ipmi.anonymous_login", authStatus&0x01 != 0)
	r.setBool("ipmi.null_user", authStatus&0x02 != 0)
	r.setBool("ipmi.non_null_user", authStatus&0x04 != 0)
	// Bit set means "disabled" in the spec; expose the positive sense.
	r.setBool("ipmi.user_level_auth", authStatus&0x08 == 0)
	r.setBool("ipmi.per_message_auth", authStatus&0x10 == 0)
	// KG status: 0 means the BMC key is the all-zero default.
	r.setBool("ipmi.kg_default", authStatus&0x20 == 0)

	r.set("ipmi.oem_id", strconv.FormatUint(uint64(oem), 10))
	if data[7] != 0 {
		r.set("ipmi.oem_aux", "0x"+hexByte(data[7]))
	}
	vendor := ipmiOEM[oem]
	if vendor == "" {
		vendor = snmpEnterprises[oem]
	}
	if vendor != "" {
		r.set("ipmi.oem", vendor)
		if p, ok := ipmiOEMProduct[vendor]; ok {
			r.Product = p
		} else {
			r.Product = vendor + " BMC"
		}
	}

	info := "IPMI " + r.Version
	if authStatus&0x01 != 0 {
		info += ", anonymous login enabled"
	}
	if authStatus&0x02 != 0 {
		info += ", null user enabled"
	}
	r.ExtraInfo = sanitize(info)
	return r
}
