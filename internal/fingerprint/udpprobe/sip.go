package udpprobe

import "strings"

// Fixed, obviously synthetic SIP identities. The Call-ID is echoed by every
// conformant UA in its response, which is the transaction id we verify. No part
// of this looks like a real user or a real domain: "invalid" is the reserved
// never-resolvable TLD of RFC 2606.
const (
	sipCallID = "nety-probe-0000000000@probe.invalid"
	sipBranch = "z9hG4bK-nety-probe-00000001"
	sipTag    = "netyprobe00000001"
	sipURI    = "sip:nety-probe@probe.invalid"
)

// sipPayload is a SIP OPTIONS request. Servers answer it with 200 OK (or
// 404/405/483), and the response headers carry the product banner, the
// supported methods and the extensions.
func sipPayload() []byte {
	req := "OPTIONS " + sipURI + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP probe.invalid:5060;branch=" + sipBranch + ";rport\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: \"NETY Probe\" <" + sipURI + ">;tag=" + sipTag + "\r\n" +
		"To: <" + sipURI + ">\r\n" +
		"Call-ID: " + sipCallID + "\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Contact: <" + sipURI + ":5060>\r\n" +
		"User-Agent: NETY-Probe\r\n" +
		"Accept: application/sdp\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	return []byte(req)
}

// decodeSIP reads a SIP response (or an inbound request, which some gateways
// send instead).
func decodeSIP(resp []byte) *Result {
	if len(resp) < 12 {
		return nil
	}
	start, hdrs := headerValues(resp, 96)
	isStatus := strings.HasPrefix(start, "SIP/2.0 ")
	isRequest := strings.HasSuffix(start, " SIP/2.0")
	if !isStatus && !isRequest {
		return nil
	}

	r := newResult("sip", 60)
	if isStatus {
		code := ""
		text := ""
		rest := start[len("SIP/2.0 "):]
		if i := strings.IndexByte(rest, ' '); i > 0 {
			code, text = rest[:i], rest[i+1:]
		} else {
			code = rest
		}
		if len(code) != 3 || code[0] < '1' || code[0] > '6' {
			return nil
		}
		for _, c := range []byte(code) {
			if c < '0' || c > '9' {
				return nil
			}
		}
		r.set("sip.status", code)
		r.set("sip.status_text", text)
		r.Confidence = 70
		if hdrs["call-id"] == sipCallID {
			r.Confidence = 90
		}
	} else {
		// An inbound request: still unmistakably SIP, but not our transaction.
		if i := strings.IndexByte(start, ' '); i > 0 {
			r.set("sip.request", start[:i])
		}
		r.Confidence = 70
	}

	for _, kv := range []struct{ hdr, key string }{
		{"server", "sip.server"},
		{"user-agent", "sip.user_agent"},
		{"allow", "sip.allow"},
		{"supported", "sip.supported"},
		{"accept", "sip.accept"},
		{"warning", "sip.warning"},
		{"allow-events", "sip.allow_events"},
		{"organization", "sip.organization"},
		{"contact", "sip.contact"},
	} {
		if v := hdrs[kv.hdr]; v != "" {
			r.set(kv.key, v)
		}
	}

	banner := hdrs["server"]
	if banner == "" {
		banner = hdrs["user-agent"]
	}
	if banner != "" {
		r.ExtraInfo = banner
		sipFingerprint(banner, r)
	}
	return r
}

// sipFingerprint maps a Server/User-Agent banner onto product/version/CPE.
func sipFingerprint(b string, r *Result) {
	switch {
	case containsFold(b, "Asterisk"):
		r.Product = "Asterisk"
		r.Version = versionAfter(b, "Asterisk PBX")
		if r.Version == "" {
			r.Version = versionAfter(b, "Asterisk")
		}
		if r.Version != "" {
			r.addCPE("cpe:/a:digium:asterisk:" + r.Version)
		}
		r.OSType = "Linux"
	case containsFold(b, "FreeSWITCH"):
		r.Product = "FreeSWITCH"
		r.Version = firstVersion(b)
		if r.Version != "" {
			r.addCPE("cpe:/a:freeswitch:freeswitch:" + r.Version)
		}
		r.OSType = "Linux"
	case containsFold(b, "kamailio") || containsFold(b, "OpenSER"):
		r.Product = "Kamailio"
		r.Version = firstVersion(b)
		if r.Version != "" {
			r.addCPE("cpe:/a:kamailio:kamailio:" + r.Version)
		}
		r.OSType = "Linux"
	case containsFold(b, "OpenSIPS"):
		r.Product = "OpenSIPS"
		r.Version = firstVersion(b)
		if r.Version != "" {
			r.addCPE("cpe:/a:opensips:opensips:" + r.Version)
		}
		r.OSType = "Linux"
	case containsFold(b, "Cisco-SIPGateway") || containsFold(b, "Cisco-CUCM") ||
		containsFold(b, "CUCM") || containsFold(b, "Cisco-SIP"):
		r.Product = "Cisco Unified Communications Manager"
		if containsFold(b, "SIPGateway") {
			r.Product = "Cisco SIP Gateway"
			r.OSType = "IOS"
		}
		r.Version = firstVersion(b)
	case containsFold(b, "Avaya"):
		r.Product = "Avaya SIP"
		r.Version = firstVersion(b)
	case containsFold(b, "3CX"):
		r.Product = "3CX Phone System"
		r.Version = firstVersion(b)
	case containsFold(b, "Grandstream"):
		r.Product = "Grandstream device"
		r.Version = firstVersion(b)
		r.OSType = "embedded"
	case containsFold(b, "Yealink"):
		r.Product = "Yealink phone"
		r.Version = firstVersion(b)
		r.OSType = "embedded"
	case containsFold(b, "Polycom"):
		r.Product = "Polycom phone"
		r.Version = firstVersion(b)
		r.OSType = "embedded"
	case containsFold(b, "Snom"):
		r.Product = "Snom phone"
		r.Version = firstVersion(b)
		r.OSType = "embedded"
	case containsFold(b, "Mitel"):
		r.Product = "Mitel SIP"
		r.Version = firstVersion(b)
	case containsFold(b, "Sipwise") || containsFold(b, "sip-router"):
		r.Product = "SIP Router"
		r.Version = firstVersion(b)
	case containsFold(b, "FPBX") || containsFold(b, "FreePBX"):
		r.Product = "FreePBX"
		r.Version = firstVersion(b)
		r.OSType = "Linux"
	default:
		name, ver := splitSlashVersion(b)
		if name != "" && ver != "" {
			r.Product = sanitize(name)
			r.Version = sanitize(ver)
		}
	}
	if r.Version == "" {
		r.Version = firstVersion(b)
	}
}
