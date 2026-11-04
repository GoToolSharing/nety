package udpprobe

import (
	"strconv"
	"strings"
	"time"
)

// ntpXmt is the fixed, synthetic transmit timestamp placed in the client
// packet. A server copies it verbatim into the Originate Timestamp field of its
// reply, which is exactly the transaction id we verify. The value is a valid
// NTP timestamp (2021-06-10-ish) whose fraction spells "NETY".
var ntpXmt = [8]byte{0xe4, 0x6b, 0xa1, 0x50, 0x4e, 0x45, 0x54, 0x59}

// ntpCtlSeq is the fixed sequence number of the mode-6 control request, echoed
// by the server in its response.
const ntpCtlSeq uint16 = 0x4e45

// ntpEpochOffset converts an NTP era-0 timestamp to Unix seconds.
const ntpEpochOffset int64 = 2208988800

// ntpClientPayload is a hand-rolled 48-byte NTPv4 client packet (mode 3).
func ntpClientPayload() []byte {
	b := make([]byte, 48)
	b[0] = 0x23 // LI=0 (no warning), VN=4, Mode=3 (client)
	b[1] = 0    // stratum: unspecified
	b[2] = 0x06 // poll interval: 64 s
	b[3] = 0xec // precision: 2^-20 s
	copy(b[40:48], ntpXmt[:])
	return b
}

// ntpReadvarPayload is an NTPv2 mode-6 control message, opcode 2 (READVAR),
// association id 0 - the system variables of the daemon, which include the
// "version", "system" and "processor" strings.
func ntpReadvarPayload() []byte {
	b := make([]byte, 12)
	b[0] = 0x16 // LI=0, VN=2, Mode=6 (control)
	b[1] = 0x02 // R=0, E=0, M=0, opcode=2 (read variables)
	b[2] = byte(ntpCtlSeq >> 8)
	b[3] = byte(ntpCtlSeq & 0xff)
	// status, association id, offset and count are all zero.
	return b
}

// decodeNTPClient reads a mode-4 server reply to our client packet.
func decodeNTPClient(resp []byte) *Result {
	if len(resp) < 48 {
		return nil
	}
	li := resp[0] >> 6
	vn := (resp[0] >> 3) & 0x07
	mode := resp[0] & 0x07
	// 4 = server, 5 = broadcast, 2 = symmetric passive.
	if mode != 4 && mode != 5 && mode != 2 {
		return nil
	}
	if vn < 1 || vn > 4 {
		return nil
	}

	r := newResult("ntp", 60)
	// The originate timestamp must echo our transmit timestamp.
	if string(resp[24:32]) == string(ntpXmt[:]) {
		r.Confidence = 90
	}

	stratum := int(resp[1])
	r.set("ntp.leap", ntpLeapName(li))
	r.set("ntp.version", itoa(int(vn)))
	r.set("ntp.mode", ntpModeName(mode))
	r.set("ntp.stratum", itoa(stratum))
	r.set("ntp.poll", itoa(int(int8(resp[2]))))
	r.set("ntp.precision", itoa(int(int8(resp[3]))))
	r.set("ntp.root_delay", ntpShort(resp[4:8]))
	r.set("ntp.root_dispersion", ntpShort(resp[8:12]))
	r.set("ntp.refid", ntpRefID(resp[12:16], stratum))
	if ts := ntpTimestamp(resp[16:24]); ts != "" {
		r.set("ntp.reference_time", ts)
	}
	if ts := ntpTimestamp(resp[40:48]); ts != "" {
		r.set("ntp.transmit_time", ts)
	}

	switch {
	case stratum == 0:
		r.ExtraInfo = "kiss-of-death / unsynchronised"
	case stratum == 1:
		r.ExtraInfo = "stratum 1 (" + ntpRefID(resp[12:16], stratum) + ")"
	default:
		r.ExtraInfo = "stratum " + itoa(stratum)
	}
	r.Version = "NTPv" + itoa(int(vn))
	return r
}

func ntpLeapName(li byte) string {
	switch li {
	case 0:
		return "none"
	case 1:
		return "add-second"
	case 2:
		return "del-second"
	default:
		return "unsynchronised"
	}
}

func ntpModeName(m byte) string {
	switch m {
	case 1:
		return "symmetric-active"
	case 2:
		return "symmetric-passive"
	case 3:
		return "client"
	case 4:
		return "server"
	case 5:
		return "broadcast"
	case 6:
		return "control"
	case 7:
		return "private"
	default:
		return itoa(int(m))
	}
}

// ntpShort renders a 32-bit NTP short format (16.16 fixed point) in seconds.
func ntpShort(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return strconv.FormatFloat(float64(v)/65536.0, 'f', 6, 64)
}

// ntpRefID renders the reference identifier: four ASCII characters for stratum
// 0 and 1, an IPv4 address otherwise.
func ntpRefID(b []byte, stratum int) string {
	if len(b) < 4 {
		return ""
	}
	if stratum <= 1 {
		s := printableASCII(b[:4])
		if s != "" {
			return s
		}
		return hexStr(b[:4])
	}
	return itoa(int(b[0])) + "." + itoa(int(b[1])) + "." + itoa(int(b[2])) + "." + itoa(int(b[3]))
}

// ntpTimestamp renders a 64-bit NTP timestamp as RFC 3339 UTC. It returns ""
// for a zero timestamp and handles the era-1 wrap (dates past 2036).
func ntpTimestamp(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	secs := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	if secs == 0 {
		return ""
	}
	unix := int64(secs) - ntpEpochOffset
	if unix < 0 {
		// Era 1: timestamps that wrapped past 2036-02-07.
		unix += 1 << 32
	}
	// Reject anything outside a sane window rather than printing year 2106.
	if unix < 0 || unix > 1<<34 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

// decodeNTPReadvar reads a mode-6 control response and parses its variable list.
func decodeNTPReadvar(resp []byte) *Result {
	if len(resp) < 12 {
		return nil
	}
	if resp[0]&0x07 != 6 { // mode 6: control
		return nil
	}
	vn := (resp[0] >> 3) & 0x07
	if vn < 1 || vn > 4 {
		return nil
	}
	flags := resp[1]
	if flags&0x80 == 0 { // response bit must be set
		return nil
	}
	opcode := flags & 0x1f
	if opcode != 2 { // READVAR
		return nil
	}
	seq, _ := u16(resp, 2)
	count, _ := u16(resp, 10)
	offset, _ := u16(resp, 8)

	r := newResult("ntp", 65)
	if seq == ntpCtlSeq {
		r.Confidence = 90
	}
	r.set("ntp.version", itoa(int(vn)))
	r.set("ntp.mode", "control")
	if flags&0x40 != 0 {
		r.set("ntp.control_error", "true")
		r.ExtraInfo = "mode 6 control enabled (error response)"
		return r
	}

	// Payload starts at 12 and is `count` bytes long; both must be sane.
	end := 12 + int(count)
	if int(offset) != 0 || end > len(resp) {
		end = len(resp)
	}
	if end < 12 {
		return r
	}
	vars := parseNTPVars(resp[12:end])
	r.ExtraInfo = "mode 6 control enabled"

	if v := vars["version"]; v != "" {
		r.set("ntp.version_string", v)
		ntpVersionFingerprint(v, r)
	}
	if v := vars["system"]; v != "" {
		r.set("ntp.system", v)
		switch {
		case containsFold(v, "Linux"):
			r.OSType = "Linux"
		case containsFold(v, "FreeBSD"):
			r.OSType = "FreeBSD"
		case containsFold(v, "Darwin"):
			r.OSType = "macOS"
		case containsFold(v, "Windows"):
			r.OSType = "Windows"
		case containsFold(v, "SunOS") || containsFold(v, "Solaris"):
			r.OSType = "Solaris"
		case containsFold(v, "Cisco"):
			r.OSType = "IOS"
		}
	}
	for _, k := range []string{"processor", "stratum", "refid", "leap", "clock", "peer", "rootdelay", "rootdisp"} {
		if v := vars[k]; v != "" {
			r.set("ntp."+k, v)
		}
	}
	return r
}

// ntpVersionFingerprint parses an ntpd "version" variable, e.g.
// "ntpd 4.2.8p15@1.3728-o Wed Sep 23 11:46:38 UTC 2020 (1)".
func ntpVersionFingerprint(v string, r *Result) {
	switch {
	case containsFold(v, "ntpd"):
		r.Product = "NTP ntpd"
		r.Version = versionAfter(v, "ntpd")
		if r.Version == "" {
			r.Version = firstVersion(v)
		}
		if r.Version != "" {
			r.addCPE("cpe:/a:ntp:ntp:" + r.Version)
		}
	case containsFold(v, "chrony"):
		r.Product = "chrony"
		r.Version = firstVersion(v)
		if r.Version != "" {
			r.addCPE("cpe:/a:tuxfamily:chrony:" + r.Version)
		}
	case containsFold(v, "Cisco"):
		r.Product = "Cisco NTP"
		r.Version = firstVersion(v)
	default:
		r.Product = "NTP"
		r.Version = firstVersion(v)
	}
}

const maxNTPVars = 64

// parseNTPVars splits a mode-6 variable list: comma separated name=value pairs
// where values may be quoted. Bounded at maxNTPVars entries.
func parseNTPVars(b []byte) map[string]string {
	out := make(map[string]string, 16)
	s := string(b)
	if len(s) > 8192 {
		s = s[:8192]
	}
	n := 0
	for _, part := range strings.Split(s, ",") {
		if n >= maxNTPVars {
			break
		}
		part = strings.TrimSpace(strings.ReplaceAll(part, "\r\n", " "))
		if part == "" {
			continue
		}
		idx := strings.IndexByte(part, '=')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:idx]))
		val := strings.TrimSpace(part[idx+1:])
		val = strings.Trim(val, "\"")
		if key == "" || val == "" {
			continue
		}
		n++
		if _, dup := out[key]; !dup {
			out[key] = sanitize(val)
		}
	}
	return out
}
