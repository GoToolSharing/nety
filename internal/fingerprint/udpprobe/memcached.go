package udpprobe

import (
	"strings"
)

// mcOpaque is the fixed, synthetic opaque value of the binary-protocol probe;
// memcached echoes it in the response header.
const mcOpaque uint32 = 0x4e455459 // "NETY"

// memcachedUDPFrameLen is the 8-byte UDP framing header memcached prepends on
// datagram transport: request id (2), sequence (2), total datagrams (2),
// reserved (2).
const memcachedUDPFrameLen = 8

// mcReqID is the UDP frame request id we send and verify.
const mcReqID uint16 = 0x4e45

// memcachedStatsPayload is the ASCII "stats" command, wrapped in the memcached
// UDP framing header that the server requires on port 11211/udp.
func memcachedStatsPayload() []byte {
	out := make([]byte, 0, memcachedUDPFrameLen+7)
	out = append(out, byte(mcReqID>>8), byte(mcReqID&0xff)) // request id
	out = append(out, 0x00, 0x00)                           // sequence number
	out = append(out, 0x00, 0x01)                           // total datagrams
	out = append(out, 0x00, 0x00)                           // reserved
	out = append(out, []byte("stats\r\n")...)
	return out
}

// memcachedVersionPayload is the binary-protocol VERSION command (opcode 0x0b)
// behind the same UDP framing header.
func memcachedVersionPayload() []byte {
	out := make([]byte, 0, memcachedUDPFrameLen+24)
	out = append(out, byte(mcReqID>>8), byte(mcReqID&0xff))
	out = append(out, 0x00, 0x00)
	out = append(out, 0x00, 0x01)
	out = append(out, 0x00, 0x00)
	hdr := make([]byte, 24)
	hdr[0] = 0x80 // magic: request
	hdr[1] = 0x0b // opcode: VERSION
	// key length, extras length, data type, vbucket and total body are zero.
	hdr[12] = byte(mcOpaque >> 24 & 0xff)
	hdr[13] = byte(mcOpaque >> 16 & 0xff)
	hdr[14] = byte(mcOpaque >> 8 & 0xff)
	hdr[15] = byte(mcOpaque & 0xff)
	return append(out, hdr...)
}

// stripMemcachedFrame removes the 8-byte UDP framing header when present.
func stripMemcachedFrame(resp []byte) ([]byte, bool) {
	if len(resp) < memcachedUDPFrameLen {
		return resp, false
	}
	id := uint16(resp[0])<<8 | uint16(resp[1])
	total := uint16(resp[4])<<8 | uint16(resp[5])
	reserved := uint16(resp[6])<<8 | uint16(resp[7])
	if reserved != 0 || total == 0 {
		return resp, false
	}
	return resp[memcachedUDPFrameLen:], id == mcReqID
}

// decodeMemcachedStats parses the ASCII "stats" output.
func decodeMemcachedStats(resp []byte) *Result {
	body, framed := stripMemcachedFrame(resp)
	if len(body) < 5 {
		return nil
	}
	text := string(body)
	if len(text) > 64*1024 {
		text = text[:64*1024]
	}
	if !strings.Contains(text, "STAT ") {
		if strings.HasPrefix(text, "ERROR") || strings.HasPrefix(text, "CLIENT_ERROR") ||
			strings.HasPrefix(text, "SERVER_ERROR") {
			r := newResult("memcached", 70)
			r.ExtraInfo = sanitize(strings.SplitN(text, "\r\n", 2)[0])
			return r
		}
		return nil
	}

	stats := make(map[string]string, 64)
	n := 0
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if n >= 256 {
			break
		}
		if !strings.HasPrefix(line, "STAT ") {
			continue
		}
		n++
		fields := strings.SplitN(strings.TrimSpace(line[5:]), " ", 2)
		if len(fields) != 2 {
			continue
		}
		if _, dup := stats[fields[0]]; !dup {
			stats[fields[0]] = fields[1]
		}
	}
	if len(stats) == 0 {
		return nil
	}

	r := newResult("memcached", 75)
	if framed && stats["pid"] != "" && stats["version"] != "" {
		r.Confidence = 90
	} else if stats["pid"] != "" && stats["version"] != "" {
		r.Confidence = 85
	}
	r.Product = "Memcached"
	memcachedStats(stats, r)
	return r
}

func memcachedStats(stats map[string]string, r *Result) {
	if v := stats["version"]; v != "" {
		r.Version = sanitize(v)
		r.set("memcached.version", v)
		if ver := firstVersion(v); ver != "" {
			r.addCPE("cpe:/a:memcached:memcached:" + ver)
		}
	}
	for key, extra := range map[string]string{
		"uptime":            "memcached.uptime",
		"pid":               "memcached.pid",
		"curr_connections":  "memcached.curr_connections",
		"pointer_size":      "memcached.pointer_size",
		"curr_items":        "memcached.curr_items",
		"total_connections": "memcached.total_connections",
		"threads":           "memcached.threads",
		"bytes":             "memcached.bytes",
		"limit_maxbytes":    "memcached.limit_maxbytes",
		"rusage_user":       "memcached.rusage_user",
	} {
		if v := stats[key]; v != "" {
			r.set(extra, v)
		}
	}
	if ps := stats["pointer_size"]; ps == "64" {
		r.ExtraInfo = "64-bit"
	} else if ps == "32" {
		r.ExtraInfo = "32-bit"
	}
	if r.ExtraInfo != "" && r.Version != "" {
		r.ExtraInfo = r.Version + ", " + r.ExtraInfo
	}
}

// decodeMemcachedVersion parses a binary-protocol VERSION response.
func decodeMemcachedVersion(resp []byte) *Result {
	body, framed := stripMemcachedFrame(resp)
	if len(body) < 24 {
		// A server with the binary protocol disabled answers the ASCII
		// "VERSION x.y.z" line instead.
		return decodeMemcachedASCIIVersion(resp)
	}
	if body[0] != 0x81 || body[1] != 0x0b {
		return decodeMemcachedASCIIVersion(resp)
	}
	keyLen := int(body[2])<<8 | int(body[3])
	extLen := int(body[4])
	status := uint16(body[6])<<8 | uint16(body[7])
	totalBody := uint32(body[8])<<24 | uint32(body[9])<<16 | uint32(body[10])<<8 | uint32(body[11])
	opaque := uint32(body[12])<<24 | uint32(body[13])<<16 | uint32(body[14])<<8 | uint32(body[15])

	if totalBody > 4096 || int(totalBody) < keyLen+extLen {
		return nil
	}
	r := newResult("memcached", 70)
	if opaque == mcOpaque {
		r.Confidence = 90
	}
	if !framed {
		r.Confidence -= 5
	}
	r.Product = "Memcached"
	r.set("memcached.protocol", "binary")
	if status != 0 {
		r.set("memcached.status", itoa(int(status)))
		return r
	}
	valOff := 24 + extLen + keyLen
	valEnd := 24 + int(totalBody)
	if valOff < len(body) && valEnd <= len(body) && valEnd > valOff {
		ver := sanitize(string(body[valOff:valEnd]))
		if ver != "" {
			r.Version = ver
			r.set("memcached.version", ver)
			if v := firstVersion(ver); v != "" {
				r.addCPE("cpe:/a:memcached:memcached:" + v)
			}
			r.ExtraInfo = ver
		}
	}
	return r
}

func decodeMemcachedASCIIVersion(resp []byte) *Result {
	body, framed := stripMemcachedFrame(resp)
	if len(body) < 9 {
		return nil
	}
	text := string(body)
	if len(text) > 256 {
		text = text[:256]
	}
	if !strings.HasPrefix(text, "VERSION ") {
		return nil
	}
	ver := sanitize(strings.SplitN(strings.TrimSpace(text[8:]), "\r", 2)[0])
	if ver == "" {
		return nil
	}
	r := newResult("memcached", 75)
	if framed {
		r.Confidence = 85
	}
	r.Product = "Memcached"
	r.Version = ver
	r.ExtraInfo = ver
	r.set("memcached.version", ver)
	r.set("memcached.protocol", "ascii")
	if v := firstVersion(ver); v != "" {
		r.addCPE("cpe:/a:memcached:memcached:" + v)
	}
	return r
}
