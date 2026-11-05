package udpprobe

import "strings"

// nbnsID is the fixed, synthetic NetBIOS transaction id, verified on decode.
const nbnsID uint16 = 0x4e03

// maxNBNames caps the node-status name table.
const maxNBNames = 256

// netbiosPayload is the NBSTAT node status request for the "*" wildcard name.
func netbiosPayload() []byte {
	b := make([]byte, 0, 50)
	b = append(b, byte(nbnsID>>8), byte(nbnsID&0xff)) // transaction id
	b = append(b, 0x00, 0x00)                         // flags: query, no recursion
	b = append(b, 0x00, 0x01)                         // qdcount = 1
	b = append(b, 0x00, 0x00)                         // ancount
	b = append(b, 0x00, 0x00)                         // nscount
	b = append(b, 0x00, 0x00)                         // arcount
	// QNAME: first-level encoded "*" padded to 16 bytes with NULs.
	name := make([]byte, 16)
	name[0] = '*'
	b = append(b, 0x20) // label length: 32 encoded characters
	for _, c := range name {
		b = append(b, 'A'+(c>>4), 'A'+(c&0x0f))
	}
	b = append(b, 0x00)       // root label
	b = append(b, 0x00, 0x21) // QTYPE = NBSTAT
	b = append(b, 0x00, 0x01) // QCLASS = IN
	return b
}

// skipNBName walks a (possibly compressed) NetBIOS name at off and returns the offset
// just past it.
func skipNBName(b []byte, off int) (int, bool) {
	for i := 0; i < 8; i++ { // bounded: at most 8 labels
		if off < 0 || off >= len(b) {
			return 0, false
		}
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xc0 == 0xc0: // compression pointer
			if off+2 > len(b) {
				return 0, false
			}
			return off + 2, true
		case l&0xc0 != 0:
			return 0, false
		default:
			off += 1 + l
		}
	}
	return 0, false
}

type nbName struct {
	name   string
	suffix byte
	group  bool
	active bool
}

// decodeNetBIOS reads a NBSTAT node status response.
func decodeNetBIOS(resp []byte) *Result {
	if len(resp) < 12 {
		return nil
	}
	id, _ := u16(resp, 0)
	if id != nbnsID {
		return nil
	}
	flags, _ := u16(resp, 2)
	if flags&0x8000 == 0 { // must be a response
		return nil
	}
	qd, _ := u16(resp, 4)
	an, _ := u16(resp, 6)
	if an == 0 {
		return nil
	}

	off := 12
	// Skip the echoed question section, if any.
	for i := 0; i < int(qd) && i < 4; i++ {
		next, ok := skipNBName(resp, off)
		if !ok || next+4 > len(resp) {
			return nil
		}
		off = next + 4
	}

	// Answer record.
	next, ok := skipNBName(resp, off)
	if !ok {
		return nil
	}
	off = next
	rrType, ok := u16(resp, off)
	if !ok {
		return nil
	}
	if rrType != 0x0021 { // NBSTAT
		return nil
	}
	rdLen, ok := u16(resp, off+8)
	if !ok {
		return nil
	}
	off += 10
	if off >= len(resp) {
		return nil
	}
	end := off + int(rdLen)
	if end > len(resp) || rdLen == 0 {
		end = len(resp)
	}
	rdata := resp[off:end]
	if len(rdata) < 1 {
		return nil
	}

	numNames := int(rdata[0])
	if numNames > maxNBNames {
		numNames = maxNBNames
	}
	if avail := (len(rdata) - 1) / 18; numNames > avail {
		numNames = avail
	}

	r := newResult("netbios-ns", 90)

	names := make([]nbName, 0, numNames)
	for i := 0; i < numNames; i++ {
		base := 1 + i*18
		raw := rdata[base : base+16]
		nf := uint16(rdata[base+16])<<8 | uint16(rdata[base+17])
		n := nbName{
			name:   strings.TrimRight(printableASCII(raw[:15]), " "),
			suffix: raw[15],
			group:  nf&0x8000 != 0,
			active: nf&0x0400 != 0,
		}
		if n.name == "" {
			continue
		}
		names = append(names, n)
	}
	if len(names) == 0 {
		r.Confidence = 70
	}

	var (
		all      []string
		unique   []string
		computer string
		server   string
		domain   string
		user     string
		hasDC    bool
		hasPDC   bool
		browser  bool
	)
	for _, n := range names {
		label := n.name + "<" + hexByte(n.suffix) + ">"
		all = append(all, label)
		if !n.group {
			unique = append(unique, label)
		}
		switch {
		case strings.HasPrefix(n.name, "\x01\x02__MSBROWSE__") || strings.Contains(n.name, "__MSBROWSE__"):
			browser = true
		case n.suffix == 0x00 && !n.group && computer == "":
			computer = n.name
		case n.suffix == 0x20 && !n.group:
			if server == "" {
				server = n.name
			}
		case n.suffix == 0x00 && n.group && domain == "":
			domain = n.name
		case n.suffix == 0x1c && n.group:
			hasDC = true
			domain = n.name
		case n.suffix == 0x1b && !n.group:
			hasPDC = true
			if domain == "" {
				domain = n.name
			}
		case n.suffix == 0x03 && !n.group && user == "":
			user = n.name
		}
	}
	if computer == "" {
		computer = server
	}

	r.set("netbios.name", computer)
	r.set("netbios.domain", domain)
	r.set("netbios.names", joinCapped(all))
	r.set("netbios.unique", joinCapped(unique))
	r.set("netbios.name_count", itoa(len(names)))
	if user != "" && user != computer {
		r.set("netbios.user", user)
	}
	if server != "" {
		r.setBool("netbios.server", true)
	}
	if hasDC {
		r.setBool("netbios.domain_controller", true)
	}
	if hasPDC {
		r.setBool("netbios.pdc", true)
	}
	if browser {
		r.setBool("netbios.master_browser", true)
	}

	// Adapter statistics follow the name table: the first 6 bytes are the unit id, i.e.
	// the adapter MAC.
	macOff := 1 + len(names)*18
	zeroMAC := true
	if macOff+6 <= len(rdata) {
		mac := rdata[macOff : macOff+6]
		for _, c := range mac {
			if c != 0 {
				zeroMAC = false
				break
			}
		}
		if !zeroMAC {
			r.set("netbios.mac", formatMAC(mac))
		} else {
			r.set("netbios.mac", "00:00:00:00:00:00")
		}
	}

	// Samba reports an all-zero adapter address; a real Windows NetBIOS stack reports the
	// NIC MAC. That, plus the Windows-specific suffixes, is the usual way to tell them
	// apart.
	windowsish := hasDC || hasPDC || server != "" || browser
	switch {
	case !zeroMAC && windowsish:
		r.OSType = "Windows"
		r.Product = "Microsoft Windows netbios-ssn"
		r.addCPE("cpe:/o:microsoft:windows")
	case zeroMAC && windowsish:
		r.Product = "Samba nmbd"
		r.OSType = "Unix"
		r.addCPE("cpe:/a:samba:samba")
	}

	switch {
	case hasPDC:
		r.ExtraInfo = computer + ", domain master browser for " + domain
	case hasDC:
		r.ExtraInfo = computer + ", domain controller for " + domain
	case domain != "":
		r.ExtraInfo = computer + ", workgroup " + domain
	default:
		r.ExtraInfo = computer
	}
	r.ExtraInfo = sanitize(r.ExtraInfo)
	return r
}

func hexByte(b byte) string {
	const hexDigits = "0123456789abcdef"
	return string([]byte{hexDigits[b>>4], hexDigits[b&0x0f]})
}
