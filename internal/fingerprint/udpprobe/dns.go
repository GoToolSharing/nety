package udpprobe

import (
	"strings"

	"github.com/miekg/dns"
)

// Fixed, synthetic transaction ids. They are verified by the matching decoder,
// which is what justifies a confidence of 90 on a successful decode. They are
// all distinct so a response to one probe cannot be mistaken for another.
const (
	dnsVersionBindID uint16 = 0x4e01
	dnsStatusID      uint16 = 0x4e02
	// mDNS responders are allowed to answer with id 0 (RFC 6762 §18.1), so the
	// query uses 0 and the decoder accepts 0 or the echoed value.
	mdnsID uint16 = 0x0000
)

// maxDNSRecords caps how many records any DNS decoder walks.
const maxDNSRecords = 64

func packQuery(id uint16, rd bool, name string, qtype, qclass uint16) []byte {
	m := new(dns.Msg)
	m.Id = id
	m.RecursionDesired = rd
	m.Question = []dns.Question{{Name: name, Qtype: qtype, Qclass: qclass}}
	b, err := m.Pack()
	if err != nil {
		// Cannot happen for the literal names below; fall back to an empty
		// payload rather than panicking at package init.
		return nil
	}
	return b
}

// dnsVersionBindPayload is a TXT query for version.bind. in class CHAOS with
// RD=0 - the classic name-server version question.
func dnsVersionBindPayload() []byte {
	return packQuery(dnsVersionBindID, false, "version.bind.", dns.TypeTXT, dns.ClassCHAOS)
}

// dnsStatusPayload is a plain IN query (SOA for the root) so a resolver that
// blocks or refuses CHAOS still identifies itself, and so we learn whether
// recursion is available.
func dnsStatusPayload() []byte {
	return packQuery(dnsStatusID, true, ".", dns.TypeSOA, dns.ClassINET)
}

// mdnsPayload is the multicast-DNS service enumeration query. The unicast
// response bit (QU, 0x8000 in QCLASS) is set so a directed unicast query gets a
// directed unicast answer.
func mdnsPayload() []byte {
	return packQuery(mdnsID, false, "_services._dns-sd._udp.local.", dns.TypePTR, dns.ClassINET|0x8000)
}

// dnsHeaderView is a bounds-checked peek at the 12-byte DNS header, used when
// full unpacking fails but the response still looks like DNS.
type dnsHeaderView struct {
	id     uint16
	qr     bool
	opcode int
	aa     bool
	tc     bool
	rd     bool
	ra     bool
	rcode  int
	qd     uint16
	an     uint16
}

func parseDNSHeader(b []byte) (dnsHeaderView, bool) {
	var h dnsHeaderView
	if len(b) < 12 {
		return h, false
	}
	h.id = uint16(b[0])<<8 | uint16(b[1])
	flags := uint16(b[2])<<8 | uint16(b[3])
	h.qr = flags&0x8000 != 0
	h.opcode = int(flags>>11) & 0x0f
	h.aa = flags&0x0400 != 0
	h.tc = flags&0x0200 != 0
	h.rd = flags&0x0100 != 0
	h.ra = flags&0x0080 != 0
	h.rcode = int(flags & 0x0f)
	h.qd = uint16(b[4])<<8 | uint16(b[5])
	h.an = uint16(b[6])<<8 | uint16(b[7])
	return h, true
}

func rcodeName(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return itoa(rcode)
}

func opcodeName(op int) string {
	if s, ok := dns.OpcodeToString[op]; ok {
		return s
	}
	return itoa(op)
}

// decodeDNSVersionBind reads the answer to the version.bind CHAOS TXT query.
func decodeDNSVersionBind(resp []byte) *Result {
	h, ok := parseDNSHeader(resp)
	if !ok || !h.qr || h.id != dnsVersionBindID {
		return nil
	}
	r := newResult("domain", 70)
	r.set("dns.rcode", rcodeName(h.rcode))
	r.setBool("dns.recursion_available", h.ra)
	if h.tc {
		r.setBool("dns.truncated", true)
	}

	var version string
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err == nil {
		n := 0
		var parts []string
		for _, rr := range msg.Answer {
			if n >= maxDNSRecords {
				break
			}
			n++
			txt, okTXT := rr.(*dns.TXT)
			if !okTXT {
				continue
			}
			for _, t := range txt.Txt {
				if t != "" {
					parts = append(parts, t)
				}
			}
		}
		version = sanitize(strings.Join(parts, " "))
	}

	if version != "" {
		r.Confidence = 90
		r.set("dns.version", version)
		r.ExtraInfo = version
		dnsFingerprint(version, r)
		return r
	}

	// The server answered but gave us no version string: REFUSED, NOTIMP,
	// SERVFAIL or an empty NOERROR. Still a name server, just less certain.
	switch h.rcode {
	case dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeServerFailure, dns.RcodeNameError:
		r.Confidence = 75
		r.ExtraInfo = "version.bind " + strings.ToLower(rcodeName(h.rcode))
	default:
		r.Confidence = 70
	}
	return r
}

// decodeDNSStatus reads the answer to the plain IN query.
func decodeDNSStatus(resp []byte) *Result {
	h, ok := parseDNSHeader(resp)
	if !ok || !h.qr || h.id != dnsStatusID {
		return nil
	}
	r := newResult("domain", 90)
	r.set("dns.rcode", rcodeName(h.rcode))
	r.set("dns.opcode", opcodeName(h.opcode))
	r.setBool("dns.recursion_available", h.ra)
	r.setBool("dns.authoritative", h.aa)
	r.set("dns.answer_count", itoa(int(h.an)))
	if h.tc {
		r.setBool("dns.truncated", true)
	}
	if h.ra {
		r.ExtraInfo = "recursive resolver"
	}
	return r
}

// dnsFingerprint maps a version.bind banner onto product/version/CPE.
func dnsFingerprint(v string, r *Result) {
	switch {
	case containsFold(v, "dnsmasq"):
		r.Product = "dnsmasq"
		r.Version = versionAfter(v, "dnsmasq")
		if r.Version == "" {
			r.Version = firstVersion(v)
		}
		if r.Version != "" {
			r.addCPE("cpe:/a:thekelleys:dnsmasq:" + r.Version)
		}
	case containsFold(v, "PowerDNS") || containsFold(v, "pdns"):
		r.Product = "PowerDNS"
		if containsFold(v, "Recursor") {
			r.Product = "PowerDNS Recursor"
		} else if containsFold(v, "Authoritative") {
			r.Product = "PowerDNS Authoritative Server"
		}
		r.Version = firstVersion(v)
		if r.Version != "" {
			if r.Product == "PowerDNS Recursor" {
				r.addCPE("cpe:/a:powerdns:recursor:" + r.Version)
			} else {
				r.addCPE("cpe:/a:powerdns:authoritative_server:" + r.Version)
			}
		}
	case containsFold(v, "Microsoft DNS"):
		r.Product = "Microsoft DNS"
		r.OSType = "Windows"
		r.Version = versionAfter(v, "Microsoft DNS")
		if r.Version != "" {
			r.addCPE("cpe:/a:microsoft:dns:" + r.Version)
		}
		r.addCPE("cpe:/o:microsoft:windows")
	case containsFold(v, "unbound"):
		r.Product = "Unbound"
		r.Version = versionAfter(v, "unbound")
		if r.Version == "" {
			r.Version = firstVersion(v)
		}
		if r.Version != "" {
			r.addCPE("cpe:/a:nlnetlabs:unbound:" + r.Version)
		}
	case containsFold(v, "Knot"):
		if containsFold(v, "Resolver") {
			r.Product = "Knot Resolver"
		} else {
			r.Product = "Knot DNS"
		}
		r.Version = firstVersion(v)
		if r.Version != "" {
			r.addCPE("cpe:/a:nic:knot_dns:" + r.Version)
		}
	case containsFold(v, "CoreDNS"):
		r.Product = "CoreDNS"
		r.Version = versionAfter(v, "CoreDNS")
		if r.Version == "" {
			r.Version = firstVersion(v)
		}
		if r.Version != "" {
			r.addCPE("cpe:/a:coredns:coredns:" + r.Version)
		}
	case containsFold(v, "NSD"):
		r.Product = "NLnet Labs NSD"
		r.Version = firstVersion(v)
		if r.Version != "" {
			r.addCPE("cpe:/a:nlnetlabs:nsd:" + r.Version)
		}
	case containsFold(v, "Nominum") || containsFold(v, "Vantio"):
		r.Product = "Nominum Vantio"
		r.Version = firstVersion(v)
	case containsFold(v, "BIND"):
		r.Product = "ISC BIND"
		r.Version = versionAfter(v, "BIND")
		if r.Version == "" {
			r.Version = firstVersion(v)
		}
		if r.Version != "" {
			r.addCPE("cpe:/a:isc:bind:" + r.Version)
		}
	default:
		// A bare dotted version is overwhelmingly BIND: that is what
		// `version.bind` historically returns, e.g. "9.16.1-Ubuntu".
		if ver := firstVersion(v); ver != "" && strings.HasPrefix(strings.TrimSpace(v), ver) {
			r.Product = "ISC BIND"
			r.Version = ver
			r.addCPE("cpe:/a:isc:bind:" + ver)
		}
	}
	if r.OSType == "" {
		switch {
		case containsFold(v, "Ubuntu") || containsFold(v, "Debian") ||
			containsFold(v, "Red Hat") || containsFold(v, "RedHat") ||
			containsFold(v, "CentOS") || containsFold(v, "Fedora"):
			r.OSType = "Linux"
		case containsFold(v, "FreeBSD"):
			r.OSType = "FreeBSD"
		}
	}
}

// decodeMDNS reads the answer to the _services._dns-sd._udp.local. query.
func decodeMDNS(resp []byte) *Result {
	h, ok := parseDNSHeader(resp)
	if !ok || !h.qr {
		return nil
	}
	// mDNS responders answer with id 0 or echo ours (which is also 0).
	if h.id != mdnsID {
		return nil
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		return nil
	}

	var (
		services []string
		hostname string
		model    string
		local    bool
		seen     = make(map[string]bool, 16)
		n        int
	)
	walk := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if n >= maxDNSRecords {
				return
			}
			n++
			hdr := rr.Header()
			if hdr == nil {
				continue
			}
			if strings.HasSuffix(strings.ToLower(hdr.Name), ".local.") {
				local = true
			}
			switch v := rr.(type) {
			case *dns.PTR:
				name := strings.TrimSuffix(v.Ptr, ".")
				if name != "" && !seen[name] {
					seen[name] = true
					services = append(services, name)
				}
			case *dns.SRV:
				if hostname == "" {
					hostname = strings.TrimSuffix(v.Target, ".")
				}
			case *dns.A:
				if hostname == "" {
					hostname = strings.TrimSuffix(hdr.Name, ".")
				}
			case *dns.AAAA:
				if hostname == "" {
					hostname = strings.TrimSuffix(hdr.Name, ".")
				}
			case *dns.TXT:
				for _, t := range v.Txt {
					lt := strings.ToLower(t)
					switch {
					case model == "" && strings.HasPrefix(lt, "md="):
						model = t[3:]
					case model == "" && strings.HasPrefix(lt, "model="):
						model = t[6:]
					case model == "" && strings.HasPrefix(lt, "ty="):
						model = t[3:]
					case model == "" && strings.HasPrefix(lt, "usb_mdl="):
						model = t[8:]
					}
				}
			}
		}
	}
	walk(msg.Answer)
	walk(msg.Ns)
	walk(msg.Extra)

	if len(services) == 0 && hostname == "" && model == "" {
		if len(msg.Question) == 0 {
			return nil
		}
	}

	r := newResult("mdns", 60)
	if local && (len(services) > 0 || hostname != "") {
		r.Confidence = 90
	}
	r.set("mdns.services", joinCapped(services))
	r.set("mdns.hostname", hostname)
	r.set("mdns.model", model)
	r.set("mdns.service_count", itoa(len(services)))

	joined := strings.ToLower(strings.Join(services, ","))
	switch {
	case strings.Contains(joined, "_googlecast."):
		r.Product = "Google Chromecast"
	case strings.Contains(joined, "_airplay.") || strings.Contains(joined, "_raop.") ||
		strings.Contains(joined, "_companion-link.") || strings.Contains(joined, "_airport."):
		r.Product = "Apple device"
		r.OSType = "Apple"
	case strings.Contains(joined, "_ipp.") || strings.Contains(joined, "_ipps.") ||
		strings.Contains(joined, "_pdl-datastream.") || strings.Contains(joined, "_printer.") ||
		strings.Contains(joined, "_scanner."):
		r.Product = "Network printer"
	case strings.Contains(joined, "_smb.") || strings.Contains(joined, "_workstation."):
		r.Product = "mDNS responder"
	case strings.Contains(joined, "_spotify-connect."):
		r.Product = "Spotify Connect device"
	case strings.Contains(joined, "_hap."):
		r.Product = "HomeKit accessory"
	}
	if model != "" {
		r.ExtraInfo = sanitize(model)
		switch {
		case strings.HasPrefix(model, "MacBook") || strings.HasPrefix(model, "iMac") ||
			strings.HasPrefix(model, "Macmini") || strings.HasPrefix(model, "MacPro"):
			r.OSType = "macOS"
			r.Product = "Apple " + model
		case strings.HasPrefix(model, "AppleTV"):
			r.OSType = "Apple"
			r.Product = "Apple TV"
		}
	} else if hostname != "" {
		r.ExtraInfo = sanitize(hostname)
	}
	return r
}
