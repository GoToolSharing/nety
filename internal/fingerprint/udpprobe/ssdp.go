package udpprobe

import "strings"

// ssdpPayload is a unicast M-SEARCH for every device type. MX is kept at 1 so a
// compliant device answers almost immediately.
func ssdpPayload() []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"USER-AGENT: NETY/1.0 UPnP/1.1 NETY-Probe/1.0\r\n" +
		"\r\n")
}

// decodeSSDP reads an SSDP M-SEARCH response (or an unsolicited NOTIFY).
func decodeSSDP(resp []byte) *Result {
	if len(resp) < 12 {
		return nil
	}
	start, hdrs := headerValues(resp, 64)
	upper := strings.ToUpper(start)
	isResponse := strings.HasPrefix(upper, "HTTP/1.1 200") || strings.HasPrefix(upper, "HTTP/1.0 200")
	isNotify := strings.HasPrefix(upper, "NOTIFY * HTTP/1.")
	isSearch := strings.HasPrefix(upper, "M-SEARCH * HTTP/1.")
	if !isResponse && !isNotify {
		return nil
	}
	if isSearch {
		return nil
	}
	// An SSDP answer is identified by its mandatory headers; a bare HTTP 200
	// with none of them is some other service.
	_, hasUSN := hdrs["usn"]
	_, hasST := hdrs["st"]
	_, hasNT := hdrs["nt"]
	_, hasLoc := hdrs["location"]
	_, hasServer := hdrs["server"]
	if !hasUSN && !hasST && !hasNT && !hasLoc {
		return nil
	}

	r := newResult("upnp", 60)
	if (hasUSN || hasNT) && (hasLoc || hasServer) {
		r.Confidence = 90
	} else if hasUSN || hasST {
		r.Confidence = 80
	}
	r.set("upnp.server", hdrs["server"])
	r.set("upnp.location", hdrs["location"])
	r.set("upnp.st", hdrs["st"])
	r.set("upnp.nt", hdrs["nt"])
	r.set("upnp.usn", hdrs["usn"])
	r.set("upnp.cache_control", hdrs["cache-control"])
	// Vendor extensions that frequently carry a model name.
	for _, k := range []string{"x-user-agent", "bootid.upnp.org", "configid.upnp.org", "opt", "01-nls"} {
		if v := hdrs[k]; v != "" {
			r.set("upnp."+strings.ReplaceAll(k, "-", "_"), v)
		}
	}
	if isNotify {
		r.set("upnp.notify", "true")
	}

	server := hdrs["server"]
	if server != "" {
		r.ExtraInfo = server
		ssdpFingerprint(server, r)
	} else if usn := hdrs["usn"]; usn != "" {
		r.ExtraInfo = usn
	}
	return r
}

// ssdpFingerprint parses an SSDP SERVER header, which is conventionally
// "<OS>/<ver> UPnP/<ver> <product>/<ver>".
func ssdpFingerprint(server string, r *Result) {
	fields := strings.Fields(server)
	if len(fields) > 8 {
		fields = fields[:8]
	}
	// The OS token comes first.
	if len(fields) > 0 {
		os := fields[0]
		switch {
		case containsFold(os, "Linux"):
			r.OSType = "Linux"
		case containsFold(os, "Windows"):
			r.OSType = "Windows"
		case containsFold(os, "Darwin"):
			r.OSType = "macOS"
		case containsFold(os, "FreeBSD"):
			r.OSType = "FreeBSD"
		}
	}
	// The product is whatever follows the UPnP/x.y token.
	for i, f := range fields {
		if strings.HasPrefix(strings.ToUpper(f), "UPNP/") && i+1 < len(fields) {
			prod := strings.Join(fields[i+1:], " ")
			name, ver := splitSlashVersion(prod)
			r.Product = sanitize(name)
			r.Version = sanitize(ver)
			break
		}
	}
	if r.Product == "" {
		name, ver := splitSlashVersion(server)
		r.Product = sanitize(name)
		r.Version = sanitize(ver)
	}

	switch {
	case containsFold(server, "Portable SDK for UPnP"):
		r.Product = "Portable SDK for UPnP devices"
		r.Version = versionAfter(server, "Portable SDK for UPnP devices/")
		r.addCPE("cpe:/a:pupnp_project:pupnp:" + r.Version)
	case containsFold(server, "MiniUPnPd"):
		r.Product = "MiniUPnP daemon"
		r.Version = versionAfter(server, "MiniUPnPd/")
		r.addCPE("cpe:/a:miniupnp_project:miniupnpd:" + r.Version)
	case containsFold(server, "Microsoft-Windows"):
		r.Product = "Microsoft Windows UPnP"
		r.OSType = "Windows"
		r.addCPE("cpe:/o:microsoft:windows")
	case containsFold(server, "Sonos"):
		r.Product = "Sonos"
	case containsFold(server, "Synology"):
		r.Product = "Synology DSM"
	case containsFold(server, "Roku"):
		r.Product = "Roku"
	case containsFold(server, "Philips") || containsFold(server, "hue"):
		r.Product = "Philips Hue bridge"
	}
	if r.Version == "" {
		r.Version = firstVersion(server)
	}
}

// splitSlashVersion splits "product/1.2.3" into ("product", "1.2.3").
func splitSlashVersion(s string) (name, version string) {
	s = strings.TrimSpace(s)
	i := strings.LastIndexByte(s, '/')
	if i <= 0 || i == len(s)-1 {
		return s, ""
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
}
