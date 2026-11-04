// Package udpprobe builds UDP service probes and decodes their responses.
//
// The package is pure: it produces payload bytes and parses response bytes. It
// performs no I/O at all — sockets, deadlines, retries and context handling are
// the caller's business. That makes every decoder trivially unit-testable and
// keeps hostile input confined to pure functions.
//
// Every decoder is written defensively: it bounds-checks each slice access,
// caps every loop, refuses absurd lengths and never allocates from an
// attacker-supplied length without a cap. Feeding random or truncated bytes to
// Decode or DecodeAny must never panic.
//
// Where a probe carries a transaction or message identifier the payload uses a
// fixed, obviously synthetic value which the matching decoder verifies. A
// verified identifier is what justifies a confidence of 90; a structurally
// plausible but unverifiable answer scores around 60.
package udpprobe

// Probe is one UDP payload to send to a service.
type Probe struct {
	Name    string   // stable id, e.g. "dns-version-bind"
	Payload []byte   // bytes to send
	Ports   []uint16 // ports this probe is normally aimed at (informational)
}

// Result is what a decoder extracted from a response.
type Result struct {
	Name       string // service name: "domain", "snmp", "ntp", "netbios-ns", ...
	Product    string
	Version    string
	ExtraInfo  string
	OSType     string
	CPEs       []string
	Extra      map[string]string // protocol-specific facts, lowercase dotted keys
	Confidence int               // 0..100
}

// decoder interprets a response body. It returns nil when resp does not look
// like a valid answer to the probe it belongs to.
type decoder func(resp []byte) *Result

type probeDef struct {
	name    string
	ports   []uint16
	payload []byte
	decode  decoder
}

func (p *probeDef) matches(port uint16) bool {
	for _, pp := range p.ports {
		if pp == port {
			return true
		}
	}
	return false
}

// registry holds every probe, best-first within a given port.
var registry = []probeDef{
	{name: "dns-version-bind", ports: []uint16{53}, payload: dnsVersionBindPayload(), decode: decodeDNSVersionBind},
	{name: "dns-status", ports: []uint16{53}, payload: dnsStatusPayload(), decode: decodeDNSStatus},
	{name: "mdns-services", ports: []uint16{5353}, payload: mdnsPayload(), decode: decodeMDNS},
	{name: "snmp-sysdescr", ports: []uint16{161, 162}, payload: snmpV2cPayload(), decode: decodeSNMPv2c},
	{name: "snmp-v1-sysdescr", ports: []uint16{161, 162}, payload: snmpV1Payload(), decode: decodeSNMPv1},
	{name: "snmp-v3-engineid", ports: []uint16{161, 162}, payload: snmpV3Payload(), decode: decodeSNMPv3},
	{name: "ntp-version", ports: []uint16{123}, payload: ntpClientPayload(), decode: decodeNTPClient},
	{name: "ntp-readvar", ports: []uint16{123}, payload: ntpReadvarPayload(), decode: decodeNTPReadvar},
	{name: "netbios-ns-status", ports: []uint16{137}, payload: netbiosPayload(), decode: decodeNetBIOS},
	{name: "ike-sa", ports: []uint16{500, 4500}, payload: ikeV1Payload(), decode: decodeIKEv1},
	{name: "ikev2-sa", ports: []uint16{500, 4500}, payload: ikeV2Payload(), decode: decodeIKEv2},
	{name: "ssdp-discover", ports: []uint16{1900}, payload: ssdpPayload(), decode: decodeSSDP},
	{name: "memcached-stats", ports: []uint16{11211}, payload: memcachedStatsPayload(), decode: decodeMemcachedStats},
	{name: "memcached-version", ports: []uint16{11211}, payload: memcachedVersionPayload(), decode: decodeMemcachedVersion},
	{name: "ipmi-rmcp", ports: []uint16{623, 664}, payload: ipmiPayload(), decode: decodeIPMI},
	{name: "sip-options", ports: []uint16{5060, 5061}, payload: sipPayload(), decode: decodeSIP},
	{name: "rpc-null", ports: []uint16{111}, payload: rpcDumpPayload(), decode: decodeRPC},
	// Tail: sent to anything we have no specific probe for. A bare empty
	// datagram is enough to elicit an ICMP port-unreachable (closed) or, on a
	// chatty service, a banner. It has no decoder of its own — use DecodeAny on
	// whatever comes back.
	{name: "generic-udp", ports: nil, payload: []byte{}, decode: nil},
}

const genericProbeName = "generic-udp"

func clonePayload(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func cloneU16(b []uint16) []uint16 {
	if len(b) == 0 {
		return nil
	}
	out := make([]uint16, len(b))
	copy(out, b)
	return out
}

func toProbe(p *probeDef) Probe {
	return Probe{Name: p.name, Payload: clonePayload(p.payload), Ports: cloneU16(p.ports)}
}

// For returns the probes worth sending to a UDP port, best first: the
// port-specific ones, then a small generic tail. It never returns nil.
func For(port uint16) []Probe {
	out := make([]Probe, 0, 4)
	for i := range registry {
		if registry[i].name == genericProbeName {
			continue
		}
		if registry[i].matches(port) {
			out = append(out, toProbe(&registry[i]))
		}
	}
	for i := range registry {
		if registry[i].name == genericProbeName {
			out = append(out, toProbe(&registry[i]))
		}
	}
	return out
}

// All returns every probe (for tests / exhaustive mode).
func All() []Probe {
	out := make([]Probe, 0, len(registry))
	for i := range registry {
		out = append(out, toProbe(&registry[i]))
	}
	return out
}

// Names returns the id of every probe, in registry order.
func Names() []string {
	out := make([]string, 0, len(registry))
	for i := range registry {
		out = append(out, registry[i].name)
	}
	return out
}

// Decode interprets resp as the answer to the probe named probeName. It
// returns nil when resp does not look like a valid answer to that probe, when
// probeName is unknown, or when the probe has no decoder (generic-udp).
func Decode(probeName string, resp []byte) (res *Result) {
	if len(resp) == 0 {
		return nil
	}
	for i := range registry {
		if registry[i].name != probeName {
			continue
		}
		if registry[i].decode == nil {
			return nil
		}
		return runDecoder(registry[i].decode, resp)
	}
	return nil
}

// DecodeAny tries every decoder that plausibly applies to port and returns the
// best result, or nil. Used when we do not know which probe got the answer.
// Decoders bound to the port are tried first; if none of them is confident the
// remaining decoders get a chance, so a service answering on an unusual port is
// still identified.
func DecodeAny(port uint16, resp []byte) *Result {
	if len(resp) == 0 {
		return nil
	}
	var best *Result
	consider := func(r *Result) {
		if r == nil {
			return
		}
		if best == nil || r.Confidence > best.Confidence {
			best = r
		}
	}

	tried := make(map[string]bool, len(registry))
	for i := range registry {
		if registry[i].decode == nil || !registry[i].matches(port) {
			continue
		}
		tried[registry[i].name] = true
		consider(runDecoder(registry[i].decode, resp))
	}
	if best != nil && best.Confidence >= 85 {
		return best
	}
	for i := range registry {
		if registry[i].decode == nil || tried[registry[i].name] {
			continue
		}
		consider(runDecoder(registry[i].decode, resp))
	}
	return best
}

// runDecoder is the last line of defence: decoders are written not to panic,
// but a response from the wire is hostile input and a panic here would take the
// whole scan down. Recovering costs nothing on the happy path.
func runDecoder(d decoder, resp []byte) (res *Result) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
		}
	}()
	return d(resp)
}

// newResult builds a Result with an initialised Extra map.
func newResult(name string, confidence int) *Result {
	return &Result{Name: name, Confidence: confidence, Extra: make(map[string]string, 8)}
}

// addCPE appends a CPE if it is not already present.
func (r *Result) addCPE(cpe string) {
	if cpe == "" {
		return
	}
	for _, c := range r.CPEs {
		if c == cpe {
			return
		}
	}
	r.CPEs = append(r.CPEs, cpe)
}

// set stores a sanitised, bounded value under key. Empty values are dropped.
func (r *Result) set(key, value string) {
	v := sanitize(value)
	if v == "" {
		return
	}
	if r.Extra == nil {
		r.Extra = make(map[string]string, 8)
	}
	r.Extra[key] = v
}

// setBool stores "true"/"false".
func (r *Result) setBool(key string, v bool) {
	if r.Extra == nil {
		r.Extra = make(map[string]string, 8)
	}
	if v {
		r.Extra[key] = "true"
	} else {
		r.Extra[key] = "false"
	}
}
