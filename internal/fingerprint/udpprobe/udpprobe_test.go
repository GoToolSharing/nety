package udpprobe

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// --- probe catalogue ------------------------------------------------------

func TestForOrdering(t *testing.T) {
	cases := []struct {
		port uint16
		want []string
	}{
		{53, []string{"dns-version-bind", "dns-status", "generic-udp"}},
		{161, []string{"snmp-sysdescr", "snmp-v1-sysdescr", "snmp-v3-engineid", "generic-udp"}},
		{162, []string{"snmp-sysdescr", "snmp-v1-sysdescr", "snmp-v3-engineid", "generic-udp"}},
		{123, []string{"ntp-version", "ntp-readvar", "generic-udp"}},
		{137, []string{"netbios-ns-status", "generic-udp"}},
		{500, []string{"ike-sa", "ikev2-sa", "generic-udp"}},
		{4500, []string{"ike-sa", "ikev2-sa", "generic-udp"}},
		{1900, []string{"ssdp-discover", "generic-udp"}},
		{5353, []string{"mdns-services", "generic-udp"}},
		{11211, []string{"memcached-stats", "memcached-version", "generic-udp"}},
		{623, []string{"ipmi-rmcp", "generic-udp"}},
		{5060, []string{"sip-options", "generic-udp"}},
		{5061, []string{"sip-options", "generic-udp"}},
		{111, []string{"rpc-null", "generic-udp"}},
		{9999, []string{"generic-udp"}}, // unknown port: generic tail only
		{0, []string{"generic-udp"}},
	}
	for _, c := range cases {
		got := For(c.port)
		if got == nil {
			t.Fatalf("For(%d) returned nil", c.port)
		}
		names := make([]string, 0, len(got))
		for _, p := range got {
			names = append(names, p.Name)
		}
		if !reflect.DeepEqual(names, c.want) {
			t.Errorf("For(%d) = %v, want %v", c.port, names, c.want)
		}
	}
}

func TestAllProbesHavePayloads(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range All() {
		if p.Name == "" {
			t.Fatal("probe with empty name")
		}
		if seen[p.Name] {
			t.Fatalf("duplicate probe name %q", p.Name)
		}
		seen[p.Name] = true
		if p.Name == genericProbeName {
			if len(p.Payload) != 0 {
				t.Errorf("%s: expected a zero-length payload, got %d bytes", p.Name, len(p.Payload))
			}
			continue
		}
		if len(p.Payload) == 0 {
			t.Errorf("%s: empty payload", p.Name)
		}
		if len(p.Payload) > 1024 {
			t.Errorf("%s: payload is %d bytes, too large for a probe", p.Name, len(p.Payload))
		}
		if len(p.Ports) == 0 {
			t.Errorf("%s: no ports declared", p.Name)
		}
	}
	// Every probe in the task list must exist.
	for _, want := range []string{
		"dns-version-bind", "dns-status", "snmp-sysdescr", "snmp-v1-sysdescr",
		"snmp-v3-engineid", "ntp-version", "ntp-readvar", "netbios-ns-status",
		"ike-sa", "ikev2-sa", "ssdp-discover", "mdns-services", "memcached-stats",
		"memcached-version", "ipmi-rmcp", "sip-options", "rpc-null", "generic-udp",
	} {
		if !seen[want] {
			t.Errorf("missing probe %q", want)
		}
	}
}

func TestPayloadsAreCopies(t *testing.T) {
	a := For(53)
	if len(a) == 0 || len(a[0].Payload) == 0 {
		t.Fatal("no payload to mutate")
	}
	orig := a[0].Payload[0]
	a[0].Payload[0] ^= 0xff
	a[0].Ports[0] = 1
	b := For(53)
	if b[0].Payload[0] != orig {
		t.Error("For() handed out a reference to the registry payload")
	}
	if b[0].Ports[0] != 53 {
		t.Error("For() handed out a reference to the registry port list")
	}
}

// --- decoders -------------------------------------------------------------

func has(t *testing.T, r *Result, key, want string) {
	t.Helper()
	if got := r.Extra[key]; got != want {
		t.Errorf("Extra[%q] = %q, want %q", key, got, want)
	}
}

func hasPrefix(t *testing.T, r *Result, key, want string) {
	t.Helper()
	if got := r.Extra[key]; !strings.HasPrefix(got, want) {
		t.Errorf("Extra[%q] = %q, want prefix %q", key, got, want)
	}
}

func hasCPE(t *testing.T, r *Result, want string) {
	t.Helper()
	for _, c := range r.CPEs {
		if c == want {
			return
		}
	}
	t.Errorf("CPEs = %v, want to contain %q", r.CPEs, want)
}

func decodeOK(t *testing.T, probe string, raw []byte) *Result {
	t.Helper()
	r := Decode(probe, raw)
	if r == nil {
		t.Fatalf("Decode(%q) returned nil", probe)
	}
	checkExtraSane(t, r)
	return r
}

func checkExtraSane(t *testing.T, r *Result) {
	t.Helper()
	for k, v := range r.Extra {
		if k != strings.ToLower(k) {
			t.Errorf("Extra key %q is not lowercase", k)
		}
		if !strings.Contains(k, ".") {
			t.Errorf("Extra key %q is not dotted", k)
		}
		if utf8.RuneCountInString(v) > maxExtraLen {
			t.Errorf("Extra[%q] is %d runes, over the %d cap", k, utf8.RuneCountInString(v), maxExtraLen)
		}
		for _, c := range v {
			if c < 0x20 || c == 0x7f {
				t.Errorf("Extra[%q] = %q contains a control character", k, v)
				break
			}
		}
	}
	if r.Confidence < 0 || r.Confidence > 100 {
		t.Errorf("Confidence %d out of range", r.Confidence)
	}
}

func TestDecodeDNSVersionBind(t *testing.T) {
	r := decodeOK(t, "dns-version-bind", mustHex(t, fxDNSBind))
	if r.Name != "domain" {
		t.Errorf("Name = %q", r.Name)
	}
	if r.Confidence != 90 {
		t.Errorf("Confidence = %d, want 90", r.Confidence)
	}
	if r.Product != "ISC BIND" || r.Version != "9.11.3" {
		t.Errorf("Product/Version = %q/%q", r.Product, r.Version)
	}
	if r.OSType != "Linux" {
		t.Errorf("OSType = %q", r.OSType)
	}
	hasCPE(t, r, "cpe:/a:isc:bind:9.11.3")
	has(t, r, "dns.version", "9.11.3-1ubuntu1.17-Ubuntu")
	has(t, r, "dns.rcode", "NOERROR")
}

func TestDecodeDNSVersionBindDnsmasq(t *testing.T) {
	r := decodeOK(t, "dns-version-bind", mustHex(t, fxDNSDnsmasq))
	if r.Product != "dnsmasq" || r.Version != "2.80" {
		t.Errorf("Product/Version = %q/%q", r.Product, r.Version)
	}
	hasCPE(t, r, "cpe:/a:thekelleys:dnsmasq:2.80")
}

func TestDecodeDNSVersionBindRefused(t *testing.T) {
	r := decodeOK(t, "dns-version-bind", mustHex(t, fxDNSRefused))
	if r.Name != "domain" {
		t.Errorf("Name = %q", r.Name)
	}
	if r.Confidence >= 90 {
		t.Errorf("Confidence = %d, want a reduced score for a refused query", r.Confidence)
	}
	has(t, r, "dns.rcode", "REFUSED")
}

func TestDecodeDNSWrongTransactionID(t *testing.T) {
	if r := Decode("dns-version-bind", mustHex(t, fxDNSWrongID)); r != nil {
		t.Errorf("wrong transaction id decoded as %+v", r)
	}
}

func TestDecodeDNSStatus(t *testing.T) {
	r := decodeOK(t, "dns-status", mustHex(t, fxDNSStatus))
	if r.Name != "domain" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "dns.rcode", "NOERROR")
	has(t, r, "dns.recursion_available", "true")
	has(t, r, "dns.opcode", "QUERY")
}

func TestDecodeMDNS(t *testing.T) {
	r := decodeOK(t, "mdns-services", mustHex(t, fxMDNS))
	if r.Name != "mdns" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "mdns.services", "_ipp._tcp.local,_printer._tcp.local")
	has(t, r, "mdns.hostname", "printer.local")
	if r.Product != "Network printer" {
		t.Errorf("Product = %q", r.Product)
	}
}

func TestDecodeSNMPv2cCisco(t *testing.T) {
	r := decodeOK(t, "snmp-sysdescr", mustHex(t, fxSNMPCisco))
	if r.Name != "snmp" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	if r.Product != "Cisco IOS" || r.OSType != "IOS" {
		t.Errorf("Product/OSType = %q/%q", r.Product, r.OSType)
	}
	if r.Version != "15.0" {
		t.Errorf("Version = %q", r.Version)
	}
	hasPrefix(t, r, "snmp.sysdescr", "Cisco IOS Software")
	has(t, r, "snmp.community", "public")
	has(t, r, "snmp.version", "v2c")
	hasCPE(t, r, "cpe:/o:cisco:ios")
}

func TestDecodeSNMPv2cLinux(t *testing.T) {
	r := decodeOK(t, "snmp-sysdescr", mustHex(t, fxSNMPLinux))
	if r.OSType != "Linux" || r.Version != "5.10.0-8-amd64" {
		t.Errorf("OSType/Version = %q/%q", r.OSType, r.Version)
	}
	hasCPE(t, r, "cpe:/o:linux:linux_kernel")
}

func TestDecodeSNMPWrongCommunity(t *testing.T) {
	r := decodeOK(t, "snmp-sysdescr", mustHex(t, fxSNMPAuthErr))
	if r.Name != "snmp" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "snmp.error_status", "authorizationError")
	has(t, r, "snmp.access", "denied")
	if !strings.Contains(r.ExtraInfo, "rejected") {
		t.Errorf("ExtraInfo = %q", r.ExtraInfo)
	}
}

func TestDecodeSNMPv1(t *testing.T) {
	r := decodeOK(t, "snmp-v1-sysdescr", mustHex(t, fxSNMPv1NoSuchName))
	has(t, r, "snmp.version", "v1")
	has(t, r, "snmp.access", "limited")
	if r.Confidence != 90 {
		t.Errorf("Confidence = %d", r.Confidence)
	}
	// The v2c decoder must not claim a v1 response with a v1 request id.
	if r2 := Decode("snmp-sysdescr", mustHex(t, fxSNMPv1NoSuchName)); r2 != nil && r2.Confidence >= 85 {
		t.Errorf("v2c decoder over-claimed a v1 response: %+v", r2)
	}
}

func TestDecodeSNMPWrongRequestID(t *testing.T) {
	r := Decode("snmp-sysdescr", mustHex(t, fxSNMPWrongID))
	if r == nil {
		t.Fatal("structurally valid SNMP should still decode")
	}
	if r.Confidence >= 85 {
		t.Errorf("Confidence = %d, want a low score for an unverified request id", r.Confidence)
	}
}

func TestDecodeSNMPv3EngineID(t *testing.T) {
	r := decodeOK(t, "snmp-v3-engineid", mustHex(t, fxSNMPv3))
	if r.Name != "snmp" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "snmp.engine_id", "80001f8803005056abcdef")
	has(t, r, "snmp.engine_boots", "5")
	has(t, r, "snmp.engine_time", "662316")
	has(t, r, "snmp.engine_enterprise", "8072")
	has(t, r, "snmp.engine_vendor", "Net-SNMP")
	has(t, r, "snmp.engine_mac", "00:50:56:ab:cd:ef")
	has(t, r, "snmp.report", "usmStatsUnknownEngineIDs")
	has(t, r, "snmp.version", "v3")
}

func TestDecodeNTPClient(t *testing.T) {
	r := decodeOK(t, "ntp-version", mustHex(t, fxNTPServer))
	if r.Name != "ntp" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "ntp.stratum", "2")
	has(t, r, "ntp.refid", "192.168.1.1")
	has(t, r, "ntp.leap", "none")
	has(t, r, "ntp.mode", "server")
	has(t, r, "ntp.version", "4")
	has(t, r, "ntp.precision", "-23")
	hasPrefix(t, r, "ntp.reference_time", "2021-06-09T")
}

func TestDecodeNTPClientNoEcho(t *testing.T) {
	r := decodeOK(t, "ntp-version", mustHex(t, fxNTPNoEcho))
	if r.Confidence >= 85 {
		t.Errorf("Confidence = %d, want a low score without the originate echo", r.Confidence)
	}
}

func TestDecodeNTPReadvar(t *testing.T) {
	r := decodeOK(t, "ntp-readvar", mustHex(t, fxNTPReadvar))
	if r.Name != "ntp" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	if r.Product != "NTP ntpd" || r.Version != "4.2.8p15" {
		t.Errorf("Product/Version = %q/%q", r.Product, r.Version)
	}
	if r.OSType != "Linux" {
		t.Errorf("OSType = %q", r.OSType)
	}
	hasCPE(t, r, "cpe:/a:ntp:ntp:4.2.8p15")
	has(t, r, "ntp.processor", "x86_64")
	has(t, r, "ntp.system", "Linux/5.4.0-74-generic")
	has(t, r, "ntp.stratum", "3")
}

func TestDecodeNetBIOS(t *testing.T) {
	r := decodeOK(t, "netbios-ns-status", mustHex(t, fxNBNS))
	if r.Name != "netbios-ns" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "netbios.name", "WORKSTATION01")
	has(t, r, "netbios.domain", "WORKGROUP")
	has(t, r, "netbios.mac", "00:0c:29:ab:cd:ef")
	has(t, r, "netbios.names", "WORKSTATION01<00>,WORKGROUP<00>,WORKSTATION01<20>")
	has(t, r, "netbios.unique", "WORKSTATION01<00>,WORKSTATION01<20>")
	has(t, r, "netbios.server", "true")
	if r.OSType != "Windows" {
		t.Errorf("OSType = %q", r.OSType)
	}
}

func TestDecodeNetBIOSWrongID(t *testing.T) {
	if r := Decode("netbios-ns-status", mustHex(t, fxNBNSWrongID)); r != nil {
		t.Errorf("wrong transaction id decoded as %+v", r)
	}
}

func TestDecodeIKEv1(t *testing.T) {
	r := decodeOK(t, "ike-sa", mustHex(t, fxIKEv1))
	if r.Name != "isakmp" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "ike.version", "1.0")
	has(t, r, "ike.exchange", "identity-protection")
	has(t, r, "ike.encryption", "AES-CBC")
	has(t, r, "ike.key_length", "128")
	has(t, r, "ike.hash", "SHA1")
	has(t, r, "ike.auth", "pre-shared-key")
	has(t, r, "ike.dh_group", "modp1024")
	has(t, r, "ike.lifetime", "28800s")
	has(t, r, "ike.vendor_ids", "afcad71368a1f1c96b8696fc77570100,4048b7d56ebce88525e7de7f00d6c2d3")
	has(t, r, "ike.vendors", "Dead Peer Detection v1.0,Cisco IKE Fragmentation")
	if r.Product != "Cisco VPN" {
		t.Errorf("Product = %q", r.Product)
	}
}

func TestDecodeIKEv1WrongCookie(t *testing.T) {
	if r := Decode("ike-sa", mustHex(t, fxIKEv1WrongCookie)); r != nil {
		t.Errorf("wrong initiator cookie decoded as %+v", r)
	}
}

func TestDecodeIKEv2(t *testing.T) {
	r := decodeOK(t, "ikev2-sa", mustHex(t, fxIKEv2))
	if r.Name != "isakmp" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "ike.version", "2.0")
	has(t, r, "ike.exchange", "IKE_SA_INIT")
	has(t, r, "ike.encryption", "AES-CBC")
	has(t, r, "ike.key_length", "128")
	has(t, r, "ike.prf", "HMAC-SHA1")
	has(t, r, "ike.integrity", "HMAC-SHA1-96")
	has(t, r, "ike.dh_group", "modp2048")
}

func TestDecodeSSDP(t *testing.T) {
	r := decodeOK(t, "ssdp-discover", []byte(fxSSDP))
	if r.Name != "upnp" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "upnp.server", "Linux/3.14.0 UPnP/1.0 MiniUPnPd/1.9")
	has(t, r, "upnp.location", "http://192.0.2.10:49152/rootDesc.xml")
	has(t, r, "upnp.st", "upnp:rootdevice")
	hasPrefix(t, r, "upnp.usn", "uuid:fc4ec57e")
	if r.Product != "MiniUPnP daemon" || r.Version != "1.9" {
		t.Errorf("Product/Version = %q/%q", r.Product, r.Version)
	}
	if r.OSType != "Linux" {
		t.Errorf("OSType = %q", r.OSType)
	}
	hasCPE(t, r, "cpe:/a:miniupnp_project:miniupnpd:1.9")
}

func TestDecodeSSDPNotUPnP(t *testing.T) {
	if r := Decode("ssdp-discover", []byte(fxSSDPNotUPnP)); r != nil {
		t.Errorf("plain HTTP 200 decoded as UPnP: %+v", r)
	}
}

func TestDecodeMemcachedStats(t *testing.T) {
	r := decodeOK(t, "memcached-stats", mustHex(t, fxMemcachedStats))
	if r.Name != "memcached" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	if r.Version != "1.6.9" {
		t.Errorf("Version = %q", r.Version)
	}
	has(t, r, "memcached.version", "1.6.9")
	has(t, r, "memcached.uptime", "98765")
	has(t, r, "memcached.pid", "1234")
	has(t, r, "memcached.curr_connections", "10")
	has(t, r, "memcached.pointer_size", "64")
	hasCPE(t, r, "cpe:/a:memcached:memcached:1.6.9")
}

func TestDecodeMemcachedBinaryVersion(t *testing.T) {
	r := decodeOK(t, "memcached-version", mustHex(t, fxMemcachedBin))
	if r.Name != "memcached" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	if r.Version != "1.6.9" {
		t.Errorf("Version = %q", r.Version)
	}
	has(t, r, "memcached.protocol", "binary")
	hasCPE(t, r, "cpe:/a:memcached:memcached:1.6.9")

	low := Decode("memcached-version", mustHex(t, fxMemcachedBinWrongOpaque))
	if low == nil || low.Confidence >= 85 {
		t.Errorf("wrong opaque should score low, got %+v", low)
	}
}

func TestDecodeIPMI(t *testing.T) {
	r := decodeOK(t, "ipmi-rmcp", mustHex(t, fxIPMI))
	if r.Name != "ipmi" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "ipmi.version", "2.0")
	has(t, r, "ipmi.oem_id", "674")
	has(t, r, "ipmi.oem", "Dell")
	has(t, r, "ipmi.auth_types", "md2,md5,password")
	has(t, r, "ipmi.anonymous_login", "false")
	has(t, r, "ipmi.null_user", "true")
	has(t, r, "ipmi.kg_default", "true")
	has(t, r, "ipmi.per_message_auth", "true")
	has(t, r, "ipmi.user_level_auth", "false")
	has(t, r, "ipmi.channel", "1")
	if r.Product != "Dell iDRAC" {
		t.Errorf("Product = %q", r.Product)
	}
}

func TestDecodeIPMIWrongSeq(t *testing.T) {
	r := Decode("ipmi-rmcp", mustHex(t, fxIPMIWrongSeq))
	if r == nil {
		t.Fatal("a structurally valid IPMI reply should still decode")
	}
	if r.Confidence >= 85 {
		t.Errorf("Confidence = %d, want a low score for an unverified sequence number", r.Confidence)
	}
}

func TestDecodeSIP(t *testing.T) {
	r := decodeOK(t, "sip-options", []byte(fxSIP))
	if r.Name != "sip" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "sip.status", "200")
	has(t, r, "sip.status_text", "OK")
	has(t, r, "sip.server", "Asterisk PBX 16.2.1~dfsg-1ubuntu1")
	hasPrefix(t, r, "sip.allow", "INVITE, ACK")
	has(t, r, "sip.supported", "replaces, timer")
	if r.Product != "Asterisk" || r.Version != "16.2.1" {
		t.Errorf("Product/Version = %q/%q", r.Product, r.Version)
	}
	hasCPE(t, r, "cpe:/a:digium:asterisk:16.2.1")
}

func TestDecodeSIPForeignCallID(t *testing.T) {
	r := decodeOK(t, "sip-options", []byte(fxSIPOtherCallID))
	if r.Confidence >= 85 {
		t.Errorf("Confidence = %d, want a low score for a foreign Call-ID", r.Confidence)
	}
	if r.Product != "Kamailio" || r.Version != "5.5.2" {
		t.Errorf("Product/Version = %q/%q", r.Product, r.Version)
	}
	has(t, r, "sip.status", "404")
}

func TestDecodeRPC(t *testing.T) {
	r := decodeOK(t, "rpc-null", mustHex(t, fxRPC))
	if r.Name != "rpcbind" || r.Confidence != 90 {
		t.Errorf("Name/Confidence = %q/%d", r.Name, r.Confidence)
	}
	has(t, r, "rpc.programs", "portmapper:111/udp,portmapper:111/tcp,nfs:2049/tcp")
	has(t, r, "rpc.entry_count", "3")
	has(t, r, "rpc.nfs", "true")
}

func TestDecodeRPCWrongXID(t *testing.T) {
	if r := Decode("rpc-null", mustHex(t, fxRPCWrongXID)); r != nil {
		t.Errorf("wrong xid decoded as %+v", r)
	}
}

func TestDecodeUnknownProbeAndGeneric(t *testing.T) {
	if r := Decode("no-such-probe", []byte("whatever")); r != nil {
		t.Errorf("unknown probe decoded as %+v", r)
	}
	if r := Decode(genericProbeName, []byte("whatever")); r != nil {
		t.Errorf("generic probe has no decoder, got %+v", r)
	}
	if r := Decode("dns-status", nil); r != nil {
		t.Errorf("empty response decoded as %+v", r)
	}
}

// --- DecodeAny ------------------------------------------------------------

func TestDecodeAny(t *testing.T) {
	cases := []struct {
		name string
		port uint16
		resp []byte
		want string
	}{
		{"dns", 53, mustHex(t, fxDNSBind), "domain"},
		{"dns-status", 53, mustHex(t, fxDNSStatus), "domain"},
		{"mdns", 5353, mustHex(t, fxMDNS), "mdns"},
		{"snmp", 161, mustHex(t, fxSNMPLinux), "snmp"},
		{"snmpv3", 161, mustHex(t, fxSNMPv3), "snmp"},
		{"ntp", 123, mustHex(t, fxNTPServer), "ntp"},
		{"ntp-readvar", 123, mustHex(t, fxNTPReadvar), "ntp"},
		{"netbios", 137, mustHex(t, fxNBNS), "netbios-ns"},
		{"ike", 500, mustHex(t, fxIKEv1), "isakmp"},
		{"ikev2", 500, mustHex(t, fxIKEv2), "isakmp"},
		{"ssdp", 1900, []byte(fxSSDP), "upnp"},
		{"memcached", 11211, mustHex(t, fxMemcachedStats), "memcached"},
		{"memcached-bin", 11211, mustHex(t, fxMemcachedBin), "memcached"},
		{"ipmi", 623, mustHex(t, fxIPMI), "ipmi"},
		{"sip", 5060, []byte(fxSIP), "sip"},
		{"rpc", 111, mustHex(t, fxRPC), "rpcbind"},
		// Services answering on a port we did not expect: the full sweep must
		// still find them.
		{"ssdp-odd-port", 37777, []byte(fxSSDP), "upnp"},
		{"netbios-on-53", 53, mustHex(t, fxNBNS), "netbios-ns"},
		{"ipmi-on-unknown", 1234, mustHex(t, fxIPMI), "ipmi"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := DecodeAny(c.port, c.resp)
			if r == nil {
				t.Fatalf("DecodeAny(%d) returned nil", c.port)
			}
			if r.Name != c.want {
				t.Errorf("DecodeAny(%d).Name = %q, want %q", c.port, r.Name, c.want)
			}
			checkExtraSane(t, r)
		})
	}
}

func TestDecodeAnyRejects(t *testing.T) {
	for _, c := range []struct {
		name string
		port uint16
		resp []byte
	}{
		{"empty", 53, nil},
		{"garbage-text", 53, []byte("hello there, this is not a protocol")},
		{"short", 161, []byte{0x30}},
		{"plain-http", 1900, []byte(fxSSDPNotUPnP)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if r := DecodeAny(c.port, c.resp); r != nil {
				t.Errorf("DecodeAny decoded %+v", r)
			}
		})
	}
}

// --- robustness -----------------------------------------------------------

func allFixtures(t testing.TB) map[string][]byte {
	return map[string][]byte{
		"dns-version-bind":  mustHex(t, fxDNSBind),
		"dns-status":        mustHex(t, fxDNSStatus),
		"mdns-services":     mustHex(t, fxMDNS),
		"snmp-sysdescr":     mustHex(t, fxSNMPCisco),
		"snmp-v1-sysdescr":  mustHex(t, fxSNMPv1NoSuchName),
		"snmp-v3-engineid":  mustHex(t, fxSNMPv3),
		"ntp-version":       mustHex(t, fxNTPServer),
		"ntp-readvar":       mustHex(t, fxNTPReadvar),
		"netbios-ns-status": mustHex(t, fxNBNS),
		"ike-sa":            mustHex(t, fxIKEv1),
		"ikev2-sa":          mustHex(t, fxIKEv2),
		"ssdp-discover":     []byte(fxSSDP),
		"memcached-stats":   mustHex(t, fxMemcachedStats),
		"memcached-version": mustHex(t, fxMemcachedBin),
		"ipmi-rmcp":         mustHex(t, fxIPMI),
		"sip-options":       []byte(fxSIP),
		"rpc-null":          mustHex(t, fxRPC),
	}
}

var probePorts = []uint16{53, 111, 123, 137, 161, 500, 623, 1900, 5060, 5353, 11211, 9999}

// TestTruncatedResponsesDoNotPanic truncates every fixture byte by byte, from
// both ends, and feeds each prefix/suffix to every decoder.
func TestTruncatedResponsesDoNotPanic(t *testing.T) {
	names := Names()
	for probe, full := range allFixtures(t) {
		for n := 0; n <= len(full); n++ {
			prefix := full[:n]
			suffix := full[len(full)-n:]
			for _, in := range [][]byte{prefix, suffix} {
				for _, name := range names {
					if r := Decode(name, in); r != nil {
						checkExtraSane(t, r)
					}
				}
				for _, port := range probePorts {
					if r := DecodeAny(port, in); r != nil {
						checkExtraSane(t, r)
					}
				}
			}
		}
		_ = probe
	}
}

// TestCorruptedResponsesDoNotPanic flips bytes inside valid fixtures.
func TestCorruptedResponsesDoNotPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(0x4e455459))
	names := Names()
	for _, full := range allFixtures(t) {
		for i := 0; i < 2000; i++ {
			b := make([]byte, len(full))
			copy(b, full)
			for k := 0; k < 1+rng.Intn(8); k++ {
				b[rng.Intn(len(b))] = byte(rng.Intn(256))
			}
			for _, name := range names {
				if r := Decode(name, b); r != nil {
					checkExtraSane(t, r)
				}
			}
			if r := DecodeAny(probePorts[rng.Intn(len(probePorts))], b); r != nil {
				checkExtraSane(t, r)
			}
		}
	}
}

// TestRandomResponsesDoNotPanic throws random bytes at every decoder.
func TestRandomResponsesDoNotPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	names := Names()
	buf := make([]byte, 2048)
	for i := 0; i < 4000; i++ {
		n := rng.Intn(len(buf) + 1)
		b := buf[:n]
		rng.Read(b)
		for _, name := range names {
			if r := Decode(name, b); r != nil {
				checkExtraSane(t, r)
			}
		}
		if r := DecodeAny(uint16(rng.Intn(65536)), b); r != nil {
			checkExtraSane(t, r)
		}
	}
}

// TestStructuredRandomDoesNotPanic keeps the leading bytes of a fixture (so the
// magic/transaction id matches) and randomises the tail — the nastiest input
// for a length-driven parser.
func TestStructuredRandomDoesNotPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	names := Names()
	for _, full := range allFixtures(t) {
		if len(full) < 8 {
			continue
		}
		for i := 0; i < 1000; i++ {
			keep := 4 + rng.Intn(min(28, len(full)-4))
			b := make([]byte, len(full)+rng.Intn(64))
			copy(b, full[:keep])
			rng.Read(b[keep:])
			for _, name := range names {
				if r := Decode(name, b); r != nil {
					checkExtraSane(t, r)
				}
			}
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, raw := range allFixtures(f) {
		f.Add(raw)
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})
	names := Names()
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, name := range names {
			if r := Decode(name, data); r != nil {
				checkExtraSane(t, r)
			}
		}
		for _, port := range probePorts {
			if r := DecodeAny(port, data); r != nil {
				checkExtraSane(t, r)
			}
		}
	})
}

// --- helpers --------------------------------------------------------------

func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"a\x00b", "a b"},
		{"  lots   of   space  ", "lots of space"},
		{"tab\there", "tab here"},
		{"\xff\xfe invalid utf8", "invalid utf8"},
	}
	for _, c := range cases {
		if got := sanitize(c.in); got != c.want {
			t.Errorf("sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	long := strings.Repeat("x", 1000)
	if got := sanitize(long); utf8.RuneCountInString(got) != maxExtraLen {
		t.Errorf("sanitize did not truncate: %d runes", utf8.RuneCountInString(got))
	}
}

func TestParseTLVBounds(t *testing.T) {
	bad := [][]byte{
		nil,
		{0x30},
		{0x30, 0x05, 0x01},             // length past the buffer
		{0x30, 0x84, 0xff, 0xff, 0xff}, // long form past the buffer
		{0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05},
		{0x3f, 0x01, 0x00}, // high-tag-number form
	}
	for _, b := range bad {
		if _, _, ok := parseTLV(b); ok {
			t.Errorf("parseTLV(% x) accepted malformed input", b)
		}
	}
	tl, rest, ok := parseTLV([]byte{0x04, 0x02, 'h', 'i', 0xff})
	if !ok || tl.tag != 0x04 || string(tl.content) != "hi" || len(rest) != 1 {
		t.Errorf("parseTLV failed on a valid element: %+v %v %v", tl, rest, ok)
	}
}

func TestDecodeOID(t *testing.T) {
	if got := decodeOID(oidSysDescr); got != oidSysDescrStr {
		t.Errorf("decodeOID = %q, want %q", got, oidSysDescrStr)
	}
	if got := decodeOID(nil); got != "" {
		t.Errorf("decodeOID(nil) = %q", got)
	}
	// A run of continuation bytes must not loop forever or overflow.
	huge := make([]byte, 128)
	for i := range huge {
		huge[i] = 0xff
	}
	_ = decodeOID(huge)
}
