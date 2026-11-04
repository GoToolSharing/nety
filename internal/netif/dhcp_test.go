package netif

import (
	"net/netip"
	"testing"
	"time"
)

func TestDHCPDiscoverRoundTrip(t *testing.T) {
	m := NewDHCPDiscover(0xdeadbeef, mac("02:00:00:11:22:33"), "nety")
	raw := m.Marshal()
	if len(raw) < 300 {
		t.Fatalf("marshalled DISCOVER is %d bytes, below the BOOTP minimum", len(raw))
	}

	got, err := ParseDHCPMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Op != 1 || got.XID != 0xdeadbeef {
		t.Errorf("op = %d xid = %#x", got.Op, got.XID)
	}
	if got.Type() != DHCPDiscover {
		t.Errorf("type = %v", got.Type())
	}
	if got.CHAddr.String() != "02:00:00:11:22:33" {
		t.Errorf("chaddr = %s", got.CHAddr)
	}
	if string(got.Options[OptHostname]) != "nety" {
		t.Errorf("hostname = %q", got.Options[OptHostname])
	}
	if got.Flags&0x8000 == 0 {
		t.Error("broadcast flag not set; a sub-interface without an address cannot receive a unicast reply")
	}
}

func TestDHCPRequestCarriesServerAndRequestedIP(t *testing.T) {
	m := NewDHCPRequest(1, mac("02:00:00:11:22:33"), "",
		netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("10.1.0.1"))
	got, err := ParseDHCPMessage(m.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got.Type() != DHCPRequest {
		t.Errorf("type = %v", got.Type())
	}
	if got.optAddr(OptRequestedIP) != netip.MustParseAddr("10.1.2.3") {
		t.Errorf("requested ip = %v", got.optAddr(OptRequestedIP))
	}
	if got.optAddr(OptServerID) != netip.MustParseAddr("10.1.0.1") {
		t.Errorf("server id = %v", got.optAddr(OptServerID))
	}
}

func TestDHCPAckToLease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := &DHCPMessage{
		Op: 2, HType: 1, HLen: 6, XID: 7,
		YIAddr: netip.MustParseAddr("192.168.7.50"),
		CHAddr: mac("02:00:00:11:22:33"),
	}
	m.SetOption(OptMessageType, []byte{byte(DHCPAck)})
	m.SetOption(OptSubnetMask, []byte{255, 255, 255, 192})
	m.SetOption(OptRouter, []byte{192, 168, 7, 1})
	m.SetOption(OptServerID, []byte{192, 168, 7, 2})
	m.SetOption(OptDNSServers, []byte{192, 168, 7, 10, 192, 168, 7, 11})
	m.SetOption(OptDomainName, []byte("corp.example"))
	m.SetOption(OptLeaseTime, []byte{0, 0, 0x02, 0x58}) // 600s
	m.SetOption(OptRenewalTime, []byte{0, 0, 0x01, 0x2c})

	parsed, err := ParseDHCPMessage(m.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	l := parsed.Lease("eth0.42", now)
	if !l.Valid() {
		t.Fatal("lease not valid")
	}
	if l.Prefix.String() != "192.168.7.50/26" {
		t.Errorf("prefix = %v, want /26", l.Prefix)
	}
	if l.Router != netip.MustParseAddr("192.168.7.1") {
		t.Errorf("router = %v", l.Router)
	}
	if l.Server != netip.MustParseAddr("192.168.7.2") {
		t.Errorf("server = %v", l.Server)
	}
	if len(l.DNS) != 2 {
		t.Errorf("dns = %v", l.DNS)
	}
	if l.DomainName != "corp.example" {
		t.Errorf("domain = %q", l.DomainName)
	}
	if !l.Expire.Equal(now.Add(600 * time.Second)) {
		t.Errorf("expire = %v", l.Expire)
	}
	if !l.Renew.Equal(now.Add(300 * time.Second)) {
		t.Errorf("renew = %v", l.Renew)
	}
}

func TestDHCPDomainSearchOption(t *testing.T) {
	// RFC 3397: "corp.example" then a pointer-compressed "lab.corp.example".
	opt := []byte{
		4, 'c', 'o', 'r', 'p', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0,
		3, 'l', 'a', 'b', 0xc0, 0x00,
	}
	got := parseDomainSearch(opt)
	if len(got) != 2 || got[0] != "corp.example" || got[1] != "lab.corp.example" {
		t.Fatalf("domain search = %v", got)
	}
}

func TestDHCPDomainSearchMalformed(t *testing.T) {
	// A truncated label must not loop forever or panic.
	if got := parseDomainSearch([]byte{9, 'a', 'b'}); len(got) != 0 {
		t.Errorf("got %v, want nothing", got)
	}
	// A self-referencing pointer must terminate.
	if got := parseDomainSearch([]byte{0xc0, 0x00}); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestParseDHCPMessageRejectsNonDHCP(t *testing.T) {
	if _, err := ParseDHCPMessage(make([]byte, 400)); err == nil {
		t.Error("a buffer without the magic cookie must be rejected")
	}
	if _, err := ParseDHCPMessage([]byte{1, 2, 3}); err == nil {
		t.Error("a short buffer must be rejected")
	}
}

func TestDHCPOptionConcatenation(t *testing.T) {
	// RFC 3396: a long option split over several instances concatenates.
	raw := make([]byte, 240)
	raw[0] = 2
	raw[236], raw[237], raw[238], raw[239] = 0x63, 0x82, 0x53, 0x63
	raw = append(raw, OptDomainName, 4, 'c', 'o', 'r', 'p')
	raw = append(raw, OptDomainName, 8, '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e')
	raw = append(raw, OptEnd)

	m, err := ParseDHCPMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(m.Options[OptDomainName]); got != "corp.example" {
		t.Errorf("domain name = %q", got)
	}
}

func TestDHCPConfigDefaults(t *testing.T) {
	var c DHCPConfig
	if c.timeout() != 8*time.Second {
		t.Errorf("default timeout = %v", c.timeout())
	}
	if c.retries() != 3 {
		t.Errorf("default retries = %d", c.retries())
	}
	c = DHCPConfig{Timeout: time.Second, Retries: 1}
	if c.timeout() != time.Second || c.retries() != 1 {
		t.Errorf("explicit values overridden: %v %d", c.timeout(), c.retries())
	}
}
