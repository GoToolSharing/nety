package netif

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const iscLeases = `lease {
  interface "eth0";
  fixed-address 192.168.42.137;
  option subnet-mask 255.255.255.0;
  option routers 192.168.42.1;
  option dhcp-lease-time 43200;
  option dhcp-message-type 5;
  option domain-name-servers 192.168.42.10,192.168.42.11;
  option dhcp-server-identifier 192.168.42.2;
  option domain-name "corp.example";
  renew 2 2026/01/06 10:00:00;
  rebind 2 2026/01/06 16:00:00;
  expire 2 2026/01/06 22:00:00;
}
lease {
  interface "eth0";
  fixed-address 192.168.42.138;
  option subnet-mask 255.255.255.128;
  option routers 192.168.42.1;
  option dhcp-server-identifier 192.168.42.3;
  option domain-search "corp.example","lab.corp.example";
  expire 3 2026/01/07 22:00:00;
}
`

func TestParseISCLeases(t *testing.T) {
	leases := ParseISCLeases(strings.NewReader(iscLeases))
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2", len(leases))
	}

	first := leases[0]
	if first.Interface != "eth0" {
		t.Errorf("interface = %q", first.Interface)
	}
	if first.Address != netip.MustParseAddr("192.168.42.137") {
		t.Errorf("address = %v", first.Address)
	}
	if first.Prefix.String() != "192.168.42.137/24" {
		t.Errorf("prefix = %v, want /24", first.Prefix)
	}
	if first.Router != netip.MustParseAddr("192.168.42.1") {
		t.Errorf("router = %v", first.Router)
	}
	if first.Server != netip.MustParseAddr("192.168.42.2") {
		t.Errorf("server = %v", first.Server)
	}
	if len(first.DNS) != 2 {
		t.Errorf("dns = %v, want 2 servers", first.DNS)
	}
	if first.DomainName != "corp.example" {
		t.Errorf("domain = %q", first.DomainName)
	}
	if first.Expire.IsZero() || first.Expire.Format("2006/01/02 15:04:05") != "2026/01/06 22:00:00" {
		t.Errorf("expire = %v", first.Expire)
	}

	// The last entry for the interface is the current lease.
	picked, ok := pickISCLease(leases, "eth0")
	if !ok {
		t.Fatal("no lease picked")
	}
	if picked.Server != netip.MustParseAddr("192.168.42.3") {
		t.Errorf("picked server = %v, want the last entry's", picked.Server)
	}
	if picked.Prefix.String() != "192.168.42.138/25" {
		t.Errorf("picked prefix = %v", picked.Prefix)
	}
	if len(picked.Search) != 2 {
		t.Errorf("search = %v, want 2 entries", picked.Search)
	}
}

func TestParseISCLeasesIgnoresOtherInterfaces(t *testing.T) {
	leases := ParseISCLeases(strings.NewReader(iscLeases))
	if _, ok := pickISCLease(leases, "eth1"); ok {
		t.Error("a lease for eth0 was returned for eth1")
	}
}

func TestParseKVLease(t *testing.T) {
	const in = `# This is private data. Do not parse.
ADDRESS=10.20.30.40
NETMASK=255.255.252.0
ROUTER=10.20.28.1
SERVER_ADDRESS=10.20.28.2
DNS=10.20.28.10 10.20.28.11
DOMAINNAME=corp.example
T1=1767700000
LIFETIME=43200
`
	l := ParseKVLease(strings.NewReader(in))
	if l.Address != netip.MustParseAddr("10.20.30.40") {
		t.Errorf("address = %v", l.Address)
	}
	if l.Prefix.String() != "10.20.30.40/22" {
		t.Errorf("prefix = %v, want /22", l.Prefix)
	}
	if l.Router != netip.MustParseAddr("10.20.28.1") {
		t.Errorf("router = %v", l.Router)
	}
	if l.Server != netip.MustParseAddr("10.20.28.2") {
		t.Errorf("server = %v", l.Server)
	}
	if len(l.DNS) != 2 {
		t.Errorf("dns = %v", l.DNS)
	}
	if l.DomainName != "corp.example" || len(l.Search) != 1 {
		t.Errorf("domain = %q search = %v", l.DomainName, l.Search)
	}
	if l.Renew.Unix() != 1767700000 {
		t.Errorf("renew = %v", l.Renew)
	}
}

func TestLeaseCIDRFallback(t *testing.T) {
	l := Lease{Address: netip.MustParseAddr("192.0.2.5")}
	if got := l.CIDR().String(); got != "192.0.2.5/24" {
		t.Errorf("CIDR = %s, want a /24 fallback", got)
	}
	l6 := Lease{Address: netip.MustParseAddr("2001:db8::5")}
	if got := l6.CIDR().String(); got != "2001:db8::5/64" {
		t.Errorf("CIDR = %s, want a /64 fallback", got)
	}
}

func TestFindLeaseISCFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "var/lib/dhcp/dhclient.eth0.leases", iscLeases)

	l, ok := FindLease(root, "eth0", 2)
	if !ok {
		t.Fatal("lease not found")
	}
	if l.Server != netip.MustParseAddr("192.168.42.3") {
		t.Errorf("server = %v", l.Server)
	}
	if !strings.HasSuffix(l.Source, "dhclient.eth0.leases") {
		t.Errorf("source = %q", l.Source)
	}
}

func TestFindLeaseSystemdNetworkd(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "run/systemd/netif/leases/7",
		"ADDRESS=172.16.5.23\nNETMASK=255.255.255.0\nROUTER=172.16.5.1\nSERVER_ADDRESS=172.16.5.1\nDNS=172.16.5.1\n")

	l, ok := FindLease(root, "ens3", 7)
	if !ok {
		t.Fatal("lease not found")
	}
	if l.Server != netip.MustParseAddr("172.16.5.1") {
		t.Errorf("server = %v", l.Server)
	}
	if l.Interface != "ens3" {
		t.Errorf("interface = %q", l.Interface)
	}
	if l.Prefix.String() != "172.16.5.23/24" {
		t.Errorf("prefix = %v", l.Prefix)
	}
}

// dhcpcd writes the raw DHCP ACK packet, so FindLease must fall through to the
// wire-format parser.
func TestFindLeaseDHCPCDRawPacket(t *testing.T) {
	root := t.TempDir()
	ack := &DHCPMessage{
		Op: 2, HType: 1, HLen: 6, XID: 0x11223344,
		YIAddr: netip.MustParseAddr("10.9.8.7"),
		CHAddr: mac("00:11:22:33:44:55"),
	}
	ack.SetOption(OptMessageType, []byte{byte(DHCPAck)})
	ack.SetOption(OptSubnetMask, []byte{255, 255, 255, 0})
	ack.SetOption(OptRouter, []byte{10, 9, 8, 1})
	ack.SetOption(OptServerID, []byte{10, 9, 8, 2})
	writeBytes(t, root, "var/lib/dhcpcd/wlan0.lease", ack.Marshal())

	l, ok := FindLease(root, "wlan0", 3)
	if !ok {
		t.Fatal("lease not found")
	}
	if l.Address != netip.MustParseAddr("10.9.8.7") {
		t.Errorf("address = %v", l.Address)
	}
	if l.Server != netip.MustParseAddr("10.9.8.2") {
		t.Errorf("server = %v", l.Server)
	}
	if l.Prefix.String() != "10.9.8.7/24" {
		t.Errorf("prefix = %v", l.Prefix)
	}
}

func TestFindLeaseNone(t *testing.T) {
	if _, ok := FindLease(t.TempDir(), "eth0", 1); ok {
		t.Error("a lease was reported although no file exists")
	}
}

func TestFindLeaseIgnoresCorruptFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "var/lib/dhcp/dhclient.eth0.leases", "lease {\n  garbage\n")
	if _, ok := FindLease(root, "eth0", 1); ok {
		t.Error("a truncated lease block must not yield a lease")
	}
}

func TestMaskToBits(t *testing.T) {
	cases := map[string]int{
		"255.255.255.0":   24,
		"255.255.252.0":   22,
		"255.255.255.255": 32,
		"0.0.0.0":         0,
		"nonsense":        -1,
		"255.0.255.0":     -1, // non-contiguous
	}
	for in, want := range cases {
		if got := maskToBits(in); got != want {
			t.Errorf("maskToBits(%q) = %d, want %d", in, got, want)
		}
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	writeBytes(t, root, rel, []byte(content))
}

func writeBytes(t *testing.T, root, rel string, content []byte) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatal(err)
	}
}
