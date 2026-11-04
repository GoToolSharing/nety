package oui

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestLookupVendors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mac  string
		want string
	}{
		// MA-L (24 bit).
		{"vmware esxi", "00:50:56:aa:bb:cc", "VMware, Inc."},
		{"vmware workstation", "00:0C:29:11:22:33", "VMware, Inc."},
		{"virtualbox", "08:00:27:11:22:33", "PCS Systemtechnik GmbH"},
		{"google", "00:1A:11:11:22:33", "Google, Inc."},
		{"cisco", "00:00:0c:12:34:56", "Cisco Systems, Inc"},
		{"raspberry pi", "B8:27:EB:01:02:03", "Raspberry Pi Foundation"},
		{"hyper-v", "00:15:5D:01:02:03", "Microsoft Corporation"},

		// MA-M (28 bit): two assignments inside the same MA-L block, which
		// only a longest-prefix match can tell apart.
		{"ma-m low nibble", "00:55:DA:01:23:45", "Shinko Technos co.,ltd."},
		{"ma-m high nibble", "00:55:DA:11:23:45", "KoolPOS Inc."},

		// MA-S / IAB (36 bit).
		{"ma-s", "70:B3:D5:00:10:00", "SOREDI touch systems GmbH"},
		{"ma-s other block", "8C:1F:64:0A:00:00", "TECHNIWAVE"},

		// Bare prefixes.
		{"bare ma-l prefix colon", "00:50:56", "VMware, Inc."},
		{"bare ma-l prefix dash", "00-50-56", "VMware, Inc."},
		{"bare ma-l prefix plain", "005056", "VMware, Inc."},
		{"bare ma-m prefix", "0055DA1", "KoolPOS Inc."},
		{"bare ma-s prefix", "70B3D5001", "SOREDI touch systems GmbH"},
		{"bare prefix falls back to ma-l", "0050561", "VMware, Inc."},

		// Multicast: the group bit is masked before the registry lookup.
		{"cdp multicast", "01:00:0c:cc:cc:cc", "Cisco Systems, Inc"},
		{"ipv4 multicast", "01:00:5e:00:00:01", "ICANN, IANA Department"},

		// Locally administered.
		{"locally administered unknown", "02:00:00:00:00:01", Randomized},
		{"randomized wifi", "da:a1:19:00:00:01", Randomized},
		{"qemu/kvm", "52:54:00:12:34:56", Randomized},
		{"locally administered known", "02:60:8C:11:22:33", "3COM (locally administered)"},

		// Unknown / special.
		{"broadcast", "ff:ff:ff:ff:ff:ff", ""},
		{"unassigned global", "AC:DE:48:00:11:22", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Lookup(c.mac); got != c.want {
				t.Errorf("Lookup(%q) = %q, want %q", c.mac, got, c.want)
			}
		})
	}
}

func TestLookupFormats(t *testing.T) {
	t.Parallel()
	const want = "VMware, Inc."
	forms := []string{
		"00:50:56:aa:bb:cc",
		"00:50:56:AA:BB:CC",
		"00-50-56-AA-BB-CC",
		"00-50-56-aa-bb-cc",
		"0050.56aa.bbcc",
		"0050.56AA.BBCC",
		"005056aabbcc",
		"005056AABBCC",
		"  00:50:56:aa:bb:cc  ",
		"\t00-50-56-AA-BB-CC\n",
		"0:50:56:aa:bb:cc",        // single-digit groups
		"50.56aa.bbcc",            // short dot group, zero-padded
		"00:50:56:ff:fe:aa:bb:cc", // EUI-64, truncated to the first 6 octets
		"00-50-56-FF-FE-AA-BB-CC", // EUI-64, dashes
	}
	for _, f := range forms {
		if got := Lookup(f); got != want {
			t.Errorf("Lookup(%q) = %q, want %q", f, got, want)
		}
	}
}

func TestLookupGarbage(t *testing.T) {
	t.Parallel()
	bad := []string{
		"",
		"   ",
		"not a mac",
		"zz:00:0c:12:34:56",
		"00:00:0c:12:34",       // 10 hex digits
		"00:00:0c:12:34:56:78", // 14 hex digits
		"000:00:0c:12:34:56",   // oversized group
		"00::0c:12:34:56",      // empty group
		"00:50:56:aa:bb:cg",    // non-hex digit
		"0050.56aa.bbccdd",     // oversized dot group
		".",
		":",
		"-",
		"::::::::::::",
		strings.Repeat("a", 65),   // over the length cap
		strings.Repeat("ab:", 40), // many groups
		"\x00\x01\x02",
		"00:50:56:aa:bb:cc extra",
		"0x005056aabbcc",
	}
	for _, b := range bad {
		if got := Lookup(b); got != "" {
			t.Errorf("Lookup(%q) = %q, want %q", b, got, "")
		}
		if IsLocallyAdministered(b) {
			t.Errorf("IsLocallyAdministered(%q) = true, want false", b)
		}
		if IsMulticast(b) {
			t.Errorf("IsMulticast(%q) = true, want false", b)
		}
		if got := Normalize(b); got != "" {
			t.Errorf("Normalize(%q) = %q, want %q", b, got, "")
		}
	}
}

func TestIsLocallyAdministered(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"02:00:00:00:00:01": true,  // U/L set
		"06:11:22:33:44:55": true,  // 0x06 = 0b0000_0110
		"da:a1:19:00:00:01": true,  // 0xda = 0b1101_1010
		"52:54:00:12:34:56": true,  // QEMU
		"02:00:00":          true,  // bare prefix
		"00:50:56:aa:bb:cc": false, // VMware, globally administered
		"00:0C:29:11:22:33": false,
		"08:00:27:11:22:33": false,
		"01:00:5e:00:00:01": false, // multicast but globally administered
		"b8:27:eb:01:02:03": false,
		"00:50:56":          false, // bare prefix
	}
	for mac, want := range cases {
		if got := IsLocallyAdministered(mac); got != want {
			t.Errorf("IsLocallyAdministered(%q) = %v, want %v", mac, got, want)
		}
	}
}

func TestIsMulticast(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"01:00:5e:00:00:01": true,
		"01:00:0c:cc:cc:cc": true,
		"33:33:00:00:00:01": true,
		"ff:ff:ff:ff:ff:ff": true,
		"00:50:56:aa:bb:cc": false,
		"02:00:00:00:00:01": false,
	}
	for mac, want := range cases {
		if got := IsMulticast(mac); got != want {
			t.Errorf("IsMulticast(%q) = %v, want %v", mac, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"AA-BB-CC-DD-EE-FF":       "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":          "aa:bb:cc:dd:ee:ff",
		"a:b:c:d:e:f":             "0a:0b:0c:0d:0e:0f",
		"aabbccddeeff":            "aa:bb:cc:dd:ee:ff",
		" AA:BB:CC:DD:EE:FF ":     "aa:bb:cc:dd:ee:ff",
		"aa:bb:cc:dd:ee:ff:00:11": "aa:bb:cc:dd:ee:ff", // EUI-64 truncated
		"aabbccddeef":             "",
		"aaa:bb:cc:dd:ee:ff":      "",
		"aabbcc":                  "", // a prefix is not a full address
		"":                        "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseBits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in    string
		bits  int
		ok    bool
		first byte
	}{
		{"005056", 24, true, 0x00},
		{"00:50:56", 24, true, 0x00},
		{"0050561", 28, true, 0x00},
		{"005056aab", 36, true, 0x00},
		{"005056aabbcc", 48, true, 0x00},
		{"02:50:56:aa:bb:cc:dd:ee", 48, true, 0x02}, // EUI-64 truncated to 48
		{"00505", 0, false, 0},
		{"", 0, false, 0},
	}
	for _, c := range cases {
		b, bits, ok := Parse(c.in)
		if ok != c.ok || bits != c.bits {
			t.Errorf("Parse(%q) = bits %d, ok %v; want bits %d, ok %v", c.in, bits, ok, c.bits, c.ok)
			continue
		}
		if ok && b[0] != c.first {
			t.Errorf("Parse(%q) first octet = %#02x, want %#02x", c.in, b[0], c.first)
		}
	}
}

// TestDatabaseLoaded checks the embedded blob really decoded, rather than
// silently falling back to the empty database.
func TestDatabaseLoaded(t *testing.T) {
	t.Parallel()
	d := load()
	if len(d.mal) < 30000 {
		t.Errorf("MA-L table has %d entries, want >= 30000", len(d.mal))
	}
	if len(d.mam) < 1000 {
		t.Errorf("MA-M table has %d entries, want >= 1000", len(d.mam))
	}
	if len(d.mas) < 1000 {
		t.Errorf("MA-S table has %d entries, want >= 1000", len(d.mas))
	}
	if len(d.off) < 2 || d.pool == "" {
		t.Fatalf("name pool is empty")
	}
	// Keys must be sorted ascending for the binary searches to be correct.
	for i := 1; i < len(d.mal); i++ {
		if d.mal[i] <= d.mal[i-1] {
			t.Fatalf("MA-L keys not strictly ascending at %d", i)
		}
	}
	for i := 1; i < len(d.mam); i++ {
		if d.mam[i] <= d.mam[i-1] {
			t.Fatalf("MA-M keys not strictly ascending at %d", i)
		}
	}
	for i := 1; i < len(d.mas); i++ {
		if d.mas[i] <= d.mas[i-1] {
			t.Fatalf("MA-S keys not strictly ascending at %d", i)
		}
	}
}

// TestDecodeCorrupt makes sure a damaged blob degrades to an empty database
// instead of panicking.
func TestDecodeCorrupt(t *testing.T) {
	t.Parallel()
	inputs := [][]byte{
		nil,
		{},
		[]byte("NETYOUI2"),
		[]byte("NETYOUI2\x01"),
		[]byte("NETYOUI2\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"),
		[]byte("NOTMAGIC\x01\x00"),
		[]byte("NETYOUI2\x02\x00"),
		append([]byte("NETYOUI2\x01"), 0x02, 0x03, 0x02, 'a', 'b', 'c', 'd', 'e'),
	}
	for i, in := range inputs {
		var d database
		if err := decode(&d, in); err == nil && i < 4 {
			t.Errorf("decode(input %d) = nil error, want failure", i)
		}
		// Whatever the outcome, the partially filled database must be safe.
		_, _ = d.find32(d.mal, d.malName, 0x005056)
		_ = d.name(0)
		_ = d.name(1 << 30)
	}
}

// TestConcurrentLoad exercises the sync.OnceValue initialisation from many
// goroutines at once; -race turns this into a real data-race check.
func TestConcurrentLoad(t *testing.T) {
	t.Parallel()
	const goroutines = 64
	macs := []string{
		"00:50:56:aa:bb:cc", "00:0C:29:11:22:33", "08:00:27:11:22:33",
		"00:1A:11:11:22:33", "02:00:00:00:00:01", "garbage",
		"70:B3:D5:00:10:00", "00:55:DA:11:23:45",
	}
	want := make([]string, len(macs))
	for i, m := range macs {
		want[i] = Lookup(m)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan string, goroutines*len(macs))
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for round := 0; round < 50; round++ {
				for i, m := range macs {
					if got := Lookup(m); got != want[i] {
						errs <- m + " => " + got
						return
					}
					_ = IsLocallyAdministered(m)
					_ = Normalize(m)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("inconsistent concurrent lookup: %s", e)
	}
}

func BenchmarkLookup(b *testing.B) {
	load()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if Lookup("00:0c:29:aa:bb:cc") == "" {
			b.Fatal("miss")
		}
	}
}

func BenchmarkLookupMiss(b *testing.B) {
	load()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Lookup("ac:de:48:11:22:33")
	}
}

func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Parse("00:0c:29:aa:bb:cc")
	}
}

// BenchmarkColdLoad measures a full cold database load, decompression
// included; it must stay well under the ~30 ms budget.
func BenchmarkColdLoad(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var d database
		zr, err := gzip.NewReader(bytes.NewReader(dbGz))
		if err != nil {
			b.Fatal(err)
		}
		raw, err := io.ReadAll(zr)
		if err != nil {
			b.Fatal(err)
		}
		zr.Close()
		if err := decode(&d, raw); err != nil {
			b.Fatal(err)
		}
	}
}
