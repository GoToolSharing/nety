package jobs

import (
	"net/netip"
	"testing"
)

func TestParseTargets(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"10.0.0.0/24", []string{"10.0.0.0/24"}},
		{"10.0.0.5", []string{"10.0.0.5/32"}},
		{"10.0.0.0/24, 192.168.1.0/24", []string{"10.0.0.0/24", "192.168.1.0/24"}},
		{"10.0.0.0-10.0.0.3", []string{"10.0.0.0/30"}},
		{"10.0.0.1-10.0.0.2", []string{"10.0.0.1/32", "10.0.0.2/32"}},
		{"10.0.0.1-4", []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/32"}},
		{"2001:db8::/64", []string{"2001:db8::/64"}},
		// A masked CIDR is normalised.
		{"10.0.0.37/24", []string{"10.0.0.0/24"}},
	}
	for _, tc := range tests {
		got, err := ParseTargets([]string{tc.in})
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i].String() != tc.want[i] {
				t.Fatalf("%s: got %v, want %v", tc.in, got, tc.want)
			}
		}
	}
}

func TestParseTargetsErrors(t *testing.T) {
	for _, bad := range []string{"10.0.0.300", "notanip", "10.0.0.0/99", "10.0.0.5-10.0.0.1", "10.0.0.1-2001:db8::1"} {
		if _, err := ParseTargets([]string{bad}); err == nil {
			t.Fatalf("expected an error for %q", bad)
		}
	}
}

func TestRangeCoversExactly(t *testing.T) {
	start := netip.MustParseAddr("192.168.1.5")
	end := netip.MustParseAddr("192.168.1.20")
	prefixes, err := rangeToPrefixes(start, end)
	if err != nil {
		t.Fatal(err)
	}
	var seen []netip.Addr
	IterateAddresses(prefixes, ExcludeFilter{}, func(a netip.Addr) bool {
		seen = append(seen, a)
		return true
	})
	if len(seen) != 16 {
		t.Fatalf("expected 16 addresses, got %d (%v)", len(seen), prefixes)
	}
	if seen[0] != start || seen[len(seen)-1] != end {
		t.Fatalf("range bounds wrong: %v..%v", seen[0], seen[len(seen)-1])
	}
}

func TestIterateCoversWholePrefix(t *testing.T) {
	prefixes, _ := ParseTargets([]string{"10.0.0.0/29"})
	var got []string
	IterateAddresses(prefixes, ExcludeFilter{}, func(a netip.Addr) bool {
		got = append(got, a.String())
		return true
	})
	want := []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3",
		"10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	// A /32 is a host route and must still be scanned.
	single, _ := ParseTargets([]string{"10.0.0.0/32"})
	count := 0
	IterateAddresses(single, ExcludeFilter{}, func(netip.Addr) bool { count++; return true })
	if count != 1 {
		t.Fatalf("a /32 should yield exactly one address, got %d", count)
	}
}

func TestExcludeFilter(t *testing.T) {
	prefixes, _ := ParseTargets([]string{"10.0.0.0/28"})
	excl, _ := ParseTargets([]string{"10.0.0.4/30"})
	f := NewExcludeFilter(excl)
	var got []string
	IterateAddresses(prefixes, f, func(a netip.Addr) bool {
		got = append(got, a.String())
		return true
	})
	for _, bad := range []string{"10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"} {
		for _, g := range got {
			if g == bad {
				t.Fatalf("%s should have been excluded", bad)
			}
		}
	}
	if len(got) != 12 { // 16 in a /28, minus 4 excluded
		t.Fatalf("expected 10 addresses, got %d: %v", len(got), got)
	}
}

func TestChunkAddresses(t *testing.T) {
	prefixes, _ := ParseTargets([]string{"10.0.0.0/24"})
	var chunks [][]netip.Addr
	ChunkAddresses(prefixes, ExcludeFilter{}, 100, func(c []netip.Addr) bool {
		chunks = append(chunks, c)
		return true
	})
	total := 0
	for _, c := range chunks {
		if len(c) > 100 {
			t.Fatalf("chunk too large: %d", len(c))
		}
		total += len(c)
	}
	if total != 256 {
		t.Fatalf("expected 256 addresses in a /24, got %d", total)
	}
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}

	// Stopping early must not deliver further chunks.
	count := 0
	ChunkAddresses(prefixes, ExcludeFilter{}, 10, func([]netip.Addr) bool {
		count++
		return count < 2
	})
	if count != 2 {
		t.Fatalf("iteration should have stopped after 2 chunks, got %d", count)
	}
}

func TestCountAddresses(t *testing.T) {
	p, _ := ParseTargets([]string{"10.0.0.0/24", "192.168.0.0/16"})
	if n := CountAddresses(p, 1<<30); n != 256+65536 {
		t.Fatalf("got %d", n)
	}
	// A huge IPv6 prefix must saturate instead of overflowing.
	v6, _ := ParseTargets([]string{"2001:db8::/32"})
	if n := CountAddresses(v6, 1000); n != 1000 {
		t.Fatalf("expected the cap, got %d", n)
	}
}

func TestLastAddr(t *testing.T) {
	cases := map[string]string{
		"10.0.0.0/24":    "10.0.0.255",
		"10.0.0.0/32":    "10.0.0.0",
		"10.0.0.8/29":    "10.0.0.15",
		"2001:db8::/126": "2001:db8::3",
	}
	for in, want := range cases {
		p := netip.MustParsePrefix(in)
		if got := lastAddr(p); got.String() != want {
			t.Fatalf("%s: got %s, want %s", in, got, want)
		}
	}
}
