package ports

import (
	"slices"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

func TestParseBasic(t *testing.T) {
	cases := []struct {
		spec string
		want []uint16
	}{
		{"22", []uint16{22}},
		{"80,22,22, 443", []uint16{22, 80, 443}},
		{"8000-8003,8001", []uint16{8000, 8001, 8002, 8003}},
		{"65534-", []uint16{65534, 65535}},
		{"-3", []uint16{1, 2, 3}},
		{"T:22,U:53", []uint16{22}},
	}
	for _, c := range cases {
		got, err := Parse(c.spec, model.TCP)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.spec, err)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("Parse(%q) = %v, want %v", c.spec, got, c.want)
		}
	}
}

func TestParseAll(t *testing.T) {
	for _, s := range []string{"all", "1-65535", "ALL", "-"} {
		got, err := Parse(s, model.TCP)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 65535 || got[0] != 1 || got[65534] != 65535 {
			t.Fatalf("%s: len=%d", s, len(got))
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{"", "0", "65536", "abc", "10-5", "top0", "topx", "x:22", ",,"} {
		if _, err := Parse(s, model.TCP); err == nil {
			t.Errorf("Parse(%q) expected error", s)
		}
	}
}

func TestTopLists(t *testing.T) {
	if n := len(tcpTop100Ordered); n != 100 {
		t.Fatalf("tcpTop100Ordered has %d entries", n)
	}
	if n := len(expandRanges(tcpTop1000Ranges)); n < 1000 {
		t.Fatalf("tcp top1000 set has %d entries", n)
	}
	for _, n := range []int{10, 100, 1000} {
		l := TopTCP(n)
		if len(l) != n {
			t.Fatalf("TopTCP(%d) len %d", n, len(l))
		}
		if !slices.IsSorted(l) {
			t.Fatal("not sorted")
		}
		if len(slices.Compact(slices.Clone(l))) != n {
			t.Fatal("duplicates")
		}
	}
	if len(TopTCP(5000)) != 1000 {
		t.Fatal("cap")
	}
	if len(TopUDP(100)) != 100 || len(TopUDP(20)) != 20 {
		t.Fatalf("udp top lens %d %d", len(TopUDP(100)), len(TopUDP(20)))
	}
	top100 := TopTCP(100)
	for _, p := range []uint16{22, 80, 443, 445, 3389} {
		if _, ok := slices.BinarySearch(top100, p); !ok {
			t.Errorf("top100 missing %d", p)
		}
	}
	top1000 := TopTCP(1000)
	for _, p := range []uint16{5985, 636, 3268, 1521, 6379, 27017} {
		if _, ok := slices.BinarySearch(top1000, p); !ok {
			t.Errorf("top1000 missing %d", p)
		}
	}
	if TopTCPOrdered(1)[0] != 80 {
		t.Fatal("ordered")
	}
}

func TestParseCombination(t *testing.T) {
	got, err := Parse("top100,8443,65000-65001", model.TCP)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 102 { // 8443 already in top100
		t.Fatalf("len %d", len(got))
	}
	u, err := Parse("top20", model.UDP)
	if err != nil || len(u) != 20 {
		t.Fatalf("udp top20 %v %d", err, len(u))
	}
	if _, ok := slices.BinarySearch(u, 161); !ok {
		t.Fatal("udp top20 missing 161")
	}
}

func TestServiceName(t *testing.T) {
	if ServiceName(22, model.TCP) != "ssh" || ServiceName(161, model.UDP) != "snmp" ||
		ServiceName(53, model.UDP) != "domain" || ServiceName(445, model.TCP) != "microsoft-ds" {
		t.Fatal("service names")
	}
	if ServiceName(31999, model.TCP) != "" {
		t.Fatal("unknown")
	}
}
