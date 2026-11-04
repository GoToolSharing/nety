package netif

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestVLANName(t *testing.T) {
	cases := []struct {
		parent string
		id     int
		want   string
	}{
		{"eth0", 20, "eth0.20"},
		{"enp0s31f6", 4094, "enp0s31f6.4094"},
		{"averylonginterfacename", 100, "averylongin.100"}, // truncated to IFNAMSIZ-1 = 15 bytes
	}
	for _, c := range cases {
		got := VLANName(c.parent, c.id)
		if got != c.want {
			t.Errorf("VLANName(%q, %d) = %q, want %q", c.parent, c.id, got, c.want)
		}
		if len(got) > 15 {
			t.Errorf("VLANName(%q, %d) = %q exceeds IFNAMSIZ-1", c.parent, c.id, got)
		}
	}
}

func TestParseVLANName(t *testing.T) {
	parent, id, ok := ParseVLANName("eth0.20")
	if !ok || parent != "eth0" || id != 20 {
		t.Errorf("got %q/%d/%v", parent, id, ok)
	}
	for _, bad := range []string{"eth0", "eth0.", ".20", "eth0.0", "eth0.4095", "eth0.abc", ""} {
		if _, _, ok := ParseVLANName(bad); ok {
			t.Errorf("ParseVLANName(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestValidVLANID(t *testing.T) {
	for _, id := range []int{1, 42, 4094} {
		if !ValidVLANID(id) {
			t.Errorf("%d should be valid", id)
		}
	}
	for _, id := range []int{-1, 0, 4095, 9999} {
		if ValidVLANID(id) {
			t.Errorf("%d should be rejected", id)
		}
	}
}

func TestPrefixesContain(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
	}
	if !PrefixesContain(prefixes, netip.MustParseAddr("10.4.5.6")) {
		t.Error("10.4.5.6 should be inside 10.0.0.0/8")
	}
	if PrefixesContain(prefixes, netip.MustParseAddr("172.16.0.1")) {
		t.Error("172.16.0.1 should not match")
	}
	if PrefixesContain(nil, netip.MustParseAddr("10.0.0.1")) {
		t.Error("an empty prefix list must never match")
	}
}

func TestHostInPrefix(t *testing.T) {
	p := netip.MustParsePrefix("192.168.5.0/24")
	gw, ok := HostInPrefix(p, 1)
	if !ok || gw.String() != "192.168.5.1" {
		t.Errorf("first host = %v/%v", gw, ok)
	}
	// Offset 0 is the network address of an IPv4 /24.
	if _, ok := HostInPrefix(p, 0); ok {
		t.Error("the network address must be rejected")
	}
	// Offset 255 is the broadcast address.
	if _, ok := HostInPrefix(p, 255); ok {
		t.Error("the broadcast address must be rejected")
	}
	if _, ok := HostInPrefix(p, 300); ok {
		t.Error("an offset beyond the prefix must fail")
	}
	// A /31 has no network/broadcast reservation.
	p31 := netip.MustParsePrefix("10.0.0.0/31")
	if a, ok := HostInPrefix(p31, 0); !ok || a.String() != "10.0.0.0" {
		t.Errorf("/31 offset 0 = %v/%v", a, ok)
	}
}

func TestHostFromEnd(t *testing.T) {
	p := netip.MustParsePrefix("192.168.5.0/24")
	a, ok := HostFromEnd(p, 5)
	if !ok || a.String() != "192.168.5.250" {
		t.Errorf("HostFromEnd(5) = %v/%v, want 192.168.5.250", a, ok)
	}
	if _, ok := HostFromEnd(p, 0); ok {
		t.Error("offset 0 is the broadcast address and must be rejected")
	}
	p6 := netip.MustParsePrefix("2001:db8::/64")
	a6, ok := HostFromEnd(p6, 1)
	if !ok || a6.String() != "2001:db8::ffff:ffff:ffff:fffe" {
		t.Errorf("IPv6 HostFromEnd = %v/%v", a6, ok)
	}
}

func TestFormatPrefixes(t *testing.T) {
	in := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16")}
	if got := FormatPrefixes(in); got != "10.0.0.0/8,192.168.0.0/16" {
		t.Errorf("got %q", got)
	}
	if got := FormatPrefixes(nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// Cleanup tracker
// ---------------------------------------------------------------------------

func TestRestoreAllUndoesInReverseOrder(t *testing.T) {
	resetTracker(t)

	var order []string
	trackChange("first", func() error { order = append(order, "first"); return nil })
	trackChange("second", func() error { order = append(order, "second"); return nil })
	trackChange("third", func() error { order = append(order, "third"); return nil })

	if got := PendingChanges(); !reflect.DeepEqual(got, []string{"first", "second", "third"}) {
		t.Fatalf("pending = %v", got)
	}
	if err := RestoreAll(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !reflect.DeepEqual(order, []string{"third", "second", "first"}) {
		t.Errorf("undo order = %v, want LIFO", order)
	}
	if got := PendingChanges(); len(got) != 0 {
		t.Errorf("pending after restore = %v", got)
	}
}

func TestRestoreAllIsIdempotent(t *testing.T) {
	resetTracker(t)
	calls := 0
	trackChange("once", func() error { calls++; return nil })
	_ = RestoreAll()
	_ = RestoreAll()
	if calls != 1 {
		t.Errorf("undo ran %d times, want 1", calls)
	}
}

func TestRestoreAllContinuesAfterFailure(t *testing.T) {
	resetTracker(t)
	ran := 0
	trackChange("ok-1", func() error { ran++; return nil })
	trackChange("boom", func() error { return errors.New("kaboom") })
	trackChange("ok-2", func() error { ran++; return nil })

	err := RestoreAll()
	if err == nil {
		t.Fatal("expected the failure to be reported")
	}
	if !strings.Contains(err.Error(), "kaboom") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("error = %v, want it to name the failing change", err)
	}
	if ran != 2 {
		t.Errorf("%d other undos ran, want 2: one failure must not abort the cleanup", ran)
	}
}

func TestRestoreAllSurvivesPanickingUndo(t *testing.T) {
	resetTracker(t)
	ran := false
	trackChange("sane", func() error { ran = true; return nil })
	trackChange("panics", func() error { panic("undo exploded") })

	err := RestoreAll()
	if err == nil {
		t.Fatal("a panicking undo must be reported as an error")
	}
	if !ran {
		t.Error("the remaining undo did not run after the panic")
	}
}

func TestForgetChange(t *testing.T) {
	resetTracker(t)
	calls := 0
	id := trackChange("explicitly reverted", func() error { calls++; return nil })
	trackChange("still pending", func() error { calls++; return nil })
	forgetChange(id)

	if got := PendingChanges(); len(got) != 1 || got[0] != "still pending" {
		t.Fatalf("pending = %v", got)
	}
	_ = RestoreAll()
	if calls != 1 {
		t.Errorf("%d undos ran, want only the one that was not forgotten", calls)
	}
	forgetChange(0) // must be a no-op
}

// resetTracker isolates a test from the process-wide change registry.
func resetTracker(t *testing.T) {
	t.Helper()
	clear := func() {
		tracker.mu.Lock()
		tracker.changes = nil
		tracker.mu.Unlock()
	}
	clear()
	t.Cleanup(clear)
}
