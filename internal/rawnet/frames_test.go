package rawnet

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

// TestZeroValueFrameBuilderDoesNotPanic guards the packet sending path: a
// FrameBuilder is normally built by NewFrameBuilder, but a zero value reached
// serialize with a nil buffer and brought the whole scan down with it.
func TestZeroValueFrameBuilderDoesNotPanic(t *testing.T) {
	var b FrameBuilder
	src, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")

	frame, err := b.ARPRequestL2(
		L2{SrcMAC: src, DstMAC: BroadcastMAC, VLAN: 100},
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
	)
	if err != nil {
		t.Fatalf("zero-value builder: %v", err)
	}
	if len(frame) < 60 {
		t.Fatalf("frame is %d bytes, expected at least the Ethernet minimum", len(frame))
	}
	// And it must produce the same thing the constructor does.
	want, err := NewFrameBuilder().ARPRequestL2(
		L2{SrcMAC: src, DstMAC: BroadcastMAC, VLAN: 100},
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame, want) {
		t.Fatalf("zero value and constructor disagree:\n got %x\nwant %x", frame, want)
	}
}
