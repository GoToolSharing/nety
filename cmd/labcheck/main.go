// Command labcheck exercises the parts of NETY that unit tests cannot reach:
// the netlink paths that create 802.1Q sub-interfaces, assign addresses and install
// routes, and the discipline that every one of them is tracked and reverted.
//
// It changes the network configuration of the machine it runs on, so it is a lab tool,
// not something to point at a client's laptop. Run it in the lab:
//
//	make lab-verify
//
// What it still cannot prove: that a real switch grants a trunk in response to DTP, or
// that an access port forwards a double-tagged frame. Those need physical switch
// hardware.
package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"

	"github.com/GoToolSharing/nety/internal/netif"
)

func main() {
	parent := flag.String("iface", "eth0", "parent interface to build the sub-interface on")
	vlan := flag.Int("vlan", 4000, "VLAN id to use for the test (must be unused)")
	flag.Parse()

	name, err := netif.AddVLAN(*parent, *vlan)
	if err != nil {
		fail("AddVLAN: %v", err)
	}
	ok("created %s", name)

	p := netip.MustParsePrefix("10.44.0.9/24")
	if err := netif.AddAddr(name, p); err != nil {
		fail("AddAddr: %v", err)
	}
	ok("addressed %s with %s", name, p)

	dst := netip.MustParsePrefix("10.55.0.0/24")
	via := netip.MustParseAddr("10.44.0.1")
	if err := netif.AddRoute(dst, via, name); err != nil {
		fail("AddRoute: %v", err)
	}
	ok("routed %s via %s dev %s", dst, via, name)

	pending := netif.PendingChanges()
	if len(pending) < 3 {
		fail("expected at least 3 tracked changes, got %v", pending)
	}
	ok("tracked %d changes: %v", len(pending), pending)

	// A second AddVLAN on the same id must reuse, not duplicate, and must not be tracked
	// a second time (NETY never deletes what it did not create).
	again, err := netif.AddVLAN(*parent, *vlan)
	if err != nil || again != name {
		fail("re-AddVLAN: %q %v", again, err)
	}
	ok("re-creating is idempotent")

	if err := netif.RestoreAll(); err != nil {
		fail("RestoreAll: %v", err)
	}
	ok("RestoreAll completed")

	if left := netif.PendingChanges(); len(left) != 0 {
		fail("changes left after restore: %v", left)
	}
	if _, err := netif.InterfaceMAC(name); err == nil {
		fail("%s still exists after cleanup", name)
	}
	ok("%s is gone, nothing left behind", name)

	// Undo helpers must be no-ops for things NETY never created.
	if err := netif.UndoVLAN(netif.VLANName(*parent, *vlan+1)); err != nil {
		fail("UndoVLAN on an unknown interface should be a no-op: %v", err)
	}
	ok("undo of an untracked change is a safe no-op")

	// The DTP advertisement NETY would send, decoded and checked against the protocol. A
	// switch is still needed to prove one answers it.
	if err := checkDTPFrame(); err != nil {
		fail("DTP frame: %v", err)
	}
	ok("DTP advertisement is well formed (Cisco SNAP 0x2004, all four TLVs)")

	// The half of dot1q-subif that does not need a switch: real tagged frames over a real
	// kernel path, scanned by the real scanner.
	fmt.Println("\n-- 802.1Q data path (veth across two namespaces) --")
	if err := runVLANDataPathCheck("netychk0", "netychk1"); err != nil {
		fail("802.1Q data path: %v", err)
	}

	fmt.Println("\nALL REAL-KERNEL CHECKS PASSED")
	fmt.Println("Still unproven without physical hardware: that a switch grants")
	fmt.Println("a trunk in response to the DTP frame above.")
}

func fail(f string, a ...any) {
	fmt.Printf("FAIL  "+f+"\n", a...)
	os.Exit(1)
}

func ok(f string, a ...any) { fmt.Printf("ok    "+f+"\n", a...) }
