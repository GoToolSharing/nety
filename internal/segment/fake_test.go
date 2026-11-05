package segment

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeApplier records every system change and lets a test assert that each one was
// reverted. Counters are incremented on "add" and decremented on the matching "remove",
// so a non-zero counter at the end of a Test call is a leak.
type fakeApplier struct {
	wireless bool
	mu       sync.Mutex
	calls    []string
	live     map[string]int

	hasRoute    bool
	failAddVLAN error
	failDHCP    error
	failRoute   error
	failFrames  error
	noMAC       bool

	// onAddVLAN runs right after a sub-interface is created, which is where a test
	// injects a cancellation to prove the cleanup still happens.
	onAddVLAN func()
	// onDHCP runs when the sub-interface is being addressed, i.e. once the sub-interface
	// exists and its removal is already registered for cleanup.
	onDHCP func()
}

func newFakeApplier() *fakeApplier {
	return &fakeApplier{live: map[string]int{}}
}

func (f *fakeApplier) record(call string, delta int, key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	if key != "" {
		f.live[key] += delta
		if f.live[key] == 0 {
			delete(f.live, key)
		}
	}
}

func (f *fakeApplier) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// leaks returns the changes that were applied and never reverted.
func (f *fakeApplier) leaks() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for k, v := range f.live {
		out[k] = v
	}
	return out
}

func (f *fakeApplier) assertClean(t *testing.T) {
	t.Helper()
	if leaks := f.leaks(); len(leaks) != 0 {
		t.Fatalf("system changes were not reverted: %v\ncall log: %v", leaks, f.callLog())
	}
}

func (f *fakeApplier) HasRoute(netip.Addr) bool { return f.hasRoute }

func (f *fakeApplier) IsWireless(string) bool { return f.wireless }

func (f *fakeApplier) UndoVLAN(name string) error { return f.DeleteVLAN(name) }

func (f *fakeApplier) UndoAddr(iface string, p netip.Prefix) error { return f.DelAddr(iface, p) }

func (f *fakeApplier) UndoRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	return f.DelRoute(dst, via, iface)
}

func (f *fakeApplier) ReleaseDHCP(iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ReleaseDHCP("+iface+")")
	return nil
}

func (f *fakeApplier) AddRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	if f.failRoute != nil {
		f.record("AddRoute:failed", 0, "")
		return f.failRoute
	}
	f.record("AddRoute "+dst.String()+" via "+via.String()+" dev "+iface, +1, "route:"+dst.String()+"|"+iface)
	return nil
}

func (f *fakeApplier) DelRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	f.record("DelRoute "+dst.String()+" dev "+iface, -1, "route:"+dst.String()+"|"+iface)
	return nil
}

func (f *fakeApplier) AddVLAN(parent string, vlanID int) (string, error) {
	if f.failAddVLAN != nil {
		f.record("AddVLAN:failed", 0, "")
		return "", f.failAddVLAN
	}
	name := parent + "." + itoa(vlanID)
	f.record("AddVLAN "+name, +1, "vlan:"+name)
	if f.onAddVLAN != nil {
		f.onAddVLAN()
	}
	return name, nil
}

func (f *fakeApplier) DeleteVLAN(name string) error {
	f.record("DeleteVLAN "+name, -1, "vlan:"+name)
	return nil
}

func (f *fakeApplier) AddAddr(iface string, p netip.Prefix) error {
	f.record("AddAddr "+p.String()+" dev "+iface, +1, "addr:"+iface+"|"+p.String())
	return nil
}

func (f *fakeApplier) DelAddr(iface string, p netip.Prefix) error {
	f.record("DelAddr "+p.String()+" dev "+iface, -1, "addr:"+iface+"|"+p.String())
	return nil
}

func (f *fakeApplier) DHCP(ctx context.Context, iface string, _ time.Duration) (netip.Prefix, netip.Addr, error) {
	if f.onDHCP != nil {
		f.onDHCP()
	}
	if f.failDHCP != nil {
		f.record("DHCP:failed "+iface, 0, "")
		return netip.Prefix{}, netip.Addr{}, f.failDHCP
	}
	p := netip.MustParsePrefix("10.20.0.77/16")
	f.record("DHCP "+iface, +1, "addr:"+iface+"|"+p.String())
	return p, netip.MustParseAddr("10.20.0.1"), nil
}

func (f *fakeApplier) RequestTrunk(ctx context.Context, iface, domain string, _ time.Duration) error {
	f.record("RequestTrunk "+iface, +1, "trunk:"+iface)
	return nil
}

func (f *fakeApplier) ReleaseTrunk(iface, domain string) error {
	f.record("ReleaseTrunk "+iface, -1, "trunk:"+iface)
	return nil
}

func (f *fakeApplier) SendFrames(iface string, frames ...[]byte) error {
	if f.failFrames != nil {
		return f.failFrames
	}
	f.record("SendFrames "+iface+" x"+itoa(len(frames)), 0, "")
	return nil
}

func (f *fakeApplier) InterfaceMAC(iface string) (net.HardwareAddr, error) {
	if f.noMAC {
		return nil, errors.New("no such device")
	}
	return net.HardwareAddr{0x02, 0x00, 0x00, 0x11, 0x22, 0x33}, nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
