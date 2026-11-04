package segment

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/GoToolSharing/nety/internal/netif"
)

// Everything in this package that changes the operator's machine or the
// client's switch goes through sysApplier, for two reasons: the netif-backed
// implementation keeps the netlink/AF_PACKET details out of the orchestration
// code, and a recording fake lets the tests prove that every change is undone
// - including when the scan is cancelled half way through.

type sysApplier interface {
	HasRoute(ip netip.Addr) bool
	AddRoute(dst netip.Prefix, via netip.Addr, iface string) error
	DelRoute(dst netip.Prefix, via netip.Addr, iface string) error

	AddVLAN(parent string, vlanID int) (string, error)
	DeleteVLAN(name string) error

	AddAddr(iface string, p netip.Prefix) error
	DelAddr(iface string, p netip.Prefix) error

	// DHCP obtains a lease on iface and applies the address. It returns the
	// configured prefix and the lease's router.
	DHCP(ctx context.Context, iface string, timeout time.Duration) (netip.Prefix, netip.Addr, error)
	// ReleaseDHCP gives back a lease taken on iface. It must be called while
	// the interface still exists, and is a no-op when no lease was taken.
	ReleaseDHCP(iface string) error
	// The Undo* calls revert a change only if this process made it, so a
	// sub-interface, address or route that was already on the operator's
	// machine is never removed by our cleanup.
	UndoVLAN(name string) error
	UndoAddr(iface string, p netip.Prefix) error
	UndoRoute(dst netip.Prefix, via netip.Addr, iface string) error
	// IsWireless reports whether iface is a Wi-Fi association rather than a
	// wired switch port.
	IsWireless(iface string) bool

	// RequestTrunk asks the switch port to form an 802.1Q trunk over DTP and
	// waits for it to converge.
	RequestTrunk(ctx context.Context, iface, domain string, settle time.Duration) error
	// ReleaseTrunk advertises access mode again. Best effort: DTP has no
	// explicit teardown.
	ReleaseTrunk(iface, domain string) error

	SendFrames(iface string, frames ...[]byte) error
	InterfaceMAC(iface string) (net.HardwareAddr, error)
}

// netifApplier is the production implementation.
type netifApplier struct{}

func (netifApplier) HasRoute(ip netip.Addr) bool { return netif.HasRoute(ip) }

func (netifApplier) AddRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	return netif.AddRoute(dst, via, iface)
}

func (netifApplier) DelRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	return netif.DelRoute(dst, via, iface)
}

func (netifApplier) AddVLAN(parent string, vlanID int) (string, error) {
	return netif.AddVLAN(parent, vlanID)
}

func (netifApplier) DeleteVLAN(name string) error { return netif.DeleteVLAN(name) }

func (netifApplier) AddAddr(iface string, p netip.Prefix) error { return netif.AddAddr(iface, p) }
func (netifApplier) DelAddr(iface string, p netip.Prefix) error { return netif.DelAddr(iface, p) }

func (netifApplier) DHCP(ctx context.Context, iface string, timeout time.Duration) (netip.Prefix, netip.Addr, error) {
	lease, err := netif.ConfigureDHCP(ctx, iface, netif.DHCPConfig{Timeout: timeout, Release: true})
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, err
	}
	return lease.CIDR(), lease.Router, nil
}

func (netifApplier) ReleaseDHCP(iface string) error { return netif.ReleaseDHCP(iface) }

func (netifApplier) IsWireless(iface string) bool { return netif.IsWireless(iface) }

func (netifApplier) UndoVLAN(name string) error { return netif.UndoVLAN(name) }

func (netifApplier) UndoAddr(iface string, p netip.Prefix) error {
	return netif.UndoAddr(iface, p)
}

func (netifApplier) UndoRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	return netif.UndoRoute(dst, via, iface)
}

func (netifApplier) RequestTrunk(ctx context.Context, iface, domain string, settle time.Duration) error {
	return netif.RequestTrunk(ctx, iface, domain, 3, settle)
}

func (netifApplier) ReleaseTrunk(iface, domain string) error {
	return netif.ReleaseTrunk(iface, domain)
}

func (netifApplier) SendFrames(iface string, frames ...[]byte) error {
	return netif.SendFrames(iface, frames...)
}

func (netifApplier) InterfaceMAC(iface string) (net.HardwareAddr, error) {
	return netif.InterfaceMAC(iface)
}

// ---------------------------------------------------------------------------
// Cleanup scope
// ---------------------------------------------------------------------------

// cleanup is the stack of undo actions for one Test call. Every setup step
// pushes its undo immediately after it succeeds, so a cancellation or a panic
// between two steps still unwinds what has been done.
type cleanup struct {
	mu    sync.Mutex
	stack []undoStep
	done  bool
}

type undoStep struct {
	desc string
	fn   func() error
}

func newCleanup() *cleanup { return &cleanup{} }

func (c *cleanup) push(desc string, fn func() error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stack = append(c.stack, undoStep{desc: desc, fn: fn})
}

// pending lists the undo descriptions, oldest first.
func (c *cleanup) pending() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.stack))
	for _, s := range c.stack {
		out = append(out, s.desc)
	}
	return out
}

// unwindTo pops and runs undo actions until the stack is back to depth n. It
// is used to tear down one technique's setup before the next one starts.
func (c *cleanup) unwindTo(n int, log *slog.Logger) error {
	var errs []error
	for {
		c.mu.Lock()
		if len(c.stack) <= n {
			c.mu.Unlock()
			break
		}
		step := c.stack[len(c.stack)-1]
		c.stack = c.stack[:len(c.stack)-1]
		c.mu.Unlock()

		if err := runStep(step); err != nil {
			errs = append(errs, err)
			if log != nil {
				log.Warn("segment: cleanup step failed", "step", step.desc, "err", err)
			}
			continue
		}
		if log != nil {
			log.Debug("segment: reverted", "step", step.desc)
		}
	}
	return errors.Join(errs...)
}

func (c *cleanup) depth() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.stack)
}

// restore unwinds everything. It is safe to call twice and never panics, so it
// can be deferred next to a recover.
func (c *cleanup) restore(log *slog.Logger) error {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return nil
	}
	c.done = true
	c.mu.Unlock()
	return c.unwindTo(0, log)
}

func runStep(s undoStep) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("panic while undoing " + s.desc)
		}
	}()
	if s.fn == nil {
		return nil
	}
	return s.fn()
}
