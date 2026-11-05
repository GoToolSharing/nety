package netif

import "sync"

// A DHCP lease taken on a client's VLAN must be given back, and it must be given back
// *while the interface it was taken on still exists*. Registering the release only on the
// process-wide tracker was not enough: the caller (the segmentation engine) deletes its
// sub-interface at the end of a test group, long before shutdown, so by the time the
// tracker ran there was no interface left to send the DHCPRELEASE on and the client's
// pool kept the lease until it expired.
//
// So a release is armed per interface here. The caller consumes it with ReleaseDHCP at
// the right moment in its own cleanup order, and whatever is left over is still swept by
// RestoreAll at shutdown.

var (
	dhcpMu       sync.Mutex
	dhcpReleases = map[string]*armedRelease{}
)

type armedRelease struct {
	once sync.Once
	run  func() error
}

// armDHCPRelease records how to release the lease held on iface, and registers a
// process-wide fallback in case the caller never consumes it.
func armDHCPRelease(iface, label string, release func() error) {
	a := &armedRelease{run: release}

	dhcpMu.Lock()
	// A new lease on the same interface supersedes the previous one.
	dhcpReleases[iface] = a
	dhcpMu.Unlock()

	trackChange(label, func() error { return a.fire() })
}

func (a *armedRelease) fire() error {
	var err error
	a.once.Do(func() { err = a.run() })
	return err
}

// ReleaseDHCP gives back the lease held on iface, if there is one. It is safe to call
// when no lease was taken, and safe to call twice: the release is sent at most once.
func ReleaseDHCP(iface string) error {
	dhcpMu.Lock()
	a := dhcpReleases[iface]
	delete(dhcpReleases, iface)
	dhcpMu.Unlock()

	if a == nil {
		return nil
	}
	return a.fire()
}
