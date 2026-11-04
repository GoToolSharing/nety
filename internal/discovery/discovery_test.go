package discovery

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/engine"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestNormalize(t *testing.T) {
	c, err := normalize(engine.DiscoveryOptions{
		Targets:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/30")},
		Excludes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/32")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.space.Len() != 3 || c.rate != DefaultRate || c.retries != DefaultRetries || c.wait != DefaultTimeout {
		t.Fatalf("defaults %+v", c)
	}
	if len(c.methods) != len(DefaultMethods) || !slices.Equal(c.udpPorts, DefaultUDPPorts) || !slices.Equal(c.ackPorts, DefaultACKPorts) {
		t.Fatal("default methods/ports")
	}
	c, err = normalize(engine.DiscoveryOptions{Targets: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}, Methods: []string{"ICMP", "tcp"}, Retries: -1, TCPPorts: []uint16{22, 22, 0}})
	if err != nil || !c.has(MethodICMPEcho) || !c.has(MethodTCPSyn) || c.retries != 0 || !slices.Equal(c.tcpPorts, []uint16{22}) {
		t.Fatalf("custom %v %+v", err, c)
	}
	if _, err := normalize(engine.DiscoveryOptions{Methods: []string{"bogus"}}); err == nil {
		t.Fatal("expected unknown method error")
	}
}

func TestCollectorMerge(t *testing.T) {
	var mu sync.Mutex
	var got []engine.DiscoveredHost
	c := newCollector(func(h engine.DiscoveredHost) { mu.Lock(); got = append(got, h); mu.Unlock() }, nil)
	c.window = 50 * time.Millisecond
	ip := netip.MustParseAddr("10.0.0.5")
	c.add(ip, "icmp-echo", nil, 64, 3*time.Millisecond)
	c.add(ip, "tcp-syn:445", nil, 0, time.Millisecond)
	c.add(ip, "icmp-echo", net.HardwareAddr{2, 0, 0, 0, 0, 1}, 0, 0)
	if !c.up(ip) || c.up(netip.MustParseAddr("10.0.0.6")) {
		t.Fatal("up")
	}
	time.Sleep(150 * time.Millisecond)
	c.add(ip, "udp:53", nil, 0, 0) // after emission: ignored
	c.add(netip.MustParseAddr("10.0.0.7"), "arp", nil, 0, 0)
	c.close()
	c.add(netip.MustParseAddr("10.0.0.8"), "arp", nil, 0, 0) // after close: ignored
	if len(got) != 2 {
		t.Fatalf("got %d hosts: %+v", len(got), got)
	}
	h := got[0]
	if h.IP != ip || !slices.Equal(h.Methods, []string{"icmp-echo", "tcp-syn:445"}) || h.TTL != 64 || h.RTT != time.Millisecond || h.MAC.String() != "02:00:00:00:00:01" {
		t.Fatalf("merged %+v", h)
	}
}

func TestUnprivilegedConnectPing(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	d := New(quiet()).(*Discoverer)
	cfg, err := normalize(engine.DiscoveryOptions{
		Targets: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		Methods: []string{MethodTCPSyn}, TCPPorts: []uint16{port}, Timeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []engine.DiscoveredHost
	var mu sync.Mutex
	col := newCollector(func(h engine.DiscoveredHost) { mu.Lock(); got = append(got, h); mu.Unlock() }, nil)
	if err := d.discoverUnprivileged(context.Background(), cfg, col, quiet()); err != nil {
		t.Fatal(err)
	}
	col.close()
	if len(got) != 1 || got[0].IP != netip.MustParseAddr("127.0.0.1") || got[0].Methods[0] != "tcp-connect:"+strconv.Itoa(int(port)) {
		t.Fatalf("got %+v", got)
	}
}

func TestDiscoverCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := New(quiet()).Discover(ctx, engine.DiscoveryOptions{
		Targets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/28")}, Methods: []string{MethodTCPSyn},
	}, func(engine.DiscoveredHost) {})
	if err == nil {
		t.Fatal("expected ctx error")
	}
}

func TestDiscoverEmpty(t *testing.T) {
	err := New(quiet()).Discover(context.Background(), engine.DiscoveryOptions{
		Targets:  []netip.Prefix{netip.MustParsePrefix("192.0.2.0/30")},
		Excludes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}, func(engine.DiscoveredHost) { t.Fatal("unexpected host") })
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnprivilegedPingLoopback(t *testing.T) {
	var got []engine.DiscoveredHost
	var mu sync.Mutex
	err := New(quiet()).Discover(context.Background(), engine.DiscoveryOptions{
		Targets: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		Methods: []string{MethodICMPEcho}, Timeout: 300 * time.Millisecond, Retries: -1,
	}, func(h engine.DiscoveredHost) { mu.Lock(); got = append(got, h); mu.Unlock() })
	if err != nil {
		t.Skipf("ping sockets unavailable here: %v", err)
	}
	if len(got) != 1 || got[0].Methods[0] != MethodICMPEcho {
		t.Fatalf("got %+v", got)
	}
}
