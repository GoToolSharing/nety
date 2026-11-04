package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/vaadata/nety/internal/portscan"
	"github.com/vaadata/nety/internal/rawnet"
)

// Unprivileged engine tuning.
const (
	connectTimeout   = 1200 * time.Millisecond
	connectHostConc  = 64 // hosts probed concurrently by TCP connect ping
	maxConnectPerSec = 2000
)

// discoverUnprivileged runs ICMP echo (ping sockets), TCP connect ping and
// UDP probes concurrently, all feeding the collector.
func (d *Discoverer) discoverUnprivileged(ctx context.Context, cfg *config, col *collector, log *slog.Logger) error {
	n := cfg.space.Len()
	cookie := rawnet.NewCookie()
	seed := rand.Uint64()

	var parts int64
	useICMP := cfg.has(MethodICMPEcho)
	useTCP := cfg.has(MethodTCPSyn) || cfg.has(MethodTCPAck)
	useUDP := cfg.has(MethodUDP)
	for _, b := range []bool{useICMP, useTCP, useUDP} {
		if b {
			parts++
		}
	}
	if cfg.has(MethodARP) || cfg.has(MethodICMPTimestamp) {
		log.Info("arp / icmp-timestamp need raw sockets; skipped in unprivileged mode")
	}
	if parts == 0 {
		return nil
	}
	prog := newProgressCounter(cfg.progress, int64(n)*parts)

	// Share the packet budget between the concurrent probe families.
	icmpRate := max(cfg.rate/int(parts), 1)
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil && ctx.Err() == nil {
				log.Warn("unprivileged probe family failed", "family", name, "err", err)
				errs <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	if useICMP {
		run(MethodICMPEcho, func() error {
			return d.pingSweep(ctx, cfg, col, cookie, seed, rawnet.NewLimiter(icmpRate, 0), prog)
		})
	}
	if useTCP {
		run(labelTCPConnect, func() error {
			return d.connectSweep(ctx, cfg, col, seed, rawnet.NewLimiter(min(icmpRate, maxConnectPerSec), 0), prog)
		})
	}
	if useUDP {
		run(MethodUDP, func() error {
			return d.udpSweep(ctx, cfg, col, seed, rawnet.NewLimiter(icmpRate, 0), prog)
		})
	}
	wg.Wait()
	close(errs)
	// Partial failures (e.g. ping sockets not allowed) are not fatal as long
	// as one family ran; report the error only if all of them failed.
	var all []error
	for e := range errs {
		all = append(all, e)
	}
	if int64(len(all)) == parts {
		return errors.Join(all...)
	}
	return nil
}

// pingSweep sends ICMP echo requests over unprivileged ping sockets
// ("udp4"/"udp6" ICMP endpoints; Linux needs net.ipv4.ping_group_range to
// include the process group, macOS always allows them). The kernel may
// rewrite the echo identifier, so replies are validated by a keyed cookie
// carried in the payload.
func (d *Discoverer) pingSweep(ctx context.Context, cfg *config, col *collector, cookie rawnet.Cookie, seed uint64, lim *rawnet.Limiter, prog *progressCounter) error {
	n := cfg.space.Len()
	var c4, c6 *icmp.PacketConn
	var err4, err6 error
	c4, err4 = icmp.ListenPacket("udp4", "0.0.0.0")
	if err4 == nil {
		defer c4.Close()
	}
	c6, err6 = icmp.ListenPacket("udp6", "::")
	if err6 == nil {
		defer c6.Close()
	}
	if c4 == nil && c6 == nil {
		prog.add(int64(n))
		return fmt.Errorf("ping sockets unavailable: %v", errors.Join(err4, err6))
	}
	start := time.Now()
	rctx, rcancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	recv := func(c *icmp.PacketConn, v6 bool) {
		defer wg.Done()
		buf := make([]byte, 1500)
		proto := 1
		if v6 {
			proto = 58
		}
		for rctx.Err() == nil {
			_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			nr, from, err := c.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				if rctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			ua, ok := from.(*net.UDPAddr)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ua.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !cfg.space.Contains(ip) {
				continue
			}
			m, err := icmp.ParseMessage(proto, buf[:nr])
			if err != nil {
				continue
			}
			echo, ok := m.Body.(*icmp.Echo)
			if !ok || (m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply) || len(echo.Data) < 16 {
				continue
			}
			if binary.BigEndian.Uint64(echo.Data[0:8]) != cookie.Sum64(ip, 0, 0, rawnet.TagICMPEcho) {
				continue
			}
			sentAt := time.Duration(binary.BigEndian.Uint64(echo.Data[8:16]))
			rtt := time.Since(start) - sentAt
			if rtt < 0 || rtt > time.Minute {
				rtt = 0
			}
			col.add(ip, MethodICMPEcho, nil, 0, rtt)
		}
	}
	if c4 != nil {
		wg.Add(1)
		go recv(c4, false)
	}
	if c6 != nil {
		wg.Add(1)
		go recv(c6, true)
	}

	var sendErr error
	batch, budget := lim.Batch(), 0
	payload := make([]byte, 24)
send:
	for round := 0; round <= cfg.retries; round++ {
		perm := rawnet.NewPermutation(n, seed^uint64(round+1)*0x2545f4914f6cdd1d)
		for i := uint64(0); i < n; i++ {
			if i&1023 == 1023 {
				prog.add(1024 / int64(cfg.retries+1))
			}
			ip := cfg.space.At(perm.At(i))
			if col.up(ip) {
				continue
			}
			c := c4
			var typ icmp.Type = ipv4.ICMPTypeEcho
			if ip.Is6() {
				c, typ = c6, ipv6.ICMPTypeEchoRequest
			}
			if c == nil {
				continue
			}
			if budget == 0 {
				if err := lim.Wait(ctx, batch); err != nil {
					sendErr = err
					break send
				}
				budget = batch
			}
			budget--
			binary.BigEndian.PutUint64(payload[0:8], cookie.Sum64(ip, 0, 0, rawnet.TagICMPEcho))
			binary.BigEndian.PutUint64(payload[8:16], uint64(time.Since(start)))
			copy(payload[16:], "nety-png")
			msg := icmp.Message{Type: typ, Body: &icmp.Echo{ID: int(uint16(seed)), Seq: round + 1, Data: payload}}
			b, err := msg.Marshal(nil)
			if err != nil {
				continue
			}
			if _, err := c.WriteTo(b, &net.UDPAddr{IP: ip.AsSlice()}); err != nil && errors.Is(err, net.ErrClosed) {
				sendErr = err
				break send
			}
		}
		if round < cfg.retries {
			if err := rawnet.SleepCtx(ctx, min(cfg.wait/2, time.Second)); err != nil {
				sendErr = err
				break
			}
		}
	}
	if sendErr == nil {
		_ = rawnet.SleepCtx(ctx, cfg.wait)
	}
	rcancel()
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return sendErr
}

// connectSweep is the TCP connect ping: for each host (random order, bounded
// concurrency) all TCP ports are dialled in parallel; the first accepted or
// refused connection proves the host is up and cancels the remaining dials.
func (d *Discoverer) connectSweep(ctx context.Context, cfg *config, col *collector, seed uint64, lim *rawnet.Limiter, prog *progressCounter) error {
	n := cfg.space.Len()
	ports := cfg.tcpPorts
	if !cfg.has(MethodTCPSyn) { // ACK ping only: use its port list
		ports = cfg.ackPorts
	}
	timeout := min(connectTimeout, cfg.wait)
	jobs := make(chan netip.Addr, connectHostConc)
	var wg sync.WaitGroup
	for range connectHostConc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				probeHostTCP(ctx, ip, ports, timeout, lim, col)
				prog.add(1)
			}
		}()
	}
	perm := rawnet.NewPermutation(n, seed^0x51ed270b)
feed:
	for i := uint64(0); i < n; i++ {
		ip := cfg.space.At(perm.At(i))
		if col.up(ip) {
			prog.add(1)
			continue
		}
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return nil
}

func probeHostTCP(ctx context.Context, ip netip.Addr, ports []uint16, timeout time.Duration, lim *rawnet.Limiter, col *collector) {
	hctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var once sync.Once
	for _, port := range ports {
		if lim.Wait(hctx, 1) != nil {
			break
		}
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			dctx, dcancel := context.WithTimeout(hctx, timeout)
			defer dcancel()
			start := time.Now()
			var dl net.Dialer
			c, err := dl.DialContext(dctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
			if err == nil {
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetLinger(0)
				}
				_ = c.Close()
			}
			if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
				once.Do(func() {
					col.add(ip, labelTCPConnect+":"+strconv.Itoa(int(port)), nil, 0, time.Since(start))
					cancel()
				})
			}
		}(port)
	}
	wg.Wait()
}

// udpSweep sends the protocol payloads of package portscan to every host's
// UDP ports from unconnected sockets; any datagram coming back from a
// probed (host, port) proves the host is up.
func (d *Discoverer) udpSweep(ctx context.Context, cfg *config, col *collector, seed uint64, lim *rawnet.Limiter, prog *progressCounter) error {
	n := cfg.space.Len()
	c4, err4 := net.ListenUDP("udp4", &net.UDPAddr{})
	if err4 == nil {
		defer c4.Close()
		_ = c4.SetReadBuffer(4 << 20)
	}
	c6, err6 := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
	if err6 == nil {
		defer c6.Close()
		_ = c6.SetReadBuffer(4 << 20)
	}
	if c4 == nil && c6 == nil {
		return fmt.Errorf("udp sockets unavailable: %v", errors.Join(err4, err6))
	}
	probed := map[uint16]bool{}
	for _, p := range cfg.udpPorts {
		probed[p] = true
	}
	rctx, rcancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	recv := func(c *net.UDPConn) {
		defer wg.Done()
		buf := make([]byte, 65536)
		for rctx.Err() == nil {
			_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				if rctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			ip := from.Addr().Unmap()
			if !cfg.space.Contains(ip) {
				continue
			}
			port := from.Port()
			if !probed[port] {
				if !probed[69] { // TFTP answers from a fresh port
					continue
				}
				port = 69
			}
			col.add(ip, MethodUDP+":"+strconv.Itoa(int(port)), nil, 0, 0)
		}
	}
	for _, c := range []*net.UDPConn{c4, c6} {
		if c != nil {
			wg.Add(1)
			go recv(c)
		}
	}
	var sendErr error
	batch, budget := lim.Batch(), 0
send:
	for round := 0; round <= cfg.retries; round++ {
		perm := rawnet.NewPermutation(n, seed^uint64(round+7)*0x9fb21c651e98df25)
		for i := uint64(0); i < n; i++ {
			if i&1023 == 1023 {
				prog.add(1024 / int64(cfg.retries+1))
			}
			ip := cfg.space.At(perm.At(i))
			if col.up(ip) {
				continue
			}
			c := c4
			if ip.Is6() {
				c = c6
			}
			if c == nil {
				continue
			}
			for _, port := range cfg.udpPorts {
				for _, pl := range portscan.UDPPayloads(port) {
					if budget == 0 {
						if err := lim.Wait(ctx, batch); err != nil {
							sendErr = err
							break send
						}
						budget = batch
					}
					budget--
					if _, err := c.WriteToUDPAddrPort(pl, netip.AddrPortFrom(ip, port)); err != nil && errors.Is(err, net.ErrClosed) {
						sendErr = err
						break send
					}
				}
			}
		}
		if round < cfg.retries {
			if err := rawnet.SleepCtx(ctx, min(cfg.wait/2, time.Second)); err != nil {
				sendErr = err
				break
			}
		}
	}
	if sendErr == nil {
		_ = rawnet.SleepCtx(ctx, cfg.wait)
	}
	rcancel()
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return sendErr
}
