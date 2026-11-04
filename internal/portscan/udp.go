package portscan

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/rawnet"
)

// udpScan sends protocol-specific payloads from one unconnected UDP socket
// per address family and reports every (host, port) that answers. It is
// stateless: replies are matched by their source address/port against the
// scanned set, so memory stays O(hosts + ports).
func (s *Scanner) udpScan(ctx context.Context, j *job) error {
	wait := j.opts.Timeout
	if wait <= 0 {
		wait = DefaultUDPWait
	}
	rate := j.opts.Rate
	if rate <= 0 {
		rate = DefaultUDPRate
	}
	var has4, has6 bool
	for _, h := range j.hosts {
		if h.Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	lc := net.ListenConfig{}
	if j.opts.SourcePort != 0 {
		lc.Control = reuseControl
	}
	var conn4, conn6 *net.UDPConn
	open := func(network, addr string) (*net.UDPConn, error) {
		pc, err := lc.ListenPacket(ctx, network, net.JoinHostPort(addr, fmt.Sprint(j.opts.SourcePort)))
		if err != nil {
			return nil, err
		}
		uc := pc.(*net.UDPConn)
		_ = uc.SetReadBuffer(8 << 20)
		_ = uc.SetWriteBuffer(4 << 20)
		return uc, nil
	}
	var err error
	if has4 {
		if conn4, err = open("udp4", "0.0.0.0"); err != nil {
			return fmt.Errorf("portscan: udp4 socket: %w", err)
		}
		defer conn4.Close()
	}
	if has6 {
		if conn6, err = open("udp6", "::"); err != nil {
			if conn4 == nil {
				return fmt.Errorf("portscan: udp6 socket: %w", err)
			}
			j.log.Warn("udp6 socket unavailable, skipping IPv6 hosts", "err", err)
		} else {
			defer conn6.Close()
		}
	}

	n := j.size()
	hidx := newHostIndex(j.hosts)
	pidx := newPortIndex(j.ports)
	done := newDoneSet(n)
	limiter := rawnet.NewLimiter(rate, max(rate/100, 1))

	rctx, rcancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	recv := func(c *net.UDPConn) {
		defer wg.Done()
		buf := make([]byte, 65536)
		for rctx.Err() == nil {
			_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			nr, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				if rctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				// ICMP errors surface as transient read errors on some
				// systems: ignore them.
				continue
			}
			h, ok := hidx.get(from.Addr())
			if !ok {
				continue
			}
			port := from.Port()
			p := pidx[port]
			if p < 0 {
				// TFTP answers from a fresh port: attribute opcode DATA/ERROR
				// replies to 69 when it was probed.
				if pidx[69] >= 0 && nr >= 4 && buf[0] == 0 && (buf[1] == 3 || buf[1] == 5) {
					port, p = 69, pidx[69]
				} else {
					continue
				}
			}
			idx := uint64(h)*uint64(len(j.ports)) + uint64(p)
			if done.testAndSet(idx) {
				continue
			}
			j.emit.emit(engine.PortResult{
				IP: j.hosts[h], Port: port, Proto: model.UDP, State: model.PortOpen,
				Reason: "udp-response",
			})
		}
	}
	for _, c := range []*net.UDPConn{conn4, conn6} {
		if c != nil {
			wg.Add(1)
			go recv(c)
		}
	}
	stopRecv := func() {
		rcancel()
		wg.Wait()
	}

	seed := rand.Uint64()
	var sendErr error
	sent := 0
send:
	for round := 0; round <= j.retries; round++ {
		perm := rawnet.NewPermutation(n, seed^uint64(round+1)*0xa0761d6478bd642f)
		batch, budget := limiter.Batch(), 0
		for i := uint64(0); i < n; i++ {
			idx := perm.At(i)
			h, p := j.split(idx)
			host, port := j.hosts[h], j.ports[p]
			payloads := UDPPayloads(port)
			if done.has(idx) {
				j.prog.add(int64(len(payloads)))
				continue
			}
			c := conn4
			if host.Is6() {
				c = conn6
			}
			if c == nil {
				j.prog.add(int64(len(payloads)))
				continue
			}
			dst := netip.AddrPortFrom(host, port)
			for _, pl := range payloads {
				if budget == 0 {
					if err := limiter.Wait(ctx, batch); err != nil {
						sendErr = err
						break send
					}
					budget = batch
				}
				budget--
				if err := writeUDP(c, pl, dst); err != nil {
					if isFatalSendError(err) {
						sendErr = fmt.Errorf("portscan: udp send to %s: %w", dst, err)
						break send
					}
					j.log.Debug("udp send", "dst", dst, "err", err)
				}
				sent++
				j.prog.add(1)
			}
		}
		// Short pause between rounds lets early replies mark ports done.
		if round < j.retries {
			if err := rawnet.SleepCtx(ctx, min(wait/2, time.Second)); err != nil {
				sendErr = err
				break
			}
		}
	}
	if sendErr == nil {
		_ = rawnet.SleepCtx(ctx, wait)
	}
	stopRecv()
	j.log.Debug("udp scan done", "datagrams", sent)
	if sendErr != nil && ctx.Err() == nil {
		return sendErr
	}
	return ctx.Err()
}

// writeUDP sends one datagram, briefly retrying when the socket send
// queue is full (ENOBUFS / EAGAIN at high rates).
func writeUDP(c *net.UDPConn, b []byte, dst netip.AddrPort) error {
	var err error
	for attempt := range 20 {
		if _, err = c.WriteToUDPAddrPort(b, dst); err == nil {
			return nil
		}
		if !errors.Is(err, syscall.ENOBUFS) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		time.Sleep(time.Duration(attempt+1) * 100 * time.Microsecond)
	}
	return err
}

// isFatalSendError reports socket-level failures that will not resolve by
// themselves (as opposed to per-destination errors like EHOSTUNREACH,
// ECONNREFUSED from a previous ICMP or ENOBUFS).
func isFatalSendError(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
