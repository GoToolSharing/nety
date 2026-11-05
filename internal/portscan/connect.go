package portscan

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/rawnet"
)

// dialOutcome classifies a connect() attempt.
type dialOutcome int

const (
	dialOpen    dialOutcome = iota // handshake completed
	dialClosed                     // RST (ECONNREFUSED)
	dialUnreach                    // ICMP unreachable / no route: definitive, not open
	dialRetry                      // timeout or local transient error: retry later
)

// connectScan runs a full TCP connect() scan with a bounded worker pool, randomized (host
// x port) order and rate limiting.
func (s *Scanner) connectScan(ctx context.Context, j *job) error {
	timeout := j.opts.Timeout
	if timeout <= 0 {
		timeout = DefaultConnectTimeout
	}
	rate := j.opts.Rate
	if rate <= 0 {
		rate = DefaultConnectRate
	}
	n := j.size()
	workers := MaxConnectWorkers
	if uint64(workers) > n {
		workers = int(n)
	}
	// Little's law: in-flight attempts ~ rate x mean attempt duration; no point keeping
	// far more goroutines than that.
	if w := rate * int(timeout/time.Millisecond) / 1000; w > 0 && w < workers {
		workers = max(w, 16)
		if uint64(workers) > n {
			workers = int(n)
		}
	}
	limiter := rawnet.NewLimiter(rate, max(rate/50, 1))
	done := newDoneSet(n)
	dialer := newDialer(timeout, j.opts.SourcePort)

	j.log.Debug("connect scan", "workers", workers, "rate", rate, "timeout", timeout, "retries", j.retries)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan uint64, workers*2)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				h, p := j.split(idx)
				host, port := j.hosts[h], j.ports[p]
				start := time.Now()
				outcome := dialer.probe(ctx, host, port)
				j.prog.add(1)
				switch outcome {
				case dialOpen:
					if !done.testAndSet(idx) {
						j.emit.emit(engine.PortResult{
							IP: host, Port: port, Proto: model.TCP, State: model.PortOpen,
							Reason: "syn-ack", RTT: time.Since(start),
						})
					}
				case dialClosed, dialUnreach:
					done.testAndSet(idx)
				}
			}
		}()
	}

	seed := rand.Uint64()
feed:
	for round := 0; round <= j.retries; round++ {
		perm := rawnet.NewPermutation(n, seed+uint64(round)*0x9e3779b97f4a7c15)
		for i := uint64(0); i < n; i++ {
			idx := perm.At(i)
			if round > 0 && done.has(idx) {
				j.prog.add(1)
				continue
			}
			if err := limiter.Wait(ctx, 1); err != nil {
				break feed
			}
			select {
			case jobs <- idx:
			case <-ctx.Done():
				break feed
			}
		}
	}
	close(jobs)
	wg.Wait()
	return ctx.Err()
}

type connDialer struct {
	d          net.Dialer
	timeout    time.Duration
	sourcePort uint16
}

func newDialer(timeout time.Duration, sourcePort uint16) *connDialer {
	cd := &connDialer{timeout: timeout, sourcePort: sourcePort}
	cd.d = net.Dialer{Timeout: timeout, KeepAlive: -1}
	if sourcePort != 0 {
		cd.d.Control = reuseControl
	}
	return cd
}

func (cd *connDialer) probe(ctx context.Context, host netip.Addr, port uint16) dialOutcome {
	d := cd.d
	if cd.sourcePort != 0 {
		if host.Is4() {
			d.LocalAddr = &net.TCPAddr{IP: net.IPv4zero, Port: int(cd.sourcePort)}
		} else {
			d.LocalAddr = &net.TCPAddr{IP: net.IPv6unspecified, Port: int(cd.sourcePort)}
		}
	}
	dctx, cancel := context.WithTimeout(ctx, cd.timeout)
	defer cancel()
	c, err := d.DialContext(dctx, "tcp", net.JoinHostPort(host.String(), strconv.Itoa(int(port))))
	if err == nil {
		if tc, ok := c.(*net.TCPConn); ok {
			// RST on close: no TIME_WAIT (lets a fixed source port be reused immediately
			// and keeps the local socket table small).
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
		return dialOpen
	}
	return classifyDialError(err)
}

func classifyDialError(err error) dialOutcome {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return dialClosed
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return dialUnreach
	}
	return dialRetry
}
