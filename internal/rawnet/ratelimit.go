package rawnet

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token bucket tuned for packet rates from a few pps to well over 100k pps.
// Instead of one timer per packet it keeps a virtual "next send" clock: Wait(n) reserves
// n tokens and sleeps only when the reservation is ahead of wall time, so sleeping
// granularity (~50µs-1ms) does not limit throughput and the long-run average stays exact.
// Callers should send in batches (see Batch) at high rates.
//
// A Limiter is safe for concurrent use.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration // per token, 0 = unlimited
	burst    int
	next     time.Time
	now      func() time.Time
}

// NewLimiter returns a limiter for rate tokens per second (<= 0 means unlimited). burst
// bounds how many tokens may be spent back-to-back after an idle period (<= 0 picks
// rate/100, at least 1).
func NewLimiter(rate, burst int) *Limiter {
	l := &Limiter{now: time.Now}
	l.SetRate(rate, burst)
	return l
}

// SetRate changes the rate (and burst) on the fly.
func (l *Limiter) SetRate(rate, burst int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rate <= 0 {
		l.interval = 0
		l.burst = 0
		return
	}
	l.interval = time.Second / time.Duration(rate)
	if l.interval <= 0 {
		l.interval = 1
	}
	if burst <= 0 {
		burst = rate / 100
	}
	if burst < 1 {
		burst = 1
	}
	l.burst = burst
}

// Batch returns a sensible batch size for the configured rate (about 1ms of traffic,
// between 1 and 256).
func (l *Limiter) Batch() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.interval == 0 {
		return 256
	}
	b := int(time.Millisecond / l.interval)
	switch {
	case b < 1:
		return 1
	case b > 256:
		return 256
	}
	return b
}

// Wait blocks until n tokens are available or ctx is done.
func (l *Limiter) Wait(ctx context.Context, n int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if n <= 0 {
		return nil
	}
	l.mu.Lock()
	if l.interval == 0 {
		l.mu.Unlock()
		return nil
	}
	now := l.now()
	floor := now.Add(-time.Duration(l.burst) * l.interval)
	if l.next.Before(floor) {
		l.next = floor
	}
	start := l.next
	l.next = l.next.Add(time.Duration(n) * l.interval)
	l.mu.Unlock()

	d := start.Sub(now)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
