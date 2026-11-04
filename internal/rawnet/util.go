package rawnet

import (
	"context"
	"time"
)

// sleepCtx sleeps for d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
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

// SleepCtx sleeps for d or until ctx is done, returning ctx.Err() in the
// latter case.
func SleepCtx(ctx context.Context, d time.Duration) error { return sleepCtx(ctx, d) }
