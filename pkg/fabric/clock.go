package fabric

import (
	"context"
	"time"
)

// Clock is the time source of the fabric. Production code uses the system
// clock; tests inject a deterministic one.
type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx is done, returning ctx.Err() in the
	// latter case. d <= 0 returns immediately (nil, or ctx.Err() if done).
	Sleep(ctx context.Context, d time.Duration) error
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) Sleep(ctx context.Context, d time.Duration) error {
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

// SystemClock returns the real clock.
func SystemClock() Clock { return systemClock{} }
