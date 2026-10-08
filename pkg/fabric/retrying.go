package fabric

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"digital.vasic.filesystem/pkg/client"
)

// MaxRetryAttempts is the largest MaxAttempts a RetryPolicy may ask for. A
// retry loop must be bounded by a number a reviewer can read; a policy that
// wants more is a mistake, not a configuration.
const MaxRetryAttempts = 100

// RetryPolicy configures Retrying.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts including the first
	// (1..MaxRetryAttempts).
	MaxAttempts int
	// BaseDelay is the wait before the second attempt; it doubles per attempt.
	// It must be > 0 when MaxAttempts > 1: a zero delay is a back-to-back
	// retry storm against a host that is already failing.
	BaseDelay time.Duration
	// MaxDelay caps the backoff (0 = no cap).
	MaxDelay time.Duration
	// Classify decides whether a failure is retried. nil means Classify (the
	// package default). Only ClassTransient is ever retried.
	Classify func(error) ErrorClass
	// Jitter, if set, maps the computed delay to the delay used (for example a
	// function returning a random duration in [0, d]). nil = no jitter. The
	// package ships no jitter function.
	Jitter func(time.Duration) time.Duration
	// Clock is the time source (nil = system clock).
	Clock Clock
}

// ErrRetryPolicy is returned for an invalid RetryPolicy.
var ErrRetryPolicy = errors.New("fabric: invalid retry policy")

func (p RetryPolicy) validate() error {
	if p.MaxAttempts < 1 || p.MaxAttempts > MaxRetryAttempts {
		return fmt.Errorf("%w: MaxAttempts=%d, want 1..%d", ErrRetryPolicy, p.MaxAttempts, MaxRetryAttempts)
	}
	if p.BaseDelay < 0 || p.MaxDelay < 0 {
		return fmt.Errorf("%w: negative delay", ErrRetryPolicy)
	}
	if p.MaxAttempts > 1 && p.BaseDelay == 0 {
		return fmt.Errorf("%w: BaseDelay=0 with MaxAttempts=%d would retry back to back, want BaseDelay > 0", ErrRetryPolicy, p.MaxAttempts)
	}
	return nil
}

func (p RetryPolicy) delay(attempt int) time.Duration {
	// closed form BaseDelay * 2^(attempt-1), saturating at MaxInt64 instead of
	// overflowing to a tiny or negative delay; O(1) in the attempt number.
	d := p.BaseDelay
	if shift := attempt - 1; shift > 0 && d > 0 {
		if shift >= 63 || d > time.Duration(math.MaxInt64>>uint(shift)) {
			d = math.MaxInt64
		} else {
			d <<= uint(shift)
		}
	}
	if p.MaxDelay > 0 && d > p.MaxDelay {
		d = p.MaxDelay
	}
	if p.Jitter != nil {
		d = p.Jitter(d)
	}
	return d
}

// Retrying returns a client that repeats READ operations (Op.Retryable) after
// a failure the policy classifies as transient. It never retries:
//   - a mutation (WriteFile, DeleteFile, CopyFile, CreateDirectory,
//     DeleteDirectory) or Disconnect;
//   - an authentication failure (repeating a login can lock the account);
//   - a permanent or unclassified failure;
//   - once the caller's context is done.
//
// When the attempts are spent the last error is returned wrapped with
// ErrRetriesExhausted. An invalid policy is reported as an error.
func Retrying(inner client.Client, policy RetryPolicy) (client.Client, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	classify := policy.Classify
	if classify == nil {
		classify = Classify
	}
	clk := policy.Clock
	if clk == nil {
		clk = SystemClock()
	}
	return newLayer(inner, func(ctx context.Context, st *callState, paths []string, call func(context.Context, []string) error) error {
		if !st.op.Retryable() {
			return call(ctx, paths)
		}
		var err error
		for attempt := 1; ; attempt++ {
			err = call(ctx, paths)
			if err == nil {
				return nil
			}
			if ctx.Err() != nil || classify(err) != ClassTransient {
				return err
			}
			if attempt >= policy.MaxAttempts {
				return fmt.Errorf("%w after %d attempts (%s): %w", ErrRetriesExhausted, attempt, st.op, err)
			}
			if serr := clk.Sleep(ctx, policy.delay(attempt)); serr != nil {
				return fmt.Errorf("%w (retry of %s interrupted): %w", err, st.op, serr)
			}
		}
	}), nil
}
