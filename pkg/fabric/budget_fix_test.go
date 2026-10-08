package fabric_test

// Round-2 review (WF19) regression tests for HostBudget: S1 (cancelled start
// slots are given back), S12 (tiny rate), S15 (leaked stream), P4 (stats).

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/fabric"
)

// acquireAsync starts Acquire in a goroutine and reports its result.
type acqResult struct {
	rel func()
	err error
}

func acquireAsync(b *fabric.HostBudget, ctx context.Context) chan acqResult {
	ch := make(chan acqResult, 1)
	go func() {
		rel, err := b.Acquire(ctx)
		ch <- acqResult{rel, err}
	}()
	return ch
}

// S1, class member 1: the LAST reservation is cancelled - the schedule is
// wound back, the next caller gets the same slot instead of one further out.
func TestBudget_CancelledTailReservationIsGivenBack(t *testing.T) {
	t.Parallel()
	clk := newParkClock()
	b := mustBudget(t, 4, 10, clk) // 100 ms spacing
	r1, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	c2 := acquireAsync(b, ctx2)
	clk.waitParked(t, 1)
	cancel2()
	if r := <-c2; !errors.Is(r.err, context.Canceled) {
		t.Fatalf("cancelled waiter: %v", r.err)
	}
	c3 := acquireAsync(b, context.Background())
	clk.waitParked(t, 1)
	clk.advance(100 * time.Millisecond)
	r3 := <-c3
	if r3.err != nil {
		t.Fatal(r3.err)
	}
	r3.rel()
	got := clk.sleeps()
	if len(got) != 2 || got[0] != 100*time.Millisecond || got[1] != 100*time.Millisecond {
		t.Fatalf("waits %v, want [100ms 100ms]: the cancelled caller's slot was not given back", got)
	}
}

// S1, class member 2: a cancelled reservation in the MIDDLE of the schedule is
// reused by the next caller, and the schedule behind it is untouched.
func TestBudget_CancelledMiddleReservationIsReused(t *testing.T) {
	t.Parallel()
	clk := newParkClock()
	b := mustBudget(t, 8, 10, clk)
	r1, _ := b.Acquire(context.Background()) // slot T+0
	defer r1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	c2 := acquireAsync(b, ctx2) // T+100
	clk.waitParked(t, 1)
	c3 := acquireAsync(b, context.Background()) // T+200
	clk.waitParked(t, 2)
	cancel2()
	<-c2
	clk.waitParked(t, 1)
	c4 := acquireAsync(b, context.Background()) // must reuse T+100
	clk.waitParked(t, 2)
	c5 := acquireAsync(b, context.Background()) // T+300
	clk.waitParked(t, 3)
	got := clk.sleeps()
	want := []time.Duration{100, 200, 100, 300}
	if len(got) != 4 {
		t.Fatalf("sleeps %v", got)
	}
	for i := range want {
		if got[i] != want[i]*time.Millisecond {
			t.Fatalf("waits %v, want %v ms: the freed middle slot was not reused / the schedule shifted", got, want)
		}
	}
	clk.advance(300 * time.Millisecond)
	for _, c := range []chan acqResult{c3, c4, c5} {
		if r := <-c; r.err != nil {
			t.Fatal(r.err)
		} else {
			r.rel()
		}
	}
}

// S1: when the LAST reservation is cancelled and time then passes, the schedule
// front must have been wound back: the next caller starts at once instead of
// waiting for a slot nobody used (without the wind-back it waits 50 ms here).
func TestBudget_CancelledTailThenIdleTimeIsNotLost(t *testing.T) {
	t.Parallel()
	clk := newParkClock()
	b := mustBudget(t, 4, 10, clk)
	r1, _ := b.Acquire(context.Background()) // T+0
	defer r1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	c2 := acquireAsync(b, ctx2) // T+100, the tail
	clk.waitParked(t, 1)
	cancel2()
	<-c2
	clk.advance(150 * time.Millisecond) // past the cancelled slot
	c3 := acquireAsync(b, context.Background())
	select {
	case r3 := <-c3:
		if r3.err != nil {
			t.Fatal(r3.err)
		}
		r3.rel()
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("the 3rd caller waits for a slot nobody used (sleeps %v)", clk.sleeps())
	}
	if got := clk.sleeps(); len(got) != 1 {
		t.Fatalf("sleeps %v: the 3rd caller waited for a slot nobody used", got)
	}
}

// S1: a freed slot that is already in the past must NOT be reused - the
// reservation after it would then be closer than one interval to the new start.
func TestBudget_PastFreedSlotIsNotReusedSoSpacingStaysStrict(t *testing.T) {
	t.Parallel()
	clk := newParkClock()
	b := mustBudget(t, 8, 10, clk)
	r1, _ := b.Acquire(context.Background()) // T+0
	defer r1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	c2 := acquireAsync(b, ctx2) // T+100
	clk.waitParked(t, 1)
	c3 := acquireAsync(b, context.Background()) // T+200
	clk.waitParked(t, 2)
	cancel2()
	<-c2
	clk.advance(150 * time.Millisecond) // T+100 is now in the past; T+200 not yet due
	c4 := acquireAsync(b, context.Background())
	clk.waitParked(t, 2)
	got := clk.sleeps()
	// the 4th caller arrives at T+150: the next slot after T+200 is T+300 -> 150 ms wait
	if got[len(got)-1] != 150*time.Millisecond {
		t.Fatalf("waits %v: the 4th caller must wait 150ms (slot T+300), a past freed slot was reused", got)
	}
	clk.advance(150 * time.Millisecond)
	for _, c := range []chan acqResult{c3, c4} {
		if r := <-c; r.err != nil {
			t.Fatal(r.err)
		} else {
			r.rel()
		}
	}
}

// S1: a caller whose deadline falls before its start slot fails fast and
// reserves nothing; the next caller is not pushed back.
func TestBudget_DeadlineBeforeSlotFailsFastWithoutReserving(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 2, 5, nil) // real clock, 200 ms spacing
	r1, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r1()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want DeadlineExceeded", err)
	}
	// "fails fast" is asserted structurally, not by wall time (a loaded host
	// makes timing flaky): a caller that merely waited out its deadline would
	// have RESERVED a slot first, which Stats().Acquired counts.
	if st := b.Stats(); st.Acquired != 1 || st.InFlight != 0 {
		t.Fatalf("stats %+v: the failed caller must not have reserved or held anything", st)
	}
	ctx3, cancel3 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel3()
	r3, err := b.Acquire(ctx3)
	if err != nil {
		t.Fatal(err)
	}
	r3()
	if w := b.Stats().TotalRateWait; w > 260*time.Millisecond {
		t.Fatalf("TotalRateWait %v: the next caller waited for the failed caller's slot", w)
	}
}

// S1: waiter cancelled while waiting for a CONCURRENCY slot reserves no start slot.
func TestBudget_CancelledWhileWaitingForConcurrencySlotReservesNothing(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 1, 1e6, nil)
	r1, _ := b.Acquire(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
	if st := b.Stats(); st.Acquired != 1 {
		t.Fatalf("Acquired=%d, want 1", st.Acquired)
	}
	r1()
}

// S1 (RV01 shape, real clock): a heavy cancellation load must leave the budget
// fully usable and keep making progress.
func TestBudget_ManyCancelledWaitersDoNotLivelock(t *testing.T) {
	b := mustBudget(t, 2, 50, nil) // 20 ms spacing, real clock
	var ok atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
				rel, err := b.Acquire(ctx)
				cancel()
				if err == nil {
					ok.Add(1)
					rel()
				}
			}
		}()
	}
	time.Sleep(600 * time.Millisecond)
	close(stop)
	wg.Wait()
	if ok.Load() < 10 {
		t.Fatalf("only %d starts in 600ms at 50/s with 30ms-patient callers: throughput collapsed", ok.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rel, err := b.Acquire(ctx)
	if err != nil {
		t.Fatalf("a fresh caller is starved after the burst: %v", err)
	}
	rel()
}

// S12: a rate whose spacing does not fit a time.Duration is rejected, not
// converted into "no spacing at all"; the smallest representable one still spaces.
func TestBudgetConfig_TinyRateRejectedNotFailOpen(t *testing.T) {
	t.Parallel()
	for _, r := range []float64{1e-11, 1e-12, 5e-324, 1.0e-10} {
		if _, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: r}); !errors.Is(err, fabric.ErrBudgetConfig) {
			t.Errorf("rate %g: err=%v, want ErrBudgetConfig", r, err)
		}
	}
	b, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1.2e-10})
	if err != nil {
		t.Fatalf("rate 1.2e-10 (spacing ~264 years) must be accepted: %v", err)
	}
	r, _ := b.Acquire(context.Background())
	r()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if r2, err := b.Acquire(ctx); err == nil {
		r2()
		t.Fatal("second start allowed immediately: limiter fails open")
	}
	if _, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: math.SmallestNonzeroFloat64}); err == nil {
		t.Fatal("subnormal rate accepted")
	}
}

// S15 / P4: Held and OldestHeld expose a leaked slot; Acquired counts
// reservations including cancelled ones.
func TestBudget_StatsExposeHeldSlotsAndReservations(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	b := mustBudget(t, 3, 1e6, clk)
	r1, _ := b.Acquire(context.Background())
	clk.advance(90 * time.Second)
	r2, _ := b.Acquire(context.Background())
	st := b.Stats()
	if st.Held != 2 || st.InFlight != 2 || st.OldestHeld != 90*time.Second {
		t.Fatalf("stats %+v, want Held=2 InFlight=2 OldestHeld=90s", st)
	}
	r1()
	r1() // idempotent
	st = b.Stats()
	if st.Held != 1 || st.OldestHeld != 0 || st.InFlight != 1 {
		t.Fatalf("stats after release %+v", st)
	}
	r2()
	if st = b.Stats(); st.Held != 0 || st.InFlight != 0 || st.Acquired != 2 {
		t.Fatalf("stats at the end %+v", st)
	}
}

// S15: a leaked (never closed) stream frees its slot after the lease; the
// stream stays readable; closing it afterwards does not release a second time.
func TestLimited_StreamLeaseFreesALeakedSlot(t *testing.T) {
	t.Parallel()
	b, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1e6}, fabric.WithStreamLease(40*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	f := newFk("p")
	c := fabric.Limited(f, b)
	rc, err := c.ReadFile(context.Background(), "/leaked")
	if err != nil {
		t.Fatal(err)
	}
	// without the lease this would block until the deadline
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.ListDirectory(ctx, "/"); err != nil {
		t.Fatalf("the leaked stream still holds the only slot: %v", err)
	}
	if b.Stats().LeaseExpired != 1 {
		t.Fatalf("LeaseExpired=%d, want 1", b.Stats().LeaseExpired)
	}
	buf := make([]byte, 5)
	if n, err := rc.Read(buf); n != 5 || err != nil {
		t.Fatalf("the stream must stay readable after the lease: %d %v", n, err)
	}
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
	// the cap must still be 1: close after lease expiry did not release twice
	hold, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	if r, err := b.Acquire(ctx2); err == nil {
		r()
		t.Fatal("two holders with MaxConcurrent=1: double release after the lease")
	}
	hold()
}

// S15: without a lease (the default) a leaked stream keeps its slot - the
// documented contract - and closing it frees it.
func TestLimited_NoLeaseByDefaultLeakedStreamHoldsSlot(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 1, 1e6, nil)
	c := fabric.Limited(newFk("p"), b)
	rc, _ := c.ReadFile(context.Background(), "/a")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, err := c.ListDirectory(ctx, "/"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want the wait to hit the deadline", err)
	}
	_ = rc.Close()
	if _, err := c.ListDirectory(context.Background(), "/"); err != nil {
		t.Fatal(err)
	}
}
