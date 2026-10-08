package fabric_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/fabric"
)

func TestBudgetConfig_Rejected(t *testing.T) {
	t.Parallel()
	bad := []fabric.BudgetConfig{
		{}, {MaxConcurrent: 0, MaxReqPerSec: 5}, {MaxConcurrent: 1, MaxReqPerSec: 0},
		{MaxConcurrent: -1, MaxReqPerSec: 5}, {MaxConcurrent: 1, MaxReqPerSec: -2},
		{MaxConcurrent: 1, MaxReqPerSec: math.NaN()}, {MaxConcurrent: 1, MaxReqPerSec: math.Inf(1)},
	}
	for _, c := range bad {
		if _, err := fabric.NewHostBudget(c); !errors.Is(err, fabric.ErrBudgetConfig) {
			t.Errorf("%+v: err=%v, want ErrBudgetConfig", c, err)
		}
	}
	if _, err := fabric.NewHostBudget(fabric.NASBudget()); err != nil {
		t.Errorf("NASBudget must be valid: %v", err)
	}
	if c := fabric.NASBudget(); c.MaxConcurrent != 4 || c.MaxReqPerSec != 10 {
		t.Errorf("NASBudget = %+v", c)
	}
}

func TestBudget_StartsAreSpacedAtTheConfiguredRate(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	b, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 10, MaxReqPerSec: 10}, fabric.WithBudgetClock(clk))
	if err != nil {
		t.Fatal(err)
	}
	t0 := clk.Now()
	for i := 0; i < 6; i++ {
		rel, err := b.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	// 6 starts at 10/s: the first is immediate, the next five wait 100 ms each.
	if got := clk.Now().Sub(t0); got != 500*time.Millisecond {
		t.Fatalf("virtual elapsed = %v, want 500ms", got)
	}
	s := clk.slept()
	if len(s) != 5 {
		t.Fatalf("sleeps = %v", s)
	}
	for _, d := range s {
		if d != 100*time.Millisecond {
			t.Fatalf("sleep %v, want 100ms each: %v", d, s)
		}
	}
	st := b.Stats()
	if st.Acquired != 6 || st.TotalRateWait != 500*time.Millisecond || st.InFlight != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestBudget_IdleTimeDoesNotBankBurst(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	b, _ := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 10, MaxReqPerSec: 10}, fabric.WithBudgetClock(clk))
	for i := 0; i < 2; i++ {
		r, _ := b.Acquire(context.Background())
		r()
	}
	clk.advance(time.Hour) // a long idle period must not allow a burst afterwards
	before := len(clk.slept())
	for i := 0; i < 3; i++ {
		r, _ := b.Acquire(context.Background())
		r()
	}
	if got := len(clk.slept()) - before; got != 2 {
		t.Fatalf("after idle: %d waits for 3 starts, want 2 (first immediate)", got)
	}
}

func TestBudget_ConcurrencyCapHoldsUnderLoad(t *testing.T) {
	t.Parallel()
	b, _ := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 3, MaxReqPerSec: 1e6})
	var g gauge
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := b.Acquire(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			g.enter()
			time.Sleep(time.Millisecond)
			g.leave()
			rel()
		}()
	}
	wg.Wait()
	if g.max.Load() > 3 || g.max.Load() < 2 {
		t.Fatalf("max in flight = %d, want 2..3", g.max.Load())
	}
	if b.Stats().InFlight != 0 {
		t.Fatalf("slots leaked: %+v", b.Stats())
	}
}

func TestBudget_ContextEndsWhileWaitingForSlot(t *testing.T) {
	t.Parallel()
	b, _ := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1e6})
	rel, _ := b.Acquire(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want DeadlineExceeded", err)
	}
	if b.Stats().InFlight != 1 {
		t.Fatalf("waiter must hold nothing: %+v", b.Stats())
	}
	rel()
	cctx, c2 := context.WithCancel(context.Background())
	c2()
	if _, err := b.Acquire(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled ctx: err=%v", err)
	}
	if b.Stats().InFlight != 0 {
		t.Fatalf("slot leaked: %+v", b.Stats())
	}
}

func TestBudget_ReleaseIsIdempotent(t *testing.T) {
	t.Parallel()
	b, _ := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1e6})
	rel, _ := b.Acquire(context.Background())
	done := make(chan struct{})
	go func() { rel(); rel(); rel(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a repeated release blocked (it released a slot that was not held)")
	}
	r1, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// a double release must not have created a second slot
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(ctx); err == nil {
		t.Fatal("second slot appeared after a double release")
	}
	r1()
}

func TestBudget_RateWaitInterruptedByContextReleasesSlot(t *testing.T) {
	t.Parallel()
	b, _ := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 2, MaxReqPerSec: 2}) // 500 ms spacing, real clock
	r, _ := b.Acquire(context.Background())
	r()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
	if b.Stats().InFlight != 0 {
		t.Fatalf("slot held after interrupted rate wait: %+v", b.Stats())
	}
}

func TestBudgets_OneBudgetPerHostAcrossProtocols(t *testing.T) {
	t.Parallel()
	reg := fabric.NewBudgets()
	cfg := fabric.BudgetConfig{MaxConcurrent: 2, MaxReqPerSec: 1e6}
	smb, err := reg.For("NAS.local:445", cfg)
	if err != nil {
		t.Fatal(err)
	}
	sftp, err := reg.For("nas.local:22", cfg)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := reg.For("other.local", cfg)
	if smb != sftp {
		t.Fatal("SMB and SFTP to the same host must share ONE budget")
	}
	if smb == other {
		t.Fatal("different hosts must not share a budget")
	}
	if len(reg.Hosts()) != 2 {
		t.Fatalf("hosts = %v", reg.Hosts())
	}
	if _, err := reg.For("nas.local", fabric.BudgetConfig{MaxConcurrent: 9, MaxReqPerSec: 1}); !errors.Is(err, fabric.ErrBudgetConflict) {
		t.Fatalf("conflicting config: err=%v", err)
	}
	if _, err := reg.For("", cfg); err == nil {
		t.Fatal("empty host must fail")
	}
	if _, err := reg.For("x", fabric.BudgetConfig{}); !errors.Is(err, fabric.ErrBudgetConfig) {
		t.Fatalf("invalid cfg: %v", err)
	}
}

func TestBudget_ConfigAndExtremeRate(t *testing.T) {
	t.Parallel()
	cfg := fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1e18} // interval rounds below 1ns: clamped, not zero
	b, err := fabric.NewHostBudget(cfg)
	if err != nil || b.Config() != cfg {
		t.Fatalf("%v %+v", err, b.Config())
	}
	for i := 0; i < 3; i++ {
		r, err := b.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		r()
	}
}
