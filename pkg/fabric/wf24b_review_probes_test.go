// ADOPTED VERBATIM (constitution 11.4.276(D)) from the independent re-review WF24 (zz_wf24b_test.go); strengthenings, if any, are marked ADOPTED AS ASSERTION / ADAPTED.
package fabric_test

// WF24 second probe batch (reviewer-authored, scratch only).

import (
	"context"
	"errors"
	"net/textproto"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/fabric"
)

// W15: cancel the MIDDLE reservation, then the TAIL: the wind-back must cascade through the freed middle slot,
// so a caller arriving after the middle slot's time starts at once. (Distinguishes surviving mutant M01.)
func TestW15_BudgetCascadeWindBack(t *testing.T) {
	clk := newParkClock()
	b := mustBudget(t, 8, 10, clk)
	r1, _ := b.Acquire(context.Background()) // T+0
	defer r1()
	ctxB, cancelB := context.WithCancel(context.Background())
	cB := acquireAsync(b, ctxB) // T+100
	clk.waitParked(t, 1)
	ctxC, cancelC := context.WithCancel(context.Background())
	cC := acquireAsync(b, ctxC) // T+200 (tail)
	clk.waitParked(t, 2)
	cancelB()
	<-cB
	clk.waitParked(t, 1)
	cancelC()
	<-cC
	clk.waitParked(t, 0)
	clk.advance(150 * time.Millisecond) // T+150: past the freed middle slot, before the freed tail
	cE := acquireAsync(b, context.Background())
	select {
	case r := <-cE:
		if r.err != nil {
			t.Fatal(r.err)
		}
		r.rel()
	case <-time.After(300 * time.Millisecond):
		clk.advance(time.Second)
		if r := <-cE; r.err == nil {
			r.rel()
		}
		t.Errorf("DEFECT: wind-back did not cascade; the caller waits for a slot nobody used (sleeps %v)", clk.sleeps())
	}
	t.Logf("sleeps %v", clk.sleeps())
}

// W16: with a stream lease configured, a stream CLOSED BEFORE the lease releases its slot at Close, and the
// lease counter stays 0. (Distinguishes surviving mutant M08 and the M07 class.)
func TestW16_LeaseNormalCloseReleasesAndIsNotCountedAsExpired(t *testing.T) {
	b, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1e6}, fabric.WithStreamLease(150*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	c := fabric.Limited(newFk("p"), b)
	rc, err := c.ReadFile(context.Background(), "/a")
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond) // well before the lease would fire
	defer cancel()
	if _, err := c.ListDirectory(ctx, "/"); err != nil {
		t.Errorf("DEFECT: a stream closed normally under a lease did not release its slot: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // past the lease
	if st := b.Stats(); st.LeaseExpired != 0 {
		t.Errorf("DEFECT: LeaseExpired=%d for a stream that was closed in time", st.LeaseExpired)
	}
}

// W17: MarkTransient's contract vs a marked structured 5yz reply.
// ADOPTED AS ASSERTION (round 3, D1): the reviewer's fix direction was to DOCUMENT the precedence on MarkTransient
// itself, which is done; the assertion therefore states the documented behaviour (a structured reply is decided by its
// code, an auth-marked leaf stays auth, a plain error becomes transient). The original assertion
// (Classify == ClassTransient for the marked 550) contradicts the documented precedence and is not kept.
func TestW17_MarkTransientOverStructuredReply(t *testing.T) {
	e := fabric.MarkTransient(&textproto.Error{Code: 550, Msg: "Data connection failed"})
	got := fabric.Classify(e)
	t.Logf("Classify(MarkTransient(550)) = %v; errors.Is(ErrTransient)=%v", got, errors.Is(e, fabric.ErrTransient))
	if got != fabric.ClassPermanent {
		t.Errorf("documented precedence broken: a structured 5yz reply is decided by its code even when marked; got %v", got)
	}
	if g := fabric.Classify(fabric.MarkTransient(errors.New("data connection dropped"))); g != fabric.ClassTransient {
		t.Errorf("MarkTransient of a plain error = %v, want transient", g)
	}
	if g := fabric.Classify(fabric.MarkTransient(errors.New("login incorrect"))); g != fabric.ClassAuth {
		t.Errorf("MarkTransient of an auth-marked leaf = %v, want auth (a lockout is never retried)", g)
	}
}

// W18 (MEASUREMENT in the review): an ACTIVELY READ stream that outlives the lease loses its slot; the host then runs
// MaxConcurrent+1 for as long as the stream is read (the docs said "briefly"; the reviewer measured 34, 35, 35 other
// operations in 400 ms against a 40 ms lease).
// ADOPTED AS ASSERTION (round 3, D2): the lease is now IDLE-based, so an actively read stream keeps its slot and NO
// other operation may run alongside it. ADAPTED constants: lease 250 ms and 800 ms of reading (the reviewer's 40 ms
// lease would expire under a scheduler stall of 40 ms on a loaded host, which is not what the probe is about).
func TestW18_LeaseOnActiveStreamExceedsCapForItsLifetime(t *testing.T) {
	g := &gauge{}
	b, _ := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1e6}, fabric.WithStreamLease(250*time.Millisecond))
	movie := newFk("smb")
	movie.readData = string(make([]byte, 1<<20))
	c := fabric.Limited(movie, b)
	rc, _ := c.ReadFile(context.Background(), "/movie.mkv")
	g.enter() // the open stream is one operation on the host
	stop := time.After(800 * time.Millisecond)
	buf := make([]byte, 1024)
	extra := 0
loop:
	for {
		select {
		case <-stop:
			break loop
		default:
		}
		_, _ = rc.Read(buf) // still being read: not leaked
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		if _, err := c.ListDirectory(ctx, "/"); err == nil {
			extra++
		}
		cancel()
		time.Sleep(10 * time.Millisecond)
	}
	_ = rc.Close()
	g.leave()
	t.Logf("MEASURED: MaxConcurrent=1, idle lease 250ms, stream actively read for 800ms: %d other operations ran alongside it (LeaseExpired=%d)", extra, b.Stats().LeaseExpired)
	if extra != 0 || b.Stats().LeaseExpired != 0 {
		t.Errorf("an actively read stream lost its slot: %d other operations ran alongside it, LeaseExpired=%d", extra, b.Stats().LeaseExpired)
	}
}
