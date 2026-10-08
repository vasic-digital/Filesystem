package fabric_test

// Round-3 (WF24 re-review) regression tests for HostBudget / Limited:
// N2 (the probe is budgeted without waiting), N8 (reused tail), D2 (idle lease),
// fail-fast error type.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
	"digital.vasic.filesystem/pkg/webdav"
)

// ---- TryAcquire ----

func TestR3_TryAcquire_RefusesWhenEverySlotIsHeld(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 2, 1e6, nil)
	r1, ok1 := b.TryAcquire()
	r2, ok2 := b.TryAcquire()
	if !ok1 || !ok2 {
		t.Fatalf("free slots refused: %v %v", ok1, ok2)
	}
	if _, ok := b.TryAcquire(); ok {
		t.Fatal("a third TryAcquire succeeded with MaxConcurrent=2")
	}
	if st := b.Stats(); st.InFlight != 2 || st.Held != 2 {
		t.Fatalf("stats %+v", st)
	}
	r1()
	r1() // idempotent
	if st := b.Stats(); st.InFlight != 1 {
		t.Fatalf("stats after release %+v", st)
	}
	r3, ok := b.TryAcquire()
	if !ok {
		t.Fatal("a released slot was not reusable")
	}
	r2()
	r3()
	if st := b.Stats(); st.InFlight != 0 || st.Held != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// The next start slot is in the future: TryAcquire refuses AND reserves nothing,
// so the schedule is exactly what it would have been without the attempt.
func TestR3_TryAcquire_RefusesWhenTheStartSlotIsNotDueAndReservesNothing(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	b := mustBudget(t, 4, 10, clk) // 100 ms spacing
	r1, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r1()
	for i := 0; i < 5; i++ { // however often it is asked, nothing is consumed
		if _, ok := b.TryAcquire(); ok {
			t.Fatalf("attempt %d: TryAcquire succeeded before its start slot", i)
		}
	}
	if st := b.Stats(); st.InFlight != 0 {
		t.Fatalf("a refused TryAcquire left a slot held: %+v", st)
	}
	before := len(clk.slept())
	r2, err := b.Acquire(context.Background()) // the very next slot: exactly one interval after the first
	if err != nil {
		t.Fatal(err)
	}
	r2()
	if s := clk.slept(); len(s) != before+1 || s[before] != 100*time.Millisecond {
		t.Fatalf("sleeps %v: the refused attempts pushed the schedule", s)
	}
	clk.advance(100 * time.Millisecond)
	r3, ok := b.TryAcquire()
	if !ok {
		t.Fatal("TryAcquire refused although its start slot is due")
	}
	r3()
}

// A returned (cancelled) slot that is still in the future is not "due" either, and goes back.
func TestR3_TryAcquire_GivesBackAFreedFutureSlot(t *testing.T) {
	t.Parallel()
	clk := newParkClock()
	b := mustBudget(t, 8, 10, clk)
	r1, _ := b.Acquire(context.Background()) // T+0
	defer r1()
	ctxB, cancelB := context.WithCancel(context.Background())
	cB := acquireAsync(b, ctxB) // T+100
	clk.waitParked(t, 1)
	ctxC, cancelC := context.WithCancel(context.Background())
	cC := acquireAsync(b, ctxC) // T+200
	clk.waitParked(t, 2)
	cancelB()
	<-cB // T+100 is free, T+200 reserved
	if _, ok := b.TryAcquire(); ok {
		t.Fatal("TryAcquire used a future slot")
	}
	// the freed slot is still available to a real caller, in order
	cD := acquireAsync(b, context.Background())
	clk.waitParked(t, 2) // C and D parked
	if s := clk.sleeps(); s[len(s)-1] != 100*time.Millisecond {
		t.Fatalf("the freed slot was lost, sleeps %v", s)
	}
	cancelC()
	<-cC
	clk.advance(time.Second)
	if r := <-cD; r.err == nil {
		r.rel()
	}
}

// ---- Limited.TestConnection ----

func TestR3_Limited_ProbeIsSkippedNotRunWhenTheBudgetIsBusy(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 1, 1e6, nil)
	inner := newFk("smb")
	c := fabric.Limited(inner, b)
	rc, err := c.ReadFile(context.Background(), "/a") // the single slot is held by an open stream
	if err != nil {
		t.Fatal(err)
	}
	acq := b.Stats().Acquired
	for i := 0; i < 5; i++ {
		if err := c.TestConnection(context.Background()); !errors.Is(err, fabric.ErrProbeSkipped) {
			t.Fatalf("probe %d: %v, want ErrProbeSkipped", i, err)
		}
	}
	if inner.count("TestConnection") != 0 {
		t.Fatalf("the probe reached the host %d times although the budget was busy", inner.count("TestConnection"))
	}
	if b.Stats().Acquired != acq || b.Stats().InFlight != 1 {
		t.Fatalf("a skipped probe changed the budget: %+v", b.Stats())
	}
	_ = rc.Close()
	if err := c.TestConnection(context.Background()); err != nil || inner.count("TestConnection") != 1 {
		t.Fatalf("with a free slot the probe must run: err=%v runs=%d", err, inner.count("TestConnection"))
	}
	if b.Stats().InFlight != 0 {
		t.Fatalf("the probe leaked its slot: %+v", b.Stats())
	}
}

// 8 goroutines probe a host whose budget allows 2: the host never sees more than
// 2 at once, and every probe either ran or was reported skipped.
func TestR3_Limited_ProbesNeverExceedMaxConcurrent(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 2, 1e6, nil)
	g := &gauge{}
	inner := newFk("smb")
	inner.g = g
	inner.work = 60 * time.Millisecond
	c := fabric.Limited(inner, b)
	var wg sync.WaitGroup
	var ran, skipped atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := c.TestConnection(context.Background()); {
			case err == nil:
				ran.Add(1)
			case errors.Is(err, fabric.ErrProbeSkipped):
				skipped.Add(1)
			default:
				t.Errorf("unexpected probe error: %v", err)
			}
		}()
	}
	wg.Wait()
	if g.max.Load() > 2 {
		t.Errorf("peak concurrency %d with MaxConcurrent=2", g.max.Load())
	}
	if ran.Load()+skipped.Load() != 8 || ran.Load() < 1 || skipped.Load() < 1 {
		t.Errorf("ran=%d skipped=%d (want both classes to occur out of 8)", ran.Load(), skipped.Load())
	}
}

func TestR3_Limited_ProbeCountsAgainstTheRate(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	b := mustBudget(t, 4, 10, clk)
	inner := newFk("smb")
	c := fabric.Limited(inner, b)
	if err := c.TestConnection(context.Background()); err != nil { // consumes the slot at T+0
		t.Fatal(err)
	}
	if err := c.TestConnection(context.Background()); !errors.Is(err, fabric.ErrProbeSkipped) { // next slot at T+100
		t.Fatalf("a probe inside the same interval: %v, want skipped", err)
	}
	clk.advance(100 * time.Millisecond)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("a probe at its start slot: %v", err)
	}
	if inner.count("TestConnection") != 2 {
		t.Fatalf("%d probes reached the host, want 2", inner.count("TestConnection"))
	}
}

// Disconnect stays exempt: a closing connection is never refused, whatever the budget.
func TestR3_Limited_DisconnectIsAlwaysAllowed(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 1, 1e6, nil)
	inner := newFk("smb")
	c := fabric.Limited(inner, b)
	rc, _ := c.ReadFile(context.Background(), "/a")
	defer rc.Close()
	if err := c.Disconnect(context.Background()); err != nil || inner.count("Disconnect") != 1 {
		t.Fatalf("Disconnect: err=%v runs=%d", err, inner.count("Disconnect"))
	}
}

// GROUND TRUTH (11.4.276(B)): the REAL pkg/webdav client (its TestConnection is a
// PROPFIND, like SMB's is a full listing) behind Limited and a Pool. The server
// side peak of requests in flight is the load the host actually sees.
func TestR3_RealWebDAVThroughPoolAndLimitedStaysWithinTheBudget(t *testing.T) {
	t.Parallel()
	var cur, peak, total atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := cur.Add(1)
		defer cur.Add(-1)
		total.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(8 * time.Millisecond)
		w.WriteHeader(http.StatusMultiStatus)
	}))
	defer srv.Close()
	b := mustBudget(t, 2, 1e6, nil)
	p := newPool(t, limitedWebdavFactory{url: srv.URL, b: b}, fabric.PoolOptions{MaxPerKey: 6})
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 12; i++ {
				c, err := p.GetClientContext(context.Background(), cfgFor("dav"))
				if err != nil {
					t.Errorf("borrow: %v", err)
					return
				}
				_ = p.ReturnClient(c)
			}
		}()
	}
	wg.Wait()
	if peak.Load() > 2 {
		t.Errorf("the WebDAV server saw %d requests at once with MaxConcurrent=2 (probes bypass the budget)", peak.Load())
	}
	if total.Load() < 6 {
		t.Errorf("only %d requests reached the server: the instrument saw no probes", total.Load())
	}
}

type limitedWebdavFactory struct {
	url string
	b   *fabric.HostBudget
}

func (f limitedWebdavFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	return fabric.Limited(webdav.NewWebDAVClient(&webdav.Config{URL: f.url, Username: "u", Password: "dummy"}), f.b), nil
}
func (limitedWebdavFactory) SupportedProtocols() []string { return nil }

// ---- fail-fast error type ----

func TestR3_FailFastErrorIsErrBudgetBusyAndADeadline(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 2, 1, nil) // 1 s spacing, real clock
	r1, _ := b.Acquire(context.Background())
	r1()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := b.Acquire(ctx)
	if !errors.Is(err, fabric.ErrBudgetBusy) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fail-fast error %v: ErrBudgetBusy=%v DeadlineExceeded=%v", err, errors.Is(err, fabric.ErrBudgetBusy), errors.Is(err, context.DeadlineExceeded))
	}
	// the caller's own ended context is NOT reported as a busy budget
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if _, err := b.Acquire(cctx); errors.Is(err, fabric.ErrBudgetBusy) {
		t.Fatalf("a cancelled caller was reported as a busy budget: %v", err)
	}
}

// ---- N8: a reused slot that becomes the tail is wound back ----

func TestR3_ReusedTailIsWoundBackAndItsCascade(t *testing.T) {
	t.Parallel()
	clk := newParkClock()
	b := mustBudget(t, 8, 10, clk)
	r1, _ := b.Acquire(context.Background()) // T+0
	defer r1()
	mk := func() (context.CancelFunc, chan acqResult) {
		ctx, cancel := context.WithCancel(context.Background())
		return cancel, acquireAsync(b, ctx)
	}
	cancelB, cB := mk() // T+100
	clk.waitParked(t, 1)
	cancelC, cC := mk() // T+200
	clk.waitParked(t, 2)
	cancelE, cE := mk() // T+300
	clk.waitParked(t, 3)
	cancelB()
	<-cB // T+100 free
	clk.waitParked(t, 2)
	cancelD, cD := mk() // reuses T+100
	clk.waitParked(t, 3)
	cancelE()
	<-cE // tail T+300 cancelled: front is T+300 again
	cancelC()
	<-cC // T+200 cancelled: wound back to T+200
	clk.waitParked(t, 1)
	cancelD()
	<-cD // the reused T+100 was the last reservation: wind back to T+100 (not leave T+200 as the front)
	clk.waitParked(t, 0)
	clk.advance(150 * time.Millisecond)
	cF := acquireAsync(b, context.Background())
	select {
	case r := <-cF:
		if r.err != nil {
			t.Fatal(r.err)
		}
		r.rel()
	case <-time.After(300 * time.Millisecond):
		clk.advance(time.Second)
		<-cF
		t.Fatalf("a caller at T+150 waits for a slot nobody used (sleeps %v)", clk.sleeps())
	}
}

// ---- D2: the lease is idle-based ----

func leased(t *testing.T, lease time.Duration) (*fabric.HostBudget, client.Client) {
	t.Helper()
	b, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1e6}, fabric.WithStreamLease(lease))
	if err != nil {
		t.Fatal(err)
	}
	f := newFk("p")
	f.readData = strings.Repeat("x", 1<<16)
	return b, fabric.Limited(f, b)
}

func TestR3_Lease_ActivelyReadStreamKeepsItsSlot(t *testing.T) {
	t.Parallel()
	b, c := leased(t, 300*time.Millisecond)
	rc, err := c.ReadFile(context.Background(), "/a")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	for i := 0; i < 40; i++ { // 40 x 25 ms = 1 s, three leases long
		if _, err := rc.Read(buf); err != nil {
			t.Fatal(err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if st := b.Stats(); st.LeaseExpired != 0 || st.InFlight != 1 {
		t.Fatalf("an actively read stream lost its slot: %+v", st)
	}
	_ = rc.Close()
	if st := b.Stats(); st.InFlight != 0 || st.LeaseExpired != 0 {
		t.Fatalf("after Close: %+v", st)
	}
}

func TestR3_Lease_IdleStreamLosesItsSlotOnceAndStaysReadable(t *testing.T) {
	t.Parallel()
	b, c := leased(t, 60*time.Millisecond)
	rc, err := c.ReadFile(context.Background(), "/a")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for b.Stats().LeaseExpired == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := b.Stats(); st.LeaseExpired != 1 || st.InFlight != 0 {
		t.Fatalf("an idle stream kept its slot: %+v", st)
	}
	if _, err := rc.Read(make([]byte, 8)); err != nil { // still readable
		t.Fatalf("read after expiry: %v", err)
	}
	if st := b.Stats(); st.InFlight != 0 {
		t.Fatalf("reading an expired stream took a slot back: %+v", st)
	}
	_ = rc.Close() // a late Close must not release twice
	_ = rc.Close()
	if st := b.Stats(); st.InFlight != 0 || st.LeaseExpired != 1 {
		t.Fatalf("after Close: %+v", st)
	}
	if _, err := c.ListDirectory(context.Background(), "/"); err != nil {
		t.Fatal(err)
	}
}

// slowWriterTo has a WriteTo that copies in chunks with a pause between them,
// like a large file written to a slow consumer.
type slowWriterTo struct {
	chunks int
	gap    time.Duration
}

func (s *slowWriterTo) Read([]byte) (int, error) { return 0, io.EOF }
func (s *slowWriterTo) Close() error             { return nil }
func (s *slowWriterTo) WriteTo(w io.Writer) (int64, error) {
	var n int64
	for i := 0; i < s.chunks; i++ {
		k, err := w.Write([]byte("0123456789abcdef"))
		n += int64(k)
		if err != nil {
			return n, err
		}
		time.Sleep(s.gap)
	}
	return n, nil
}

type wtClient struct{ *fk }

func (wtClient) ReadFile(context.Context, string) (io.ReadCloser, error) {
	return &slowWriterTo{chunks: 16, gap: 25 * time.Millisecond}, nil
}

// A long WriteTo is activity while it copies, not one event at its end.
func TestR3_Lease_WriteToCountsAsActivityWhileItCopies(t *testing.T) {
	t.Parallel()
	b, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1e6}, fabric.WithStreamLease(150*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	c := fabric.Limited(wtClient{newFk("p")}, b)
	rc, err := c.ReadFile(context.Background(), "/a")
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, rc) // uses WriteTo: 16 chunks, 400 ms in total, longer than the lease
	if err != nil || n != 16*16 {
		t.Fatalf("copy: n=%d err=%v", n, err)
	}
	if st := b.Stats(); st.LeaseExpired != 0 || st.InFlight != 1 {
		t.Fatalf("a stream being copied lost its slot: %+v", st)
	}
	_ = rc.Close()
}
