package fabric_test

// Round-2 review (WF19) regression tests for Pool: S2 (cancellation is not a
// health verdict), S3 (no repeated logins after a rejected one), S4 (health
// probe vs budget, bounded connect), S8 (comparability / lock safety), and the
// pool findings of T1/T2 (idle order, boundaries, waiters, IsConnected).

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
)

// slowClient honours ctx like a real network client: Connect and TestConnection
// take `delay` and return ctx.Err() when the context ends first.
type slowClient struct {
	*fk
	f *slowFactory
}

func (c *slowClient) wait(ctx context.Context) error {
	select {
	case <-time.After(c.f.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *slowClient) Connect(ctx context.Context) error {
	c.f.conn.Add(1)
	if c.f.connectErr != nil {
		return c.f.connectErr
	}
	if err := c.wait(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()
	return nil
}
func (c *slowClient) TestConnection(ctx context.Context) error {
	if c.f.probe > 0 {
		select {
		case <-time.After(c.f.probe):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return c.wait(ctx)
}
func (c *slowClient) Disconnect(context.Context) error {
	c.f.disc.Add(1)
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
	return nil
}
func (c *slowClient) IsConnected() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.connected }

type slowFactory struct {
	disc, conn atomic.Int64
	delay      time.Duration
	probe      time.Duration // if > 0: TestConnection takes this instead of delay
	connectErr error
}

func (f *slowFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	k := newFk("p")
	k.connected = false
	return &slowClient{fk: k, f: f}, nil
}
func (f *slowFactory) SupportedProtocols() []string { return nil }

// fill returns a pool with n healthy idle connections for root "a".
func fill(t *testing.T, f client.Factory, n int, o fabric.PoolOptions) *fabric.Pool {
	t.Helper()
	o.MaxPerKey = n
	p := newPool(t, f, o)
	var cs []client.Client
	for i := 0; i < n; i++ {
		c, err := p.GetClient(cfgFor("a"))
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
	}
	for _, c := range cs {
		if err := p.ReturnClient(c); err != nil {
			t.Fatal(err)
		}
	}
	if p.Stats().Idle != n {
		t.Fatalf("setup: %+v", p.Stats())
	}
	return p
}

// S2 (RV03), member 1: the caller's context ends during the health probe.
func TestPool_CancelledBorrowDuringProbeKeepsHealthyIdle(t *testing.T) {
	t.Parallel()
	f := &slowFactory{delay: 20 * time.Millisecond}
	p := fill(t, f, 3, fabric.PoolOptions{})
	conns, discs := f.conn.Load(), f.disc.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := p.GetClientContext(ctx, cfgFor("a"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want the caller's deadline", err)
	}
	if f.disc.Load() != discs || f.conn.Load() != conns || p.Stats().Idle != 3 {
		t.Fatalf("a caller giving up destroyed pool state: disconnects %d->%d connects %d->%d idle=%d",
			discs, f.disc.Load(), conns, f.conn.Load(), p.Stats().Idle)
	}
	// and the pool is still fully usable: the same idle connections serve the next caller
	c, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	_ = p.ReturnClient(c)
	if f.conn.Load() != conns {
		t.Fatal("a new connection was opened although healthy idle ones exist")
	}
}

// S2, member 2: an ALREADY-ended context never touches the pool (the token
// select would otherwise pick the ready token about half of the time).
func TestPool_PreCancelledContextNeverTouchesIdle(t *testing.T) {
	t.Parallel()
	f := &slowFactory{}
	p := fill(t, f, 2, fabric.PoolOptions{})
	conns, discs := f.conn.Load(), f.disc.Load()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 200; i++ {
		if _, err := p.GetClientContext(ctx, cfgFor("a")); !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d: err=%v", i, err)
		}
	}
	if f.conn.Load() != conns || f.disc.Load() != discs || p.Stats().Idle != 2 || p.Stats().InUse != 0 {
		t.Fatalf("pre-cancelled borrows changed the pool: %+v connects %d disconnects %d", p.Stats(), f.conn.Load()-conns, f.disc.Load()-discs)
	}
}

// S2, member 3: cancelled while a NEW connection logs in: the context error is
// returned, the slot is freed, no login amplification.
func TestPool_CancelledDuringConnectFreesTheSlot(t *testing.T) {
	t.Parallel()
	f := &slowFactory{delay: 200 * time.Millisecond}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := p.GetClientContext(ctx, cfgFor("a")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
	f.delay = 0
	if _, err := p.GetClient(cfgFor("a")); err != nil {
		t.Fatalf("slot leaked by the cancelled connect: %v", err)
	}
}

// S2/S8: a genuinely unhealthy idle connection is still replaced when the
// caller's context is fine (the fix must not turn every probe failure into a keep).
func TestPool_UnhealthyWithLiveContextIsStillReplaced(t *testing.T) {
	t.Parallel()
	f := &slowFactory{probe: 30 * time.Millisecond}
	p := fill(t, f, 1, fabric.PoolOptions{HealthTimeout: 5 * time.Millisecond}) // probe takes 30ms > 5ms health timeout
	discs := f.disc.Load()
	c, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	_ = p.ReturnClient(c)
	if f.disc.Load() != discs+1 {
		t.Fatalf("the probe timed out under a live caller context: the connection must be retired (disconnects %d->%d)", discs, f.disc.Load())
	}
}

// S3 (RV05): after a rejected login the pool does not log in again.
func TestPool_RejectedLoginIsNotRepeatedAcrossBorrows(t *testing.T) {
	t.Parallel()
	f := &slowFactory{connectErr: fabric.MarkAuth(errors.New("530 Login incorrect"))}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 4})
	for i := 0; i < 50; i++ {
		_, err := p.GetClient(cfgFor("a"))
		if fabric.Classify(err) != fabric.ClassAuth {
			t.Fatalf("borrow %d: %v (class %v)", i, err, fabric.Classify(err))
		}
	}
	if f.conn.Load() != 1 {
		t.Fatalf("%d login attempts for 50 borrows after an authentication failure, want 1", f.conn.Load())
	}
	// GetClientContext too, and another ACCOUNT is independent (round 3, N3:
	// the memory is per account, so a second root of the SAME account is not
	// independent - see TestR3_RejectedLoginIsSharedByTheRootsOfOneAccount)
	if _, err := p.GetClientContext(context.Background(), cfgFor("a")); fabric.Classify(err) != fabric.ClassAuth {
		t.Fatalf("err=%v", err)
	}
	if f.conn.Load() != 1 {
		t.Fatal("GetClientContext logged in again")
	}
	if _, err := p.GetClient(cfgForUser("b", "other-account")); fabric.Classify(err) != fabric.ClassAuth {
		t.Fatalf("account b: %v", err)
	}
	if f.conn.Load() != 2 {
		t.Fatalf("another account must get its own single attempt, connects=%d", f.conn.Load())
	}
}

// S3: the way out - Evict, a change of settings, or CloseAll+new pool; and
// failures that are not credentials are never remembered.
func TestPool_RejectedLoginResets(t *testing.T) {
	t.Parallel()
	f := &slowFactory{connectErr: fabric.MarkAuth(errors.New("530 nope"))}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	_, _ = p.GetClient(cfgFor("a"))
	_, _ = p.GetClient(cfgFor("a"))
	if f.conn.Load() != 1 {
		t.Fatalf("connects=%d", f.conn.Load())
	}
	p.Evict("a")
	_, _ = p.GetClient(cfgFor("a"))
	if f.conn.Load() != 2 {
		t.Fatalf("Evict did not allow a new login attempt: connects=%d", f.conn.Load())
	}
	_, _ = p.GetClient(cfgFor("a"))
	if f.conn.Load() != 2 {
		t.Fatal("the rejection after Evict was not remembered again")
	}
	changed := cfgFor("a")
	changed.Settings = map[string]interface{}{"password": "new"}
	_, _ = p.GetClient(changed)
	if f.conn.Load() != 3 {
		t.Fatalf("a changed settings fingerprint must allow a new attempt: connects=%d", f.conn.Load())
	}

	g := &slowFactory{connectErr: fabric.MarkTransient(errors.New("reset"))}
	q := newPool(t, g, fabric.PoolOptions{MaxPerKey: 2})
	for i := 0; i < 5; i++ {
		_, _ = q.GetClient(cfgFor("a"))
	}
	if g.conn.Load() != 5 {
		t.Fatalf("a transient connect failure must not be cached: connects=%d", g.conn.Load())
	}
	_ = p.CloseAll()
	if _, err := p.GetClient(cfgFor("a")); !errors.Is(err, fabric.ErrPoolClosed) {
		t.Fatalf("closed pool: %v", err)
	}
}

// S4 (RV15): a busy host budget must neither make GetClient wait nor cost the
// healthy idle connection (the probe is not budgeted).
func TestPool_BusyBudgetDoesNotBlockBorrowNorDiscardHealthyIdle(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 1, 1e6, nil)
	f := &limitedPoolFactory{b: b}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2, HealthTimeout: 50 * time.Millisecond})
	c1, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	_ = p.ReturnClient(c1)
	other := fabric.Limited(newFk("sftp"), b)
	rc, err := other.ReadFile(context.Background(), "/movie.mkv") // a long stream holds the host's only slot
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	done := make(chan error, 1)
	go func() { _, e := p.GetClient(cfgFor("a")); done <- e }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("GetClient (without waiting) is blocked on a busy host budget")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.made) != 1 || f.made[0].count("Disconnect") != 0 {
		t.Fatalf("healthy idle connection was replaced: created=%d disconnects=%d", len(f.made), f.made[0].count("Disconnect"))
	}
}

// S4: opening a NEW connection is bounded by ConnectTimeout even for the
// no-wait GetClient (which used context.Background), and frees the slot.
func TestPool_GetClientConnectIsBounded(t *testing.T) {
	t.Parallel()
	f := &slowFactory{delay: time.Hour}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 1, ConnectTimeout: 40 * time.Millisecond})
	t0 := time.Now()
	_, err := p.GetClient(cfgFor("a"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want the connect timeout", err)
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Fatalf("GetClient blocked %v with ConnectTimeout=40ms", d)
	}
	f.delay = 0
	if _, err := p.GetClient(cfgFor("a")); err != nil {
		t.Fatalf("slot leaked: %v", err)
	}
	if _, err := fabric.NewPool(f, fabric.PoolOptions{MaxPerKey: 1, ConnectTimeout: -1}); !errors.Is(err, fabric.ErrPoolConfig) {
		t.Fatalf("negative ConnectTimeout: %v", err)
	}
}

// S8: nil and wrapper values (RV04/RV04b are in review_probes_test.go).
func TestPool_ReturnClientNilAndComparableWrapperOK(t *testing.T) {
	t.Parallel()
	p := newPool(t, &poolFactory{}, fabric.PoolOptions{MaxPerKey: 1})
	if err := p.ReturnClient(nil); !errors.Is(err, fabric.ErrNotFromPool) {
		t.Fatalf("nil: %v", err)
	}
	c, _ := p.GetClient(cfgFor("a"))
	if err := p.ReturnClient(holder{c}); !errors.Is(err, fabric.ErrNotFromPool) {
		t.Fatalf("a different (wrapper) value is not the borrowed client: %v", err)
	}
	if err := p.ReturnClient(c); err != nil {
		t.Fatal(err)
	}
}

// T1 R05: the pool's own IsConnected checks go through decorators.
func TestPool_ReturnOfDisconnectedDecoratedClientIsNotPooled(t *testing.T) {
	t.Parallel()
	pf := &poolFactory{}
	p := newPool(t, &decoratedFactory{pf, mustBudget(t, 4, 1e6, nil)}, fabric.PoolOptions{MaxPerKey: 1})
	c, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Disconnect(context.Background())
	if c.IsConnected() {
		t.Fatal("a decorated client must report the inner IsConnected")
	}
	if err := p.ReturnClient(c); err != nil {
		t.Fatal(err)
	}
	if p.Stats().Idle != 0 {
		t.Fatal("a disconnected client was pooled")
	}
}

type decoratedFactory struct {
	in *poolFactory
	b  *fabric.HostBudget
}

func (d *decoratedFactory) CreateClient(cfg *client.StorageConfig) (client.Client, error) {
	c, err := d.in.CreateClient(cfg)
	if err != nil {
		return nil, err
	}
	return fabric.Limited(c, d.b), nil
}
func (d *decoratedFactory) SupportedProtocols() []string { return nil }

// T1 R08: idle connections are used most-recently-returned first.
func TestPool_IdleOrderIsMostRecentlyUsedFirst(t *testing.T) {
	t.Parallel()
	pf := &poolFactory{}
	p := newPool(t, pf, fabric.PoolOptions{MaxPerKey: 3})
	a, _ := p.GetClient(cfgFor("a"))
	b, _ := p.GetClient(cfgFor("a"))
	_ = p.ReturnClient(a)
	_ = p.ReturnClient(b) // b is the most recent
	got, _ := p.GetClient(cfgFor("a"))
	if got != b {
		t.Fatal("the most recently returned connection must be borrowed first")
	}
	next, _ := p.GetClient(cfgFor("a"))
	if next != a {
		t.Fatal("then the older one")
	}
}

// T1 R09: MaxLifetime is inclusive at the exact boundary (borrow and return).
func TestPool_MaxLifetimeBoundaryIsInclusive(t *testing.T) {
	t.Parallel()
	for _, onReturn := range []bool{false, true} {
		clk := newFakeClock()
		pf := &poolFactory{}
		p := newPool(t, pf, fabric.PoolOptions{MaxPerKey: 1, MaxLifetime: time.Minute, Clock: clk})
		c, _ := p.GetClient(cfgFor("a"))
		if onReturn {
			clk.advance(time.Minute) // exactly MaxLifetime old when returned
			_ = p.ReturnClient(c)
			if p.Stats().Idle != 0 {
				t.Fatal("a connection exactly MaxLifetime old was pooled on return")
			}
			continue
		}
		_ = p.ReturnClient(c)
		clk.advance(time.Minute - time.Nanosecond)
		c2, _ := p.GetClient(cfgFor("a"))
		if pf.count() != 1 {
			t.Fatal("a connection one tick younger than MaxLifetime was retired")
		}
		_ = p.ReturnClient(c2)
		clk.advance(time.Nanosecond) // now exactly MaxLifetime since creation
		_, _ = p.GetClient(cfgFor("a"))
		if pf.count() != 2 {
			t.Fatal("a connection exactly MaxLifetime old was reused")
		}
	}
}

// T1 R10: a client that got disconnected while borrowed is not re-pooled.
func TestPool_DisconnectedWhileBorrowedIsRetiredOnReturn(t *testing.T) {
	t.Parallel()
	pf := &poolFactory{}
	p := newPool(t, pf, fabric.PoolOptions{MaxPerKey: 1})
	c, _ := p.GetClient(cfgFor("a"))
	_ = c.Disconnect(context.Background())
	_ = p.ReturnClient(c)
	if p.Stats().Idle != 0 || p.Stats().InUse != 0 {
		t.Fatalf("stats %+v", p.Stats())
	}
}

// T1 R11: CloseAll wakes a GetClientContext waiter with ErrPoolClosed, and
// the waiter's result is ASSERTED.
func TestPool_CloseAllWakesWaiterWithErrPoolClosed(t *testing.T) {
	t.Parallel()
	p := newPool(t, &poolFactory{}, fabric.PoolOptions{MaxPerKey: 1})
	c, _ := p.GetClient(cfgFor("a"))
	res := make(chan error, 1)
	go func() { _, err := p.GetClientContext(context.Background(), cfgFor("a")); res <- err }()
	time.Sleep(30 * time.Millisecond)
	_ = p.CloseAll()
	select {
	case err := <-res:
		if !errors.Is(err, fabric.ErrPoolClosed) {
			t.Fatalf("waiter got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter was not woken by CloseAll")
	}
	_ = p.ReturnClient(c)
}

// T1 R06/R07/R20 (T2): the default health timeout is positive, a new connection
// honours the caller's context, and discard is bounded - all with fakes that
// HONOUR the context.
func TestPool_DefaultHealthTimeoutIsPositiveAndConnectHonoursContext(t *testing.T) {
	t.Parallel()
	f := &slowFactory{delay: 5 * time.Millisecond}
	p := fill(t, f, 1, fabric.PoolOptions{}) // default HealthTimeout (5s)
	discs := f.disc.Load()
	c, err := p.GetClient(cfgFor("a")) // probe takes 5ms; a 0 timeout would fail it at once
	if err != nil {
		t.Fatal(err)
	}
	_ = p.ReturnClient(c)
	if f.disc.Load() != discs {
		t.Fatal("the default health timeout is not positive: a healthy probe failed")
	}
	f.delay = time.Hour
	p.Evict("a")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	if _, err := p.GetClientContext(ctx, cfgFor("a")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
	if time.Since(t0) > 5*time.Second {
		t.Fatal("a new connection ignores the caller's context")
	}
}

// boundedDiscardClient blocks Disconnect until its ctx ends.
type hangDisconnect struct{ *poolClient }

func (h hangDisconnect) Disconnect(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

type hangFactory struct{}

func (hangFactory) CreateClient(cfg *client.StorageConfig) (client.Client, error) {
	k := newFk("p")
	k.connected = false
	return hangDisconnect{&poolClient{k}}, nil
}
func (hangFactory) SupportedProtocols() []string { return nil }

func TestPool_DiscardOfAHangingConnectionIsBounded(t *testing.T) {
	t.Parallel()
	p := newPool(t, hangFactory{}, fabric.PoolOptions{MaxPerKey: 1, HealthTimeout: 30 * time.Millisecond})
	c, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	_ = p.CloseAll()
	done := make(chan struct{})
	go func() { _ = p.ReturnClient(c); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("discarding a connection whose Disconnect hangs is unbounded")
	}
}

// P2 / RV18: IdleTimeout retires expired idle connections BELOW the most
// recently used one too (lazy: at the next pool call, no reaper goroutine).
func TestPool_IdleTimeoutRetiresOlderIdleConnections(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	pf := &poolFactory{}
	p := newPool(t, pf, fabric.PoolOptions{MaxPerKey: 2, IdleTimeout: time.Minute, Clock: clk})
	a, _ := p.GetClient(cfgFor("a"))
	b, _ := p.GetClient(cfgFor("a"))
	_ = p.ReturnClient(a)
	_ = p.ReturnClient(b)
	for i := 0; i < 10; i++ { // a single worker keeps reusing the MRU entry
		clk.advance(time.Minute - time.Second)
		c, err := p.GetClient(cfgFor("a"))
		if err != nil {
			t.Fatal(err)
		}
		_ = p.ReturnClient(c)
	}
	if pf.made[0].count("Disconnect") == 0 || p.Stats().Idle != 1 {
		t.Fatalf("the idle connection below the MRU was never retired (idle=%d, disconnects=%d)", p.Stats().Idle, pf.made[0].count("Disconnect"))
	}
}

// Sample.Protocol is set (T1 R18) - see TestMetered_SampleCarriesProtocol.

// cancelClock cancels a context on its first Now() call after being armed, so
// the context ends at a point the test controls: inside Pool.get, after the
// early ctx check and before the token select.
type cancelClock struct {
	mu     sync.Mutex
	armed  bool
	cancel context.CancelFunc
}

func (c *cancelClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.armed && c.cancel != nil {
		c.cancel()
		c.armed = false
	}
	return time.Unix(3_000_000, 0)
}
func (c *cancelClock) Sleep(ctx context.Context, d time.Duration) error { return ctx.Err() }

// S2: a context that ends after the early check but before a connection is
// created never costs a CreateClient (the token select picks the ready token
// about half of the time, so 100 pools make "never" a certainty).
func TestPool_ContextEndedWhileWaitingNeverCreatesAClient(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		clk := &cancelClock{}
		pf := &poolFactory{}
		p := newPool(t, pf, fabric.PoolOptions{MaxPerKey: 1, Clock: clk})
		ctx, cancel := context.WithCancel(context.Background())
		clk.mu.Lock()
		clk.cancel, clk.armed = cancel, true
		clk.mu.Unlock()
		if _, err := p.GetClientContext(ctx, cfgFor("a")); !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d: err=%v, want context.Canceled", i, err)
		}
		if pf.count() != 0 || p.Stats().InUse != 0 {
			t.Fatalf("iteration %d: a client was created for a caller whose context had ended (created=%d)", i, pf.count())
		}
		// the slot must not leak either
		if _, err := p.GetClient(cfgFor("a")); err != nil {
			t.Fatalf("iteration %d: slot leaked: %v", i, err)
		}
	}
}

// P2, borrow seam alone: borrowing sweeps the expired idle connections of OTHER
// roots too, with no return involved.
func TestPool_BorrowSweepsExpiredIdleConnectionsOfOtherRoots(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	pf := &poolFactory{}
	p := newPool(t, pf, fabric.PoolOptions{MaxPerKey: 1, IdleTimeout: time.Minute, Clock: clk})
	b, _ := p.GetClient(cfgFor("b"))
	_ = p.ReturnClient(b)
	clk.advance(2 * time.Minute)
	if _, err := p.GetClient(cfgFor("a")); err != nil { // no return of anything
		t.Fatal(err)
	}
	if pf.made[0].count("Disconnect") != 1 || p.Stats().Idle != 0 {
		t.Fatalf("root b's expired idle connection survived a borrow of root a: disconnects=%d idle=%d", pf.made[0].count("Disconnect"), p.Stats().Idle)
	}
}

// P2, return seam alone: returning a client sweeps the expired idle
// connections, with no borrow involved.
func TestPool_ReturnSweepsExpiredIdleConnections(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	pf := &poolFactory{}
	p := newPool(t, pf, fabric.PoolOptions{MaxPerKey: 2, IdleTimeout: time.Minute, Clock: clk})
	a1, _ := p.GetClient(cfgFor("a"))
	a2, _ := p.GetClient(cfgFor("a"))
	_ = p.ReturnClient(a1) // idle since T
	clk.advance(2 * time.Minute)
	_ = p.ReturnClient(a2) // fresh; must retire a1
	if pf.made[0].count("Disconnect") != 1 || p.Stats().Idle != 1 {
		t.Fatalf("the expired idle connection survived a return: disconnects=%d idle=%d", pf.made[0].count("Disconnect"), p.Stats().Idle)
	}
}
