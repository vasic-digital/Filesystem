package fabric_test

// The independent reviewer's probes (WF19, Opus xhigh), adopted VERBATIM as
// permanent regression tests (11.4.276(D)). Each asserts the CORRECT
// behaviour; against the pre-fix code each of them FAILED (see
// evidence/wp12/fabric/fix-r2-red.txt). Where the original was a measurement
// or an observation (RV10, RV12, RV14, RV18) the assertion was made strict and
// the change is marked "ADOPTED AS ASSERTION".

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
	"digital.vasic.filesystem/pkg/local"
)

// RV01: a burst of callers whose contexts end while they wait for a start slot
// leaves their reserved slots unused, nextSlot drifts ahead of real time, and a
// later caller is starved although almost nothing reached the host.
func TestRV01_BudgetCancelledReservationsDrift(t *testing.T) {
	b := mustBudget(t, 2, 20, nil) // 50 ms spacing, real clock
	var ok, failed atomic.Int64
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
				} else {
					failed.Add(1)
				}
			}
		}()
	}
	time.Sleep(800 * time.Millisecond)
	close(stop)
	wg.Wait()
	st := b.Stats()
	t.Logf("burst: successful starts=%d cancelled=%d reservations(Stats.Acquired)=%d TotalRateWait=%v", ok.Load(), failed.Load(), st.Acquired, st.TotalRateWait)
	// The host saw ok.Load() starts in 0.8 s; at 20/s a fresh caller must get a slot within ~50 ms.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	t0 := time.Now()
	rel, err := b.Acquire(ctx)
	t.Logf("fresh caller after the burst: err=%v waited=%v", err, time.Since(t0))
	if err != nil {
		t.Fatalf("DEFECT: a fresh caller with a 1s budget is starved after a burst of cancelled waiters (host saw only %d starts): %v", ok.Load(), err)
	}
	rel()
}

// RV01b: callers whose patience (80 ms) exceeds the 50 ms start spacing. A rate
// limiter that returns unused start slots serves ~20 starts/s here; the current
// one livelocks after the first few starts (throughput collapses to zero).
func TestRV01b_BudgetLivelockWithServeableCallers(t *testing.T) {
	b := mustBudget(t, 2, 20, nil)
	var mu sync.Mutex
	var okAt []time.Duration
	t0 := time.Now()
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
				ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
				rel, err := b.Acquire(ctx)
				cancel()
				if err == nil {
					mu.Lock()
					okAt = append(okAt, time.Since(t0))
					mu.Unlock()
					time.Sleep(time.Millisecond)
					rel()
				}
			}
		}()
	}
	time.Sleep(1600 * time.Millisecond)
	close(stop)
	wg.Wait()
	var win [4]int
	for _, d := range okAt {
		if i := int(d / (400 * time.Millisecond)); i < 4 {
			win[i]++
		}
	}
	t.Logf("successful starts per 400ms window (nominal 8 each at 20/s): %v total=%d reservations=%d", win, len(okAt), b.Stats().Acquired)
	if len(okAt) < 10 {
		t.Fatalf("DEFECT: livelock - %d starts in 1.6s at a 20/s budget with callers willing to wait 80ms (> 50ms spacing)", len(okAt))
	}
}

// RV02: a valid-but-tiny MaxReqPerSec overflows the interval conversion and the
// limiter fails OPEN (no spacing at all).
func TestRV02_BudgetTinyRateFailsOpen(t *testing.T) {
	b, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1e-11})
	if err != nil {
		// ADOPTED AS ASSERTION (was t.Skipf): rejecting the config IS the fix; a
		// skip would report success without checking that the rejection is the
		// right error.
		if !errors.Is(err, fabric.ErrBudgetConfig) {
			t.Fatalf("rejected with the wrong error: %v", err)
		}
		return
	}
	r, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if r2, err := b.Acquire(ctx); err == nil {
		r2()
		t.Fatalf("DEFECT: rate 1e-11/s (one start per ~3000 years) allowed an immediate second start: limiter fails open (TotalRateWait=%v)", b.Stats().TotalRateWait)
	}
}

// ctxClient honours ctx like a real network client (TestConnection/Connect take 20 ms).
type ctxClient struct {
	*fk
	disconnects *atomic.Int64
	connects    *atomic.Int64
}

func (c *ctxClient) wait(ctx context.Context) error {
	select {
	case <-time.After(20 * time.Millisecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *ctxClient) Connect(ctx context.Context) error {
	c.connects.Add(1)
	if err := c.wait(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()
	return nil
}
func (c *ctxClient) TestConnection(ctx context.Context) error { return c.wait(ctx) }
func (c *ctxClient) Disconnect(context.Context) error {
	c.disconnects.Add(1)
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
	return nil
}
func (c *ctxClient) IsConnected() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.connected }

type ctxFactory struct {
	disc, conn atomic.Int64
	authFail   bool
}

func (f *ctxFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	k := newFk("p")
	k.connected = false
	c := &ctxClient{fk: k, disconnects: &f.disc, connects: &f.conn}
	if f.authFail {
		return &authFailClient{c}, nil
	}
	return c, nil
}
func (f *ctxFactory) SupportedProtocols() []string { return nil }

// RV03: one borrower whose context ends during the health probe destroys every
// healthy idle connection of the root (and forces new logins).
func TestRV03_PoolCancelledBorrowDestroysHealthyIdle(t *testing.T) {
	f := &ctxFactory{}
	p, err := fabric.NewPool(f, fabric.PoolOptions{MaxPerKey: 3})
	if err != nil {
		t.Fatal(err)
	}
	var cs []client.Client
	for i := 0; i < 3; i++ {
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
	if p.Stats().Idle != 3 {
		t.Fatalf("setup: %+v", p.Stats())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, gerr := p.GetClientContext(ctx, cfgFor("a"))
	t.Logf("cancelled borrow: err=%v idle=%d disconnects=%d connects=%d", gerr, p.Stats().Idle, f.disc.Load(), f.conn.Load())
	if f.disc.Load() != 0 || p.Stats().Idle != 3 {
		t.Fatalf("DEFECT: a caller-cancelled borrow disconnected %d healthy idle connections (idle now %d)", f.disc.Load(), p.Stats().Idle)
	}
}

type authFailClient struct{ *ctxClient }

func (c *authFailClient) Connect(context.Context) error {
	c.connects.Add(1)
	return fabric.MarkAuth(errors.New("530 Login incorrect"))
}

// RV05: after an authentication failure the pool keeps logging in on every borrow.
func TestRV05_PoolAuthFailureNoCircuitBreaker(t *testing.T) {
	f := &ctxFactory{authFail: true}
	p, err := fabric.NewPool(f, fabric.PoolOptions{MaxPerKey: 4})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		_, err := p.GetClient(cfgFor("a"))
		if fabric.Classify(err) != fabric.ClassAuth {
			t.Fatalf("borrow %d: %v (class %v)", i, err, fabric.Classify(err))
		}
	}
	t.Logf("50 borrows after a bad password produced %d login attempts", f.conn.Load())
	if f.conn.Load() > 1 {
		t.Fatalf("DEFECT: %d login attempts for 50 borrows after an authentication failure (account lockout risk)", f.conn.Load())
	}
}

// non-hashable dynamic value behind a comparable static type
type mapFk struct {
	*fk
	tags map[string]int
}
type holder struct{ client.Client }

// RV04: a foreign client whose dynamic value is unhashable panics inside
// ReturnClient while p.mu is held (no defer), wedging the pool.
func TestRV04_PoolForeignUnhashableReturnWedges(t *testing.T) {
	p, err := fabric.NewPool(&poolFactory{}, fabric.PoolOptions{MaxPerKey: 1})
	if err != nil {
		t.Fatal(err)
	}
	foreign := holder{mapFk{newFk("x"), map[string]int{}}}
	var rerr error
	panicked := func() (v any) {
		defer func() { v = recover() }()
		rerr = p.ReturnClient(foreign)
		return nil
	}()
	t.Logf("ReturnClient(foreign unhashable): err=%v panic=%v", rerr, panicked)
	done := make(chan struct{})
	go func() { _ = p.Stats(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("DEFECT: pool deadlocked after ReturnClient of a foreign client panicked with the mutex held (panic: %v)", panicked)
	}
	if panicked != nil {
		t.Fatalf("DEFECT: ReturnClient of a foreign client panicked instead of returning ErrNotFromPool: %v", panicked)
	}
	if !errors.Is(rerr, fabric.ErrNotFromPool) {
		t.Fatalf("err=%v", rerr)
	}
}

// RV04b: the same type from a factory makes GetClient panic.
type unhashFactory struct{}

func (unhashFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	return holder{mapFk{newFk("x"), map[string]int{}}}, nil
}
func (unhashFactory) SupportedProtocols() []string { return nil }

func TestRV04b_PoolUnhashableClientPanicsOnBorrow(t *testing.T) {
	p, _ := fabric.NewPool(unhashFactory{}, fabric.PoolOptions{MaxPerKey: 1})
	var gerr error
	pv := func() (v any) {
		defer func() { v = recover() }()
		_, gerr = p.GetClient(cfgFor("a"))
		return nil
	}()
	t.Logf("GetClient(unhashable): err=%v panic=%v", gerr, pv)
	if pv != nil {
		t.Fatalf("DEFECT: GetClient panicked for a client type the comparability guard accepted: %v", pv)
	}
}

// RV06: Confined refuses NUL but forwards CR/LF (and other C0 controls) to the inner client.
func TestRV06_ConfinedPassesCRLF(t *testing.T) {
	for _, p := range []string{"/data/a\r\nDELE /data/b", "/data/a\nx", "/data/a\x1b[2J"} {
		f := newFk("p")
		c := confined(t, f, "/data")
		_, err := c.GetFileInfo(context.Background(), p)
		if !errors.Is(err, fabric.ErrOutsideRoot) {
			t.Errorf("DEFECT (defence in depth): control characters reached the inner client: %q err=%v inner saw %q", p, err, f.paths("GetFileInfo"))
		}
	}
}

// RV07: every fabric layer hides io.ReaderAt / io.Seeker / io.WriterTo of the inner stream.
func TestRV07_StreamsHideReaderAtAndSeeker(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	lc := local.NewLocalClient(&local.Config{BasePath: dir})
	_ = lc.Connect(context.Background())
	raw, _ := lc.OpenSeekable(context.Background(), "a")
	_, rawRA := raw.(io.ReaderAt)
	_ = raw.Close()
	rawRF, _ := lc.ReadFile(context.Background(), "a")
	_, rawSeek := rawRF.(io.ReadSeeker)
	_ = rawRF.Close()
	c := fabric.Limited(lc, mustBudget(t, 2, 1e6, nil)).(client.SeekableClient)
	s, err := c.OpenSeekable(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	_, ra := s.(io.ReaderAt)
	_ = s.Close()
	rf, err := c.(client.Client).ReadFile(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	_, sk := rf.(io.ReadSeeker)
	_ = rf.Close()
	t.Logf("raw local: OpenSeekable ReaderAt=%v ReadFile ReadSeeker=%v; Limited: OpenSeekable ReaderAt=%v ReadFile ReadSeeker=%v", rawRA, rawSeek, ra, sk)
	if rawRA && !ra {
		t.Errorf("DEFECT: Limited(OpenSeekable) dropped io.ReaderAt (catalog-api comic_pages_handler Strategy 1 needs it)")
	}
	if rawSeek && !sk {
		t.Errorf("DEFECT: Limited(ReadFile) dropped io.ReadSeeker (catalog-api stream_handler second-chance Range path needs it)")
	}
}

// RV08: the substring classifier reads attacker/server-controlled path text.
func TestRV08_ClassifyMarkerFromPathText(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want fabric.ErrorClass
	}{
		{"reset on a file named 'Access Denied'", &os.PathError{Op: "open", Path: "/media/Access Denied (2019).mkv", Err: syscall.ECONNRESET}, fabric.ClassTransient},
		{"not-found on a file named 'not logged in'", fmt.Errorf("stat /m/not logged in.txt: %w", os.ErrNotExist), fabric.ClassPermanent},
		{"FTP 550 Access denied (file level, RFC 959 permanent)", &textproto.Error{Code: 550, Msg: "Access denied"}, fabric.ClassPermanent},
		{"FTP 452 (RFC 959 4yz transient)", &textproto.Error{Code: 452, Msg: "Insufficient storage"}, fabric.ClassTransient},
	}
	for _, c := range cases {
		if got := fabric.Classify(c.err); got != c.want {
			t.Errorf("DEFECT: %s: Classify=%v, want %v", c.name, got, c.want)
		}
	}
}

// RV09: HostKey on a URL collapses every host to the scheme name.
func TestRV09_HostKeyURLCollapsesToScheme(t *testing.T) {
	a, ea := fabric.HostKey("smb://nas-a.example")
	b, eb := fabric.HostKey("smb://nas-b.example")
	t.Logf("HostKey(smb://nas-a.example)=%q,%v HostKey(smb://nas-b.example)=%q,%v", a, ea, b, eb)
	if ea == nil && eb == nil && a == b {
		t.Errorf("DEFECT: two different hosts share budget key %q", a)
	}
}

// RV10 (observation): equivalent spellings of one host get different keys.
func TestRV10_HostKeyEquivalentSpellings(t *testing.T) {
	pairs := [][2]string{{"::1", "0:0:0:0:0:0:0:1"}, {"192.168.1.5", "::ffff:192.168.1.5"}, {"[::1]:22", "[0::1]:445"}}
	for _, p := range pairs {
		a, _ := fabric.HostKey(p[0])
		b, _ := fabric.HostKey(p[1])
		if a != b { // ADOPTED AS ASSERTION (was t.Logf OBSERVATION)
			t.Errorf("equivalent spellings %q -> %q and %q -> %q do not share a budget key", p[0], a, p[1], b)
		}
	}
}

// RV11: a typed-nil inner is accepted at construction (doc: "nil inner panics at construction").
func TestRV11_TypedNilInnerAccepted(t *testing.T) {
	var lc *local.Client
	pv := func() (v any) {
		defer func() { v = recover() }()
		fabric.Limited(lc, mustBudget(t, 1, 1, nil))
		return nil
	}()
	if pv == nil {
		t.Errorf("DEFECT (claim): typed-nil inner accepted at construction; it panics on first use instead")
	}
}

// RV12 (measurement): a zero BaseDelay policy is accepted and retries back to back.
func TestRV12_RetryZeroDelayStorm(t *testing.T) {
	f := newFk("p")
	for i := 0; i < 1000; i++ {
		f.queue("ListDirectory", fmt.Errorf("dial: %w", syscall.ECONNREFUSED))
	}
	c, err := fabric.Retrying(f, fabric.RetryPolicy{MaxAttempts: 1000})
	if !errors.Is(err, fabric.ErrRetryPolicy) { // ADOPTED AS ASSERTION (was a measurement that accepted the policy)
		t.Fatalf("MaxAttempts=1000 BaseDelay=0 must be rejected, got err=%v client=%v", err, c)
	}
}

// RV14 (measurement): one leaked stream per protocol on a SHARED host budget blocks every protocol.
func TestRV14_LeakedStreamsStarveSharedHost(t *testing.T) {
	reg := fabric.NewBudgets()
	cfg := fabric.BudgetConfig{MaxConcurrent: 2, MaxReqPerSec: 1e6}
	b1, _ := reg.For("nas.local:445", cfg)
	b2, _ := reg.For("nas.local:22", cfg)
	smb := fabric.Limited(newFk("smb"), b1)
	sftp := fabric.Limited(newFk("sftp"), b2)
	_, _ = smb.ReadFile(context.Background(), "/a")  // never closed
	_, _ = sftp.ReadFile(context.Background(), "/b") // never closed
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := smb.ListDirectory(ctx, "/")
	t.Logf("MEASURED: after two unclosed streams (one per protocol) a third op on the host: %v (InFlight=%d)", err, b1.Stats().InFlight)
	// ADOPTED AS ASSERTION: the documented contract (no lease) still starves, and the leak is now VISIBLE
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("without a lease the leaked streams must still hold the host: %v", err)
	}
	if st := b1.Stats(); st.Held != 2 || st.OldestHeld <= 0 { // round 3 (T4): `< 0` could never be true; a leaked stream has a positive age
		t.Errorf("the leak is not visible in Stats: %+v", st)
	}
}

// RV15: pooled clients decorated with Limited share the host budget with their own health probe.
// When the budget is busy (an open stream holds it), GetClient - documented as "without waiting" -
// discards the healthy idle connection (probe times out on the budget) and then blocks in Connect
// (context.Background) until the budget frees.
type limitedPoolFactory struct {
	b    *fabric.HostBudget
	made []*fk
	mu   sync.Mutex
}

func (f *limitedPoolFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	k := newFk("p")
	k.connected = false
	f.mu.Lock()
	f.made = append(f.made, k)
	f.mu.Unlock()
	return fabric.Limited(&poolClient{k}, f.b), nil
}
func (f *limitedPoolFactory) SupportedProtocols() []string { return nil }

func TestRV15_PoolHealthProbeThrottledByOwnBudget(t *testing.T) {
	b := mustBudget(t, 1, 1e6, nil)
	f := &limitedPoolFactory{b: b}
	p, err := fabric.NewPool(f, fabric.PoolOptions{MaxPerKey: 2, HealthTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
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
	done := make(chan error, 1)
	t0 := time.Now()
	go func() { _, e := p.GetClient(cfgFor("a")); done <- e }()
	returned := false // ADOPTED: the original drained `done` unconditionally and would hang on the (now correct) fast path
	select {
	case e := <-done:
		returned = true
		if e != nil {
			t.Errorf("GetClient: %v", e)
		}
		t.Logf("GetClient returned after %v: %v", time.Since(t0), e)
	case <-time.After(time.Second):
		f.mu.Lock()
		d := f.made[0].count("Disconnect")
		f.mu.Unlock()
		t.Errorf("DEFECT: GetClient (\"without waiting\") still blocked after 1s on a busy host budget; healthy idle connection disconnected %d time(s)", d)
	}
	_ = rc.Close()
	if !returned {
		<-done
	}
	f.mu.Lock()
	t.Logf("after the stream closed: connections created=%d, first connection disconnects=%d", len(f.made), f.made[0].count("Disconnect"))
	f.mu.Unlock()
}

// RV16: the doc says authentication is decided first; a transient FTP code wins over auth text.
func TestRV16_ClassifyTransientCodeBeatsAuthText(t *testing.T) {
	e := &textproto.Error{Code: 421, Msg: "Login authentication failed, too many attempts"}
	if got := fabric.Classify(e); got != fabric.ClassAuth {
		t.Errorf("DEFECT (claim 'auth first'): %v classified %v", e, got)
	}
}

// RV18: IdleTimeout is enforced only lazily for the most-recently-used entry; an older idle
// connection below it stays open (and counts against the server's per-IP limit) indefinitely.
func TestRV18_IdleTimeoutNotEnforcedBelowMRU(t *testing.T) {
	clk := newFakeClock()
	pf := &poolFactory{}
	p, _ := fabric.NewPool(pf, fabric.PoolOptions{MaxPerKey: 2, IdleTimeout: time.Minute, Clock: clk})
	a, _ := p.GetClient(cfgFor("a"))
	b2, _ := p.GetClient(cfgFor("a"))
	_ = p.ReturnClient(a)
	_ = p.ReturnClient(b2)
	for i := 0; i < 10; i++ { // a single-worker scan keeps reusing the MRU entry for 10 minutes
		clk.advance(time.Minute - time.Second)
		c, err := p.GetClient(cfgFor("a"))
		if err != nil {
			t.Fatal(err)
		}
		_ = p.ReturnClient(c)
	}
	t.Logf("after 10 min of single-worker use: idle=%d, first connection disconnects=%d (IdleTimeout=1m)", p.Stats().Idle, pf.made[0].count("Disconnect"))
	if pf.made[0].count("Disconnect") == 0 {
		t.Errorf("a connection idle for ~10x IdleTimeout was never retired") // ADOPTED AS ASSERTION
	}
}
