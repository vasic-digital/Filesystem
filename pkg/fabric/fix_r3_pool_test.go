package fabric_test

// Round-3 (WF24 re-review) regression tests for Pool: N3 (rejected-login memory
// is single-flight and per ACCOUNT), N10 (duplicate client from the factory),
// N2 (a skipped probe is not an unhealthy connection).

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
)

// cfgForUser is a storage root of the NAS account `user` (the root id and the
// share differ per call; the account is what the settings below identify).
func cfgForUser(id, user string) *client.StorageConfig {
	return &client.StorageConfig{ID: id, Protocol: "fk", Settings: map[string]interface{}{"host": "nas", "username": user, "password": "dummy-pw"}}
}

// cfgRoot is root `id` of ONE account: only the root-selecting keys differ.
func cfgRoot(id, share string) *client.StorageConfig {
	c := cfgForUser(id, "u")
	c.Settings["share"] = share
	c.Settings["path"] = "/" + share
	return c
}

// r3Factory builds clients whose Connect is observable: the number of calls, the
// peak number of Connects in flight, and an error chosen per call.
type r3Factory struct {
	conn, cur, peak, disc atomic.Int64
	delay                 time.Duration
	errFor                func(n int64) error // nil = success
}

func (f *r3Factory) CreateClient(*client.StorageConfig) (client.Client, error) {
	k := newFk("p")
	k.connected = false
	return &r3Client{fk: k, f: f}, nil
}
func (f *r3Factory) SupportedProtocols() []string { return nil }

type r3Client struct {
	*fk
	f *r3Factory
}

func (c *r3Client) Connect(ctx context.Context) error {
	n := c.f.conn.Add(1)
	cur := c.f.cur.Add(1)
	defer c.f.cur.Add(-1)
	for {
		p := c.f.peak.Load()
		if cur <= p || c.f.peak.CompareAndSwap(p, cur) {
			break
		}
	}
	select {
	case <-time.After(c.f.delay):
	case <-ctx.Done():
		return ctx.Err()
	}
	if c.f.errFor != nil {
		if err := c.f.errFor(n); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()
	return nil
}
func (c *r3Client) Disconnect(context.Context) error {
	c.f.disc.Add(1)
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
	return nil
}
func (c *r3Client) IsConnected() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.connected }

var errBadPassword = fabric.MarkAuth(errors.New("530 Login incorrect"))

func borrowAll(p *fabric.Pool, n int, cfg func(i int) *client.StorageConfig) (errs []error, ok []client.Client) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := p.GetClientContext(context.Background(), cfg(i))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			} else {
				ok = append(ok, c)
			}
		}(i)
	}
	wg.Wait()
	return
}

// N3 member 1: concurrent first borrowers of one root make ONE login.
func TestR3_ConcurrentBorrowersAfterRejectionMakeOneLogin(t *testing.T) {
	t.Parallel()
	f := &r3Factory{delay: 30 * time.Millisecond, errFor: func(int64) error { return errBadPassword }}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 8})
	errs, ok := borrowAll(p, 8, func(int) *client.StorageConfig { return cfgForUser("a", "u") })
	if f.conn.Load() != 1 {
		t.Fatalf("%d logins for 8 concurrent borrows with a wrong password, want 1", f.conn.Load())
	}
	if len(ok) != 0 || len(errs) != 8 {
		t.Fatalf("ok=%d errs=%d", len(ok), len(errs))
	}
	for _, e := range errs {
		if fabric.Classify(e) != fabric.ClassAuth {
			t.Errorf("a waiter got a non-auth error: %v", e)
		}
	}
}

// N3 member 2: three roots of ONE account (they differ only in share/path) make ONE login.
func TestR3_RejectedLoginIsSharedByTheRootsOfOneAccount(t *testing.T) {
	t.Parallel()
	f := &r3Factory{errFor: func(int64) error { return errBadPassword }}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	for _, root := range []string{"movies", "music", "photos"} {
		if _, err := p.GetClient(cfgRoot(root, root)); fabric.Classify(err) != fabric.ClassAuth {
			t.Fatalf("root %s: %v", root, err)
		}
	}
	if f.conn.Load() != 1 {
		t.Fatalf("%d logins for 3 roots of one account, want 1", f.conn.Load())
	}
}

// N3 member 3: a DIFFERENT account is independent (a different user, a different host).
func TestR3_RejectedLoginDoesNotBlockAnotherAccount(t *testing.T) {
	t.Parallel()
	f := &r3Factory{errFor: func(n int64) error {
		if n == 1 {
			return errBadPassword
		}
		return nil
	}}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	if _, err := p.GetClient(cfgForUser("a", "alice")); fabric.Classify(err) != fabric.ClassAuth {
		t.Fatal(err)
	}
	c, err := p.GetClient(cfgForUser("b", "bob"))
	if err != nil {
		t.Fatalf("another account was refused: %v", err)
	}
	_ = p.ReturnClient(c)
	other := cfgForUser("c", "alice")
	other.Settings["host"] = "other-nas"
	if _, err := p.GetClient(other); err != nil {
		t.Fatalf("the same user name on another host was refused: %v", err)
	}
}

// A refusal found at one root never cuts off the working idle connections of
// another root of the same account; only NEW logins are refused.
func TestR3_AccountRefusalDoesNotCutOffIdleConnections(t *testing.T) {
	t.Parallel()
	f := &r3Factory{errFor: func(n int64) error {
		if n >= 2 {
			return errBadPassword // the password was changed on the server after the first login
		}
		return nil
	}}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	c, err := p.GetClient(cfgRoot("movies", "movies"))
	if err != nil {
		t.Fatal(err)
	}
	_ = p.ReturnClient(c)
	if _, err := p.GetClient(cfgRoot("music", "music")); fabric.Classify(err) != fabric.ClassAuth {
		t.Fatalf("music: %v", err)
	}
	c2, err := p.GetClient(cfgRoot("movies", "movies")) // the idle, working connection of movies
	if err != nil || c2 != c {
		t.Fatalf("an idle working connection was refused after another root's rejection: c2==c %v err=%v", c2 == c, err)
	}
	if _, err := p.GetClient(cfgRoot("movies", "movies")); fabric.Classify(err) != fabric.ClassAuth {
		t.Fatalf("a NEW login for movies must be refused now: %v", err)
	}
	_ = p.ReturnClient(c2)
}

// Settings that identify no account (the factory knows it some other way, as in
// pkg/ftp) make each root its own account: nothing is merged on no evidence.
func TestR3_ConfigsWithoutAccountSettingsAreSeparateAccounts(t *testing.T) {
	t.Parallel()
	f := &r3Factory{errFor: func(int64) error { return errBadPassword }}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	_, _ = p.GetClient(cfgFor("a"))
	_, _ = p.GetClient(cfgFor("b"))
	_, _ = p.GetClient(cfgFor("a"))
	if f.conn.Load() != 2 {
		t.Fatalf("%d logins for roots a, b, a with no account settings, want 2 (one per root)", f.conn.Load())
	}
}

// N3 member 4: correcting the password (a settings change) is a new attempt, for every root of the account.
func TestR3_ChangedCredentialsAreANewAttempt(t *testing.T) {
	t.Parallel()
	f := &r3Factory{errFor: func(n int64) error {
		if n == 1 {
			return errBadPassword
		}
		return nil
	}}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	if _, err := p.GetClient(cfgForUser("a", "u")); fabric.Classify(err) != fabric.ClassAuth {
		t.Fatal(err)
	}
	fixed := cfgForUser("a", "u")
	fixed.Settings["password"] = "corrected-dummy-pw"
	c, err := p.GetClient(fixed)
	if err != nil {
		t.Fatalf("a corrected password was not tried: %v", err)
	}
	_ = p.ReturnClient(c)
	// the refusal of the OLD credentials was dropped when the settings changed:
	// going back to them is a new attempt, not a stale refusal
	p.Evict("a") // the idle connection of the corrected settings is retired (same root ID)
	before := f.conn.Load()
	c2, err := p.GetClient(cfgForUser("a", "u"))
	if f.conn.Load() != before+1 {
		t.Fatalf("returning to the old settings: %d new logins (err=%v), want 1", f.conn.Load()-before, err)
	}
	if err == nil {
		_ = p.ReturnClient(c2)
	}
}

// N3 member 5: Evict of one root lifts the refusal of its account.
func TestR3_EvictLiftsTheRefusalOfTheAccount(t *testing.T) {
	t.Parallel()
	f := &r3Factory{errFor: func(n int64) error {
		if n == 1 {
			return errBadPassword
		}
		return nil
	}}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	_, _ = p.GetClient(cfgRoot("movies", "movies"))
	if _, err := p.GetClient(cfgRoot("music", "music")); fabric.Classify(err) != fabric.ClassAuth {
		t.Fatalf("music should share the refusal: %v", err)
	}
	p.Evict("movies")
	c, err := p.GetClient(cfgRoot("music", "music"))
	if err != nil {
		t.Fatalf("after Evict the account must be tried again: %v", err)
	}
	_ = p.ReturnClient(c)
}

// N3 member 6: a TRANSIENT failure of the pilot is not remembered and does not
// serialise the waiters: they all try (concurrently) afterwards.
func TestR3_TransientPilotFailureReleasesTheWaitersToTryConcurrently(t *testing.T) {
	t.Parallel()
	f := &r3Factory{delay: 40 * time.Millisecond, errFor: func(n int64) error {
		if n == 1 {
			return errReset
		}
		return nil
	}}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 6})
	errs, ok := borrowAll(p, 6, func(int) *client.StorageConfig { return cfgForUser("a", "u") })
	if len(errs) != 1 || len(ok) != 5 {
		t.Fatalf("ok=%d errs=%d, want 5 and 1 (only the pilot failed): %v", len(ok), len(errs), errs)
	}
	if f.conn.Load() != 6 {
		t.Fatalf("%d logins, want 6", f.conn.Load())
	}
	if f.peak.Load() < 2 {
		t.Fatalf("the waiters were serialised after a transient pilot failure (peak concurrent logins %d)", f.peak.Load())
	}
}

// N3 member 6b: while an account has never logged in, transient failures must
// not turn the waiters into a queue: with every login failing transiently they
// still try concurrently (each one is a fresh pilot only if nobody else is).
func TestR3_TransientFailuresDoNotSerialiseAnUnprovenAccount(t *testing.T) {
	t.Parallel()
	f := &r3Factory{delay: 40 * time.Millisecond, errFor: func(int64) error { return errReset }}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 6})
	errs, ok := borrowAll(p, 6, func(int) *client.StorageConfig { return cfgForUser("a", "u") })
	if len(ok) != 0 || len(errs) != 6 {
		t.Fatalf("ok=%d errs=%d", len(ok), len(errs))
	}
	if f.conn.Load() != 6 {
		t.Fatalf("%d logins, want 6 (transient failures are never remembered)", f.conn.Load())
	}
	if f.peak.Load() < 2 {
		t.Fatalf("the waiters of a transiently failing pilot were serialised (peak concurrent logins %d)", f.peak.Load())
	}
}

// N3 member 7: once ONE login of the account worked, further logins are not serialised.
func TestR3_ProvenAccountLoginsRunConcurrently(t *testing.T) {
	t.Parallel()
	f := &r3Factory{delay: 200 * time.Millisecond}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 6})
	c, err := p.GetClient(cfgForUser("a", "u")) // the pilot
	if err != nil {
		t.Fatal(err)
	}
	_ = p.ReturnClient(c)
	f.peak.Store(0)
	_, ok := borrowAll(p, 6, func(int) *client.StorageConfig { return cfgForUser("a", "u") })
	if len(ok) != 6 {
		t.Fatalf("ok=%d", len(ok))
	}
	// the idle connection of the pilot serves one borrower, the other five log in AT ONCE: a gate
	// that still made one of them a pilot would show at most 4 simultaneous logins
	if f.peak.Load() < 5 {
		t.Fatalf("logins of a proven account are serialised (peak %d simultaneous logins, want 5)", f.peak.Load())
	}
}

// N3 member 8: while a pilot is in flight a waiter whose context ends leaves at once, holding nothing.
func TestR3_WaiterForThePilotHonoursItsContext(t *testing.T) {
	t.Parallel()
	f := &r3Factory{delay: 400 * time.Millisecond}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 3})
	pilotDone := make(chan struct{})
	go func() {
		defer close(pilotDone)
		if c, err := p.GetClientContext(context.Background(), cfgForUser("a", "u")); err == nil {
			_ = p.ReturnClient(c)
		}
	}()
	for f.conn.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	_, err := p.GetClientContext(ctx, cfgForUser("a", "u"))
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(t0) > 300*time.Millisecond {
		t.Fatalf("waiter: %v after %v", err, time.Since(t0))
	}
	<-pilotDone
	if st := p.Stats(); st.InUse != 0 {
		t.Fatalf("stats %+v", st)
	}
	// the waiter's token was released: the pool still serves MaxPerKey borrowers
	for i := 0; i < 3; i++ {
		if _, err := p.GetClient(cfgForUser("a", "u")); err != nil {
			t.Fatalf("borrow %d: %v", i, err)
		}
	}
}

// N3 member 8b: Evict lifts a per-root denial (a share or file refusal) too.
func TestR3_EvictLiftsAPerRootDenial(t *testing.T) {
	t.Parallel()
	denied := fmt.Errorf("failed to mount SMB share: %w", &smb2.ResponseError{Code: 0xC0000022}) // STATUS_ACCESS_DENIED
	f := &r3Factory{errFor: func(n int64) error {
		if n == 1 {
			return denied
		}
		return nil
	}}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	if _, err := p.GetClient(cfgRoot("private", "private")); err == nil {
		t.Fatal("the first login should have been denied")
	}
	if _, err := p.GetClient(cfgRoot("private", "private")); err == nil || f.conn.Load() != 1 {
		t.Fatalf("the denied root must not be tried again: err=%v connects=%d", err, f.conn.Load())
	}
	p.Evict("private")
	c, err := p.GetClient(cfgRoot("private", "private"))
	if err != nil {
		t.Fatalf("after Evict the root must be tried again: %v", err)
	}
	_ = p.ReturnClient(c)
}

// N3 member 9: CloseAll wakes the waiters of a pilot.
func TestR3_CloseAllWakesTheWaitersOfAPilot(t *testing.T) {
	t.Parallel()
	f := &r3Factory{delay: 2 * time.Second}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 3, ConnectTimeout: 5 * time.Second})
	go func() { _, _ = p.GetClientContext(context.Background(), cfgForUser("a", "u")) }()
	for f.conn.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	res := make(chan error, 1)
	go func() { _, err := p.GetClientContext(context.Background(), cfgForUser("a", "u")); res <- err }()
	time.Sleep(50 * time.Millisecond)
	_ = p.CloseAll()
	select {
	case err := <-res:
		if !errors.Is(err, fabric.ErrPoolClosed) {
			t.Fatalf("waiter: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseAll did not wake the waiter of the pilot")
	}
}

// N3: unmarshalable settings have no account identity: no memory and no gate.
func TestR3_UnmarshalableSettingsHaveNoAccountMemoryAndNoGate(t *testing.T) {
	t.Parallel()
	f := &r3Factory{delay: 20 * time.Millisecond, errFor: func(int64) error { return errBadPassword }}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 4})
	cfg := func(int) *client.StorageConfig {
		c := cfgFor("a")
		c.Settings = map[string]interface{}{"opaque": make(chan int)}
		return c
	}
	borrowAll(p, 4, cfg)
	if f.conn.Load() != 4 {
		t.Fatalf("%d logins, want 4 (documented: no memory for settings that cannot be fingerprinted)", f.conn.Load())
	}
}

// ---- N10: a factory that returns a client the pool already holds ----

type dupFactory struct {
	mu   sync.Mutex
	c    *r3Client
	f    *r3Factory
	made atomic.Int64
}

func (d *dupFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.made.Add(1)
	if d.c == nil {
		k := newFk("p")
		k.connected = false
		d.c = &r3Client{fk: k, f: d.f}
	}
	return d.c, nil
}
func (*dupFactory) SupportedProtocols() []string { return nil }

// The second borrow is refused BEFORE the shared client is connected again or
// disconnected, and the pool keeps all its capacity.
func TestR3_DuplicateClientFromTheFactoryIsRefusedWithoutTouchingIt(t *testing.T) {
	t.Parallel()
	d := &dupFactory{f: &r3Factory{}}
	p := newPool(t, d, fabric.PoolOptions{MaxPerKey: 2})
	c1, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetClient(cfgFor("a")); !errors.Is(err, fabric.ErrDuplicateClient) {
		t.Fatalf("second borrow: %v, want ErrDuplicateClient", err)
	}
	if d.f.conn.Load() != 1 || d.f.disc.Load() != 0 || !c1.IsConnected() {
		t.Fatalf("the held client was touched: connects=%d disconnects=%d connected=%v", d.f.conn.Load(), d.f.disc.Load(), c1.IsConnected())
	}
	if st := p.Stats(); st.InUse != 1 {
		t.Fatalf("stats %+v", st)
	}
	// capacity: after the holder returns it, one borrow works again and the slot count is intact
	if err := p.ReturnClient(c1); err != nil {
		t.Fatal(err)
	}
	c3, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	_ = p.ReturnClient(c3)
	// the same while the duplicate sits IDLE in the pool
	if _, err := p.GetClient(cfgFor("a")); err != nil {
		t.Fatal(err)
	}
}

// Two borrowers pass the early duplicate check together (neither is registered
// yet) and both connect: the second REGISTRATION is the one refused, and the
// holder's connection is not disconnected by the loser.
func TestR3_ConcurrentDuplicateIsRefusedAtRegistration(t *testing.T) {
	t.Parallel()
	d := &dupFactory{f: &r3Factory{delay: 80 * time.Millisecond}}
	p := newPool(t, d, fabric.PoolOptions{MaxPerKey: 2})
	cfg := func(int) *client.StorageConfig { // unmarshalable settings: no account identity, so no login gate
		c := cfgFor("a")
		c.Settings = map[string]interface{}{"opaque": make(chan int)}
		return c
	}
	errs, ok := borrowAll(p, 2, cfg)
	if len(ok) != 1 || len(errs) != 1 || !errors.Is(errs[0], fabric.ErrDuplicateClient) {
		t.Fatalf("ok=%d errs=%v, want one success and one ErrDuplicateClient", len(ok), errs)
	}
	if d.f.disc.Load() != 0 || !ok[0].IsConnected() {
		t.Fatalf("the loser disconnected the holder's client: disconnects=%d connected=%v", d.f.disc.Load(), ok[0].IsConnected())
	}
	if st := p.Stats(); st.InUse != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// ---- N2: Pool treats a skipped probe as "no evidence of a fault" ----

type skipProbeFactory struct{ disc, conn atomic.Int64 }

func (f *skipProbeFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	k := newFk("p")
	k.connected = false
	return &skipProbeClient{fk: k, f: f}, nil
}
func (f *skipProbeFactory) SupportedProtocols() []string { return nil }

type skipProbeClient struct {
	*fk
	f *skipProbeFactory
}

func (c *skipProbeClient) Connect(context.Context) error {
	c.f.conn.Add(1)
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()
	return nil
}
func (c *skipProbeClient) TestConnection(context.Context) error {
	return errors.Join(errors.New("budget"), fabric.ErrProbeSkipped)
}
func (c *skipProbeClient) Disconnect(context.Context) error {
	c.f.disc.Add(1)
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
	return nil
}
func (c *skipProbeClient) IsConnected() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.connected }

func TestR3_SkippedProbeKeepsTheConnection(t *testing.T) {
	t.Parallel()
	f := &skipProbeFactory{}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 1})
	c, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	_ = p.ReturnClient(c)
	for i := 0; i < 5; i++ {
		c2, err := p.GetClient(cfgFor("a"))
		if err != nil || c2 != c {
			t.Fatalf("borrow %d: c2==c %v err=%v", i, c2 == c, err)
		}
		_ = p.ReturnClient(c2)
	}
	if f.disc.Load() != 0 || f.conn.Load() != 1 {
		t.Fatalf("a skipped probe cost the connection: disconnects=%d connects=%d", f.disc.Load(), f.conn.Load())
	}
}

// control for the above: a probe that FAILS (any other error) still retires the connection.
type failProbeFactory struct{ skipProbeFactory }

func (f *failProbeFactory) CreateClient(cfg *client.StorageConfig) (client.Client, error) {
	c, _ := f.skipProbeFactory.CreateClient(cfg)
	return &failProbeClient{c.(*skipProbeClient)}, nil
}

type failProbeClient struct{ *skipProbeClient }

func (c *failProbeClient) TestConnection(context.Context) error { return errors.New("dead") }

func TestR3_FailedProbeStillRetiresTheConnection(t *testing.T) {
	t.Parallel()
	f := &failProbeFactory{}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 1})
	c, _ := p.GetClient(cfgFor("a"))
	_ = p.ReturnClient(c)
	c2, err := p.GetClient(cfgFor("a"))
	if err != nil || c2 == c || f.disc.Load() != 1 {
		t.Fatalf("c2==c %v err=%v disconnects=%d, want a new connection and 1 disconnect", c2 == c, err, f.disc.Load())
	}
}
