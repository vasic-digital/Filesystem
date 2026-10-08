package fabric_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
)

// poolFactory creates fk clients and remembers them (unit tests only).
type poolFactory struct {
	mu      sync.Mutex
	made    []*fk
	failFor error
}

func (p *poolFactory) CreateClient(cfg *client.StorageConfig) (client.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failFor != nil {
		return nil, p.failFor
	}
	f := newFk(cfg.Protocol)
	f.connected = false
	p.made = append(p.made, f)
	return &poolClient{f}, nil
}
func (p *poolFactory) SupportedProtocols() []string { return []string{"fk"} }
func (p *poolFactory) count() int                   { p.mu.Lock(); defer p.mu.Unlock(); return len(p.made) }

// poolClient makes IsConnected follow Connect/Disconnect like a real client.
type poolClient struct{ *fk }

func (c *poolClient) Connect(ctx context.Context) error {
	if err := c.fk.Connect(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()
	return nil
}
func (c *poolClient) Disconnect(ctx context.Context) error {
	err := c.fk.Disconnect(ctx)
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
	return err
}
func (c *poolClient) IsConnected() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.connected }

func cfgFor(id string) *client.StorageConfig { return &client.StorageConfig{ID: id, Protocol: "fk"} }

func newPool(t testing.TB, f client.Factory, o fabric.PoolOptions) *fabric.Pool {
	t.Helper()
	p, err := fabric.NewPool(f, o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPool_ConfigValidation(t *testing.T) {
	t.Parallel()
	f := &poolFactory{}
	for _, o := range []fabric.PoolOptions{{}, {MaxPerKey: 0}, {MaxPerKey: 1, MaxLifetime: -1}, {MaxPerKey: 1, IdleTimeout: -1}, {MaxPerKey: 1, HealthTimeout: -1}} {
		if _, err := fabric.NewPool(f, o); !errors.Is(err, fabric.ErrPoolConfig) {
			t.Errorf("%+v: %v", o, err)
		}
	}
	if _, err := fabric.NewPool(nil, fabric.PoolOptions{MaxPerKey: 1}); !errors.Is(err, fabric.ErrPoolConfig) {
		t.Errorf("nil factory: %v", err)
	}
}

func TestPool_KeyRequired(t *testing.T) {
	t.Parallel()
	p := newPool(t, &poolFactory{}, fabric.PoolOptions{MaxPerKey: 1})
	if _, err := p.GetClient(nil); !errors.Is(err, fabric.ErrPoolKey) {
		t.Errorf("nil: %v", err)
	}
	if _, err := p.GetClient(&client.StorageConfig{}); !errors.Is(err, fabric.ErrPoolKey) {
		t.Errorf("empty id: %v", err)
	}
}

func TestPool_ReusesConnectionAndSeparatesRoots(t *testing.T) {
	t.Parallel()
	f := &poolFactory{}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	a, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsConnected() {
		t.Fatal("borrowed client must be connected")
	}
	if err := p.ReturnClient(a); err != nil {
		t.Fatal(err)
	}
	a2, _ := p.GetClient(cfgFor("a"))
	if a2 != a || f.count() != 1 {
		t.Fatalf("connection not reused: made=%d", f.count())
	}
	b, _ := p.GetClient(cfgFor("b"))
	if b == a2 || f.count() != 2 {
		t.Fatal("different roots must not share a connection")
	}
	if st := p.Stats(); st.InUse != 2 || st.Idle != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestPool_UnhealthyIdleConnectionIsReplaced(t *testing.T) {
	t.Parallel()
	f := &poolFactory{}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 1})
	a, _ := p.GetClient(cfgFor("a"))
	_ = p.ReturnClient(a)
	f.made[0].queue("TestConnection", errors.New("stale session")) // health probe fails once
	a2, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	if a2 == a || f.count() != 2 {
		t.Fatalf("stale connection reused (made=%d)", f.count())
	}
	if f.made[0].count("Disconnect") != 1 {
		t.Fatal("stale connection must be disconnected")
	}
}

func TestPool_DisconnectedIdleConnectionIsReplaced(t *testing.T) {
	t.Parallel()
	f := &poolFactory{}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 1})
	a, _ := p.GetClient(cfgFor("a"))
	_ = p.ReturnClient(a)
	_ = a.Disconnect(context.Background()) // dropped behind the pool's back
	a2, _ := p.GetClient(cfgFor("a"))
	if a2 == a || f.count() != 2 {
		t.Fatalf("dead connection reused (made=%d)", f.count())
	}
}

func TestPool_MaxLifetimeAndIdleTimeoutRetire(t *testing.T) {
	t.Parallel()
	for name, o := range map[string]fabric.PoolOptions{
		"lifetime": {MaxPerKey: 1, MaxLifetime: time.Minute},
		"idle":     {MaxPerKey: 1, IdleTimeout: time.Minute},
	} {
		clk := newFakeClock()
		o.Clock = clk
		f := &poolFactory{}
		p := newPool(t, f, o)
		a, _ := p.GetClient(cfgFor("a"))
		_ = p.ReturnClient(a)
		clk.advance(30 * time.Second)
		a2, _ := p.GetClient(cfgFor("a"))
		if a2 != a {
			t.Errorf("%s: retired too early", name)
		}
		_ = p.ReturnClient(a2)
		clk.advance(61 * time.Second)
		a3, _ := p.GetClient(cfgFor("a"))
		if a3 == a || f.count() != 2 {
			t.Errorf("%s: not retired (made=%d)", name, f.count())
		}
	}
}

func TestPool_LifetimeExpiredClientIsNotPooledOnReturn(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	f := &poolFactory{}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 1, MaxLifetime: time.Minute, Clock: clk})
	a, _ := p.GetClient(cfgFor("a"))
	clk.advance(2 * time.Minute)
	_ = p.ReturnClient(a)
	if p.Stats().Idle != 0 || f.made[0].count("Disconnect") != 1 {
		t.Fatalf("expired client pooled: %+v", p.Stats())
	}
}

func TestPool_ExhaustionAndBlockingBorrow(t *testing.T) {
	t.Parallel()
	p := newPool(t, &poolFactory{}, fabric.PoolOptions{MaxPerKey: 1})
	a, _ := p.GetClient(cfgFor("a"))
	if _, err := p.GetClient(cfgFor("a")); !errors.Is(err, fabric.ErrPoolExhausted) {
		t.Fatalf("err=%v", err)
	}
	// blocking borrow is served when the first is returned
	got := make(chan client.Client, 1)
	go func() {
		c, err := p.GetClientContext(context.Background(), cfgFor("a"))
		if err != nil {
			t.Error(err)
		}
		got <- c
	}()
	select {
	case <-got:
		t.Fatal("served before a slot was free")
	case <-time.After(30 * time.Millisecond):
	}
	_ = p.ReturnClient(a)
	select {
	case c := <-got:
		if c != a {
			t.Fatal("waiter should receive the returned connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter never served")
	}
	// context ends while waiting
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.GetClientContext(ctx, cfgFor("a")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func TestPool_ReturnValidation(t *testing.T) {
	t.Parallel()
	p := newPool(t, &poolFactory{}, fabric.PoolOptions{MaxPerKey: 2})
	a, _ := p.GetClient(cfgFor("a"))
	if err := p.ReturnClient(a); err != nil {
		t.Fatal(err)
	}
	if err := p.ReturnClient(a); !errors.Is(err, fabric.ErrNotFromPool) {
		t.Fatalf("double return: %v", err)
	}
	if err := p.ReturnClient(newFk("x")); !errors.Is(err, fabric.ErrNotFromPool) {
		t.Fatalf("foreign client: %v", err)
	}
	if err := p.ReturnClient(nil); !errors.Is(err, fabric.ErrNotFromPool) {
		t.Fatalf("nil: %v", err)
	}
}

func TestPool_CreateAndConnectFailuresFreeTheSlot(t *testing.T) {
	t.Parallel()
	f := &poolFactory{failFor: errors.New("cannot create")}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 1})
	if _, err := p.GetClient(cfgFor("a")); err == nil {
		t.Fatal("expected create error")
	}
	f.failFor = nil
	// connect failure: first client's Connect errors once
	c, err := p.GetClient(cfgFor("a"))
	if err != nil {
		t.Fatalf("slot leaked after create failure: %v", err)
	}
	_ = p.ReturnClient(c)

	// connect failure: the first client created by the hook factory refuses Connect once
	hook := &failConnectFactory{inner: &poolFactory{}}
	p3 := newPool(t, hook, fabric.PoolOptions{MaxPerKey: 1})
	if _, err := p3.GetClient(cfgFor("z")); err == nil {
		t.Fatal("expected connect error")
	}
	if _, err := p3.GetClient(cfgFor("z")); err != nil {
		t.Fatalf("slot leaked after connect failure: %v", err)
	}
}

type failConnectFactory struct {
	inner *poolFactory
	once  sync.Once
}

func (f *failConnectFactory) CreateClient(cfg *client.StorageConfig) (client.Client, error) {
	c, err := f.inner.CreateClient(cfg)
	if err != nil {
		return nil, err
	}
	f.once.Do(func() { c.(*poolClient).queue("Connect", errors.New("refused")) })
	return c, nil
}
func (f *failConnectFactory) SupportedProtocols() []string { return nil }

func TestPool_CloseAll(t *testing.T) {
	t.Parallel()
	f := &poolFactory{}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	a, _ := p.GetClient(cfgFor("a"))
	b, _ := p.GetClient(cfgFor("a"))
	_ = p.ReturnClient(b) // idle
	// a waiter blocked on a full root is woken with ErrPoolClosed
	c, _ := p.GetClient(cfgFor("a")) // takes the idle b
	_ = c
	waitErr := make(chan error, 1)
	go func() {
		_, err := p.GetClientContext(context.Background(), cfgFor("a"))
		waitErr <- err
	}()
	time.Sleep(30 * time.Millisecond)
	_ = p.ReturnClient(c)
	if err := p.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if err := p.CloseAll(); err != nil {
		t.Fatalf("second CloseAll: %v", err)
	}
	select {
	case err := <-waitErr:
		// the waiter either got c before close, or ErrPoolClosed: both are valid outcomes of a race,
		// but it must not hang.
		_ = err
	case <-time.After(2 * time.Second):
		t.Fatal("waiter hung after CloseAll")
	}
	if _, err := p.GetClient(cfgFor("a")); !errors.Is(err, fabric.ErrPoolClosed) {
		t.Fatalf("borrow after close: %v", err)
	}
	if err := p.ReturnClient(a); err != nil {
		t.Fatalf("return after close: %v", err)
	}
	if p.Stats().Idle != 0 {
		t.Fatal("idle connections left after CloseAll")
	}
	if f.made[0].count("Disconnect") < 1 {
		t.Fatal("borrowed client must be disconnected when returned to a closed pool")
	}
}

func TestPool_EvictDisconnectsIdle(t *testing.T) {
	t.Parallel()
	f := &poolFactory{}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 1})
	a, _ := p.GetClient(cfgFor("a"))
	_ = p.ReturnClient(a)
	p.Evict("a")
	if p.Stats().Idle != 0 || f.made[0].count("Disconnect") != 1 {
		t.Fatalf("evict failed: %+v", p.Stats())
	}
}

func TestPool_RaceManyBorrowers(t *testing.T) {
	t.Parallel()
	f := &poolFactory{}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 3})
	var g gauge
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := p.GetClientContext(context.Background(), cfgFor("a"))
			if err != nil {
				t.Error(err)
				return
			}
			g.enter()
			time.Sleep(time.Millisecond)
			g.leave()
			if err := p.ReturnClient(c); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if g.max.Load() > 3 {
		t.Fatalf("%d borrowed at once, cap 3", g.max.Load())
	}
	if f.count() > 3 {
		t.Fatalf("%d connections created for cap 3", f.count())
	}
	if st := p.Stats(); st.InUse != 0 {
		t.Fatalf("leak %+v", st)
	}
}
