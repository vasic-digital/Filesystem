package fabric

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"digital.vasic.filesystem/pkg/client"
)

// Pool errors.
var (
	ErrPoolClosed      = errors.New("fabric: pool is closed")
	ErrPoolExhausted   = errors.New("fabric: pool exhausted for this storage root")
	ErrNotFromPool     = errors.New("fabric: client was not borrowed from this pool (or was already returned)")
	ErrPoolConfig      = errors.New("fabric: invalid pool configuration")
	ErrPoolKey         = errors.New("fabric: storage config has no ID, cannot key the pool")
	errClientNotMapKey = errors.New("fabric: client dynamic type is not comparable")
)

// PoolOptions configures a Pool. MaxPerKey is required; the durations may be 0
// (= never expires / default probe timeout).
type PoolOptions struct {
	// MaxPerKey bounds borrowed + idle connections per storage root (>= 1).
	MaxPerKey int
	// MaxLifetime retires a connection this long after it was created (0 = off).
	MaxLifetime time.Duration
	// IdleTimeout retires a connection that sat idle this long (0 = off).
	IdleTimeout time.Duration
	// HealthTimeout bounds the health probe on borrow and the disconnect of a
	// retired connection (0 = 5s).
	HealthTimeout time.Duration
	// ConnectTimeout bounds the login of a NEW connection on borrow, whether
	// or not the caller waits for a pool slot (0 = 30s). It is applied on top
	// of the caller's context, so GetClient never blocks without bound.
	ConnectTimeout time.Duration
	// Clock is the time source (nil = system clock).
	Clock Clock
}

type pooled struct {
	c        client.Client
	key      string
	created  time.Time
	lastUsed time.Time
}

// Pool implements client.ConnectionPool with health checking on borrow and
// MaxLifetime/IdleTimeout retirement. Retirement is lazy - there is no
// background reaper, the pool starts no goroutine: every borrow and return
// sweeps the expired idle connections of ALL roots, so an idle connection can
// outlive IdleTimeout until the next pool call. The cap MaxPerKey is per
// storage root, not per host: N roots on one NAS can hold N*MaxPerKey
// connections; bound the host with a HostBudget. A storage root is identified by
// StorageConfig.ID; two configs with the same ID share connections, so change
// the ID (or call Evict) when the settings of a root change.
type Pool struct {
	factory client.Factory
	opts    PoolOptions
	clock   Clock

	mu     sync.Mutex
	closed bool
	done   chan struct{}
	idle   map[string][]*pooled
	inUse  map[client.Client]*pooled
	tokens map[string]chan struct{}
	// authFail remembers, per storage root, a login rejected for credentials:
	// the pool fails fast with it instead of logging in again (repeated failed
	// logins are what trips a NAS's auto-block). It is cleared by Evict, by
	// CloseAll, or when the root's settings change (different fingerprint).
	authFail map[string]authFailure
}

type authFailure struct {
	fingerprint [sha256.Size]byte
	err         error
}

var _ client.ConnectionPool = (*Pool)(nil)

// NewPool validates opts and returns an empty pool.
func NewPool(factory client.Factory, opts PoolOptions) (*Pool, error) {
	if factory == nil {
		return nil, fmt.Errorf("%w: nil factory", ErrPoolConfig)
	}
	if opts.MaxPerKey < 1 {
		return nil, fmt.Errorf("%w: MaxPerKey=%d, want >= 1", ErrPoolConfig, opts.MaxPerKey)
	}
	if opts.MaxLifetime < 0 || opts.IdleTimeout < 0 || opts.HealthTimeout < 0 || opts.ConnectTimeout < 0 {
		return nil, fmt.Errorf("%w: negative duration", ErrPoolConfig)
	}
	if opts.HealthTimeout == 0 {
		opts.HealthTimeout = 5 * time.Second
	}
	if opts.ConnectTimeout == 0 {
		opts.ConnectTimeout = 30 * time.Second
	}
	clk := opts.Clock
	if clk == nil {
		clk = SystemClock()
	}
	return &Pool{
		factory: factory, opts: opts, clock: clk, done: make(chan struct{}),
		idle: map[string][]*pooled{}, inUse: map[client.Client]*pooled{}, tokens: map[string]chan struct{}{}, authFail: map[string]authFailure{},
	}, nil
}

// GetClient borrows a connected client without waiting for a pool slot:
// ErrPoolExhausted when MaxPerKey are already borrowed. Opening a new
// connection can still take up to ConnectTimeout (and its login waits for a
// HostBudget slot if the client is Limited). It implements
// client.ConnectionPool.
func (p *Pool) GetClient(config *client.StorageConfig) (client.Client, error) {
	return p.get(context.Background(), config, false)
}

// GetClientContext borrows a connected client, waiting for a free slot until
// ctx is done.
func (p *Pool) GetClientContext(ctx context.Context, config *client.StorageConfig) (client.Client, error) {
	return p.get(ctx, config, true)
}

func (p *Pool) tokenChan(key string) chan struct{} {
	ch, ok := p.tokens[key]
	if !ok {
		ch = make(chan struct{}, p.opts.MaxPerKey)
		p.tokens[key] = ch
	}
	return ch
}

func (p *Pool) expired(e *pooled, now time.Time) bool {
	if p.opts.MaxLifetime > 0 && now.Sub(e.created) >= p.opts.MaxLifetime {
		return true
	}
	return p.opts.IdleTimeout > 0 && now.Sub(e.lastUsed) >= p.opts.IdleTimeout
}

func (p *Pool) discard(e *pooled) {
	ctx, cancel := context.WithTimeout(context.Background(), p.opts.HealthTimeout)
	defer cancel()
	_ = e.c.Disconnect(ctx)
}

func (p *Pool) healthy(ctx context.Context, e *pooled) bool {
	if !e.c.IsConnected() {
		return false
	}
	hctx, cancel := context.WithTimeout(ctx, p.opts.HealthTimeout)
	defer cancel()
	return e.c.TestConnection(hctx) == nil
}

// sweep retires every expired idle connection of every root. Callers must not
// hold p.mu.
func (p *Pool) sweep() {
	now := p.clock.Now()
	var dead []*pooled
	p.mu.Lock()
	for k, l := range p.idle {
		kept := l[:0:0]
		for _, e := range l {
			if p.expired(e, now) {
				dead = append(dead, e)
			} else {
				kept = append(kept, e)
			}
		}
		p.idle[k] = kept
	}
	p.mu.Unlock()
	for _, e := range dead {
		p.discard(e)
	}
}

// fingerprint identifies the settings of a root without keeping them (a hash,
// never the config: it carries credentials).
func fingerprint(cfg *client.StorageConfig) [sha256.Size]byte {
	b, err := json.Marshal(cfg)
	if err != nil { // unmarshalable settings: never equal, so never cached
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(b)
}

func (p *Pool) get(ctx context.Context, cfg *client.StorageConfig, wait bool) (client.Client, error) {
	if cfg == nil || cfg.ID == "" {
		return nil, ErrPoolKey
	}
	// A caller whose context is already done never reaches the pool: the token
	// select below would pick the ready token about half the time.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := cfg.ID
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPoolClosed
	}
	if af, ok := p.authFail[key]; ok {
		if af.fingerprint == fingerprint(cfg) && af.fingerprint != ([sha256.Size]byte{}) {
			p.mu.Unlock()
			return nil, fmt.Errorf("fabric: not logging in to %s again after a rejected login (Evict(%q) or change the settings to retry): %w", key, key, af.err)
		}
		delete(p.authFail, key) // the settings changed: a new login is a new attempt
	}
	tok := p.tokenChan(key)
	p.mu.Unlock()

	p.sweep()

	if wait {
		select {
		case tok <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.done:
			return nil, ErrPoolClosed
		}
	} else {
		select {
		case tok <- struct{}{}:
		default:
			return nil, fmt.Errorf("%w: %s", ErrPoolExhausted, key)
		}
	}
	release := func() { <-tok }

	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			release()
			return nil, ErrPoolClosed
		}
		var cand *pooled
		if n := len(p.idle[key]); n > 0 {
			cand = p.idle[key][n-1] // most recently used first
			p.idle[key] = p.idle[key][:n-1]
		}
		p.mu.Unlock()
		if cand == nil {
			break
		}
		if p.expired(cand, p.clock.Now()) {
			p.discard(cand)
			continue
		}
		if !p.healthy(ctx, cand) {
			if err := ctx.Err(); err != nil {
				// The caller's context ended during the probe: that is the
				// caller giving up, not a verdict on the connection. Put it
				// back (it was the most recently used) and leave.
				p.requeue(cand)
				release()
				return nil, err
			}
			p.discard(cand)
			continue
		}
		if err := p.register(cand); err != nil {
			p.discard(cand)
			release()
			return nil, err
		}
		return cand.c, nil
	}

	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	c, err := p.factory.CreateClient(cfg)
	if err != nil {
		release()
		return nil, fmt.Errorf("fabric: create client for %s: %w", key, err)
	}
	cctx, cancel := context.WithTimeout(ctx, p.opts.ConnectTimeout)
	err = c.Connect(cctx)
	cancel()
	if err != nil {
		release()
		if Classify(err) == ClassAuth {
			p.mu.Lock()
			if !p.closed {
				p.authFail[key] = authFailure{fingerprint: fingerprint(cfg), err: err}
			}
			p.mu.Unlock()
		}
		return nil, fmt.Errorf("fabric: connect %s: %w", key, err)
	}
	now := p.clock.Now()
	e := &pooled{c: c, key: key, created: now, lastUsed: now}
	if err := p.register(e); err != nil {
		p.discard(e)
		release()
		return nil, err
	}
	return c, nil
}

// requeue puts a connection that was popped for a probe back as the most
// recently used idle entry of its root (or retires it if the pool closed).
func (p *Pool) requeue(e *pooled) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.discard(e)
		return
	}
	p.idle[e.key] = append(p.idle[e.key], e)
	p.mu.Unlock()
}

// comparableClient reports whether c can be a map key: the DYNAMIC value must
// be comparable (reflect.Value.Comparable looks inside interface fields; the
// type-level check does not and let an unhashable value through to a runtime
// panic).
func comparableClient(c client.Client) bool {
	return c != nil && reflect.ValueOf(c).Comparable()
}

func (p *Pool) register(e *pooled) error {
	if !comparableClient(e.c) {
		return errClientNotMapKey
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrPoolClosed
	}
	p.inUse[e.c] = e
	return nil
}

// ReturnClient gives a borrowed client back. A client that is disconnected,
// past MaxLifetime, or returned to a closed pool is disconnected instead of
// pooled. A second return of the same client, or a client not borrowed from
// this pool, is ErrNotFromPool.
func (p *Pool) ReturnClient(c client.Client) error {
	if !comparableClient(c) {
		return ErrNotFromPool
	}
	e, closed, tok, err := p.unborrow(c)
	if err != nil {
		return err
	}

	now := p.clock.Now()
	keep := !closed && c.IsConnected() && !(p.opts.MaxLifetime > 0 && now.Sub(e.created) >= p.opts.MaxLifetime)
	if keep {
		p.mu.Lock()
		if p.closed {
			keep = false
		} else {
			e.lastUsed = now
			p.idle[e.key] = append(p.idle[e.key], e)
		}
		p.mu.Unlock()
	}
	if !keep {
		p.discard(e)
	}
	<-tok
	p.sweep()
	return nil
}

// unborrow removes c from the borrowed set. The lock is released by defer, so
// no panic can leave the pool wedged.
func (p *Pool) unborrow(c client.Client) (e *pooled, closed bool, tok chan struct{}, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.inUse[c]
	if !ok {
		return nil, false, nil, ErrNotFromPool
	}
	delete(p.inUse, c)
	return e, p.closed, p.tokenChan(e.key), nil
}

// Evict disconnects the idle connections of one storage root (borrowed ones
// are retired when returned if disconnected) and forgets a remembered
// rejected login, so the next borrow logs in again. Use it after the settings
// of a root changed.
func (p *Pool) Evict(id string) {
	p.mu.Lock()
	list := p.idle[id]
	delete(p.idle, id)
	delete(p.authFail, id)
	p.mu.Unlock()
	for _, e := range list {
		p.discard(e)
	}
}

// Stats is a point-in-time view of a Pool.
type PoolStats struct {
	Idle  int
	InUse int
}

// Stats returns the number of idle and borrowed connections.
func (p *Pool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, l := range p.idle {
		n += len(l)
	}
	return PoolStats{Idle: n, InUse: len(p.inUse)}
}

// CloseAll closes the pool: idle connections are disconnected now, borrowed
// ones when they are returned, waiting GetClientContext callers get
// ErrPoolClosed, and further borrows are refused. It is idempotent.
func (p *Pool) CloseAll() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.authFail = map[string]authFailure{}
	close(p.done)
	var all []*pooled
	for k, l := range p.idle {
		all = append(all, l...)
		delete(p.idle, k)
	}
	p.mu.Unlock()
	for _, e := range all {
		p.discard(e)
	}
	return nil
}
