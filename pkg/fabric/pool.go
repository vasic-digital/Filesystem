package fabric

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"digital.vasic.filesystem/pkg/client"
)

// Pool errors.
var (
	ErrPoolClosed    = errors.New("fabric: pool is closed")
	ErrPoolExhausted = errors.New("fabric: pool exhausted for this storage root")
	ErrNotFromPool   = errors.New("fabric: client was not borrowed from this pool (or was already returned)")
	ErrPoolConfig    = errors.New("fabric: invalid pool configuration")
	ErrPoolKey       = errors.New("fabric: storage config has no ID, cannot key the pool")
	// ErrDuplicateClient is returned when the factory hands out a client the
	// pool already holds (a memoising factory): two borrowers would share one
	// connection and one pool bookkeeping entry. The held client is left alone.
	ErrDuplicateClient = errors.New("fabric: factory returned a client that the pool already holds")
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
	// authFail remembers, per ACCOUNT (see accountKey), a login rejected for
	// credentials: the pool fails fast with it instead of logging in again
	// (repeated failed logins are what trips a NAS's auto-block). It is cleared
	// by Evict, by CloseAll, or when the root's settings change (a different
	// account key).
	//
	// Keys: "a:"+account for a failure that proves the credentials bad
	// (isCredentialFailure), "r:"+root for a generic refusal (a share or file
	// denied) that only that root remembers.
	authFail map[string]authFailure
	// accounts: storage root ID -> account key it last borrowed with.
	accounts map[string]string
	// pilots: account key -> the first login of that account that is in
	// flight. Until one login of an account has succeeded, the other borrowers
	// of that account wait for the pilot's outcome (single-flight), so N
	// concurrent first borrowers make ONE login, not N.
	pilots map[string]*pilotLogin
	// proven: account keys with at least one successful login; their further
	// logins run concurrently.
	proven map[string]bool
}

type authFailure struct {
	err  error
	acct string // the account key at record time (a root-level entry is void once the settings change)
}

// pilotLogin is one in-flight first login of an account.
type pilotLogin struct{ done chan struct{} }

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
		accounts: map[string]string{}, pilots: map[string]*pilotLogin{}, proven: map[string]bool{},
	}, nil
}

// GetClient borrows a connected client without waiting for a pool slot:
// ErrPoolExhausted when MaxPerKey are already borrowed. Opening a new
// connection can still take up to ConnectTimeout (and its login waits for a
// HostBudget slot if the client is Limited); while the FIRST login of an
// account is in flight it also waits for that login's outcome. It implements
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

// healthy probes a pooled connection. A probe that was SKIPPED because the host
// budget is busy (ErrProbeSkipped) is not evidence of a fault: the connection
// stays in use, and a dead one fails its first real operation, which Retrying
// handles.
func (p *Pool) healthy(ctx context.Context, e *pooled) bool {
	if !e.c.IsConnected() {
		return false
	}
	hctx, cancel := context.WithTimeout(ctx, p.opts.HealthTimeout)
	defer cancel()
	err := e.c.TestConnection(hctx)
	return err == nil || errors.Is(err, ErrProbeSkipped)
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

// rootSettingKeys are Settings keys that choose WHICH tree of an account a
// storage root is (they are not part of the account's identity), compared
// case-insensitively. Every other key - host, port, username, password,
// domain, URL, TLS options, anything unknown - is part of the account
// identity: an unknown key can only make two roots look like different
// accounts (one more login), never the same account.
var rootSettingKeys = map[string]bool{
	"path": true, "root": true, "base_path": true, "basepath": true, "root_path": true, "remote_path": true,
	"share": true, "export": true, "directory": true, "dir": true, "folder": true, "mount": true,
	"mount_path": true, "prefix": true,
}

// accountKey identifies the account (server + credentials) a storage config
// logs in with, as a hash (never the settings: they carry credentials). Two
// roots of one NAS that differ only in rootSettingKeys share an account key. A
// config whose Settings say nothing about the account (nothing left after the
// root-selecting keys are removed: the factory knows the account some other
// way, as pkg/ftp's scan factory does) is its own account, keyed by its ID -
// roots are never merged on the strength of settings that identify nothing.
// "" means unmarshalable settings: no memory and no single-flight for them.
func accountKey(cfg *client.StorageConfig) string {
	view := struct {
		Protocol string                 `json:"p"`
		Settings map[string]interface{} `json:"s"`
		Root     string                 `json:"r,omitempty"`
	}{Protocol: cfg.Protocol, Settings: map[string]interface{}{}}
	for k, v := range cfg.Settings {
		if !rootSettingKeys[strings.ToLower(k)] {
			view.Settings[k] = v
		}
	}
	if len(view.Settings) == 0 {
		view.Root = cfg.ID
	}
	b, err := json.Marshal(view)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
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
	acct := accountKey(cfg)
	if old, ok := p.accounts[key]; ok && old != acct {
		delete(p.authFail, "a:"+old) // the settings of this root changed: a new login is a new attempt
		delete(p.authFail, "r:"+key)
	}
	p.accounts[key] = acct
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

	skipGate := false // set once a pilot login ended without a credential failure
	var pilot *pilotLogin
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
		if cand == nil {
			// A new connection is needed (an idle one that still works is always
			// served, whatever another root of the account found out). A
			// remembered rejection refuses the login; otherwise the first login
			// of an account is a pilot: others wait for its outcome (one login,
			// not N, when the credentials are wrong; no serialisation once one
			// login worked).
			if err := p.rejectedLoginLocked(key, acct); err != nil {
				p.mu.Unlock()
				release()
				return nil, err
			}
			if acct != "" && !skipGate && !p.proven[acct] {
				if fl, busy := p.pilots[acct]; busy {
					p.mu.Unlock()
					select {
					case <-fl.done:
						skipGate = true // the pilot is over; whatever it found is now in p.authFail / p.proven
						continue
					case <-ctx.Done():
						release()
						return nil, ctx.Err()
					case <-p.done:
						release()
						return nil, ErrPoolClosed
					}
				}
				pilot = &pilotLogin{done: make(chan struct{})}
				p.pilots[acct] = pilot
			}
			p.mu.Unlock()
			break
		}
		p.mu.Unlock()
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
			if !errors.Is(err, ErrDuplicateClient) {
				p.discard(cand)
			}
			release()
			return nil, err
		}
		return cand.c, nil
	}

	// From here on this call may own the pilot: whatever the outcome, wake the
	// waiters and record what the login showed.
	var loginOK bool
	var loginErr error
	finish := func() {
		p.mu.Lock()
		if acct != "" && !p.closed {
			if loginOK {
				p.proven[acct] = true
			}
			switch {
			case loginErr == nil:
			case isCredentialFailure(loginErr):
				p.authFail["a:"+acct] = authFailure{err: loginErr, acct: acct}
			case ClassifyLogin(loginErr) == ClassAuth:
				p.authFail["r:"+key] = authFailure{err: loginErr, acct: acct}
			}
		}
		if pilot != nil {
			delete(p.pilots, acct)
			close(pilot.done)
		}
		p.mu.Unlock()
	}
	defer finish()

	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	c, err := p.factory.CreateClient(cfg)
	if err != nil {
		release()
		return nil, fmt.Errorf("fabric: create client for %s: %w", key, err)
	}
	if p.holds(c) {
		release()
		return nil, fmt.Errorf("%w: %s", ErrDuplicateClient, key) // neither connected nor disconnected: it belongs to its holder
	}
	cctx, cancel := context.WithTimeout(ctx, p.opts.ConnectTimeout)
	err = c.Connect(cctx)
	cancel()
	if err != nil {
		release()
		loginErr = err
		return nil, fmt.Errorf("fabric: connect %s: %w", key, err)
	}
	loginOK = true
	now := p.clock.Now()
	e := &pooled{c: c, key: key, created: now, lastUsed: now}
	if err := p.register(e); err != nil {
		if !errors.Is(err, ErrDuplicateClient) {
			p.discard(e)
		}
		release()
		return nil, err
	}
	return c, nil
}

// rejectedLoginLocked returns the remembered credential failure of the account,
// if any, as the error a borrower gets instead of a new login. p.mu is held.
func (p *Pool) rejectedLoginLocked(key, acct string) error {
	if acct == "" {
		return nil
	}
	for _, k := range []string{"a:" + acct, "r:" + key} {
		if af, ok := p.authFail[k]; ok && af.acct == acct {
			return fmt.Errorf("fabric: not logging in to %s again after a rejected login (Evict(%q) or change the settings to retry): %w", key, key, af.err)
		}
	}
	return nil
}

// holds reports whether the pool already holds c, borrowed or idle.
func (p *Pool) holds(c client.Client) bool {
	if !comparableClient(c) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.inUse[c]; ok {
		return true
	}
	for _, l := range p.idle {
		for _, e := range l {
			if e.c == c {
				return true
			}
		}
	}
	return false
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
	if _, dup := p.inUse[e.c]; dup {
		return fmt.Errorf("%w: %s", ErrDuplicateClient, e.key)
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
// rejected login of the root's account (which also lifts the refusal for the
// other roots of that account), so the next borrow logs in again. Use it after
// the credentials of a root were corrected on the server.
func (p *Pool) Evict(id string) {
	p.mu.Lock()
	list := p.idle[id]
	delete(p.idle, id)
	if acct, ok := p.accounts[id]; ok {
		delete(p.authFail, "a:"+acct)
		delete(p.proven, acct) // the next login of this account is a pilot again
	}
	delete(p.authFail, "r:"+id)
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
	p.proven = map[string]bool{}
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
