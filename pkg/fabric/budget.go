package fabric

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// BudgetConfig bounds the load one host sees from this process, across ALL
// protocols used against it. Both limits are required and positive: there is
// no silent default, a zero value is rejected by NewHostBudget.
//
// What the bound covers: every operation taken through Limited, including the
// connection probe (TestConnection, taken without waiting: a busy budget skips
// the probe, see TryAcquire). What it does not cover: Disconnect (closing a
// connection must always be possible and is a local close plus at most a
// logoff), the local calls IsConnected / GetProtocol / GetConfig, and, with
// WithStreamLease, a stream that has been idle past its lease (its slot is
// taken back; the leaked stream is the case the lease exists for).
type BudgetConfig struct {
	// MaxConcurrent is the maximum number of operations (and open read
	// streams) in flight at once, within the coverage described above.
	MaxConcurrent int
	// MaxReqPerSec is the maximum rate at which operations may START.
	// Starts are spaced evenly (no burst): 10 req/s means 100 ms apart.
	MaxReqPerSec float64
}

// NASBudget is the explicit conservative budget for a NAS-class host:
// 4 concurrent operations, 10 starts per second. Callers choose it on
// purpose; nothing applies it implicitly.
func NASBudget() BudgetConfig { return BudgetConfig{MaxConcurrent: 4, MaxReqPerSec: 10} }

// ErrBudgetConfig is returned for an invalid BudgetConfig.
var ErrBudgetConfig = errors.New("fabric: invalid host budget")

// ErrBudgetBusy is wrapped (together with context.DeadlineExceeded) by the
// error Acquire returns when the caller's deadline falls before its start slot,
// so a caller can tell "the host budget is saturated" from "my own context
// ended" and back off instead of looping.
var ErrBudgetBusy = errors.New("fabric: host budget busy")

// ErrBudgetConflict is returned by Budgets.For when a host is already
// registered with a different configuration.
var ErrBudgetConflict = errors.New("fabric: host budget already registered with a different configuration")

func (c BudgetConfig) validate() error {
	if c.MaxConcurrent < 1 {
		return fmt.Errorf("%w: MaxConcurrent=%d, want >= 1", ErrBudgetConfig, c.MaxConcurrent)
	}
	if math.IsNaN(c.MaxReqPerSec) || math.IsInf(c.MaxReqPerSec, 0) || c.MaxReqPerSec <= 0 {
		return fmt.Errorf("%w: MaxReqPerSec=%v, want a finite value > 0", ErrBudgetConfig, c.MaxReqPerSec)
	}
	// A rate so small that the spacing does not fit a time.Duration (about 292
	// years) would overflow the conversion and fail OPEN (no spacing at all).
	if float64(time.Second)/c.MaxReqPerSec >= float64(math.MaxInt64) {
		return fmt.Errorf("%w: MaxReqPerSec=%v is too small, the start spacing does not fit a time.Duration", ErrBudgetConfig, c.MaxReqPerSec)
	}
	return nil
}

// HostBudget is a concurrency semaphore plus an even-spacing rate limiter.
// Safe for concurrent use.
type HostBudget struct {
	cfg      BudgetConfig
	clock    Clock
	interval time.Duration
	sem      chan struct{}

	lease time.Duration // see WithStreamLease (0 = off)

	mu       sync.Mutex
	nextSlot time.Time
	free     []time.Time // cancelled start slots in the future, ascending, reusable
	acquired uint64
	waited   time.Duration
	nextID   uint64
	held     map[uint64]time.Time // slot id -> when it was taken
	leased   uint64               // slots released by the lease, not by the holder
}

// BudgetOption customises NewHostBudget.
type BudgetOption func(*HostBudget)

// WithBudgetClock injects the time source (tests).
func WithBudgetClock(c Clock) BudgetOption { return func(b *HostBudget) { b.clock = c } }

// WithStreamLease makes a slot held by an open read stream (Limited ReadFile /
// OpenSeekable) be released automatically once the stream has been IDLE for d:
// no byte read (Read, ReadAt or WriteTo, which counts while it copies) and not
// closed (0 = off, the default: a slot is held until Close). Every read resets
// the clock, so a stream that is actively read - a two-hour movie - keeps its
// slot for its whole life and the cap holds; only a leaked, never-closed or
// abandoned stream loses it, which is what bounds the blast radius of a leak
// that would otherwise starve every protocol sharing the host. An expired
// stream stays readable; its slot is gone for good (reading it again does not
// take a slot back), so the host may see MaxConcurrent+1 operations from the
// moment a stream is read after it had been idle past d.
// BudgetStats.LeaseExpired counts the slots taken back this way.
func WithStreamLease(d time.Duration) BudgetOption { return func(b *HostBudget) { b.lease = d } }

// NewHostBudget validates cfg and returns a budget.
func NewHostBudget(cfg BudgetConfig, opts ...BudgetOption) (*HostBudget, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	b := &HostBudget{cfg: cfg, clock: SystemClock(), sem: make(chan struct{}, cfg.MaxConcurrent), held: map[uint64]time.Time{}}
	for _, o := range opts {
		o(b)
	}
	b.interval = time.Duration(float64(time.Second) / cfg.MaxReqPerSec)
	if b.interval < 1 {
		b.interval = 1
	}
	return b, nil
}

// Config returns the configuration of the budget.
func (b *HostBudget) Config() BudgetConfig { return b.cfg }

// Acquire takes one concurrency slot and one start slot, waiting as needed.
// The returned release must be called exactly once per successful Acquire
// (further calls are no-ops). On error nothing is held.
//
// A start slot reserved by a caller whose context ends while it waits is GIVEN
// BACK: it is reused by the next caller (or the reservation front is wound
// back), so cancelled waiters never push the schedule ahead of real time and
// the spacing between real starts stays at least one interval. A caller whose
// deadline falls before its start slot fails fast, without reserving.
func (b *HostBudget) Acquire(ctx context.Context) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case b.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	b.mu.Lock()
	now := b.clock.Now()
	start, reused := b.takeSlot(now)
	if dl, ok := ctx.Deadline(); ok && start.After(dl) {
		b.giveBack(start, reused)
		b.mu.Unlock()
		<-b.sem
		return nil, fmt.Errorf("%w: start slot %v is after the deadline: %w", ErrBudgetBusy, start.Sub(now), context.DeadlineExceeded)
	}
	wait := start.Sub(now)
	b.acquired++
	b.waited += wait
	b.mu.Unlock()
	if wait > 0 {
		if err := b.clock.Sleep(ctx, wait); err != nil {
			b.mu.Lock()
			b.giveBack(start, reused)
			b.mu.Unlock()
			<-b.sem
			return nil, err
		}
	}
	return b.newHold(), nil
}

// newHold registers a slot whose wait is over as held and returns its
// idempotent release. The concurrency token must already be taken.
func (b *HostBudget) newHold() func() {
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	b.held[id] = b.clock.Now()
	b.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.held, id)
			b.mu.Unlock()
			<-b.sem
		})
	}
}

// TryAcquire takes one concurrency slot and one start slot ONLY IF both are
// available right now: it never waits and never reserves. It reports ok=false,
// leaving the schedule untouched, when all MaxConcurrent slots are held or the
// next start slot lies in the future. It is how Limited budgets the connection
// probe: a probe is worth running only when it costs the host nothing it could
// not afford, and a busy budget must never turn into an "unhealthy" verdict.
func (b *HostBudget) TryAcquire() (release func(), ok bool) {
	select {
	case b.sem <- struct{}{}:
	default:
		return nil, false
	}
	b.mu.Lock()
	now := b.clock.Now()
	start, reused := b.takeSlot(now)
	if start.After(now) {
		b.giveBack(start, reused)
		b.mu.Unlock()
		<-b.sem
		return nil, false
	}
	b.acquired++
	b.mu.Unlock()
	return b.newHold(), true
}

// takeSlot returns the start time for a caller arriving at now: the earliest
// returned (cancelled) slot that is still in the future, else the next slot at
// the end of the schedule. Past free slots are dropped: using one would put a
// start closer than one interval to the reservation after it. b.mu is held.
func (b *HostBudget) takeSlot(now time.Time) (start time.Time, reused bool) {
	for len(b.free) > 0 && b.free[0].Before(now) {
		b.free = b.free[1:]
	}
	if len(b.free) > 0 {
		start, b.free = b.free[0], b.free[1:]
		return start, true
	}
	start = b.nextSlot
	if start.Before(now) {
		start = now
	}
	b.nextSlot = start.Add(b.interval)
	return start, false
}

// giveBack returns a start slot nobody used. b.mu is held.
func (b *HostBudget) giveBack(start time.Time, reused bool) {
	if b.nextSlot.Equal(start.Add(b.interval)) {
		// The last reservation - whether it was a fresh slot or a returned one
		// that another caller had reused and that became the tail: wind the
		// front back, so a slot nobody used is not waited for.
		b.nextSlot = start
		// and wind further while the slots just before it are free
		for n := len(b.free); n > 0 && b.free[n-1].Add(b.interval).Equal(b.nextSlot); n = len(b.free) {
			b.nextSlot = b.free[n-1]
			b.free = b.free[:n-1]
		}
		return
	}
	// insert keeping ascending order
	i := len(b.free)
	for i > 0 && b.free[i-1].After(start) {
		i--
	}
	b.free = append(b.free, time.Time{})
	copy(b.free[i+1:], b.free[i:])
	b.free[i] = start
}

// lease is the idle timer of one stream slot (WithStreamLease).
type lease struct {
	b       *HostBudget
	d       time.Duration
	release func()

	mu   sync.Mutex
	last time.Time // wall clock of the last activity; the timer is real time, see WithStreamLease
	done bool      // closed, or expired
	t    *time.Timer
}

// leaseRelease arranges for release to run once the stream has been idle for
// the stream lease, if any. It returns the function to call when the stream is
// closed and the function to call for every read (nil when there is no lease).
func (b *HostBudget) leaseRelease(release func()) (onClose func(), touch func()) {
	if b.lease <= 0 {
		return release, nil
	}
	l := &lease{b: b, d: b.lease, release: release, last: time.Now()}
	l.mu.Lock()
	l.t = time.AfterFunc(l.d, l.fire)
	l.mu.Unlock()
	return l.close, l.touch
}

func (l *lease) touch() {
	l.mu.Lock()
	if !l.done {
		l.last = time.Now()
	}
	l.mu.Unlock()
}

func (l *lease) fire() {
	l.mu.Lock()
	if l.done {
		l.mu.Unlock()
		return
	}
	if idle := time.Since(l.last); idle < l.d { // read meanwhile: wait out the rest
		l.t.Reset(l.d - idle)
		l.mu.Unlock()
		return
	}
	l.done = true
	l.mu.Unlock()
	l.b.mu.Lock()
	l.b.leased++
	l.b.mu.Unlock()
	l.release()
}

func (l *lease) close() {
	l.mu.Lock()
	l.done = true
	l.t.Stop()
	l.mu.Unlock()
	l.release()
}

// BudgetStats is a point-in-time view of a HostBudget.
//
// Semantics: InFlight counts held concurrency slots, including callers that
// hold one while they sleep for their start slot. Acquired counts start-slot
// RESERVATIONS, including ones later given back because the caller's context
// ended - it is not the number of operations the host saw. TotalRateWait sums
// the wait imposed at reservation time, cancelled or not.
type BudgetStats struct {
	InFlight int
	Acquired uint64
	// TotalRateWait is the total time callers were told to wait for a start slot.
	TotalRateWait time.Duration
	// Held is the number of slots currently held by callers that finished
	// waiting (running operations and open streams); OldestHeld is the age of
	// the oldest of them (0 if none) - a leaked stream shows up here.
	Held       int
	OldestHeld time.Duration
	// LeaseExpired counts slots taken back by WithStreamLease.
	LeaseExpired uint64
}

// Stats returns the current counters.
func (b *HostBudget) Stats() BudgetStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := BudgetStats{InFlight: len(b.sem), Acquired: b.acquired, TotalRateWait: b.waited, Held: len(b.held), LeaseExpired: b.leased}
	now := b.clock.Now()
	for _, since := range b.held {
		if age := now.Sub(since); age > st.OldestHeld {
			st.OldestHeld = age
		}
	}
	return st
}

// Budgets hands out ONE HostBudget per host, so that SMB and SFTP (or any
// two protocols) used against the same host share a single cap.
type Budgets struct {
	mu    sync.Mutex
	hosts map[string]*HostBudget
	opts  []BudgetOption
}

// NewBudgets creates an empty registry; opts apply to every budget created.
func NewBudgets(opts ...BudgetOption) *Budgets {
	return &Budgets{hosts: map[string]*HostBudget{}, opts: opts}
}

// For returns the budget of host (host or host:port, see HostKey), creating
// it with cfg on first use. A later call for the same host with a different
// cfg returns ErrBudgetConflict instead of silently picking one.
func (r *Budgets) For(host string, cfg BudgetConfig) (*HostBudget, error) {
	key, err := HostKey(host)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, ok := r.hosts[key]; ok {
		if b.cfg != cfg {
			return nil, fmt.Errorf("%w: host %s has %+v, requested %+v", ErrBudgetConflict, key, b.cfg, cfg)
		}
		return b, nil
	}
	b, err := NewHostBudget(cfg, r.opts...)
	if err != nil {
		return nil, err
	}
	r.hosts[key] = b
	return b, nil
}

// Hosts lists the registered host keys (for diagnostics).
func (r *Budgets) Hosts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.hosts))
	for k := range r.hosts {
		out = append(out, k)
	}
	return out
}
