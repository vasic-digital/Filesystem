package fabric_test

import (
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
)

// gauge tracks the highest number of simultaneous operations (shared across fakes).
type gauge struct{ cur, max atomic.Int64 }

func (g *gauge) enter() {
	n := g.cur.Add(1)
	for {
		m := g.max.Load()
		if n <= m || g.max.CompareAndSwap(m, n) {
			return
		}
	}
}
func (g *gauge) leave() { g.cur.Add(-1) }

// fk is a recording stand-in for a protocol client (unit tests only).
type fk struct {
	proto string
	g     *gauge
	work  time.Duration

	mu        sync.Mutex
	calls     map[string]int
	lastPaths map[string][]string
	errs      map[string][]error // queue per op name; consumed one per call
	connected bool
	readData  string
}

func newFk(proto string) *fk {
	return &fk{proto: proto, calls: map[string]int{}, lastPaths: map[string][]string{}, errs: map[string][]error{}, connected: true, readData: "hello world"}
}

func (f *fk) queue(op string, errs ...error) *fk {
	f.mu.Lock()
	f.errs[op] = append(f.errs[op], errs...)
	f.mu.Unlock()
	return f
}

func (f *fk) do(op string, paths ...string) error {
	if f.g != nil {
		f.g.enter()
		defer f.g.leave()
	}
	if f.work > 0 {
		time.Sleep(f.work)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[op]++
	f.lastPaths[op] = paths
	if q := f.errs[op]; len(q) > 0 {
		e := q[0]
		f.errs[op] = q[1:]
		return e
	}
	return nil
}

func (f *fk) count(op string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls[op] }
func (f *fk) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := 0
	for _, v := range f.calls {
		t += v
	}
	return t
}
func (f *fk) paths(op string) []string { f.mu.Lock(); defer f.mu.Unlock(); return f.lastPaths[op] }

func (f *fk) Connect(context.Context) error        { return f.do("Connect") }
func (f *fk) Disconnect(context.Context) error     { return f.do("Disconnect") }
func (f *fk) IsConnected() bool                    { return f.connected }
func (f *fk) TestConnection(context.Context) error { return f.do("TestConnection") }
func (f *fk) ReadFile(_ context.Context, p string) (io.ReadCloser, error) {
	if err := f.do("ReadFile", p); err != nil {
		return nil, err
	}
	return io.NopCloser(strings.NewReader(f.readData)), nil
}
func (f *fk) WriteFile(_ context.Context, p string, d io.Reader) error {
	if _, err := io.Copy(io.Discard, d); err != nil {
		return err
	}
	return f.do("WriteFile", p)
}
func (f *fk) GetFileInfo(_ context.Context, p string) (*client.FileInfo, error) {
	if err := f.do("GetFileInfo", p); err != nil {
		return nil, err
	}
	return &client.FileInfo{Name: p, Path: p}, nil
}
func (f *fk) FileExists(_ context.Context, p string) (bool, error) {
	if err := f.do("FileExists", p); err != nil {
		return false, err
	}
	return true, nil
}
func (f *fk) DeleteFile(_ context.Context, p string) error  { return f.do("DeleteFile", p) }
func (f *fk) CopyFile(_ context.Context, a, b string) error { return f.do("CopyFile", a, b) }
func (f *fk) ListDirectory(_ context.Context, p string) ([]*client.FileInfo, error) {
	if err := f.do("ListDirectory", p); err != nil {
		return nil, err
	}
	return []*client.FileInfo{{Name: "a", Path: p + "/a"}}, nil
}
func (f *fk) CreateDirectory(_ context.Context, p string) error { return f.do("CreateDirectory", p) }
func (f *fk) DeleteDirectory(_ context.Context, p string) error { return f.do("DeleteDirectory", p) }
func (f *fk) GetProtocol() string                               { return f.proto }
func (f *fk) GetConfig() interface{}                            { return nil }

type fkSeek struct{ *fk }

type nopSeek struct{ io.Reader }

func (nopSeek) Seek(int64, int) (int64, error) { return 0, nil }
func (nopSeek) Close() error                   { return nil }

func (f fkSeek) OpenSeekable(_ context.Context, p string) (client.ReadSeekCloser, error) {
	if err := f.do("OpenSeekable", p); err != nil {
		return nil, err
	}
	return nopSeek{strings.NewReader(f.readData)}, nil
}

// fakeClock is a deterministic fabric.Clock: Sleep advances virtual time.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_000_000, 0)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return nil
}
func (c *fakeClock) advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }
func (c *fakeClock) slept() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

// invokeOp calls the method of op on c with generated arguments and returns
// the error result. Path arguments use the given paths in order.
func invokeOp(t testing.TB, c client.Client, op fabric.Op, paths ...string) error {
	t.Helper()
	ctx := context.Background()
	p := func(i int) string {
		if i < len(paths) {
			return paths[i]
		}
		return "/x"
	}
	switch op {
	case fabric.OpConnect:
		return c.Connect(ctx)
	case fabric.OpDisconnect:
		return c.Disconnect(ctx)
	case fabric.OpTestConnection:
		return c.TestConnection(ctx)
	case fabric.OpReadFile:
		rc, err := c.ReadFile(ctx, p(0))
		if rc != nil {
			_, _ = io.Copy(io.Discard, rc)
			_ = rc.Close()
		}
		return err
	case fabric.OpWriteFile:
		return c.WriteFile(ctx, p(0), strings.NewReader("data"))
	case fabric.OpGetFileInfo:
		_, err := c.GetFileInfo(ctx, p(0))
		return err
	case fabric.OpFileExists:
		_, err := c.FileExists(ctx, p(0))
		return err
	case fabric.OpDeleteFile:
		return c.DeleteFile(ctx, p(0))
	case fabric.OpCopyFile:
		return c.CopyFile(ctx, p(0), p(1))
	case fabric.OpListDirectory:
		_, err := c.ListDirectory(ctx, p(0))
		return err
	case fabric.OpCreateDirectory:
		return c.CreateDirectory(ctx, p(0))
	case fabric.OpDeleteDirectory:
		return c.DeleteDirectory(ctx, p(0))
	case fabric.OpOpenSeekable:
		sc, ok := c.(client.SeekableClient)
		if !ok {
			t.Fatalf("client %T is not seekable", c)
		}
		rc, err := sc.OpenSeekable(ctx, p(0))
		if rc != nil {
			_, _ = io.Copy(io.Discard, rc)
			_ = rc.Close()
		}
		return err
	}
	t.Fatalf("unknown op %v", op)
	return nil
}

// parkClock is a deterministic fabric.Clock whose Sleep BLOCKS until the
// virtual time reaches the wake-up time or the context ends (like a real
// timer); fakeClock.Sleep returns at once, so it cannot show what happens
// to a reservation whose waiter is cancelled mid-wait.
type parkClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*parked
	slept   []time.Duration
}

type parked struct {
	at time.Time
	ch chan struct{}
}

func newParkClock() *parkClock { return &parkClock{now: time.Unix(2_000_000, 0)} }

func (c *parkClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *parkClock) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	c.mu.Lock()
	w := &parked{at: c.now.Add(d), ch: make(chan struct{})}
	c.waiters = append(c.waiters, w)
	c.slept = append(c.slept, d)
	c.mu.Unlock()
	select {
	case <-w.ch:
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		for i, x := range c.waiters {
			if x == w {
				c.waiters = append(c.waiters[:i], c.waiters[i+1:]...)
				break
			}
		}
		c.mu.Unlock()
		return ctx.Err()
	}
}

// advance moves virtual time forward and wakes every sleeper that is due.
func (c *parkClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	keep := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.at.After(c.now) {
			close(w.ch)
		} else {
			keep = append(keep, w)
		}
	}
	c.waiters = keep
	c.mu.Unlock()
}

// parkedCount is the number of goroutines currently asleep in Sleep.
func (c *parkClock) parkedCount() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.waiters) }

// waitParked waits (real time, bounded) until n goroutines are asleep.
func (c *parkClock) waitParked(t testing.TB, n int) {
	t.Helper()
	for i := 0; i < 2000; i++ {
		if c.parkedCount() == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("waited for %d parked sleepers, have %d", n, c.parkedCount())
}

func (c *parkClock) sleeps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.slept...)
}
