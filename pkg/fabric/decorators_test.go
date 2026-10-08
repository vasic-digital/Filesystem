package fabric_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
)

func mustBudget(t testing.TB, max int, rate float64, clk fabric.Clock) *fabric.HostBudget {
	t.Helper()
	var opts []fabric.BudgetOption
	if clk != nil {
		opts = append(opts, fabric.WithBudgetClock(clk))
	}
	b, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: max, MaxReqPerSec: rate}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---------------------------------------------------------------- Limited

// Round 3 (N2): TestConnection is budgeted too (taken without waiting, see
// TestR3_Limited_Probe*); only Disconnect is exempt.
func TestLimited_EveryOpTakesOneSlotExceptDisconnect(t *testing.T) {
	t.Parallel()
	for _, op := range fabric.AllOps() {
		b := mustBudget(t, 3, 1e6, nil)
		f := newFk("p")
		c := fabric.Limited(fkSeek{f}, b)
		if err := invokeOp(t, c, op, "/a", "/b"); err != nil {
			t.Fatalf("%v: %v", op, err)
		}
		want := uint64(1)
		if op == fabric.OpDisconnect {
			want = 0 // never throttled: closing a connection must always be possible
		}
		if got := b.Stats().Acquired; got != want {
			t.Errorf("%v acquired %d slots, want %d", op, got, want)
		}
		if f.count(op.String()) != 1 {
			t.Errorf("%v reached inner %d times", op, f.count(op.String()))
		}
		if b.Stats().InFlight != 0 {
			t.Errorf("%v leaked a slot", op)
		}
	}
}

func TestLimited_FailedCallReleasesItsSlot(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	for _, op := range fabric.AllOps() {
		b := mustBudget(t, 1, 1e6, nil)
		f := newFk("p").queue(op.String(), boom)
		c := fabric.Limited(fkSeek{f}, b)
		if err := invokeOp(t, c, op, "/a", "/b"); !errors.Is(err, boom) {
			t.Fatalf("%v: err=%v", op, err)
		}
		if b.Stats().InFlight != 0 {
			t.Errorf("%v: slot leaked after failure", op)
		}
	}
}

func TestLimited_StreamHoldsSlotUntilClose(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 1, 1e6, nil)
	c := fabric.Limited(fkSeek{newFk("p")}, b)
	rc, err := c.ReadFile(context.Background(), "/a")
	if err != nil {
		t.Fatal(err)
	}
	if b.Stats().InFlight != 1 {
		t.Fatal("slot must be held while the stream is open")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.GetFileInfo(ctx, "/a"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second op must wait for the open stream: %v", err)
	}
	_, _ = io.Copy(io.Discard, rc)
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
	_ = rc.Close() // double close must not free a second slot
	if b.Stats().InFlight != 0 {
		t.Fatal("slot not released on Close")
	}
	// seekable stream too
	sc := c.(client.SeekableClient)
	s, err := sc.OpenSeekable(context.Background(), "/a")
	if err != nil || b.Stats().InFlight != 1 {
		t.Fatalf("seekable: %v inflight=%d", err, b.Stats().InFlight)
	}
	_ = s.Close()
	if b.Stats().InFlight != 0 {
		t.Fatal("seekable slot not released")
	}
}

func TestLimited_DisconnectIsNeverThrottled(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 1, 1e6, nil)
	f := newFk("p")
	c := fabric.Limited(f, b)
	rc, _ := c.ReadFile(context.Background(), "/a") // holds the only slot
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect blocked by budget: %v", err)
	}
	_ = rc.Close()
}

func TestLimited_SharedBudgetCapsTwoProtocolsTogether(t *testing.T) {
	t.Parallel()
	reg := fabric.NewBudgets()
	cfg := fabric.BudgetConfig{MaxConcurrent: 2, MaxReqPerSec: 1e6}
	var g gauge
	mk := func(proto, hostport string) client.Client {
		b, err := reg.For(hostport, cfg)
		if err != nil {
			t.Fatal(err)
		}
		f := newFk(proto)
		f.g, f.work = &g, 2*time.Millisecond
		return fabric.Limited(f, b)
	}
	smb, sftp := mk("smb", "nas.local:445"), mk("sftp", "NAS.local:22")
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		c := smb
		if i%2 == 1 {
			c = sftp
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := invokeOp(t, c, fabric.OpListDirectory, "/d"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if g.max.Load() > 2 {
		t.Fatalf("host saw %d concurrent ops across protocols, cap is 2", g.max.Load())
	}
	if g.max.Load() < 2 {
		t.Fatalf("expected the cap to be reached, max=%d", g.max.Load())
	}
}

func TestLimited_NilBudgetPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fabric.Limited(newFk("p"), nil)
}

// --------------------------------------------------------------- Classify

func TestClassify_Table(t *testing.T) {
	t.Parallel()
	timeout := &net.OpError{Op: "read", Err: timeoutErr{}}
	cases := []struct {
		name string
		err  error
		want fabric.ErrorClass
	}{
		{"nil", nil, fabric.ClassPermanent},
		{"marked auth", fabric.MarkAuth(errors.New("x")), fabric.ClassAuth},
		{"ftp 530", &textproto.Error{Code: 530, Msg: "Please login with USER and PASS."}, fabric.ClassAuth},
		{"ftp 430", &textproto.Error{Code: 430, Msg: "Invalid username or password"}, fabric.ClassAuth},
		{"ftp 535 is a security-policy reply, not credentials", &textproto.Error{Code: 535, Msg: "denied by policy"}, fabric.ClassPermanent},
		{"smb logon", errors.New("response error: STATUS_LOGON_FAILURE"), fabric.ClassAuth},
		{"ssh", errors.New("ssh: unable to authenticate, attempted methods [none password]"), fabric.ClassAuth},
		{"auth beats reset", fmt.Errorf("%w: %w", syscall.ECONNRESET, fabric.ErrAuth), fabric.ClassAuth},
		{"auth text in a leaf beats timeout", fmt.Errorf("%w: %w", errors.New("login incorrect"), timeout), fabric.ClassAuth},
		{"auth text in a wrapper prefix is not trusted (glue must MarkAuth)", fmt.Errorf("login incorrect: %w", timeout), fabric.ClassTransient},
		{"ftp 421", &textproto.Error{Code: 421, Msg: "too many"}, fabric.ClassTransient},
		{"ftp 550", &textproto.Error{Code: 550, Msg: "no such file"}, fabric.ClassPermanent},
		{"marked transient", fabric.MarkTransient(errors.New("x")), fabric.ClassTransient},
		{"reset", fmt.Errorf("read: %w", syscall.ECONNRESET), fabric.ClassTransient},
		{"epipe", syscall.EPIPE, fabric.ClassTransient},
		{"unexpected eof", io.ErrUnexpectedEOF, fabric.ClassTransient},
		{"net timeout", timeout, fabric.ClassTransient},
		{"dns temp", &net.DNSError{IsTemporary: true}, fabric.ClassTransient},
		{"dns notfound", &net.DNSError{IsNotFound: true}, fabric.ClassPermanent},
		{"canceled", context.Canceled, fabric.ClassPermanent},
		{"deadline", context.DeadlineExceeded, fabric.ClassPermanent},
		{"not exist", fmt.Errorf("x: %w", os.ErrNotExist), fabric.ClassPermanent},
		{"permission", os.ErrPermission, fabric.ClassPermanent},
		{"outside root", fabric.ErrOutsideRoot, fabric.ClassPermanent},
		{"unknown", errors.New("something odd"), fabric.ClassPermanent},
	}
	for _, c := range cases {
		if got := fabric.Classify(c.err); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if fabric.MarkAuth(nil) != nil || fabric.MarkTransient(nil) != nil {
		t.Error("Mark*(nil) must stay nil")
	}
	for c, s := range map[fabric.ErrorClass]string{fabric.ClassAuth: "auth", fabric.ClassTransient: "transient", fabric.ClassPermanent: "permanent"} {
		if c.String() != s {
			t.Errorf("String %v", c)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// --------------------------------------------------------------- Retrying

var errReset = fmt.Errorf("read tcp: %w", syscall.ECONNRESET)

func retrying(t testing.TB, in client.Client, p fabric.RetryPolicy) client.Client {
	t.Helper()
	c, err := fabric.Retrying(in, p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRetrying_PolicyValidation(t *testing.T) {
	t.Parallel()
	for _, p := range []fabric.RetryPolicy{{}, {MaxAttempts: 0}, {MaxAttempts: 2, BaseDelay: -1}, {MaxAttempts: 2, MaxDelay: -1}} {
		if _, err := fabric.Retrying(newFk("p"), p); !errors.Is(err, fabric.ErrRetryPolicy) {
			t.Errorf("%+v: err=%v", p, err)
		}
	}
}

func TestRetrying_ReadsRetryTransientThenSucceed(t *testing.T) {
	t.Parallel()
	for _, op := range fabric.AllOps() {
		if !op.Retryable() {
			continue
		}
		f := newFk("p").queue(op.String(), errReset, errReset)
		clk := newFakeClock()
		c := retrying(t, fkSeek{f}, fabric.RetryPolicy{MaxAttempts: 4, BaseDelay: 10 * time.Millisecond, Clock: clk})
		if err := invokeOp(t, c, op, "/a", "/b"); err != nil {
			t.Fatalf("%v: %v", op, err)
		}
		if f.count(op.String()) != 3 {
			t.Errorf("%v: %d attempts, want 3", op, f.count(op.String()))
		}
	}
}

func TestRetrying_NeverRetriesAuthFailure(t *testing.T) {
	t.Parallel()
	authErrs := []error{fabric.MarkAuth(errors.New("bad")), &textproto.Error{Code: 530, Msg: "Please login with USER and PASS."}, errors.New("STATUS_LOGON_FAILURE")}
	for _, op := range fabric.AllOps() {
		for _, ae := range authErrs {
			f := newFk("p").queue(op.String(), ae, nil, nil)
			c := retrying(t, fkSeek{f}, fabric.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond, Clock: newFakeClock()})
			err := invokeOp(t, c, op, "/a", "/b")
			if err == nil {
				t.Fatalf("%v: auth failure swallowed", op)
			}
			if f.count(op.String()) != 1 {
				t.Errorf("%v with %v: %d attempts, want exactly 1 (no retry on auth failure)", op, ae, f.count(op.String()))
			}
		}
	}
}

func TestRetrying_NeverRetriesMutationsOrDisconnect(t *testing.T) {
	t.Parallel()
	for _, op := range fabric.AllOps() {
		if op.Retryable() {
			continue
		}
		f := newFk("p").queue(op.String(), errReset, nil)
		c := retrying(t, fkSeek{f}, fabric.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond, Clock: newFakeClock()})
		if err := invokeOp(t, c, op, "/a", "/b"); !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("%v: err=%v", op, err)
		}
		if f.count(op.String()) != 1 {
			t.Errorf("%v retried %d times", op, f.count(op.String()))
		}
	}
}

func TestRetrying_PermanentAndUnknownAreNotRetried(t *testing.T) {
	t.Parallel()
	for _, e := range []error{os.ErrNotExist, errors.New("weird"), context.DeadlineExceeded} {
		f := newFk("p").queue("ListDirectory", e, nil)
		c := retrying(t, f, fabric.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond, Clock: newFakeClock()})
		if err := invokeOp(t, c, fabric.OpListDirectory, "/a"); !errors.Is(err, e) {
			t.Fatalf("%v: %v", e, err)
		}
		if f.count("ListDirectory") != 1 {
			t.Errorf("%v retried", e)
		}
	}
}

func TestRetrying_ExhaustionWrapsLastError(t *testing.T) {
	t.Parallel()
	f := newFk("p").queue("ListDirectory", errReset, errReset, errReset, errReset)
	clk := newFakeClock()
	c := retrying(t, f, fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: 10 * time.Millisecond, Clock: clk})
	err := invokeOp(t, c, fabric.OpListDirectory, "/a")
	if !errors.Is(err, fabric.ErrRetriesExhausted) || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("err=%v", err)
	}
	if f.count("ListDirectory") != 3 {
		t.Fatalf("attempts=%d", f.count("ListDirectory"))
	}
	if !strings.Contains(err.Error(), "3 attempts") {
		t.Fatalf("message lacks attempt count: %v", err)
	}
}

func TestRetrying_BackoffDoublesAndCaps(t *testing.T) {
	t.Parallel()
	f := newFk("p")
	for i := 0; i < 6; i++ {
		f.queue("TestConnection", errReset)
	}
	clk := newFakeClock()
	c := retrying(t, f, fabric.RetryPolicy{MaxAttempts: 6, BaseDelay: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond, Clock: clk})
	_ = c.TestConnection(context.Background())
	want := []time.Duration{10, 20, 40, 50, 50}
	got := clk.slept()
	if len(got) != len(want) {
		t.Fatalf("sleeps=%v", got)
	}
	for i := range want {
		if got[i] != want[i]*time.Millisecond {
			t.Fatalf("sleeps=%v, want %v ms", got, want)
		}
	}
}

func TestRetrying_JitterAndCustomClassifier(t *testing.T) {
	t.Parallel()
	f := newFk("p").queue("ListDirectory", errors.New("custom-transient"), nil)
	clk := newFakeClock()
	c := retrying(t, f, fabric.RetryPolicy{
		MaxAttempts: 3, BaseDelay: 100 * time.Millisecond, Clock: clk,
		Jitter:   func(d time.Duration) time.Duration { return d / 2 },
		Classify: func(e error) fabric.ErrorClass { return fabric.ClassTransient },
	})
	if err := invokeOp(t, c, fabric.OpListDirectory, "/a"); err != nil {
		t.Fatal(err)
	}
	if s := clk.slept(); len(s) != 1 || s[0] != 50*time.Millisecond {
		t.Fatalf("jitter not applied: %v", s)
	}
}

func TestRetrying_CallerContextStopsRetries(t *testing.T) {
	t.Parallel()
	f := newFk("p").queue("ListDirectory", errReset, errReset, errReset)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := retrying(t, f, fabric.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond, Clock: newFakeClock()})
	if _, err := c.ListDirectory(ctx, "/a"); err == nil {
		t.Fatal("expected error")
	}
	if f.count("ListDirectory") != 1 {
		t.Fatalf("retried on a cancelled context: %d", f.count("ListDirectory"))
	}
}

func TestRetrying_SleepInterruptedByContext(t *testing.T) {
	t.Parallel()
	f := newFk("p").queue("ListDirectory", errReset, errReset)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	c := retrying(t, f, fabric.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Hour}) // real clock
	_, err := c.ListDirectory(ctx, "/a")
	if !errors.Is(err, syscall.ECONNRESET) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want both the failure and the deadline", err)
	}
}

func TestRetrying_RetryTakesAFreshBudgetSlotPerAttempt(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 2, 1e6, nil)
	f := newFk("p").queue("ListDirectory", errReset, errReset)
	c := retrying(t, fabric.Limited(f, b), fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, Clock: newFakeClock()})
	if err := invokeOp(t, c, fabric.OpListDirectory, "/a"); err != nil {
		t.Fatal(err)
	}
	if b.Stats().Acquired != 3 || b.Stats().InFlight != 0 {
		t.Fatalf("budget stats %+v, want 3 acquisitions", b.Stats())
	}
}

// --------------------------------------------------------------- Confined

func confined(t testing.TB, in client.Client, root string) client.Client {
	t.Helper()
	c, err := fabric.Confined(in, root)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfined_RootValidation(t *testing.T) {
	t.Parallel()
	for _, r := range []string{"", "relative/dir", "a\x00b"} {
		if _, err := fabric.Confined(newFk("p"), r); err == nil {
			t.Errorf("root %q must be rejected", r)
		}
	}
}

func TestConfined_EscapesNeverReachInner(t *testing.T) {
	t.Parallel()
	bad := []string{
		"/data/media/../secret", "/etc/passwd", "../../etc/passwd", "/data/media2/x", "/data", "/",
		"/data/media/../../etc", "\\data\\media\\..\\..\\etc", "..\\..\\x", "/data/media/\x00/x", "/data/../data2",
		"/data/media/./../x", "//etc/passwd",
	}
	for _, op := range fabric.AllOps() {
		if op.Paths() == 0 {
			continue
		}
		for _, p := range bad {
			f := newFk("p")
			c := confined(t, fkSeek{f}, "/data/media")
			err := invokeOp(t, c, op, p, "/data/media/ok")
			if !errors.Is(err, fabric.ErrOutsideRoot) {
				t.Errorf("%v(%q): err=%v, want ErrOutsideRoot", op, p, err)
			}
			if f.total() != 0 {
				t.Errorf("%v(%q) reached the inner client", op, p)
			}
		}
	}
}

func TestConfined_CopyChecksBothPathsBeforeTouchingEither(t *testing.T) {
	t.Parallel()
	f := newFk("p")
	c := confined(t, f, "/data/media")
	if err := c.CopyFile(context.Background(), "/data/media/a", "/etc/x"); !errors.Is(err, fabric.ErrOutsideRoot) {
		t.Fatalf("dst escape: %v", err)
	}
	if err := c.CopyFile(context.Background(), "/etc/x", "/data/media/a"); !errors.Is(err, fabric.ErrOutsideRoot) {
		t.Fatalf("src escape: %v", err)
	}
	if f.total() != 0 {
		t.Fatal("inner reached")
	}
}

func TestConfined_InsidePathsAreCleanedAndForwarded(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"/data/media":             "/data/media",
		"/data/media/":            "/data/media",
		"/data/media/a/b.mkv":     "/data/media/a/b.mkv",
		"/data/media/a/../b":      "/data/media/b",
		"/data/media/./x//y":      "/data/media/x/y",
		"rel/file":                "/data/media/rel/file",
		"":                        "/data/media",
		"\\data\\media\\s\\f.txt": "/data/media/s/f.txt",
		"sub\\f":                  "/data/media/sub/f",
	}
	for _, op := range fabric.AllOps() {
		if op.Paths() == 0 {
			continue
		}
		for in, want := range cases {
			f := newFk("p")
			c := confined(t, fkSeek{f}, "/data/media")
			if err := invokeOp(t, c, op, in, "/data/media/second"); err != nil {
				t.Errorf("%v(%q): %v", op, in, err)
				continue
			}
			got := f.paths(op.String())
			if len(got) != op.Paths() || got[0] != want {
				t.Errorf("%v(%q): inner saw %v, want first %q", op, in, got, want)
			}
		}
	}
}

func TestConfined_RootSlashAllowsAnyAbsolutePath(t *testing.T) {
	t.Parallel()
	f := newFk("p")
	c := confined(t, f, "/")
	if err := c.DeleteFile(context.Background(), "/anything/../etc/x"); err != nil {
		t.Fatal(err)
	}
	if f.paths("DeleteFile")[0] != "/etc/x" {
		t.Fatalf("saw %v", f.paths("DeleteFile"))
	}
}

func TestConfined_ConnectionOpsPassThrough(t *testing.T) {
	t.Parallel()
	f := newFk("p")
	c := confined(t, f, "/data")
	ctx := context.Background()
	if c.Connect(ctx) != nil || c.TestConnection(ctx) != nil || c.Disconnect(ctx) != nil {
		t.Fatal("connection ops failed")
	}
	if f.total() != 3 || !c.IsConnected() || c.GetProtocol() != "p" || c.GetConfig() != nil {
		t.Fatalf("passthrough broken: %v", f.calls)
	}
}

// ---------------------------------------------------------------- Metered

func TestMetered_CountsCallsErrorsAndBytes(t *testing.T) {
	t.Parallel()
	sink := &fabric.CounterSink{}
	f := newFk("p")
	f.readData = strings.Repeat("z", 1000)
	f.queue("FileExists", errors.New("x"))
	clk := newFakeClock()
	c := fabric.Metered(fkSeek{f}, sink, clk)
	ctx := context.Background()

	rc, err := c.ReadFile(ctx, "/a")
	if err != nil {
		t.Fatal(err)
	}
	if sink.Snapshot(fabric.OpReadFile).Calls != 0 {
		t.Fatal("a stream must be reported at Close, not at open")
	}
	_, _ = io.Copy(io.Discard, rc)
	clk.advance(250 * time.Millisecond)
	_ = rc.Close()
	_ = rc.Close()
	rs := sink.Snapshot(fabric.OpReadFile)
	if rs.Calls != 1 || rs.Bytes != 1000 || rs.Errors != 0 || rs.TotalDuration != 250*time.Millisecond {
		t.Fatalf("ReadFile counters %+v", rs)
	}

	if err := c.WriteFile(ctx, "/w", strings.NewReader(strings.Repeat("q", 321))); err != nil {
		t.Fatal(err)
	}
	if w := sink.Snapshot(fabric.OpWriteFile); w.Calls != 1 || w.Bytes != 321 {
		t.Fatalf("WriteFile counters %+v", w)
	}
	if _, err := c.FileExists(ctx, "/e"); err == nil {
		t.Fatal("expected error")
	}
	if e := sink.Snapshot(fabric.OpFileExists); e.Calls != 1 || e.Errors != 1 {
		t.Fatalf("FileExists counters %+v", e)
	}
	s, _ := c.(client.SeekableClient).OpenSeekable(ctx, "/s")
	_, _ = io.Copy(io.Discard, s)
	_ = s.Close()
	if o := sink.Snapshot(fabric.OpOpenSeekable); o.Calls != 1 || o.Bytes != int64(len(f.readData)) {
		t.Fatalf("OpenSeekable counters %+v", o)
	}
	if sink.Snapshot(fabric.Op(99)).Calls != 0 {
		t.Fatal("invalid op must be inert")
	}
	sink.Observe(fabric.Sample{Op: fabric.Op(99)}) // ignored, no panic
}

func TestMetered_EveryOpProducesExactlyOneSample(t *testing.T) {
	t.Parallel()
	for _, op := range fabric.AllOps() {
		sink := &fabric.CounterSink{}
		c := fabric.Metered(fkSeek{newFk("p")}, sink, nil)
		if err := invokeOp(t, c, op, "/a", "/b"); err != nil {
			t.Fatalf("%v: %v", op, err)
		}
		if got := sink.Snapshot(op).Calls; got != 1 {
			t.Errorf("%v produced %d samples", op, got)
		}
	}
}

func TestMetered_NilSinkPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fabric.Metered(newFk("p"), nil, nil)
}

// ----------------------------------------------------- shared decorator facts

func TestDecorators_SeekableOnlyWhenInnerIs(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 2, 1e6, nil)
	mk := map[string]func(client.Client) client.Client{
		"Limited":  func(c client.Client) client.Client { return fabric.Limited(c, b) },
		"Retrying": func(c client.Client) client.Client { return retrying(t, c, fabric.RetryPolicy{MaxAttempts: 1}) },
		"Confined": func(c client.Client) client.Client { return confined(t, c, "/") },
		"Metered":  func(c client.Client) client.Client { return fabric.Metered(c, &fabric.CounterSink{}, nil) },
	}
	for name, d := range mk {
		if _, ok := d(newFk("p")).(client.SeekableClient); ok {
			t.Errorf("%s made a non-seekable client seekable", name)
		}
		if _, ok := d(fkSeek{newFk("p")}).(client.SeekableClient); !ok {
			t.Errorf("%s lost OpenSeekable", name)
		}
	}
}

func TestDecorators_NilInnerPanics(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, 1, 1, nil)
	fns := map[string]func(){
		"Limited":  func() { fabric.Limited(nil, b) },
		"Metered":  func() { fabric.Metered(nil, &fabric.CounterSink{}, nil) },
		"Retrying": func() { _, _ = fabric.Retrying(nil, fabric.RetryPolicy{MaxAttempts: 1}) },
		"Confined": func() { _, _ = fabric.Confined(nil, "/") },
	}
	for n, fn := range fns {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic for nil inner", n)
				}
			}()
			fn()
		}()
	}
}

func TestChain_FirstDecoratorIsOutermost(t *testing.T) {
	t.Parallel()
	var order []string
	mark := func(name string) fabric.Decorator {
		return func(c client.Client) client.Client {
			order = append(order, name)
			return c
		}
	}
	fabric.Chain(newFk("p"), mark("A"), mark("B"), mark("C"))
	if strings.Join(order, "") != "CBA" { // applied innermost-first
		t.Fatalf("application order %v", order)
	}
	// behavioural: Metered outermost sees the retried final outcome as ONE sample
	sink := &fabric.CounterSink{}
	f := newFk("p").queue("ListDirectory", errReset)
	c := fabric.Chain(f,
		func(c client.Client) client.Client { return fabric.Metered(c, sink, nil) },
		func(c client.Client) client.Client {
			return retrying(t, c, fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, Clock: newFakeClock()})
		},
	)
	if err := invokeOp(t, c, fabric.OpListDirectory, "/a"); err != nil {
		t.Fatal(err)
	}
	if s := sink.Snapshot(fabric.OpListDirectory); s.Calls != 1 || s.Errors != 0 || f.count("ListDirectory") != 2 {
		t.Fatalf("sample %+v inner=%d", s, f.count("ListDirectory"))
	}
}

// An inner client that returns BOTH a stream and an error must not leak the stream.
type leakyOpen struct {
	*fk
	closed *int
}

type countClose struct{ n *int }

func (c countClose) Read([]byte) (int, error) { return 0, io.EOF }
func (c countClose) Close() error             { *c.n++; return nil }

func (l leakyOpen) ReadFile(context.Context, string) (io.ReadCloser, error) {
	return countClose{l.closed}, errors.New("open failed")
}

func TestLayer_ClosesStreamReturnedAlongsideAnError(t *testing.T) {
	t.Parallel()
	n := 0
	c := fabric.Limited(leakyOpen{newFk("p"), &n}, mustBudget(t, 1, 1e6, nil))
	if rc, err := c.ReadFile(context.Background(), "/a"); err == nil || rc != nil {
		t.Fatalf("rc=%v err=%v", rc, err)
	}
	if n != 1 {
		t.Fatalf("stream closed %d times, want 1", n)
	}
}

func TestRetrying_HugeBackoffDoesNotOverflow(t *testing.T) {
	t.Parallel()
	f := newFk("p")
	for i := 0; i < 70; i++ {
		f.queue("TestConnection", errReset)
	}
	clk := newFakeClock()
	c := retrying(t, f, fabric.RetryPolicy{MaxAttempts: 70, BaseDelay: time.Hour, MaxDelay: 2 * time.Hour, Clock: clk})
	_ = c.TestConnection(context.Background())
	for _, d := range clk.slept() {
		if d < 0 || d > 2*time.Hour {
			t.Fatalf("delay %v outside [0, MaxDelay]", d)
		}
	}
	// no MaxDelay: the doubling must saturate, never go negative
	f2 := newFk("p")
	for i := 0; i < 70; i++ {
		f2.queue("TestConnection", errReset)
	}
	clk2 := newFakeClock()
	c2 := retrying(t, f2, fabric.RetryPolicy{MaxAttempts: 70, BaseDelay: time.Hour, Clock: clk2})
	_ = c2.TestConnection(context.Background())
	prev := time.Duration(0)
	for i, d := range clk2.slept() {
		if d < prev {
			t.Fatalf("delay %d = %v shrank from %v: overflow", i, d, prev)
		}
		prev = d
	}
	if prev != time.Duration(math.MaxInt64) {
		t.Fatalf("final delay %v did not saturate", prev)
	}
}
