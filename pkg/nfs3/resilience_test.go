package nfs3

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- retries, timeouts, cancellation ----

func TestRetryReconnectsAfterDroppedConnection(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.ReadSize = 65536; c.MaxRetries = 8 })
	s.set(func(o *fakeOpts) { o.DropEveryN = 10 }) // every tenth call on a connection kills it
	got := readAll(t, c, "/big.bin")
	if !bytes.Equal(got, s.root.kids[3].data) {
		t.Fatal("data differs after reconnects")
	}
	if s.conns.Load() < 5 {
		t.Errorf("only %d connections: no reconnect happened", s.conns.Load())
	}
}

func TestRetryJukeboxBounded(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.MaxRetries = 3; c.JukeboxRetries = 3 })
	s.set(func(o *fakeOpts) { o.Jukebox = 3 })
	before := s.procs[procGetattr].Load() + s.procs[procLookup].Load()
	if _, err := c.GetFileInfo(bg, "/docs"); err != nil {
		t.Fatalf("3 JUKEBOX replies with 3 retries should succeed: %v", err)
	}
	if n := s.procs[procGetattr].Load() + s.procs[procLookup].Load() - before; n != 4 {
		t.Errorf("%d attempts, want 4", n)
	}
	s.set(func(o *fakeOpts) { o.Jukebox = 100 })
	before = s.procs[procGetattr].Load() + s.procs[procLookup].Load()
	_, err := c.GetFileInfo(bg, "/docs/b.txt")
	var ne *NFSError
	if !errors.As(err, &ne) || ne.Status != NFS3ErrJukebox {
		t.Fatalf("exhausted retries: %v", err)
	}
	if n := s.procs[procLookup].Load() + s.procs[procGetattr].Load() - before; n != 4 {
		t.Errorf("%d attempts for JukeboxRetries=3, want exactly 4", n)
	}
	if !strings.Contains(err.Error(), "attempts") {
		t.Errorf("error does not say it retried: %v", err)
	}
}

func TestNoRetryWhenDisabledOrPermanent(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.MaxRetries = -1; c.JukeboxRetries = -1 })
	s.set(func(o *fakeOpts) { o.Jukebox = 1 })
	before := s.procs[procLookup].Load() + s.procs[procGetattr].Load()
	if _, err := c.GetFileInfo(bg, "/docs"); err == nil {
		t.Fatal("expected the JUKEBOX error with retries disabled")
	}
	if n := s.procs[procLookup].Load() + s.procs[procGetattr].Load() - before; n != 1 {
		t.Errorf("%d attempts with retries disabled", n)
	}
	// A permanent error (NOENT) is never retried even with retries enabled.
	c2 := connected(t, s, nil)
	before = s.procs[procLookup].Load()
	_, _ = c2.GetFileInfo(bg, "/missing")
	if n := s.procs[procLookup].Load() - before; n != 1 {
		t.Errorf("NOENT retried: %d attempts", n)
	}
}

func TestCallTimeoutIsBounded(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.CallTimeout = 150 * time.Millisecond; c.MaxRetries = 1 })
	s.set(func(o *fakeOpts) { o.NoReply = true })
	start := time.Now()
	_, err := c.GetFileInfo(bg, "/docs")
	el := time.Since(start)
	if !errors.Is(err, ErrCallTimeout) {
		t.Fatalf("want ErrCallTimeout, got %v", err)
	}
	if el < 250*time.Millisecond || el > 3*time.Second {
		t.Errorf("elapsed %v: expected about 2 x 150ms plus backoff", el)
	}
}

func TestContextCancellationAndDeadline(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.CallTimeout = 30 * time.Second })
	s.set(func(o *fakeOpts) { o.NoReply = true })
	ctx, cancel := context.WithTimeout(bg, 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.GetFileInfo(ctx, "/docs")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("deadline: %v after %v", err, time.Since(start))
	}
	ctx2, cancel2 := context.WithCancel(bg)
	go func() { time.Sleep(50 * time.Millisecond); cancel2() }()
	if _, err = c.ListDirectory(ctx2, "/"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	pre, cancel3 := context.WithCancel(bg)
	cancel3()
	if _, err = c.GetFileInfo(pre, "/"); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled: %v", err)
	}
	// A cancelled reader aborts instead of hanging.
	s.set(func(o *fakeOpts) { o.NoReply = false })
	rctx, rcancel := context.WithCancel(bg)
	r, err := c.ReadFile(rctx, "/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	s.set(func(o *fakeOpts) { o.NoReply = true })
	go func() { time.Sleep(50 * time.Millisecond); rcancel() }()
	buf := make([]byte, 10)
	_, err = r.Read(buf)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reader cancel: %v", err)
	}
	_ = r.Close()
}

func TestCloseUnblocksReader(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.CallTimeout = 30 * time.Second })
	r, err := c.ReadFile(bg, "/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	s.set(func(o *fakeOpts) { o.NoReply = true })
	done := make(chan error, 1)
	go func() { _, err := r.Read(make([]byte, 5)); done <- err }()
	time.Sleep(50 * time.Millisecond)
	_ = r.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Read succeeded after Close with no data")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock a pending Read")
	}
}

func TestStaleCachedParentIsDropped(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil { // caches the parents
		t.Fatal(err)
	}
	s.set(func(o *fakeOpts) { o.StaleOnce = true })
	fi, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt")
	if err != nil || fi.Size != 4 {
		t.Fatalf("stale parent not recovered: %+v %v", fi, err)
	}
}

// ---- reserved source ports ----

func TestReservedPortRefusalIsPrecise(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PortOK = func(p int) bool { return p < 1024 } })
	c, _ := New(s.cfg())
	err := c.Connect(bg)
	var ae *AccessError
	if !errors.As(err, &ae) {
		t.Fatalf("want *AccessError, got %v", err)
	}
	if ae.Layer != "mount" || ae.SourcePort < 1024 || ae.Privileged {
		t.Errorf("%+v", ae)
	}
	var me *MountError
	if !errors.As(err, &me) || me.Status != mnt3ErrAcces {
		t.Errorf("underlying MNT3ERR_ACCES not preserved: %v", err)
	}
	msg := err.Error()
	for _, frag := range []string{"unprivileged source port", "below 1024", "TryPrivilegedPort"} {
		if !strings.Contains(msg, frag) {
			t.Errorf("message lacks %q: %s", frag, msg)
		}
	}
}

func TestPrivilegedRetrySucceedsWhenAllowed(t *testing.T) {
	s := newFakeServer(t)
	var mu sync.Mutex
	priv := map[int]bool{}
	s.set(func(o *fakeOpts) {
		o.PortOK = func(p int) bool { mu.Lock(); defer mu.Unlock(); return priv[p] }
	})
	var privDials, plainDials int
	cfg := s.cfg()
	cfg.TryPrivilegedPort = true
	cfg.Dial = func(ctx context.Context, network, addr string, privileged bool) (net.Conn, error) {
		var d net.Dialer
		nc, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		if privileged {
			privDials++
			priv[nc.LocalAddr().(*net.TCPAddr).Port] = true // simulate "this one came from a reserved port"
		} else {
			plainDials++
		}
		return nc, nil
	}
	c, _ := New(cfg)
	if err := c.Connect(bg); err != nil {
		t.Fatalf("privileged retry failed: %v", err)
	}
	if plainDials == 0 || privDials == 0 {
		t.Errorf("plain=%d privileged=%d: unprivileged must be tried first, then privileged", plainDials, privDials)
	}
	if _, err := c.GetFileInfo(bg, "/docs"); err != nil {
		t.Errorf("session unusable after privileged connect: %v", err)
	}
	_ = c.Disconnect(bg)
}

func TestPrivilegedRetryDoesNotFireForOtherErrors(t *testing.T) {
	s := newFakeServer(t)
	cfg := s.cfg()
	cfg.Export = "/nope"
	cfg.TryPrivilegedPort = true
	var priv int
	cfg.Dial = func(ctx context.Context, network, addr string, privileged bool) (net.Conn, error) {
		if privileged {
			priv++
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	c, _ := New(cfg)
	if err := c.Connect(bg); err == nil {
		t.Fatal("expected MNT3ERR_NOENT")
	}
	if priv != 0 {
		t.Errorf("privileged retry on a NOENT refusal (%d dials)", priv)
	}
}

func TestPrivilegedRetryReportsUnavailable(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PortOK = func(p int) bool { return false } })
	cfg := s.cfg()
	cfg.TryPrivilegedPort = true
	cfg.Dial = func(ctx context.Context, network, addr string, privileged bool) (net.Conn, error) {
		if privileged {
			return nil, ErrPrivilegedPortUnavailable
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	c, _ := New(cfg)
	err := c.Connect(bg)
	if !errors.Is(err, ErrPrivilegedPortUnavailable) {
		t.Fatalf("want ErrPrivilegedPortUnavailable, got %v", err)
	}
}

// TestRealPrivilegedBind exercises dialPrivileged without any simulation: it
// either binds a reserved port or reports ErrPrivilegedPortUnavailable; any
// other outcome is a bug. Which one happened is logged.
func TestRealPrivilegedBind(t *testing.T) {
	s := newFakeServer(t)
	conn, err := dialPrivileged(bg, s.pmLn.Addr().String(), time.Second)
	switch {
	case err == nil:
		defer conn.Close()
		p := conn.LocalAddr().(*net.TCPAddr).Port
		if p >= 1024 {
			t.Fatalf("bound port %d is not reserved", p)
		}
		t.Logf("bound reserved source port %d", p)
	case errors.Is(err, ErrPrivilegedPortUnavailable):
		t.Logf("cannot bind a reserved port here (expected unprivileged): %v", err)
	default:
		t.Fatalf("unclassified failure: %v", err)
	}
}

func TestAuthErrorOnNFSPortIsAccessError(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.RPCDeny = 1 })
	c, _ := New(s.cfg())
	err := c.Connect(bg)
	var ae *AccessError
	var re *RPCError
	if !errors.As(err, &ae) || !errors.As(err, &re) || !re.isAuth() || ae.Layer != "nfs" {
		t.Fatalf("%v", err)
	}
}

// ---- malformed and hostile replies ----

func corrupt(f func(proc uint32, reply []byte) []byte) func(*fakeOpts) {
	return func(o *fakeOpts) { o.Corrupt = f }
}

func TestMalformedRepliesAreErrorsNotPanics(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.MaxRetries = -1 })
	cases := []struct {
		name string
		proc uint32
		mut  func([]byte) []byte
		call func() error
	}{
		{"truncated GETATTR", procGetattr, func(b []byte) []byte { return b[:20] }, func() error { _, e := c.GetFileInfo(bg, "/"); return e }},
		{"empty LOOKUP", procLookup, func(b []byte) []byte { return nil }, func() error { _, e := c.GetFileInfo(bg, "/docs"); return e }},
		{"bad bool in LOOKUP", procLookup, func(b []byte) []byte {
			b = append([]byte(nil), b...)
			b[23] = 7 // the attributes_follow word after status(4)+handle(4+12)
			return b
		}, func() error { _, e := c.GetFileInfo(bg, "/docs"); return e }},
		{"huge name in READDIRPLUS", procReaddirplus, func(b []byte) []byte {
			var e encoder
			e.u32(0)
			e.boolean(false)
			e.fixed(make([]byte, 8))
			e.boolean(true)
			e.u64(1)
			e.u32(0x7fffffff) // name length
			return e.b
		}, func() error { _, e := c.ListDirectory(bg, "/docs"); return e }},
		{"name with slash", procReaddirplus, func(b []byte) []byte {
			var e encoder
			e.u32(0)
			e.boolean(false)
			e.fixed(make([]byte, 8))
			e.boolean(true)
			e.u64(1)
			e.str("../etc")
			e.u64(3)
			e.boolean(true) // attributes present: no LOOKUP fallback can fail first, only the name check
			e.fattr(sampleAttr())
			e.boolean(false)
			e.boolean(false)
			e.boolean(true)
			return e.b
		}, func() error { _, e := c.ListDirectory(bg, "/docs"); return e }},
		{"name with NUL", procReaddirplus, func(b []byte) []byte {
			var e encoder
			e.u32(0)
			e.boolean(false)
			e.fixed(make([]byte, 8))
			e.boolean(true)
			e.u64(1)
			e.str("a\x00b")
			e.u64(3)
			e.boolean(true)
			e.fattr(sampleAttr())
			e.boolean(false)
			e.boolean(false)
			e.boolean(true)
			return e.b
		}, func() error { _, e := c.ListDirectory(bg, "/docs"); return e }},
		{"READ count mismatch", procRead, func(b []byte) []byte {
			var e encoder
			e.u32(0)
			e.boolean(false)
			e.u32(100)
			e.boolean(true)
			e.opaque([]byte("short"))
			return e.b
		}, func() error { _, e := c.ReadRange(bg, "/docs/a.txt", 0, 100); return e }},
		{"READ oversize", procRead, func(b []byte) []byte {
			var e encoder
			e.u32(0)
			e.boolean(false)
			e.u32(1 << 30)
			e.boolean(true)
			e.u32(1 << 30)
			return e.b
		}, func() error { _, e := c.ReadRange(bg, "/docs/a.txt", 0, 100); return e }},
		{"READ zero bytes no EOF", procRead, func(b []byte) []byte {
			var e encoder
			e.u32(0)
			e.boolean(false)
			e.u32(0)
			e.boolean(false)
			e.opaque(nil)
			return e.b
		}, func() error { _, e := c.ReadRange(bg, "/docs/a.txt", 0, 100); return e }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s.set(corrupt(func(p uint32, r []byte) []byte {
				if p == tc.proc {
					return tc.mut(r)
				}
				return r
			}))
			defer s.set(corrupt(nil))
			done := make(chan error, 1)
			go func() { done <- tc.call() }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("malformed reply accepted")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("hang on malformed reply")
			}
		})
	}
	// The client recovers: a good reply after the bad ones works.
	s.set(corrupt(nil))
	if _, err := c.GetFileInfo(bg, "/docs"); err != nil {
		t.Fatalf("client unusable after malformed replies: %v", err)
	}
}

func TestWrongXIDReplyIsIgnored(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.set(func(o *fakeOpts) { o.WrongXID = true })
	for i := 0; i < 5; i++ {
		if fi, err := c.GetFileInfo(bg, "/docs/a.txt"); err != nil || fi.Size != 6 {
			t.Fatalf("%+v %v", fi, err)
		}
	}
	c.mu.Lock()
	n := c.nfs
	c.mu.Unlock()
	if n == nil || n.dropped.Load() == 0 {
		t.Fatal("unmatched replies were not counted as dropped")
	}
}

func TestGarbageStreamClosesConnection(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte{0x80, 0, 0, 3, 1, 2, 3}) // a 3-byte record: no room for xid and type
		time.Sleep(time.Second)
		c.Close()
	}()
	nc, _ := net.Dial("tcp", ln.Addr().String())
	rc := newRPCConn(nc, authSysCred{}, 0, 1)
	_, err := rc.call(bg, 2*time.Second, progNFS, 3, 0, nil)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("want ErrProtocol, got %v", err)
	}
	if !rc.isClosed() {
		t.Error("connection left open after a framing violation")
	}
}

func TestServerCloseFailsPendingCalls(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		c.Close()
	}()
	nc, _ := net.Dial("tcp", ln.Addr().String())
	rc := newRPCConn(nc, authSysCred{}, 0, 1)
	_, err := rc.call(bg, 5*time.Second, progNFS, 3, 0, nil)
	if !errors.Is(err, ErrConnClosed) {
		t.Fatalf("want ErrConnClosed, got %v", err)
	}
}
