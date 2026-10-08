package nfs3

// Tests of the third fix pass (constitution 11.4.276, round 3 = the fix for the WF24 re-review). This file uses only API that already
// existed at the committed code (83c0ac1), so the whole file compiles there and its RED is measured on the committed package
// (evidence fix-r3-red-new.txt). The tests that need the new internals are in fixr3_api_test.go.
//
// Every test states the class it belongs to (fix-r3-convergence.md) and carries a positive control where an absence is asserted.

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- class A: which handle does STALE / BADHANDLE refer to ----

// A STALE or BADHANDLE answering the LOOKUP of the attribute fallback names the DIRECTORY (RFC 1813 3.3.3), so the listing fails; it is never
// an empty directory. The adopted probe W1 covers STALE; this covers BADHANDLE, the error type, and that the entries are not counted as vanished.
func TestFixR3LookupLegBadHandleFailsTheListing(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.OmitAttrs = true; o.OmitHandles = true })
	c := connected(t, s, nil)
	if l, err := c.ListDirectory(bg, "/docs"); err != nil || len(l) != 2 { // positive control
		t.Fatalf("control: %v %v", names(l), err)
	}
	var listed, bad atomic.Int64
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc == procReaddirplus {
				listed.Add(1)
			}
			if proc == procLookup && listed.Load() > 0 {
				bad.Add(1)
				var e encoder
				e.u32(NFS3ErrBadHandle)
				e.boolean(false)
				return e.b
			}
			return reply
		}
	})
	v0 := c.VanishedEntries()
	l, err := c.ListDirectory(bg, "/docs")
	if bad.Load() == 0 {
		t.Fatal("instrument blind: no LOOKUP was answered BADHANDLE")
	}
	var ne *NFSError
	if err == nil || !errors.As(err, &ne) || ne.Status != NFS3ErrBadHandle {
		t.Fatalf("BADHANDLE on the directory during the attribute fallback: want the NFS error, got %d entries and err=%v", len(l), err)
	}
	if d := c.VanishedEntries() - v0; d != 0 {
		t.Errorf("VanishedEntries +%d: a directory-level error was counted as vanished entries", d)
	}
}

// ---- class B: cache validity is a chain property ----

// The parent entry is gone (evicted, or dropped by a reset) while its children are still in the map. The directory is replaced; the walk learns
// the new handle of the parent. The children of the OLD directory must not be reachable through it. (W2 is the expiry order; this is the eviction order.)
func TestFixR3EvictedParentDoesNotLeaveReachableChildren(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/deep/a", "/deep/a/b", "/deep/a/b/c"} { // positive control: the chain was cached
		if _, ok := c.cached(p); !ok {
			t.Fatalf("setup: %s not cached", p)
		}
	}
	deep := findKid(s.root, "deep")
	s.mu.Lock()
	findKid(deep, "a").name = "moved" // mv /deep/a /deep/moved; mkdir /deep/a
	s.mu.Unlock()
	s.mk(deep, "a", TypeDir, nil)
	c.mu.Lock()
	delete(c.cache, "/deep/a") // the parent entry alone is gone; /deep/a/b and /deep/a/b/c remain in the map
	c.mu.Unlock()
	for _, p := range []string{"/deep/a/b", "/deep/a/b/c"} { // validity is a property of the whole chain, not of the nearest parent
		if _, ok := c.cached(p); ok {
			t.Errorf("%s is reachable although the entry of its ancestor /deep/a is gone", p)
		}
	}
	_, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the new /deep/a is empty: /deep/a/b/c/leaf.txt must not resolve through the children of the replaced directory (err=%v)", err)
	}
}

// Control for the chain rule (it must not over-invalidate): the parent expires first and is looked up again, the directory is UNCHANGED, so its
// children (learned later, still inside their own TTL) stay usable: 3 LOOKUPs (/deep, /deep/a, leaf), the children come from the cache.
func TestFixR3UnchangedExpiredParentKeepsItsChildren(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	c.mu.Lock()
	c.now = clk.now
	c.cache = map[string]cacheEntry{"/": {h: c.root, at: clk.now()}}
	c.mu.Unlock()
	ttl := c.cfg.HandleCacheTTL
	if _, err := c.GetFileInfo(bg, "/deep/a"); err != nil {
		t.Fatal(err)
	}
	clk.advance(ttl * 6 / 10)
	if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil {
		t.Fatal(err)
	}
	clk.advance(ttl * 5 / 10) // /deep and /deep/a expired, /deep/a/b and /deep/a/b/c not
	lk0 := s.procs[procLookup].Load()
	if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil {
		t.Fatalf("unchanged tree: %v", err)
	}
	if n := s.procs[procLookup].Load() - lk0; n != 3 {
		t.Errorf("%d LOOKUPs, want 3: the chain rule threw away children of a directory whose handle did not change", n)
	}
}

// A path whose parent is not remembered is not remembered: a handle of unknown ancestry must not become reachable.
func TestFixR3HandleWithoutRememberedParentIsNotCached(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	c.remember("/known", Handle("k")) // positive control: a path under the root is cached
	if _, ok := c.cached("/known"); !ok {
		t.Fatal("control: /known not cached")
	}
	c.remember("/nope/child", Handle("c"))
	if _, ok := c.cached("/nope/child"); ok {
		t.Error("/nope/child was cached although /nope is not")
	}
}

// When the cache is full it starts over from the root but keeps the chain of the path being added, so the entry can still be linked.
func TestFixR3FullCacheKeepsTheChainOfTheNewEntry(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	c.remember("/x", Handle("x"))
	c.remember("/x/y", Handle("y"))
	for i := 0; ; i++ { // fill to one below the bound with siblings
		c.mu.Lock()
		n := len(c.cache)
		c.mu.Unlock()
		if n >= handleCacheMax-1 {
			break
		}
		c.remember("/s"+itoa(i), Handle("s"+itoa(i)))
	}
	c.remember("/s-last", Handle("l")) // reaches the bound
	c.remember("/x/y/z", Handle("z"))  // triggers the reset
	c.mu.Lock()
	n := len(c.cache)
	c.mu.Unlock()
	if n > handleCacheMax {
		t.Fatalf("cache holds %d entries, bound %d", n, handleCacheMax)
	}
	for _, p := range []string{"/x", "/x/y", "/x/y/z"} {
		if _, ok := c.cached(p); !ok {
			t.Errorf("%s was lost by the reset although it is on the chain of the new entry", p)
		}
	}
	if _, ok := c.cached("/s0"); ok {
		t.Error("an unrelated sibling survived the reset: the reset did not happen (instrument blind)")
	}
}

// ---- class C: context, and the effect of one caller's cancellation on the others ----

// W7, deterministic: the interrupted Write sent 0 bytes (nobody reads the other end of the pipe), so the stream is intact. The cancelled call returns
// the context error and the connection stays usable for the next caller.
func TestFixR3CancelledZeroByteWriteKeepsTheConnection(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { srv.Close() })
	rc := newRPCConn(cli, authSysCred{}, 0, 1)
	t.Cleanup(rc.close)
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := rc.call(ctx, 10*time.Second, progNFS, versNFS, procGetattr, nil)
		errc <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for len(rc.wsem) != 1 { // the call holds the write slot, so it is blocked inside Write
		if time.Now().After(deadline) {
			t.Fatal("instrument blind: the call never reached the Write")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled call returned %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the cancelled call did not return")
	}
	if rc.isClosed() {
		t.Fatalf("one caller's cancellation (0 bytes written) failed the shared connection: %v", rc.connErr())
	}
	// Positive control: the connection really is usable.
	go func() {
		br := bufio.NewReader(srv)
		rec, err := readRecord(br, 1<<20)
		if err != nil {
			return
		}
		out := getattrOK(binary.BigEndian.Uint32(rec))
		_, _ = srv.Write(append(binary.BigEndian.AppendUint32(nil, 0x80000000|uint32(len(out))), out...))
	}()
	if _, err := rc.call(bg, 5*time.Second, progNFS, versNFS, procGetattr, nil); err != nil {
		t.Fatalf("the connection was not usable after the cancelled call: %v", err)
	}
}

// A write that times out with a LIVE context (the peer stopped reading: nothing was sent) fails the connection: a stuck send buffer is the server's
// state, not one caller's cancellation. The control is the cancelled-context test above.
func TestFixR3WriteTimeoutWithLiveContextFailsTheConnection(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { srv.Close() })
	rc := newRPCConn(cli, authSysCred{}, 0, 1)
	t.Cleanup(rc.close)
	_, err := rc.call(bg, 150*time.Millisecond, progNFS, versNFS, procGetattr, nil)
	if !errors.Is(err, ErrConnClosed) {
		t.Fatalf("want ErrConnClosed, got %v", err)
	}
	if !rc.isClosed() {
		t.Error("a write that timed out against a silent peer left the connection open")
	}
}

// A cancellation that interrupts a Write AFTER part of the record left the socket must fail the connection: the stream holds half a record.
func TestFixR3CancelledPartialWriteFailsTheConnection(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { srv.Close() })
	rc := newRPCConn(cli, authSysCred{}, 0, 1)
	t.Cleanup(rc.close)
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := rc.call(ctx, 10*time.Second, progNFS, versNFS, procGetattr, nil)
		errc <- err
	}()
	var got [3]byte
	if _, err := io.ReadFull(srv, got[:]); err != nil { // the peer takes 3 bytes and then stops reading
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled call returned %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the cancelled call did not return")
	}
	if !rc.isClosed() {
		t.Error("the connection holds a half-written record and was left open")
	}
}

// failingConn: the first Write blocks until gate is closed and then fails after sending 3 bytes (a half record); Read blocks until Close.
type failingConn struct {
	gate   chan struct{}
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	writes int
}

func newFailingConn() *failingConn {
	return &failingConn{gate: make(chan struct{}), closed: make(chan struct{})}
}
func (f *failingConn) Write(b []byte) (int, error) {
	f.mu.Lock()
	f.writes++
	n := f.writes
	f.mu.Unlock()
	if n == 1 {
		<-f.gate
		return 3, errors.New("boom: half a record left the socket")
	}
	return 0, net.ErrClosed
}
func (f *failingConn) Read([]byte) (int, error)         { <-f.closed; return 0, io.EOF }
func (f *failingConn) Close() error                     { f.once.Do(func() { close(f.closed) }); return nil }
func (f *failingConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (f *failingConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (f *failingConn) SetDeadline(time.Time) error      { return nil }
func (f *failingConn) SetReadDeadline(time.Time) error  { return nil }
func (f *failingConn) SetWriteDeadline(time.Time) error { return nil }
func (f *failingConn) writeCount() int                  { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }

// W7, second half: after a write failed half way, the connection is failed BEFORE the write slot is released and a caller that was already waiting
// for the slot re-checks the connection once it has it. No later record is appended to the half record. halfWriteTrial runs one such scenario; this test
// runs it 100 times as a plain race (it covers the re-check, mutant F16); the deterministic ordering test, which needs rpcConn.failHook, is
// TestFixR3FailedWriterKeepsTheSlotUntilTheConnectionIsFailed in fixr3_api_test.go.
func halfWriteTrial(t *testing.T, trial int, setup func(rc *rpcConn, fc *failingConn)) {
	t.Helper()
	fc := newFailingConn()
	rc := newRPCConn(fc, authSysCred{}, 0, uint32(trial)<<8)
	if setup != nil {
		setup(rc, fc)
	}
	errA, errB := make(chan error, 1), make(chan error, 1)
	go func() { _, err := rc.call(bg, 10*time.Second, progNFS, versNFS, procGetattr, nil); errA <- err }()
	waitFor(t, func() bool { return fc.writeCount() == 1 }, "caller A inside Write")
	go func() { _, err := rc.call(bg, 10*time.Second, progNFS, versNFS, procGetattr, nil); errB <- err }()
	waitFor(t, func() bool { rc.mu.Lock(); defer rc.mu.Unlock(); return len(rc.pending) == 2 }, "caller B registered")
	close(fc.gate)
	for _, ch := range []chan error{errA, errB} {
		select {
		case err := <-ch:
			if !errors.Is(err, ErrConnClosed) {
				t.Fatalf("trial %d: want ErrConnClosed, got %v", trial, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("trial %d: a caller did not return", trial)
		}
	}
	if n := fc.writeCount(); n != 1 {
		t.Fatalf("trial %d: %d writes: a record was appended to a stream that a half write had already broken", trial, n)
	}
	rc.close()
}

func TestFixR3NoRecordIsAppendedToAHalfWrittenStream(t *testing.T) {
	for trial := 1; trial <= 100; trial++ {
		halfWriteTrial(t, trial, nil)
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("instrument blind: timed out waiting for %s", what)
		}
		time.Sleep(200 * time.Microsecond)
	}
}

// I2: a Seek makes the read-ahead stale, so the READs still in flight are cancelled, not left to run against the server. The server never answers.
func TestFixR3SeekCancelsTheReadsInFlight(t *testing.T) {
	addr := rawServer(t, func(conn, call int, rec []byte) [][]byte { return nil })
	c := rawClient(t, addr, func(c *Config) { c.CallTimeout = 30 * time.Second; c.MaxRetries = -1 })
	rctx, cancel := context.WithCancel(bg)
	defer cancel()
	r := &fileReader{c: c, ctx: rctx, cancel: cancel, fh: Handle("h"), size: 1 << 20, chunk: 64 << 10, window: 4, limit: math.MaxInt64}
	r.restartRamp()
	r.cw = 4
	r.topUp()
	futs := append([]*future(nil), r.q...)
	if len(futs) != 4 {
		t.Fatalf("setup: %d READs in flight, want 4", len(futs))
	}
	select { // positive control: nothing is delivered while the server is silent
	case res := <-futs[0].ch:
		t.Fatalf("control: a READ completed against a silent server: %+v", res)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := r.Seek(500, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	for i, f := range futs {
		select {
		case res := <-f.ch:
			if !errors.Is(res.err, context.Canceled) {
				t.Errorf("READ %d finished with %v, want context.Canceled", i, res.err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("READ %d is still in flight after the Seek made it stale", i)
		}
	}
}

// ---- class E: cleanup after a successful MNT ----

// mntServer answers MNT with the given reply body and counts UMNT calls (it answers them unless silentUmnt is set).
func mntServer(t *testing.T, mntBody func() []byte, silentUmnt ...bool) (addr string, umnt *atomic.Int64) {
	t.Helper()
	umnt = new(atomic.Int64)
	addr = rawServer(t, func(conn, call int, rec []byte) [][]byte {
		xid := binary.BigEndian.Uint32(rec)
		switch binary.BigEndian.Uint32(rec[20:24]) {
		case procMnt:
			return [][]byte{append(replyHdr(xid, msgAccepted, 0, 0, acceptSuccess), mntBody()...)}
		case procUmnt:
			umnt.Add(1)
			if len(silentUmnt) > 0 && silentUmnt[0] {
				return nil
			}
			return [][]byte{replyHdr(xid, msgAccepted, 0, 0, acceptSuccess)}
		}
		return nil
	})
	return addr, umnt
}

func connectTo(t *testing.T, mountAddr string) error {
	t.Helper()
	_, mp, _ := net.SplitHostPort(mountAddr)
	cfg := Config{Host: "127.0.0.1", Export: "/x", MountPort: atoiT(t, mp), NFSPort: 1, CallTimeout: time.Second, MaxRetries: -1, RetryBackoff: time.Millisecond}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.Connect(bg)
}

// I1: a MNT whose status is OK but whose body is malformed (a handle longer than 64 bytes) still left a mount record on the server: UMNT is sent.
// The control is a MNT refusal (status ACCES): no mount record exists, no UMNT is sent.
func TestFixR3MalformedOKMountReplyIsUnmounted(t *testing.T) {
	var e encoder
	e.u32(0)
	e.opaque(make([]byte, 65)) // handle longer than the 64 bytes RFC 1813 allows
	e.u32(1)
	e.u32(authSys)
	addr, umnt := mntServer(t, func() []byte { return e.b })
	if err := connectTo(t, addr); err == nil {
		t.Fatal("a 65-byte file handle was accepted")
	}
	waitFor(t, func() bool { return umnt.Load() >= 1 }, "the UMNT of a malformed OK mount reply")

	var r encoder
	r.u32(mnt3ErrAcces)
	addr2, umnt2 := mntServer(t, func() []byte { return r.b })
	if err := connectTo(t, addr2); err == nil {
		t.Fatal("control: a refused MNT connected")
	}
	time.Sleep(200 * time.Millisecond)
	if n := umnt2.Load(); n != 0 {
		t.Errorf("a refused MNT (no mount record) was followed by %d UMNT", n)
	}
}

// TN6 / class E: a Connect that fails AFTER the mount (here: FSINFO answered with an error) leaves the client disconnected and the mount record removed.
func TestFixR3ConnectFailingAfterMountLeavesTheClientDisconnected(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc == procFsinfo {
				var e encoder
				e.u32(NFS3ErrIO)
				e.boolean(false)
				return e.b
			}
			return reply
		}
	})
	c, err := New(s.cfg())
	if err != nil {
		t.Fatal(err)
	}
	u0 := s.mntProcs[procUmnt].Load()
	if err := c.Connect(bg); err == nil {
		t.Fatal("Connect succeeded although FSINFO failed")
	}
	if c.IsConnected() {
		t.Error("client marked connected after a failed Connect")
	}
	if n := s.mntProcs[procUmnt].Load() - u0; n != 1 {
		t.Errorf("%d UMNT after a failed Connect, want 1", n)
	}
}

// ---- class G: the real-NAS finding ----

// With TryPrivilegedPort the server's ORIGINAL refusal must survive when the reserved-port retry cannot even be made (this process may not bind a
// reserved port): the operator has to learn that the export rule refused, not only that a local bind failed.
func TestFixR3PrivilegedRetryFailureKeepsTheOriginalRefusal(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PortOK = func(int) bool { return false } })
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
	var ae *AccessError
	if !errors.As(err, &ae) {
		t.Fatalf("the server's access refusal is lost: %v", err)
	}
	if ae.Privileged {
		t.Errorf("the original refusal came from an unprivileged source port, Privileged=%v", ae.Privileged)
	}
	var me *MountError
	if !errors.As(err, &me) || me.Status != mnt3ErrAcces {
		t.Errorf("MNT3ERR_ACCES not visible in the error: %v", err)
	}
	if !errors.Is(err, ErrPrivilegedPortUnavailable) {
		t.Errorf("the reason the retry failed is lost: %v", err)
	}
}

// ---- class F: configuration limits ----

func TestFixR3ConfigLimitsAreBounded(t *testing.T) {
	base := Config{Host: "h", Export: "/x"}
	for name, mod := range map[string]func(*Config){
		"MaxPipeline above the limit":    func(c *Config) { c.MaxPipeline = 65 },
		"MaxPipeline far above":          func(c *Config) { c.MaxPipeline = 1 << 20 },
		"DirCount above DirMaxCount":     func(c *Config) { c.DirCount = 20000; c.DirMaxCount = 10000 },
		"DirCount above the default Max": func(c *Config) { c.DirCount = 200000 },
	} {
		cfg := base
		mod(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, mod := range map[string]func(*Config){
		"MaxPipeline at the limit":   func(c *Config) { c.MaxPipeline = 64 },
		"DirCount equal DirMaxCount": func(c *Config) { c.DirCount = 10000; c.DirMaxCount = 10000 },
		"defaults":                   func(c *Config) {},
	} {
		cfg := base
		mod(&cfg)
		if _, err := New(cfg); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

// The cleanup UMNT of a failed Connect is bounded by CallTimeout even when the caller's context is alive and the mount daemon accepts but never
// answers: Connect returns after about CallTimeout, not after the 2 s cleanup bound.
func TestFixR3FailedConnectUmntIsBoundedByCallTimeout(t *testing.T) {
	var e encoder
	e.u32(0)
	e.opaque(make([]byte, 65)) // malformed OK reply: the connect fails after the mount
	addr, umnt := mntServer(t, func() []byte { return e.b }, true)
	_, mp, _ := net.SplitHostPort(addr)
	cfg := Config{Host: "127.0.0.1", Export: "/x", MountPort: atoiT(t, mp), NFSPort: 1, CallTimeout: 300 * time.Millisecond, MaxRetries: -1}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := c.Connect(bg); err == nil {
		t.Fatal("a 65-byte file handle was accepted")
	}
	el := time.Since(start)
	waitFor(t, func() bool { return umnt.Load() >= 1 }, "the UMNT")
	if el > 1200*time.Millisecond {
		t.Errorf("Connect returned after %v: the silent UMNT was not bounded by CallTimeout (300 ms)", el.Round(time.Millisecond))
	}
	if el < 250*time.Millisecond {
		t.Errorf("Connect returned after %v, before the UMNT could have timed out: instrument blind", el.Round(time.Millisecond))
	}
}
