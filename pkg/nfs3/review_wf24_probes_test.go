package nfs3

// ADOPTED (fix-r3, constitution 11.4.276 D): the WF24 reviewer's probes W1 to W4 and W7, verbatim from
// WF24-nfs3-artifacts/wf24_probe_test.go except that the reviewer's header sentence "scratch copy only, never in the real tree" is replaced by
// this note. Each probe asserts the CORRECT behaviour and carries its own positive control. On the committed code (83c0ac1) all five FAIL
// (evidence fix-r3-red-probes.txt); after the fixes they PASS. W7 is probabilistic; its deterministic twin is
// TestFixR3CancelledZeroByteWriteKeepsTheConnection in fixr3_test.go.

// Each probe asserts the CORRECT behaviour: a FAIL demonstrates a defect. Lines starting with
// "PROBE" are the captured measurements. Every probe carries a positive control so that a PASS
// can not come from a blind instrument (constitution 11.4.273).

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// W1: in the attribute-fallback path of a listing, LOOKUP(dir, name) answering NFS3ERR_STALE means the
// DIRECTORY handle is invalid (RFC 1813 3.3.3: the only handle in LOOKUP3args is the directory). It is
// counted as a vanished ENTRY, so the whole directory reads back as empty with no error.
func TestWF24ProbeW1StaleDirectoryDuringAttributeFallback(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.OmitAttrs = true; o.OmitHandles = true })
	c := connected(t, s, nil)
	// Positive control: the same listing without the injected staleness has both entries.
	if l, err := c.ListDirectory(bg, "/docs"); err != nil || len(l) != 2 {
		t.Fatalf("control: %v %v", names(l), err)
	}
	var listed atomic.Bool
	var stale atomic.Int64
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc == procReaddirplus {
				listed.Store(true)
				return reply
			}
			if proc == procLookup && listed.Load() { // the directory was removed / the server lost its handles
				stale.Add(1)
				var e encoder
				e.u32(NFS3ErrStale)
				e.boolean(false)
				return e.b
			}
			return reply
		}
	})
	v0 := c.VanishedEntries()
	l, err := c.ListDirectory(bg, "/docs")
	t.Logf("PROBE W1: listing whose directory handle went stale after READDIRPLUS -> %d entries %v err=%v; STALE LOOKUPs=%d; VanishedEntries +%d", len(l), names(l), err, stale.Load(), c.VanishedEntries()-v0)
	if stale.Load() == 0 {
		t.Fatal("instrument blind: no LOOKUP was answered STALE")
	}
	if err == nil {
		t.Errorf("DEFECT W1: a directory whose handle went stale is reported as an EMPTY directory with no error (%d entries); the STALE is about the directory, not the entries", len(l))
	}
}

// W2: the descendant purge of remember() only runs when the parent's OLD cache entry is still present.
// When the parent expired first (cached() deletes it) and its children were cached later, a walk learns
// the parent's NEW handle and then still uses the children of the OLD directory.
func TestWF24ProbeW2ExpiredParentKeepsChildrenOfTheOldTree(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	c.mu.Lock()
	c.now = clk.now
	c.cache = map[string]cacheEntry{"/": {h: c.root, at: clk.now()}}
	c.mu.Unlock()
	ttl := c.cfg.HandleCacheTTL
	if _, err := c.GetFileInfo(bg, "/deep/a"); err != nil { // caches /deep and /deep/a at t0
		t.Fatal(err)
	}
	clk.advance(ttl * 6 / 10)
	if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil { // /deep/a/b and /deep/a/b/c at t0+0.6 TTL
		t.Fatal(err)
	}
	deep := findKid(s.root, "deep")
	s.mu.Lock()
	findKid(deep, "a").name = "moved" // another client: mv /deep/a /deep/moved; mkdir /deep/a
	s.mu.Unlock()
	s.mk(deep, "a", TypeDir, nil)
	clk.advance(ttl * 5 / 10) // t0+1.1 TTL: /deep and /deep/a expired, /deep/a/b and /deep/a/b/c are not
	lk0 := s.procs[procLookup].Load()
	fi, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt")
	lk := s.procs[procLookup].Load() - lk0
	// Positive control: the client DID learn the new handle of /deep/a in this walk (a LOOKUP of "a" happened).
	h, ok := c.cached("/deep/a")
	newA := findKid(deep, "a")
	learned := ok && string(h) == string(s.fh(newA))
	t.Logf("PROBE W2: after mv+mkdir and parent expiry: GetFileInfo -> %+v err=%v; LOOKUPs=%d; /deep/a now cached as the NEW directory=%v", fi, err, lk, learned)
	if !learned {
		t.Fatalf("instrument blind: the walk did not learn the new /deep/a handle")
	}
	if err == nil {
		t.Errorf("DEFECT W2: /deep/a was just resolved to a NEW, empty directory, yet /deep/a/b/c/leaf.txt still resolves through the children of the OLD (renamed) directory: the purge of remember() is skipped when the parent's old entry had expired")
	}
}

// W3: the best-effort UMNT of a failed Connect runs on context.Background() with the full CallTimeout:
// a caller whose context ends during Connect still waits for it.
func TestWF24ProbeW3FailedConnectUmntIgnoresCallerContext(t *testing.T) {
	var umnt atomic.Int64
	mnt := rawServer(t, func(conn, call int, rec []byte) [][]byte {
		xid := binary.BigEndian.Uint32(rec)
		switch binary.BigEndian.Uint32(rec[20:24]) {
		case procMnt:
			b := replyHdr(xid, msgAccepted, 0, 0, acceptSuccess)
			var e encoder
			e.u32(0)
			e.opaque([]byte("rootfh01"))
			e.u32(1)
			e.u32(authSys)
			return [][]byte{append(b, e.b...)}
		case procUmnt:
			umnt.Add(1)
			return nil // a mount daemon that does not answer
		}
		return nil
	})
	nfs := rawServer(t, func(conn, call int, rec []byte) [][]byte { return nil }) // FSINFO never answered
	_, mp, _ := net.SplitHostPort(mnt)
	_, np, _ := net.SplitHostPort(nfs)
	cfg := Config{Host: "127.0.0.1", Export: "/x", MountPort: atoiT(t, mp), NFSPort: atoiT(t, np), CallTimeout: 2 * time.Second, MaxRetries: -1, RetryBackoff: time.Millisecond}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = c.Connect(ctx)
	el := time.Since(start)
	t.Logf("PROBE W3: Connect with a 200ms context -> err=%v after %v; UMNT calls received=%d", err, el.Round(time.Millisecond), umnt.Load())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("setup: want the context error, got %v", err)
	}
	if umnt.Load() == 0 {
		t.Fatal("instrument blind: the failure path sent no UMNT")
	}
	if el > time.Second {
		t.Errorf("DEFECT W3: the caller's 200ms context ended but Connect returned only after %v (the cleanup UMNT waited the whole CallTimeout on a background context)", el.Round(time.Millisecond))
	}
}

func atoiT(t *testing.T, s string) int {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			t.Fatalf("bad port %q", s)
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// W4: the run-time allow-list is keyed on (program, procedure) only. NFS version 4 procedure 1 is
// COMPOUND, which carries WRITE/REMOVE/RENAME operations; it shares the number of v3 GETATTR and passes.
func TestWF24ProbeW4AllowListIgnoresTheVersion(t *testing.T) {
	var got atomic.Int64
	addr := rawServer(t, func(conn, call int, rec []byte) [][]byte { got.Add(1); return nil })
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	rc := newRPCConn(nc, authSysCred{}, 0, 1)
	defer rc.close()
	// Positive control: a v3 write procedure is refused and reaches nothing.
	if _, err := rc.call(bg, time.Second, progNFS, versNFS, 7, nil); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("control: WRITE v3 not refused: %v", err)
	}
	ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
	defer cancel()
	_, err = rc.call(ctx, time.Second, progNFS, 4, procGetattr /* = 1 = NFSv4 COMPOUND */, nil)
	time.Sleep(100 * time.Millisecond)
	t.Logf("PROBE W4: NFS v4 proc 1 (COMPOUND) -> err=%v; records that reached the server=%d", err, got.Load())
	if !errors.Is(err, ErrReadOnly) || got.Load() != 0 {
		t.Errorf("DEFECT W4: an NFSv4 COMPOUND call (version 4, procedure 1) passes the read-only allow-list and reaches the server (%d records)", got.Load())
	}
}

// writeTap records how many bytes each failed Write had sent.
type writeTap struct {
	net.Conn
	zero, partial atomic.Int64
}

func (w *writeTap) Write(b []byte) (int, error) {
	n, err := w.Conn.Write(b)
	if err != nil {
		if n == 0 {
			w.zero.Add(1)
		} else {
			w.partial.Add(1)
		}
	}
	return n, err
}

// W7: one caller's context ending while it holds the write slot fails the whole SHARED connection, so every
// other call pipelined on it fails as well, even when the interrupted Write had sent nothing (n == 0, the
// stream is intact and there is no half record to protect).
func TestWF24ProbeW7OneCancelledCallerFailsTheSharedConnection(t *testing.T) {
	addr := rawServer(t, func(conn, call int, rec []byte) [][]byte { return [][]byte{getattrOK(binary.BigEndian.Uint32(rec))} })
	var conns, killed, zeroKills, otherFailures, bCalls int64
	for trial := 0; trial < 40 && killed == 0; trial++ {
		nc, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		tap := &writeTap{Conn: nc}
		rc := newRPCConn(tap, authSysCred{}, 0, uint32(trial)<<20)
		conns++
		stop := make(chan struct{})
		var aErr atomic.Value
		done := make(chan struct{})
		go func() { // caller A: ordinary calls with a context that never ends
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := rc.call(bg, time.Second, progNFS, versNFS, procGetattr, nil); err != nil {
					aErr.Store(err)
					return
				}
			}
		}()
		for i := 0; i < 3000 && !rc.isClosed(); i++ { // caller B: calls whose context is cancelled concurrently
			ctx, cancel := context.WithCancel(bg)
			go cancel()
			_, _ = rc.call(ctx, time.Second, progNFS, versNFS, procGetattr, nil)
			bCalls++
		}
		close(stop)
		<-done
		if rc.isClosed() {
			killed++
			if tap.zero.Load() > 0 && tap.partial.Load() == 0 {
				zeroKills++
			}
			if e, _ := aErr.Load().(error); e != nil {
				otherFailures++
				t.Logf("PROBE W7 trial %d: connection failed by a cancelled caller: %v; caller A failed with %v; interrupted writes: %d with 0 bytes, %d partial", trial, rc.connErr(), e, tap.zero.Load(), tap.partial.Load())
			}
		}
		rc.close()
	}
	t.Logf("PROBE W7: connections=%d, cancelled calls=%d, connections failed by a cancellation=%d (of which every interrupted write had sent 0 bytes: %d), other callers failed=%d", conns, bCalls, killed, zeroKills, otherFailures)
	if bCalls < 1000 {
		t.Fatalf("instrument blind: only %d cancelled calls", bCalls)
	}
	if zeroKills > 0 {
		t.Errorf("DEFECT W7: a cancellation whose Write sent 0 bytes failed the shared connection (%d times); %d other in-flight callers failed with it", zeroKills, otherFailures)
	}
}
