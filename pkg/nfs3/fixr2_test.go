package nfs3

// Regression tests added with the second-round fix of the WF19 review findings (constitution
// 11.4.276, one convergence pass). Each test names the finding it closes. The reviewer's own probes
// and killers live in review_probes_test.go and review_killers_test.go; this file holds the
// tests the fixes needed beyond them (a probe shows the defect, these pin the mechanism).

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ---- S1: hostile READDIRPLUS paging terminates ----

// hostileListing makes every READDIRPLUS answer with pages built by page(n), n = 0,1,2 ... never EOF.
func hostileListing(s *fakeServer, calls *atomic.Int64, page func(n int64) (names []string, cookies []uint64)) {
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc != procReaddirplus {
				return reply
			}
			n := calls.Add(1) - 1
			names, cookies := page(n)
			var e encoder
			e.u32(0)
			e.boolean(false)
			e.fixed(make([]byte, 8))
			for i, nm := range names {
				e.boolean(true)
				e.u64(uint64(900 + i))
				e.str(nm)
				e.u64(cookies[i])
				e.boolean(true)
				e.fattr(sampleAttr())
				e.boolean(false)
			}
			e.boolean(false)
			e.boolean(false) // never EOF
			return e.b
		}
	})
}

func TestListingHostilePagesTerminate(t *testing.T) {
	cases := []struct {
		name string
		page func(n int64) ([]string, []uint64)
		max  int64 // most READDIRPLUS calls the client may make before it must have stopped
	}{
		{"cookie cycle 5,6,5", func(n int64) ([]string, []uint64) {
			return []string{"x"}, []uint64{[]uint64{5, 6, 5, 6, 5, 6, 5, 6}[n%8]}
		}, 6},
		{"dots only with ever advancing cookies", func(n int64) ([]string, []uint64) {
			return []string{".", ".."}, []uint64{uint64(2*n + 1), uint64(2*n + 2)}
		}, 6},
		{"empty page", func(n int64) ([]string, []uint64) { return nil, nil }, 3},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeServer(t)
			c := connected(t, s, nil)
			var calls atomic.Int64
			hostileListing(s, &calls, tc.page)
			ctx, cancel := context.WithTimeout(bg, 5*time.Second)
			defer cancel()
			_, err := c.ListDirectory(ctx, "/docs")
			if !errors.Is(err, ErrNotProgressing) {
				t.Fatalf("want ErrNotProgressing, got %v after %d calls", err, calls.Load())
			}
			if n := calls.Load(); n > tc.max {
				t.Errorf("%d READDIRPLUS calls before giving up, want at most %d", n, tc.max)
			}
		})
	}
	// Advancing cookies with a real entry on every page is bounded by MaxEntries.
	t.Run("advancing cookies, endless real entries", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, func(c *Config) { c.MaxEntries = 40 })
		var calls atomic.Int64
		hostileListing(s, &calls, func(n int64) ([]string, []uint64) { return []string{"same"}, []uint64{uint64(n + 1)} })
		ctx, cancel := context.WithTimeout(bg, 5*time.Second)
		defer cancel()
		_, err := c.ListDirectory(ctx, "/docs")
		if err == nil || !strings.Contains(err.Error(), "more than 40 entries") {
			t.Fatalf("want the MaxEntries error, got %v after %d calls", err, calls.Load())
		}
		if n := calls.Load(); n > 45 {
			t.Errorf("%d READDIRPLUS calls for MaxEntries=40", n)
		}
	})
}

// ---- S2 / S3: adaptive read-ahead ----

func TestReadAheadStartsSmallAndRampsUp(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.FSInfoRTPref = 1 << 20 })
	s.mk(s.root, "huge.bin", TypeRegular, make([]byte, 16<<20))
	c := connected(t, s, nil)
	var sent atomic.Int64
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(p uint32, r []byte) []byte {
			if p == procRead {
				sent.Add(int64(len(r)))
			}
			return r
		}
	})
	// A header probe: one small Read, then Close, moves one small chunk, not a window of megabytes.
	r, err := c.ReadFile(bg, "/huge.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	time.Sleep(300 * time.Millisecond)
	if got := sent.Load(); got > 2*firstReadChunk {
		t.Errorf("a 16-byte read moved %d reply bytes, want at most %d", got, 2*firstReadChunk)
	}
	// A sequential full read still reaches the full chunk size and a pipeline.
	s.maxReadCount.Store(0)
	s.maxInflight.Store(0)
	s.set(func(o *fakeOpts) { o.Shuffle = true }) // the test server handles requests concurrently only in this mode
	got := readAll(t, c, "/huge.bin")
	if len(got) != 16<<20 {
		t.Fatalf("read %d bytes", len(got))
	}
	if m := s.maxReadCount.Load(); m != 1<<20 {
		t.Errorf("largest READ %d, want the 1 MiB ceiling to be reached", m)
	}
	if m := s.maxInflight.Load(); m < 2 {
		t.Errorf("max in-flight READs %d: no pipelining after the ramp", m)
	}
}

func TestReadRangeNeverReadsPastTheRange(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.FSInfoRTPref = 1 << 20 })
	s.mk(s.root, "huge.bin", TypeRegular, bytes.Repeat([]byte("0123456789abcdef"), 1<<20)) // 16 MiB
	c := connected(t, s, nil)
	var sent atomic.Int64
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(p uint32, r []byte) []byte {
			if p == procRead {
				sent.Add(int64(len(r)))
			}
			return r
		}
	})
	for _, tc := range []struct{ off, n int64 }{{0, 100}, {5000, 1}, {1<<20 - 5, 70000}, {16<<20 - 10, 100}} {
		sent.Store(0)
		b, err := c.ReadRange(bg, "/huge.bin", tc.off, tc.n)
		if err != nil {
			t.Fatal(err)
		}
		want := tc.n
		if tc.off+want > 16<<20 {
			want = 16<<20 - tc.off
		}
		if int64(len(b)) != want {
			t.Fatalf("range %+v returned %d bytes, want %d", tc, len(b), want)
		}
		if !bytes.Equal(b, bytes.Repeat([]byte("0123456789abcdef"), 1<<20)[tc.off:tc.off+want]) {
			t.Errorf("range %+v: wrong bytes", tc)
		}
		time.Sleep(100 * time.Millisecond)
		if got := sent.Load(); got > want+1024 {
			t.Errorf("range %+v moved %d reply bytes for %d wanted", tc, got, want)
		}
	}
}

func TestShortReadsAreAvoidedWhenFSInfoSaysSo(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.MaxRead = 4096; o.FSInfoRTMax = 4096; o.FSInfoRTPref = 4096 })
	c := connected(t, s, func(c *Config) { c.ReadSize = 65536 })
	before := s.procs[procRead].Load()
	got := readAll(t, c, "/big.bin")
	if !bytes.Equal(got, s.root.kids[3].data) {
		t.Fatal("data differs")
	}
	n := s.procs[procRead].Load() - before
	useful := int64((len(got) + 4095) / 4096)
	if n > useful+8 {
		t.Errorf("%d READs for %d useful replies although FSINFO rtmax is 4096", n, useful)
	}
	if m := s.maxReadCount.Load(); m > 4096 {
		t.Errorf("a READ of %d bytes was requested, above rtmax 4096", m)
	}
}

func TestShortReadKeepsTheWindowAndShrinksTheChunk(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.MaxRead = 5000 }) // FSINFO still advertises 1 MiB: the short replies are a surprise
	c := connected(t, s, func(c *Config) { c.ReadSize = 65536 })
	before := s.procs[procRead].Load()
	got := readAll(t, c, "/big.bin")
	if !bytes.Equal(got, s.root.kids[3].data) {
		t.Fatal("data differs")
	}
	n := s.procs[procRead].Load() - before
	useful := int64((len(got) + 4999) / 5000)
	if n > useful+useful/4+16 {
		t.Errorf("%d READs for %d useful replies: short replies are discarding read-ahead", n, useful)
	}
}

// ---- S4: a failed READ never turns into a silent end of file ----

func TestErrorOnLaterChunkThenSeekReadsTheRest(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.MaxRetries = -1; c.ReadSize = 4096 })
	want := s.root.kids[3].data
	f, err := c.OpenSeekable(bg, "/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := io.ReadFull(f, make([]byte, 10000)); err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	fail.Store(true)
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, r []byte) []byte {
			if proc == procRead && fail.Load() {
				var e encoder
				e.u32(NFS3ErrIO)
				e.boolean(false)
				return e.b
			}
			return r
		}
	})
	var rerr error
	for rerr == nil {
		_, rerr = f.Read(make([]byte, 4096))
	}
	if rerr == io.EOF {
		t.Fatal("the injected NFS3ERR_IO surfaced as EOF")
	}
	fail.Store(false)
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(rest, want[pos:]) {
		t.Fatalf("after the error and Seek(0, SeekCurrent) at %d: read %d bytes (want %d), err %v", pos, len(rest), len(want)-int(pos), err)
	}
}

// ---- S5 / S16: configuration limits ----

func TestConfigLimitsAreValidated(t *testing.T) {
	base := Config{Host: "h", Export: "/x"}
	for name, mod := range map[string]func(*Config){
		"MaxRecord below the minimum":        func(c *Config) { c.MaxRecord = 1000 },
		"DirMaxCount does not fit MaxRecord": func(c *Config) { c.MaxRecord = 65536; c.DirMaxCount = 65536 },
		"ReadSize does not fit MaxRecord":    func(c *Config) { c.MaxRecord = 65536; c.ReadSize = 65536 },
	} {
		cfg := base
		mod(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted the configuration", name)
		}
	}
	cfg := base
	cfg.MaxRecord = 65536
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("a small MaxRecord with default sizes must be usable: %v", err)
	}
	if int(c.cfg.DirMaxCount)+recordHeadroom > 65536 {
		t.Errorf("default DirMaxCount %d does not fit a 64 KiB record", c.cfg.DirMaxCount)
	}
}

func TestSmallMaxRecordStillReadsAndLists(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.FSInfoRTPref = 1 << 20 })
	c := connected(t, s, func(c *Config) { c.MaxRecord = 40000; c.MaxRetries = -1 })
	if got := readAll(t, c, "/big.bin"); !bytes.Equal(got, s.root.kids[3].data) {
		t.Fatal("data differs with a 40000-byte record cap")
	}
	l, err := c.ListDirectory(bg, "/many")
	if err != nil || len(l) != 250 {
		t.Fatalf("listing with a 40000-byte record cap: %d entries, %v", len(l), err)
	}
}

func TestNegativeMaxRetriesCallBudgetIsPositive(t *testing.T) {
	for _, mr := range []int{-1, -2, -100, 0, 1, 5, 1 << 30} {
		c, err := New(Config{Host: "h", Export: "/x", MaxRetries: mr})
		if err != nil {
			t.Fatal(err)
		}
		if b := c.callBudget(); b < c.cfg.CallTimeout || b <= 0 {
			t.Errorf("MaxRetries=%d: call budget %v", mr, b)
		}
	}
}

func TestFattrSizeAtTheSignedLimit(t *testing.T) {
	enc := func(size uint64) []byte {
		a := sampleAttr()
		a.Size = size
		var e encoder
		e.fattr(a)
		return e.b
	}
	if a, err := newDecoder(enc(1<<63 - 1)).fattr(); err != nil || a.Size != 1<<63-1 {
		t.Fatalf("2^63-1 refused: %v", err)
	}
	for _, sz := range []uint64{1 << 63, 1<<63 + 1, ^uint64(0)} {
		if _, err := newDecoder(enc(sz)).fattr(); !errors.Is(err, ErrBadXDR) {
			t.Errorf("size %d accepted: %v", sz, err)
		}
	}
}

// ---- S6: the handle cache is bounded in time ----

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.t }
func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

func TestHandleCacheExpires(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	c.mu.Lock()
	c.now = clk.now
	c.cache = map[string]cacheEntry{"/": {h: c.root, at: clk.now()}}
	c.mu.Unlock()
	const deepFile = "/deep/a/b/c/leaf.txt"
	if _, err := c.GetFileInfo(bg, deepFile); err != nil {
		t.Fatal(err)
	}
	deep := findKid(s.root, "deep")
	s.mu.Lock()
	findKid(deep, "a").name = "moved" // another client: mv /deep/a /deep/moved, mkdir /deep/a
	s.mu.Unlock()
	s.mk(deep, "a", TypeDir, nil)

	// Control: inside the TTL the stale chain is still served. This is the documented bound; the
	// check proves the next one is decided by the clock and not by anything else.
	clk.advance(c.cfg.HandleCacheTTL / 2)
	if _, err := c.GetFileInfo(bg, deepFile); err != nil {
		t.Fatalf("inside the TTL the cached chain should still resolve: %v", err)
	}
	clk.advance(c.cfg.HandleCacheTTL)
	if _, err := c.GetFileInfo(bg, deepFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("after the TTL the renamed directory must no longer be reachable under its old path: %v", err)
	}
}

func TestHandleCacheDisabledWalksEveryTime(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.HandleCacheTTL = -1 })
	for i := 0; i < 3; i++ {
		before := s.procs[procLookup].Load()
		if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil {
			t.Fatal(err)
		}
		if n := s.procs[procLookup].Load() - before; n != 5 {
			t.Fatalf("round %d: %d LOOKUPs, want 5 (no cached parents)", i, n)
		}
	}
}

func TestReplacedDirectoryDropsItsCachedDescendants(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.cached("/deep/a/b/c"); !ok {
		t.Fatal("setup: /deep/a/b/c was not cached")
	}
	c.remember("/deep/a", Handle("a-different-handle"))
	for _, p := range []string{"/deep/a/b", "/deep/a/b/c"} {
		if _, ok := c.cached(p); ok {
			t.Errorf("%s is still cached after its ancestor's handle changed", p)
		}
	}
	if _, ok := c.cached("/deep"); !ok {
		t.Error("an unrelated sibling/ancestor entry was dropped")
	}
}

// ---- S15: a root handle that went stale is mounted again ----

func TestStaleRootHandleIsRemounted(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	if _, err := c.GetFileInfo(bg, "/ünï.txt"); err != nil {
		t.Fatal(err)
	}
	mnt0 := s.mntProcs[procMnt].Load()
	s.mu.Lock() // the server re-exports: the root gets a new file handle, the old one is stale
	delete(s.byID, s.root.id)
	s.root.id = 9999
	s.byID[9999] = s.root
	s.mu.Unlock()
	fi, err := c.GetFileInfo(bg, "/ünï.txt")
	if err != nil || fi.Size != int64(len("unicode name")) {
		t.Fatalf("after the root handle changed: %+v %v", fi, err)
	}
	if n := s.mntProcs[procMnt].Load() - mnt0; n != 1 {
		t.Errorf("%d MNT calls for the recovery, want exactly 1", n)
	}
	if _, err := c.ListDirectory(bg, "/"); err != nil {
		t.Errorf("listing the new root: %v", err)
	}
}

func TestRemountFailureReturnsTheOriginalStaleError(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.mu.Lock()
	delete(s.byID, s.root.id)
	s.mu.Unlock()
	s.set(func(o *fakeOpts) { o.MountStatus = mnt3ErrAcces })
	_, err := c.GetFileInfo(bg, "/ünï.txt")
	var ne *NFSError
	if !errors.As(err, &ne) || ne.Status != NFS3ErrStale {
		t.Fatalf("want the original NFS3ERR_STALE, got %v", err)
	}
}

// ---- S13: JUKEBOX has its own, seconds-scale schedule ----

func TestJukeboxDefaultsAreSecondsScale(t *testing.T) {
	c, err := New(Config{Host: "h", Export: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.JukeboxBackoff < time.Second || c.cfg.JukeboxRetries < 3 {
		t.Errorf("JUKEBOX defaults %v x %d: far too short for spun-down storage", c.cfg.JukeboxBackoff, c.cfg.JukeboxRetries)
	}
	if c.cfg.RetryBackoff >= c.cfg.JukeboxBackoff {
		t.Errorf("the transport back-off (%v) is not shorter than the JUKEBOX back-off (%v)", c.cfg.RetryBackoff, c.cfg.JukeboxBackoff)
	}
}

func TestJukeboxWaitsOnItsOwnSchedule(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) {
		c.JukeboxRetries = 2
		c.JukeboxBackoff = 80 * time.Millisecond
		c.RetryBackoff = time.Millisecond
	})
	s.set(func(o *fakeOpts) { o.Jukebox = 2 })
	start := time.Now()
	if _, err := c.GetFileInfo(bg, "/docs"); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 200*time.Millisecond { // 80 + 160 ms, whatever RetryBackoff is
		t.Errorf("two JUKEBOX replies were answered after only %v", el)
	}
	// And the wait is cancellable.
	s.set(func(o *fakeOpts) { o.Jukebox = 100 })
	ctx, cancel := context.WithTimeout(bg, 100*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err := c.GetFileInfo(ctx, "/docs/a.txt")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Errorf("JUKEBOX wait ignored the context: %v after %v", err, time.Since(start))
	}
}

// ---- S8: a vanished entry is skipped and counted ----

func TestVanishedEntryIsCounted(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.OmitAttrs = true; o.OmitHandles = true })
	c := connected(t, s, nil)
	var n atomic.Int64
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc == procLookup && n.Add(1) == 3 {
				var e encoder
				e.u32(NFS3ErrNoEnt)
				e.boolean(false)
				return e.b
			}
			return reply
		}
	})
	l, err := c.ListDirectory(bg, "/docs")
	if err != nil || len(l) != 1 || l[0].Name != "a.txt" {
		t.Fatalf("%v %v", names(l), err)
	}
	if c.VanishedEntries() != 1 {
		t.Errorf("VanishedEntries = %d, want 1", c.VanishedEntries())
	}
	// Any other LOOKUP failure is still an error.
	n.Store(0)
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc == procLookup && n.Add(1) == 3 {
				var e encoder
				e.u32(NFS3ErrIO)
				e.boolean(false)
				return e.b
			}
			return reply
		}
	})
	if _, err := c.ListDirectory(bg, "/docs"); err == nil {
		t.Error("an NFS3ERR_IO during the attribute fallback was swallowed")
	}
}

// ---- S11: no mount record is left behind by a failed Connect ----

func TestFailedConnectAfterMountSendsUmnt(t *testing.T) {
	for name, mod := range map[string]func(*fakeOpts){
		"FSINFO refused (RPC auth error)": func(o *fakeOpts) { o.RPCDeny = 1 },
		"FSINFO garbage":                  func(o *fakeOpts) { o.Corrupt = func(p uint32, r []byte) []byte { return r[:2] } },
	} {
		mod := mod
		t.Run(name, func(t *testing.T) {
			s := newFakeServer(t)
			s.set(mod)
			cfg := s.cfg()
			cfg.MaxRetries = -1
			c, _ := New(cfg)
			if err := c.Connect(bg); err == nil {
				t.Fatal("Connect succeeded")
			}
			deadline := time.Now().Add(2 * time.Second)
			for s.mntProcs[procUmnt].Load() < s.mntProcs[procMnt].Load() && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if m, u := s.mntProcs[procMnt].Load(), s.mntProcs[procUmnt].Load(); m == 0 || u != m {
				t.Errorf("MNT=%d UMNT=%d: every successful MNT of a failed Connect needs its UMNT", m, u)
			}
		})
	}
}

func TestPrivilegedRetryUnmountsTheFailedFirstAttempt(t *testing.T) {
	s := newFakeServer(t)
	// The MOUNT service accepts everyone; the NFS service refuses the ordinary source port.
	s.set(func(o *fakeOpts) { o.RPCDeny = 1 })
	cfg := s.cfg()
	cfg.TryPrivilegedPort = true
	var privDials atomic.Int64
	cfg.Dial = func(ctx context.Context, network, addr string, privileged bool) (net.Conn, error) {
		var d net.Dialer
		if privileged {
			privDials.Add(1)
			s.set(func(o *fakeOpts) { o.RPCDeny = 0 }) // the "reserved" connection is accepted
		}
		return d.DialContext(ctx, network, addr)
	}
	c, _ := New(cfg)
	t.Cleanup(func() { _ = c.Disconnect(bg) })
	if err := c.Connect(bg); err != nil {
		t.Fatalf("the privileged retry should have succeeded: %v", err)
	}
	if privDials.Load() == 0 {
		t.Fatal("no privileged dial happened")
	}
	if m, u := s.mntProcs[procMnt].Load(), s.mntProcs[procUmnt].Load(); m != 2 || u != 1 {
		t.Errorf("MNT=%d UMNT=%d: want 2 MNT (both attempts) and 1 UMNT (the refused first attempt)", m, u)
	}
}

// ---- S12: the nfs-layer AccessError names the port that was refused ----

func TestNFSLayerAccessErrorNamesTheRealPort(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.RPCDeny = 1 })
	c, _ := New(s.cfg())
	err := c.Connect(bg)
	var ae *AccessError
	if !errors.As(err, &ae) || ae.Layer != "nfs" {
		t.Fatalf("want an nfs-layer AccessError, got %v", err)
	}
	if ae.SourcePort < 1024 {
		t.Fatalf("SourcePort %d: not a real ephemeral port", ae.SourcePort)
	}
	if !strings.Contains(ae.Error(), "source port") || !strings.Contains(ae.Error(), itoa(ae.SourcePort)) {
		t.Errorf("the message does not state the port: %v", ae)
	}
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		if n /= 10; n == 0 {
			break
		}
	}
	return string(b[i:])
}

// ---- S14: a blocked write honours the context ----

// blackhole accepts connections and never reads from them, so a large write stops when the kernel
// buffers are full.
func blackhole(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
	})
	return ln.Addr().String()
}

func TestBlockedWriteHonoursTheContext(t *testing.T) {
	addr := blackhole(t)
	big := make([]byte, 32<<20)
	// Control: with no context to cancel, the same call blocks until the write deadline, which
	// proves the server really stops the stream (an instrument that cannot block proves nothing).
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	rc := newRPCConn(nc, authSysCred{}, 0, 1)
	start := time.Now()
	_, err = rc.call(bg, 700*time.Millisecond, progNFS, versNFS, procRead, big)
	rc.close()
	if el := time.Since(start); err == nil || el < 500*time.Millisecond {
		t.Fatalf("control: the 32 MiB write was not blocked (err=%v after %v)", err, el)
	}

	nc2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	rc2 := newRPCConn(nc2, authSysCred{}, 0, 1)
	defer rc2.close()
	ctx, cancel := context.WithTimeout(bg, 800*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err = rc2.call(ctx, 20*time.Second, progNFS, versNFS, procRead, big)
	el := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the context error, got %v", err)
	}
	if el > 3*time.Second {
		t.Errorf("a cancelled caller stayed blocked in the write for %v (write deadline was 20s)", el)
	}
	if !rc2.isClosed() {
		t.Error("an interrupted write left half a record on the stream but the connection was kept")
	}
}

func TestWaitingForTheWriteSlotHonoursTheContext(t *testing.T) {
	addr := blackhole(t)
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	rc := newRPCConn(nc, authSysCred{}, 0, 1)
	big := make([]byte, 32<<20)
	hold := make(chan error, 1)
	go func() {
		_, err := rc.call(bg, 3*time.Second, progNFS, versNFS, procRead, big) // holds the write slot
		hold <- err
	}()
	time.Sleep(300 * time.Millisecond)
	ctx, cancel := context.WithTimeout(bg, 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = rc.call(ctx, 3*time.Second, progNFS, versNFS, procNull, nil)
	el := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) || el > time.Second {
		t.Errorf("a caller waiting for the write slot ignored its context: %v after %v", err, el)
	}
	rc.close()
	select {
	case <-hold:
	case <-time.After(5 * time.Second):
		t.Fatal("the blocked writer did not end after close")
	}
}

// ---- T2: the runtime allow-list at the single choke point ----

func TestRuntimeAllowListRefusesWritesBeforeAnyByteIsSent(t *testing.T) {
	var got atomic.Int64
	addr := rawServer(t, func(conn, call int, rec []byte) [][]byte { got.Add(1); return nil })
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	rc := newRPCConn(nc, authSysCred{}, 0, 1)
	defer rc.close()
	// SETATTR, WRITE, CREATE, MKDIR, SYMLINK, MKNOD, REMOVE, RMDIR, RENAME, LINK, COMMIT.
	for _, proc := range []uint32{2, 7, 8, 9, 10, 11, 12, 13, 14, 15, 21} {
		if _, err := rc.call(bg, time.Second, progNFS, versNFS, proc, nil); !errors.Is(err, ErrReadOnly) {
			t.Errorf("NFS procedure %d: want ErrReadOnly, got %v", proc, err)
		}
	}
	// A procedure number that is only allowed for another program is refused as well.
	if _, err := rc.call(bg, time.Second, progMount, versMount, 21, nil); !errors.Is(err, ErrReadOnly) {
		t.Errorf("MOUNT procedure 21: %v", err)
	}
	if _, err := rc.call(bg, time.Second, progPortmap, versPortmap, 4, nil); !errors.Is(err, ErrReadOnly) { // PMAPPROC_SET-class
		t.Errorf("portmap procedure 4: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := got.Load(); n != 0 {
		t.Fatalf("%d records reached the server for refused procedures", n)
	}
	// Control: an allowed procedure does reach it, so the zero above is not a blind server.
	ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
	defer cancel()
	_, _ = rc.call(ctx, time.Second, progNFS, versNFS, procGetattr, nil)
	if got.Load() != 1 {
		t.Fatalf("control: the allowed GETATTR did not reach the server (%d)", got.Load())
	}
	// And through the client: a literal procedure number at callNFS is refused with nothing sent.
	s := newFakeServer(t)
	c := connected(t, s, nil)
	before := s.writeProcCalls()
	if _, err := c.callNFS(bg, 21, nil, "COMMIT"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("callNFS(21): %v", err)
	}
	if s.writeProcCalls() != before {
		t.Error("a write-class procedure reached the server")
	}
}

// ---- S17: xids never repeat across connections of one client ----

func TestXidsAreUniqueAcrossManyReconnects(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	for i := 0; i < 5; i++ {
		c.mu.Lock()
		n := c.nfs
		c.mu.Unlock()
		c.dropConn(n)
		if err := c.TestConnection(bg); err != nil {
			t.Fatal(err)
		}
	}
	s.xidMu.Lock()
	defer s.xidMu.Unlock()
	seen := map[uint32]bool{}
	for _, x := range s.xidLog {
		if seen[x] {
			t.Fatalf("xid %d used twice", x)
		}
		seen[x] = true
	}
	if len(s.xidLog) < 12 {
		t.Fatalf("instrument blind: %d NFS calls logged", len(s.xidLog))
	}
}

// ---- tests that keep each layer of a defence in depth individually load-bearing ----

// A08b: dropping the handle cache must be enough for a deleted-and-recreated parent; the
// remount of S15 is a second, later step and must not be what rescues this case.
func TestKillA08bStaleParentNeedsNoRemount(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil {
		t.Fatal(err)
	}
	deep := kfind(s.root, "deep")
	var kept []*fnode
	for _, k := range deep.kids {
		if k.name != "a" {
			kept = append(kept, k)
		}
	}
	var drop func(n *fnode)
	drop = func(n *fnode) {
		delete(s.byID, n.id)
		for _, k := range n.kids {
			drop(k)
		}
	}
	drop(kfind(deep, "a"))
	deep.kids = kept
	d := deep
	for _, n := range []string{"a", "b", "c"} {
		d = s.mk(d, n, TypeDir, nil)
	}
	s.mk(d, "leaf.txt", TypeRegular, []byte("new leaf"))
	mnt0 := s.mntProcs[procMnt].Load()
	if fi, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil || fi.Size != 8 {
		t.Fatalf("%+v %v", fi, err)
	}
	if n := s.mntProcs[procMnt].Load() - mnt0; n != 0 {
		t.Errorf("%d MNT calls: the first recovery step (drop the cache) did not suffice", n)
	}
}

// A10b: the 1 MiB ceiling holds even when the server advertises a larger rtmax.
func TestKillA10bReadSizeCappedAgainstALargeRTMax(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.FSInfoRTMax = 8 << 20; o.FSInfoRTPref = 8 << 20 })
	s.mk(s.root, "huge.bin", TypeRegular, make([]byte, 24<<20)) // large enough for the ramp to reach any ceiling
	for _, rs := range []uint32{0, 4 << 20} {
		s.maxReadCount.Store(0)
		c := connected(t, s, func(c *Config) { c.ReadSize = rs })
		_ = readAll(t, c, "/huge.bin")
		if m := s.maxReadCount.Load(); m > 1<<20 {
			t.Fatalf("ReadSize=%d: READ of %d bytes", rs, m)
		}
	}
}

// S1: the first page that does not advance ends the listing (no second request for the same cookie).
func TestListingStopsAtTheFirstNonAdvancingPage(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	var calls atomic.Int64
	hostileListing(s, &calls, func(n int64) ([]string, []uint64) { return []string{"x"}, []uint64{1} })
	if _, err := c.ListDirectory(bg, "/docs"); !errors.Is(err, ErrNotProgressing) {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("%d READDIRPLUS calls, want exactly 2 (cookie 0, then cookie 1 which came back unchanged)", n)
	}
}

// S1/S8: entries that vanish one by one must not let a hostile server keep the loop alive
// without ever growing the result.
func TestListingOfOnlyVanishingEntriesTerminates(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.MaxEntries = 30; c.MaxRetries = -1 })
	var calls atomic.Int64
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			switch proc {
			case procReaddirplus:
				n := calls.Add(1)
				var e encoder
				e.u32(0)
				e.boolean(false)
				e.fixed(make([]byte, 8))
				e.boolean(true)
				e.u64(77)
				e.str("ghost")
				e.u64(uint64(n)) // an ever advancing cookie
				e.boolean(false) // no attributes: the LOOKUP fallback runs
				e.boolean(false) // no handle
				e.boolean(false)
				e.boolean(false) // never EOF
				return e.b
			case procLookup:
				if calls.Load() == 0 { // the path walk before the first page is answered normally
					return reply
				}
				var e encoder
				e.u32(NFS3ErrNoEnt)
				e.boolean(false)
				return e.b
			}
			return reply
		}
	})
	ctx, cancel := context.WithTimeout(bg, 10*time.Second)
	defer cancel()
	_, err := c.ListDirectory(ctx, "/docs")
	if !errors.Is(err, ErrNotProgressing) {
		t.Fatalf("want ErrNotProgressing from the page cap, got %v after %d calls", err, calls.Load())
	}
	if n := calls.Load(); n > 40 {
		t.Errorf("%d pages for MaxEntries=30", n)
	}
}

// S3: after a short reply the READs that follow are sized to what the server really returns.
func TestShortReplyShrinksLaterRequests(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.MaxRead = 5000 })
	c := connected(t, s, func(c *Config) { c.ReadSize = 65536 })
	_ = readAll(t, c, "/big.bin")
	s.xidMu.Lock()
	log := append([]uint32(nil), s.readLog...)
	s.xidMu.Unlock()
	if len(log) < 100 {
		t.Fatalf("instrument blind: %d READs logged", len(log))
	}
	for i, n := range log[len(log)-50:] {
		if n > 5000 {
			t.Fatalf("READ #%d near the end still asks for %d bytes although every reply was cut at 5000", len(log)-50+i, n)
		}
	}
}

// S4, both layers: the failing read drops the read-ahead itself, and Seek drops it again
// whenever an error is pending, even to the current position.
func TestFailedReadDropsReadAhead(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.MaxRetries = -1 })
	f, err := c.OpenSeekable(bg, "/docs/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, r []byte) []byte {
			if proc == procRead {
				var e encoder
				e.u32(NFS3ErrIO)
				e.boolean(false)
				return e.b
			}
			return r
		}
	})
	if _, err := f.Read(make([]byte, 4)); err == nil {
		t.Fatal("expected the injected error")
	}
	r := f.(*fileReader)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.q) != 0 || r.next != r.pos {
		t.Errorf("after a failed READ: %d futures queued, next=%d pos=%d", len(r.q), r.next, r.pos)
	}
}

func TestSeekToTheSamePositionWithAPendingErrorResets(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	f, err := c.OpenSeekable(bg, "/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := f.(*fileReader)
	r.mu.Lock()
	r.err = errors.New("sticky")
	r.q = []*future{{off: 0, count: 1, ch: make(chan chunkResult, 1)}}
	r.next = 1
	r.mu.Unlock()
	if _, err := r.Seek(0, io.SeekCurrent); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil || len(r.q) != 0 || r.next != 0 {
		t.Errorf("Seek(0, SeekCurrent) with a pending error left err=%v queued=%d next=%d", r.err, len(r.q), r.next)
	}
}

// S7, both layers.
func TestPrivilegedModeDoesNotLeakIntoLaterCalls(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PortOK = func(int) bool { return false } })
	cfg := s.cfg()
	cfg.TryPrivilegedPort = true
	var priv atomic.Int64
	cfg.Dial = func(ctx context.Context, network, addr string, privileged bool) (net.Conn, error) {
		if privileged {
			priv.Add(1)
			return nil, ErrPrivilegedPortUnavailable
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	c, _ := New(cfg)
	if err := c.Connect(bg); !errors.Is(err, ErrPrivilegedPortUnavailable) {
		t.Fatalf("setup: %v", err)
	}
	// Layer 1: right after the failed Connect an unrelated call (Exports) must dial ordinarily.
	p0 := priv.Load()
	s.set(func(o *fakeOpts) { o.PortOK = nil })
	if _, err := c.Exports(bg); err != nil {
		t.Fatalf("Exports after a failed privileged Connect: %v", err)
	}
	if priv.Load() != p0 {
		t.Error("Exports dialled from a privileged port after the privileged attempt had failed")
	}
	// Layer 2: a successful privileged Connect does not make the NEXT Connect start privileged.
	s.set(func(o *fakeOpts) { o.PortOK = func(int) bool { return false } })
	cfg2 := s.cfg()
	cfg2.TryPrivilegedPort = true
	var dials []bool
	var mu sync.Mutex
	cfg2.Dial = func(ctx context.Context, network, addr string, privileged bool) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, privileged)
		mu.Unlock()
		if privileged {
			s.set(func(o *fakeOpts) { o.PortOK = nil }) // the reserved connection is accepted
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	c2, _ := New(cfg2)
	t.Cleanup(func() { _ = c2.Disconnect(bg) })
	if err := c2.Connect(bg); err != nil {
		t.Fatalf("privileged connect: %v", err)
	}
	mu.Lock()
	dials = nil
	mu.Unlock()
	if err := c2.Connect(bg); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dials) == 0 || dials[0] {
		t.Errorf("a new Connect did not start from an ordinary port: %v", dials)
	}
}

// S3: ONE short reply must cost one extra READ (the gap), not the read-ahead window.
func TestOneShortReplyCostsOnlyTheGap(t *testing.T) {
	count := func(shortAt int) (int64, []byte) {
		s := newFakeServer(t)
		c := connected(t, s, func(c *Config) { c.MaxPipeline = 8 })
		s.set(func(o *fakeOpts) { o.ShortAtRead = shortAt })
		before := s.procs[procRead].Load()
		got := readAll(t, c, "/big.bin")
		time.Sleep(100 * time.Millisecond)
		return s.procs[procRead].Load() - before, got
	}
	base, data := count(0)
	if base < 20 {
		t.Fatalf("instrument blind: the baseline read took %d READs", base)
	}
	n, got := count(6)
	if !bytes.Equal(got, data) {
		t.Fatal("data differs after a short reply")
	}
	// The gap READ, plus the smaller chunks of the restarted ramp; discarding the read-ahead
	// window instead would cost another 8 or so.
	if n < base+1 || n > base+4 {
		t.Errorf("%d READs with one short reply, want %d to %d (baseline %d plus the gap READ and a restarted ramp)", n, base+1, base+4, base)
	}
}

// A04 made deterministic: a refused or reset connection (net.OpError from the dial, not an EOF on
// an established stream) is a transient failure and is retried on a new connection.
func TestDialFailureIsRetried(t *testing.T) {
	s := newFakeServer(t)
	var failNext atomic.Bool
	var failed atomic.Int64
	c := connected(t, s, func(c *Config) {
		c.Dial = func(ctx context.Context, network, addr string, privileged bool) (net.Conn, error) {
			if failNext.CompareAndSwap(true, false) {
				failed.Add(1)
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
	})
	c.mu.Lock()
	n := c.nfs
	c.mu.Unlock()
	c.dropConn(n)
	failNext.Store(true)
	if _, err := c.GetFileInfo(bg, "/docs"); err != nil {
		t.Fatalf("a refused dial was not retried: %v", err)
	}
	if failed.Load() != 1 {
		t.Fatalf("instrument blind: the injected dial failure happened %d times", failed.Load())
	}
	if !transient(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}) {
		t.Error("net.OpError is not classified as transient")
	}
	if transient(context.Canceled) || transient(&NFSError{Op: "LOOKUP", Status: NFS3ErrNoEnt}) {
		t.Error("a permanent error is classified as transient")
	}
}
