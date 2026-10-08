package nfs3

// Independent-review probes, adopted verbatim from the WF19 review of this package
// (scratchpad/WF19-nfs3-artifacts/review_probe_test.go), as permanent regression tests.
// Each probe asserts the CORRECT behaviour; a FAIL demonstrates a defect.
// Lines starting with "PROBE" are the captured measurements. Deviations from the reviewer's
// text are marked ADOPTED-CHANGE and are limited to (a) the three probes that only logged
// (P12, P14, P15), which now assert the fixed behaviour, and (b) the goroutine name of the
// read-ahead worker in P17, which moved from topUp to issue, and (c) a Disconnect cleanup in P3,
// whose second Connect now succeeds.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func runtimeStack(b []byte) int         { return runtime.Stack(b, true) }
func splitGoroutines(s string) []string { return strings.Split(s, "\n\n") }
func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func findKid(d *fnode, name string) *fnode {
	for _, k := range d.kids {
		if k.name == name {
			return k
		}
	}
	return nil
}

// P1: a server that keeps answering READDIRPLUS with entries whose cookies never
// advance and never sets EOF. ErrNotProgressing is documented for exactly this.
func TestProbeP1ListingNonAdvancingCookie(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
	}{
		{"dots only", []string{".", ".."}},
		{"same real entry", []string{"x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeServer(t)
			c := connected(t, s, nil)
			var calls atomic.Int64
			s.set(func(o *fakeOpts) {
				o.Corrupt = func(proc uint32, reply []byte) []byte {
					if proc != procReaddirplus {
						return reply
					}
					calls.Add(1)
					var e encoder
					e.u32(0)
					e.boolean(false)
					e.fixed(make([]byte, 8))
					for i, n := range tc.names {
						e.boolean(true)
						e.u64(uint64(900 + i))
						e.str(n)
						e.u64(uint64(i + 1)) // the same cookies on every page
						e.boolean(true)
						e.fattr(sampleAttr())
						e.boolean(false)
					}
					e.boolean(false)
					e.boolean(false) // never EOF
					return e.b
				}
			})
			ctx, cancel := context.WithTimeout(bg, 3*time.Second)
			defer cancel()
			start := time.Now()
			_, err := c.ListDirectory(ctx, "/docs")
			t.Logf("PROBE P1 %s: err=%v after %v; READDIRPLUS calls=%d", tc.name, err, time.Since(start).Round(time.Millisecond), calls.Load())
			if !errors.Is(err, ErrNotProgressing) {
				t.Errorf("DEFECT P1: non-advancing READDIRPLUS not detected; the listing only ended because of the caller's 3 s deadline (%d RPCs)", calls.Load())
			}
		})
	}
}

// P2: MaxRetries is documented as "negative means none". -1 works; -2 must too.
func TestProbeP2NegativeMaxRetries(t *testing.T) {
	s := newFakeServer(t)
	for _, mr := range []int{-1, -2, -5} {
		cfg := s.cfg()
		cfg.MaxRetries = mr
		c, _ := New(cfg)
		err := c.Connect(bg)
		t.Logf("PROBE P2: MaxRetries=%d Connect err=%v", mr, err)
		if err != nil {
			t.Errorf("DEFECT P2: MaxRetries=%d (documented: negative disables retries) makes Connect fail: %v", mr, err)
		}
		_ = c.Disconnect(bg)
	}
}

// P3: after a failed privileged retry the client stays in privileged mode forever.
func TestProbeP3PrivilegedModeSticksAfterFailure(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PortOK = func(int) bool { return false } })
	cfg := s.cfg()
	cfg.TryPrivilegedPort = true
	var priv, plain atomic.Int64
	cfg.Dial = func(ctx context.Context, network, addr string, privileged bool) (net.Conn, error) {
		if privileged {
			priv.Add(1)
			return nil, ErrPrivilegedPortUnavailable
		}
		plain.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	c, _ := New(cfg)
	// ADOPTED-CHANGE: the second Connect now succeeds, so the client must be closed at the end
	// (otherwise its connection is a live goroutine that P17's process-wide census would count).
	t.Cleanup(func() { _ = c.Disconnect(bg) })
	if err := c.Connect(bg); !errors.Is(err, ErrPrivilegedPortUnavailable) {
		t.Fatalf("setup: %v", err)
	}
	s.set(func(o *fakeOpts) { o.PortOK = nil }) // operator sets the export to 'insecure'
	p0, q0 := plain.Load(), priv.Load()
	err := c.Connect(bg)
	t.Logf("PROBE P3: second Connect err=%v; plain dials=%d privileged dials=%d", err, plain.Load()-p0, priv.Load()-q0)
	if err != nil {
		t.Errorf("DEFECT P3: a later Connect on the same Client never tries an unprivileged port again: %v", err)
	}
}

// P4: ReadRange(n=100) against a server with rtpref = 1 MiB.
func TestProbeP4ReadRangeReadAmplification(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.FSInfoRTPref = 1 << 20 })
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
	before := s.procs[procRead].Load()
	b, err := c.ReadRange(bg, "/big.bin", 0, 100)
	time.Sleep(500 * time.Millisecond)
	n := s.procs[procRead].Load() - before
	t.Logf("PROBE P4: ReadRange(n=100) returned %d bytes; server got %d READ calls and sent %d reply bytes (%.0fx)", len(b), n, sent.Load(), float64(sent.Load())/100)
	if err != nil || len(b) != 100 {
		t.Fatalf("%v %d", err, len(b))
	}
	if sent.Load() > 64<<10 {
		t.Errorf("DEFECT P4: a 100-byte ReadRange made the server read and send %d bytes", sent.Load())
	}
}

// P5: a server that answers every READ short (rtmax below the requested size).
func TestProbeP5ShortReadAmplification(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.MaxRead = 1000 })
	c := connected(t, s, func(c *Config) { c.ReadSize = 16384 })
	before := s.procs[procRead].Load()
	start := time.Now()
	got := readAll(t, c, "/big.bin")
	el := time.Since(start)
	time.Sleep(300 * time.Millisecond)
	n := s.procs[procRead].Load() - before
	useful := (len(got) + 999) / 1000
	t.Logf("PROBE P5: %d bytes in %v; %d READ calls for %d useful replies (%.1fx)", len(got), el.Round(time.Millisecond), n, useful, float64(n)/float64(useful))
	if n > int64(useful)*2 {
		t.Errorf("DEFECT P5: every short reply discards the whole read-ahead window: %d READs for %d useful", n, useful)
	}
}

// P6: path -> handle cache is never revalidated; a server-side rename makes old paths resolve to moved directories.
func TestProbeP6CacheSurvivesRename(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil {
		t.Fatal(err)
	}
	deep := findKid(s.root, "deep")
	s.mu.Lock()
	findKid(deep, "a").name = "moved" // mv /deep/a /deep/moved
	s.mu.Unlock()
	s.mk(deep, "a", TypeDir, nil) // mkdir /deep/a (empty)
	la, errA := c.ListDirectory(bg, "/deep/a")
	fi, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt")
	lb, errB := c.ListDirectory(bg, "/deep/a/b")
	t.Logf("PROBE P6: list /deep/a -> %d entries (%v); GetFileInfo /deep/a/b/c/leaf.txt -> %+v %v; list /deep/a/b -> %d entries (%v)", len(la), errA, fi, err, len(lb), errB)
	if err == nil {
		t.Errorf("DEFECT P6: /deep/a is now empty but /deep/a/b/c/leaf.txt still resolves through the cached handle of the renamed directory")
	}
}

// P7: an entry name holding a NUL byte is listed although the path API refuses it.
func TestProbeP7NulNameListed(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc != procReaddirplus {
				return reply
			}
			var e encoder
			e.u32(0)
			e.boolean(false)
			e.fixed(make([]byte, 8))
			e.boolean(true)
			e.u64(77)
			e.str("a\x00b")
			e.u64(3)
			e.boolean(true)
			e.fattr(sampleAttr())
			e.boolean(false)
			e.boolean(false)
			e.boolean(true)
			return e.b
		}
	})
	l, err := c.ListDirectory(bg, "/docs")
	var p string
	if len(l) == 1 {
		p = l[0].Path
	}
	s.set(func(o *fakeOpts) { o.Corrupt = nil })
	_, gerr := c.GetFileInfo(bg, p)
	t.Logf("PROBE P7: list err=%v entries=%d path=%q; GetFileInfo(path) err=%v", err, len(l), p, gerr)
	if err == nil {
		t.Errorf("DEFECT P7: a NUL-bearing name is listed (path %q) but every later call on that path fails with %v", p, gerr)
	}
}

// P8: an entry deleted between READDIRPLUS and the attribute-fallback LOOKUP fails the whole listing.
func TestProbeP8VanishedEntryFailsListing(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.OmitAttrs = true; o.OmitHandles = true })
	c := connected(t, s, nil)
	var n atomic.Int64
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc == procLookup && n.Add(1) == 3 { // 1 = docs, 2 = a.txt, 3 = b.txt
				var e encoder
				e.u32(NFS3ErrNoEnt)
				e.boolean(false)
				return e.b
			}
			return reply
		}
	})
	l, err := c.ListDirectory(bg, "/docs")
	t.Logf("PROBE P8: listing with one entry removed mid-listing -> %v, err=%v", names(l), err)
	if err != nil {
		t.Errorf("DEFECT P8: one concurrently removed entry fails the whole directory listing: %v", err)
	}
}

// P9: the documented AccessError "local source port that was refused" is 0 for the nfs layer.
func TestProbeP9NFSLayerAccessErrorPort(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.RPCDeny = 1 })
	c, _ := New(s.cfg())
	err := c.Connect(bg)
	var ae *AccessError
	if !errors.As(err, &ae) {
		t.Fatal(err)
	}
	t.Logf("PROBE P9: layer=%s SourcePort=%d msg=%q", ae.Layer, ae.SourcePort, ae.Error())
	if ae.SourcePort == 0 {
		t.Errorf("DEFECT P9: nfs-layer AccessError does not state the source port (0) although the connection's local port is known")
	}
}

// P10: a Connect that fails after a successful MNT leaves the server-side mount record.
func TestProbeP10NoUmntAfterFailedConnect(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.AuthFlavors = []uint32{390003} })
	c, _ := New(s.cfg())
	err := c.Connect(bg)
	_ = c.Disconnect(bg)
	t.Logf("PROBE P10: Connect err=%v; MNT=%d UMNT=%d", err, s.mntProcs[procMnt].Load(), s.mntProcs[procUmnt].Load())
	if s.mntProcs[procMnt].Load() == 1 && s.mntProcs[procUmnt].Load() == 0 {
		t.Errorf("DEFECT P10: MNT succeeded, Connect failed, no UMNT was sent (Disconnect skips it because connected=false)")
	}
}

// P11: a bogus size >= 2^63 becomes a negative int64; ReadFile silently returns no data.
func TestProbeP11HugeSizeSilentEmptyRead(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, r []byte) []byte {
			if proc == procLookup && len(r) > 52 && binary.BigEndian.Uint32(r) == 0 {
				r = append([]byte(nil), r...)
				binary.BigEndian.PutUint64(r[44:], ^uint64(0)) // status 4 + fh 16 + bool 4 + type..gid 20 = 44
			}
			return r
		}
	})
	fi, ferr := c.GetFileInfo(bg, "/docs/a.txt")
	r, err := c.ReadFile(bg, "/docs/a.txt")
	var b []byte
	var rerr error
	if err == nil {
		b, rerr = io.ReadAll(r)
		r.Close()
	}
	var size int64 = -999
	if fi != nil {
		size = fi.Size
	}
	t.Logf("PROBE P11: FileInfo.Size=%d (%v); ReadFile open err=%v read %d bytes, err=%v", size, ferr, err, len(b), rerr)
	if err == nil && rerr == nil && len(b) == 0 {
		t.Errorf("DEFECT P11: a 6-byte file reported with size 2^64-1 reads back as 0 bytes with no error")
	}
}

// P12: a reconnect must not restart the xid sequence. ADOPTED-CHANGE: the reviewer's version only
// logged; this asserts that no xid is used twice across the two connections.
func TestProbeP12XidRestartsPerConnection(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	c.mu.Lock()
	n1 := c.nfs
	c.mu.Unlock()
	x1 := n1.xid.Load()
	c.dropConn(n1)
	_ = c.TestConnection(bg)
	c.mu.Lock()
	n2 := c.nfs
	c.mu.Unlock()
	t.Logf("PROBE P12: conn1 last xid=%d; conn2 after 2 calls xid=%d", x1, n2.xid.Load())
	s.xidMu.Lock()
	seen := map[uint32]int{}
	for _, x := range s.xidLog {
		seen[x]++
	}
	n := len(s.xidLog)
	s.xidMu.Unlock()
	if n < 4 {
		t.Fatalf("instrument blind: only %d NFS calls logged by the server", n)
	}
	for x, k := range seen {
		if k > 1 {
			t.Errorf("DEFECT P12: xid %d was used %d times across reconnects", x, k)
		}
	}
	if n2.xid.Load() <= x1 {
		t.Errorf("DEFECT P12: the second connection's xid sequence (%d) does not continue past the first (%d)", n2.xid.Load(), x1)
	}
}

// P13 (coverage probe, expected PASS): an EMPTY flavor list (not nil) means AUTH_SYS.
func TestProbeP13EmptyFlavorList(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.AuthFlavors = []uint32{} })
	c := connected(t, s, nil)
	_, _ = c.GetFileInfo(bg, "/docs")
	t.Logf("PROBE P13: empty flavor list -> flavor %d", s.lastFlavor.Load())
	if s.lastFlavor.Load() != authSys {
		t.Errorf("empty flavor list did not use AUTH_SYS")
	}
}

// P14: an unset identity must not be root on the wire. ADOPTED-CHANGE: asserts nobody (65534);
// AsRoot is the explicit way to send uid 0.
func TestProbeP14DefaultIdentityIsRoot(t *testing.T) {
	c, _ := New(Config{Host: "h", Export: "/x"})
	cr := c.cred()
	t.Logf("PROBE P14: default AUTH_SYS uid=%d gid=%d machine=%q", cr.UID, cr.GID, cr.Machine)
	if cr.UID != 65534 || cr.GID != 65534 {
		t.Errorf("DEFECT P14: an unset identity is sent as uid=%d gid=%d, want 65534/65534", cr.UID, cr.GID)
	}
	r, _ := New(Config{Host: "h", Export: "/x", AsRoot: true})
	if rc := r.cred(); rc.UID != 0 || rc.GID != 0 {
		t.Errorf("AsRoot did not send uid 0 / gid 0: %d/%d", rc.UID, rc.GID)
	}
	u, _ := New(Config{Host: "h", Export: "/x", UID: 1000, GID: 100})
	if uc := u.cred(); uc.UID != 1000 || uc.GID != 100 {
		t.Errorf("an explicit identity was changed: %d/%d", uc.UID, uc.GID)
	}
}

// P15: NFS3ERR_PERM (what Linux knfsd sends for a request from an insecure port) is classified as access.
// ADOPTED-CHANGE: asserts the classification.
func TestProbeP15PermIsAccess(t *testing.T) {
	err := &NFSError{Op: "FSINFO", Status: NFS3ErrPerm}
	t.Logf("PROBE P15: isAccess(NFS3ERR_PERM)=%v", isAccess(err))
	if !isAccess(err) {
		t.Error("DEFECT P15: NFS3ERR_PERM is not classified as an access refusal")
	}
}

// P16: a READ error on the last in-flight chunk, then Seek to the SAME position: the retry silently reads nothing.
func TestProbeP16SeekSamePosAfterErrorSilentEOF(t *testing.T) {
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
	_, rerr := f.Read(make([]byte, 4))
	s.set(func(o *fakeOpts) { o.Corrupt = nil })
	p, _ := f.Seek(0, io.SeekCurrent)
	b, err := io.ReadAll(f)
	t.Logf("PROBE P16: first Read err=%v; Seek(0,SeekCurrent)=%d; ReadAll -> %q err=%v", rerr, p, b, err)
	if err == nil && string(b) != "alpha\n" {
		t.Errorf("DEFECT P16: after a failed READ and a Seek to the current position the 6-byte file reads back as %d bytes with NO error", len(b))
	}
}

// P4b: the same small ReadRange against a 16 MiB file (window 8 x 1 MiB).
func TestProbeP4bReadRangeLargeFile(t *testing.T) {
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
	before := s.procs[procRead].Load()
	b, err := c.ReadRange(bg, "/huge.bin", 0, 100)
	time.Sleep(time.Second)
	t.Logf("PROBE P4b: ReadRange(n=100) of a 16 MiB file -> %d bytes (%v); %d READ calls; %d reply bytes (%.0fx)", len(b), err, s.procs[procRead].Load()-before, sent.Load(), float64(sent.Load())/100)
	if sent.Load() > 64<<10 {
		t.Errorf("DEFECT P4b: %d bytes moved for a 100-byte range", sent.Load())
	}
}

// P17: no package goroutine survives Close/Disconnect (readLoop, read-ahead) even after cancelled and timed-out calls.
func TestProbeP17NoGoroutineLeak(t *testing.T) {
	count := func() (int, string) {
		buf := make([]byte, 1<<20)
		st := string(buf[:runtimeStack(buf)])
		n := 0
		for _, g := range splitGoroutines(st) {
			if containsAny(g, "nfs3.(*rpcConn).readLoop", "nfs3.(*fileReader).issue", "nfs3.(*Client).callNFS") {
				n++
			}
		}
		return n, st
	}
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.CallTimeout = 300 * time.Millisecond; c.MaxRetries = 1 })
	_, _ = c.ListDirectory(bg, "/many")
	r, _ := c.ReadFile(bg, "/big.bin")
	_, _ = r.Read(make([]byte, 10))
	_ = r.Close() // closes with up to 7 prefetches in flight
	s.set(func(o *fakeOpts) { o.NoReply = true })
	ctx, cancel := context.WithTimeout(bg, 100*time.Millisecond)
	_, _ = c.GetFileInfo(ctx, "/docs/a.txt")
	cancel()
	_, _ = c.GetFileInfo(bg, "/docs/b.txt") // times out twice
	s.set(func(o *fakeOpts) { o.NoReply = false })
	if err := c.TestConnection(bg); err != nil {
		t.Fatal(err)
	}
	live, _ := count()
	t.Logf("PROBE P17 positive control: package goroutines while connected: %d (must be >= 1)", live)
	if live < 1 {
		t.Fatal("instrument blind: no readLoop seen on a live connection")
	}
	_ = c.Disconnect(bg)
	deadline := time.Now().Add(3 * time.Second)
	n, st := count()
	for n > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		n, st = count()
	}
	t.Logf("PROBE P17: package goroutines alive 3 s after Disconnect: %d", n)
	if n > 0 {
		t.Errorf("DEFECT P17: goroutine leak\n%s", st)
	}
}
