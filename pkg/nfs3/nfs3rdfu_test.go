package nfs3

// UNIT-CLASS tests (hermetic in-process fake NFS server) for NFS3RDFU-m1 (the listing cap bounds the entries
// ATTEMPTED, so a server whose entry LOOKUPs all answer NOENT cannot bypass it) and NFS3RDFU-n1 (negative
// FallbackMaxEntries rejected). Not evidence about a real server.

import (
	"math"
	"strings"
	"sync/atomic"
	"testing"
)

// noentLookups makes the entry LOOKUPs answer NFS3ERR_NOENT: the first LOOKUP (the walk to the listed directory
// always looks its leaf up) passes, then firstN LOOKUPs vanish (firstN < 0: all the rest).
func noentLookups(s *fakeServer, firstN int64, n *atomic.Int64) {
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc != procLookup {
				return reply
			}
			k := n.Add(1)
			if k == 1 || (firstN >= 0 && k-1 > firstN) {
				return reply
			}
			var e encoder
			e.u32(NFS3ErrNoEnt)
			e.boolean(false)
			return e.b
		}
	})
}

func fallbackClient(t *testing.T, s *fakeServer, cap int) *Client {
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp })
	c := connected(t, s, func(cfg *Config) { cfg.FallbackMaxEntries = cap })
	// list "/" first so the handle of /many is cached and the later NOENT probe only hits entry LOOKUPs
	if _, err := c.ListDirectory(bg, "/"); err != nil {
		t.Fatal(err)
	}
	return c
}

// m1: 250 entries, every LOOKUP NOENT, cap 10: the listing must fail with the cap error and stop soon.
func TestNFS3RDFUm1_AllNoentCannotBypassCap(t *testing.T) {
	s := newFakeServer(t)
	c := fallbackClient(t, s, 10)
	var n atomic.Int64
	before := s.procs[procLookup].Load()
	noentLookups(s, -1, &n)
	l, err := c.ListDirectory(bg, "/many")
	if err == nil || !strings.Contains(err.Error(), "more than 10 entries") {
		t.Fatalf("len=%d err=%v, want the cap error", len(l), err)
	}
	if d := s.procs[procLookup].Load() - before; d > 11 {
		t.Errorf("%d LOOKUPs despite cap 10", d)
	}
}

// m1, same bypass with MaxEntries (not FallbackMaxEntries) as the cap: all-NOENT with MaxEntries 10 over plain
// READDIR (PlusStatus=NotSupp makes the client fall back; NFS3RDFUFU-n1 corrected this comment).
func TestNFS3RDFUm1_AllNoentCannotBypassMaxEntries(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp })
	c := connected(t, s, func(cfg *Config) { cfg.MaxEntries = 10 })
	if _, err := c.ListDirectory(bg, "/"); err != nil {
		t.Fatal(err)
	}
	var n atomic.Int64
	noentLookups(s, -1, &n)
	if _, err := c.ListDirectory(bg, "/many"); err == nil || !strings.Contains(err.Error(), "more than 10 entries") {
		t.Fatalf("err=%v", err)
	}
}

// m1 honest side: a few vanished entries inside the bound are still tolerated (listing succeeds, counted).
func TestNFS3RDFUm1_FewVanishedEntriesTolerated(t *testing.T) {
	s := newFakeServer(t)
	c := fallbackClient(t, s, 300)
	var n atomic.Int64
	noentLookups(s, 3, &n) // first 3 LOOKUPs vanish
	l, err := c.ListDirectory(bg, "/many")
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 247 {
		t.Fatalf("listed %d, want 247 (250 minus 3 vanished)", len(l))
	}
	if c.vanished.Load() != 3 {
		t.Errorf("vanished=%d want 3", c.vanished.Load())
	}
}

// m1 boundary: exactly cap entries all present still lists; the cap error needs cap+1 attempted.
func TestNFS3RDFUm1_ExactlyCapEntriesOK(t *testing.T) {
	s := newFakeServer(t)
	c := fallbackClient(t, s, 250)
	if l, err := c.ListDirectory(bg, "/many"); err != nil || len(l) != 250 {
		t.Fatalf("%d %v", len(l), err)
	}
}

// n1: negative FallbackMaxEntries is rejected.
func TestNFS3RDFUn1_NegativeFallbackMaxEntriesRejected(t *testing.T) {
	_, err := New(Config{Host: "h", Export: "/x", FallbackMaxEntries: -1})
	if err == nil || !strings.Contains(err.Error(), "FallbackMaxEntries") {
		t.Fatalf("err=%v", err)
	}
	if _, err := New(Config{Host: "h", Export: "/x", FallbackMaxEntries: 0}); err != nil {
		t.Fatal(err)
	}
}

// NFS3RDFUFU-m1: near the cap with honestly vanished entries. Cap 250 on /many (250 entries), 3 of them NOENT:
// listing must succeed with 247. Mutant "vanished LOOKUP counted twice" makes attempted reach 253 > 250.
func TestNFS3RDFUFUm1_NearCapHonestVanishedStillLists(t *testing.T) {
	s := newFakeServer(t)
	c := fallbackClient(t, s, 250)
	var n atomic.Int64
	noentLookups(s, 3, &n)
	l, err := c.ListDirectory(bg, "/many")
	if err != nil {
		t.Fatalf("near-cap listing with 3 vanished failed: %v", err)
	}
	if len(l) != 247 || c.vanished.Load() != 3 {
		t.Fatalf("listed %d vanished %d, want 247 / 3", len(l), c.vanished.Load())
	}
}

// NFS3RDFUFU-m2: every negative FallbackMaxEntries is rejected, not just -1.
func TestNFS3RDFUFUm2_AllNegativesRejected(t *testing.T) {
	for _, v := range []int{-1, -2, -1000, math.MinInt} {
		if _, err := New(Config{Host: "h", Export: "/x", FallbackMaxEntries: v}); err == nil || !strings.Contains(err.Error(), "FallbackMaxEntries") {
			t.Errorf("FallbackMaxEntries %d: err=%v", v, err)
		}
	}
}

// NFS3RDFUFU-n2/n3: the cap error says "offered more than" (vanished entries count too) and quotes the path with
// %q (a control character is escaped, not emitted raw). Drives the real listOnce with a path carrying BEL+newline.
func TestNFS3RDFUFUn2n3_CapErrorWordingAndQuoting(t *testing.T) {
	s := newFakeServer(t)
	c := fallbackClient(t, s, 10)
	dir, _, err := c.walk(bg, "/many")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.listOnce(bg, dir, "/ma\a\nny", true)
	if err == nil {
		t.Fatal("want cap error")
	}
	if !strings.Contains(err.Error(), `"/ma\a\nny" offered more than 10 entries`) {
		t.Fatalf("err=%q", err.Error())
	}
	if strings.ContainsAny(err.Error(), "\a\n") {
		t.Fatalf("raw control character in %q", err.Error())
	}
}
