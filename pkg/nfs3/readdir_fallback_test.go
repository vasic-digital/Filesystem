package nfs3

// UNIT-CLASS tests (hermetic in-process fake NFS server, fakeserver_test.go): they prove the DECISION to fall back from
// READDIRPLUS to plain READDIR (procedure 16) and the paging/eof/error handling of that path. They are NOT evidence that
// a real server works; the live leg is catalog-api/tests/nfsemu (unfs3 emulator, class EMULATOR).

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func sortedNames(t *testing.T, c *Client, p string) []string {
	t.Helper()
	l, err := c.ListDirectory(bg, p)
	if err != nil {
		t.Fatalf("ListDirectory(%s): %v", p, err)
	}
	n := names(l)
	sort.Strings(n)
	return n
}

// NOTSUPP on READDIRPLUS -> READDIR; every entry present with real type/size (via LOOKUP).
func TestReaddirFallbackOnNotSupp(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp })
	c := connected(t, s, nil)
	l, err := c.ListDirectory(bg, "/")
	if err != nil {
		t.Fatal(err)
	}
	got := names(l)
	sort.Strings(got)
	want := []string{"big.bin", "deep", "docs", "empty.txt", "link", "many", "ünï.txt"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listing %v want %v", got, want)
	}
	for _, f := range l {
		if f.Name == "docs" && (!f.IsDir || f.Path != "/docs") {
			t.Errorf("docs %+v", f)
		}
		if f.Name == "big.bin" && f.Size != 3<<20+13 {
			t.Errorf("big.bin size %d", f.Size)
		}
	}
	if s.procs[procReaddir].Load() == 0 {
		t.Error("READDIR was never sent")
	}
	if s.procs[procLookup].Load() == 0 {
		t.Error("attributes were not filled via LOOKUP")
	}
}

// RPC-level PROC_UNAVAIL for procedure 17 is the equivalent refusal.
func TestReaddirFallbackOnRPCProcUnavail(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusProcUnavail = true })
	c := connected(t, s, nil)
	if n := sortedNames(t, c, "/docs"); !reflect.DeepEqual(n, []string{"a.txt", "b.txt"}) {
		t.Fatalf("%v", n)
	}
	if s.procs[procReaddir].Load() == 0 {
		t.Error("READDIR was never sent")
	}
}

// Any other READDIRPLUS error propagates; READDIR is not tried.
func TestReaddirNoFallbackOnOtherErrors(t *testing.T) {
	for _, st := range []uint32{NFS3ErrAcces, NFS3ErrIO, NFS3ErrServerFault, NFS3ErrTooSmall, NFS3ErrBadHandle} {
		t.Run(fmt.Sprint(st), func(t *testing.T) {
			s := newFakeServer(t)
			s.set(func(o *fakeOpts) { o.PlusStatus = st })
			c := connected(t, s, nil)
			_, err := c.ListDirectory(bg, "/docs")
			var ne *NFSError
			if !errors.As(err, &ne) || ne.Status != st || ne.Op != "READDIRPLUS" {
				t.Fatalf("err = %v, want READDIRPLUS status %d", err, st)
			}
			if n := s.procs[procReaddir].Load(); n != 0 {
				t.Errorf("READDIR sent %d times after a non-NOTSUPP error", n)
			}
		})
	}
}

// NOTSUPP from a procedure other than READDIRPLUS must not trigger the fallback (decision is on the op).
func TestReaddirFallbackOnlyForReaddirplusOp(t *testing.T) {
	if readdirplusUnsupported(&NFSError{Op: "LOOKUP", Status: NFS3ErrNotSupp}) {
		t.Error("NOTSUPP from LOOKUP treated as READDIRPLUS unsupported")
	}
	if readdirplusUnsupported(&RPCError{Proc: procRead, AcceptStat: acceptProcUnavail}) {
		t.Error("PROC_UNAVAIL of READ treated as READDIRPLUS unsupported")
	}
	if readdirplusUnsupported(&RPCError{Proc: procReaddirplus, Denied: true}) {
		t.Error("a denied call treated as unsupported")
	}
	if readdirplusUnsupported(errors.New("x")) {
		t.Error("plain error treated as unsupported")
	}
}

// A READDIR error after the fallback is reported as READDIR error, not swallowed or retried as success.
func TestReaddirErrorAfterFallbackPropagates(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp; o.PlainStatus = NFS3ErrIO })
	c := connected(t, s, nil)
	l, err := c.ListDirectory(bg, "/docs")
	var ne *NFSError
	if !errors.As(err, &ne) || ne.Op != "READDIR" || ne.Status != NFS3ErrIO || len(l) != 0 {
		t.Fatalf("got %v err=%v", names(l), err)
	}
}

// Paging with cookie + cookieverf across many READDIR calls; no duplicates, all 250 present.
func TestReaddirPagingAcrossCalls(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp; o.PageEntries = 17 })
	c := connected(t, s, nil)
	l, err := c.ListDirectory(bg, "/many")
	if err != nil || len(l) != 250 {
		t.Fatalf("%d entries, %v", len(l), err)
	}
	if pages := s.procs[procReaddir].Load(); pages < 250/17 {
		t.Errorf("only %d READDIR pages for 250 entries at 17 per page", pages)
	}
	seen := map[string]bool{}
	for _, f := range l {
		if seen[f.Name] {
			t.Errorf("duplicate %s", f.Name)
		}
		seen[f.Name] = true
	}
	for i := 0; i < 250; i++ {
		if !seen[fmt.Sprintf("f%04d", i)] {
			t.Fatalf("missing f%04d", i)
		}
	}
}

// The cookieverf is sent back: a server that rejects a resumed cookie with a stale verifier (BAD_COOKIE) is
// answered by a restart of the listing, exactly as for READDIRPLUS; and the final listing is complete.
func TestReaddirBadCookieRestarts(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp; o.PageEntries = 40; o.BadCookieOnce = true })
	c := connected(t, s, nil)
	l, err := c.ListDirectory(bg, "/many")
	if err != nil || len(l) != 250 {
		t.Fatalf("%d entries, %v", len(l), err)
	}
}

// eof: a short directory ends after one READDIR page (no extra call), an empty-looking page with no eof is a loop error.
func TestReaddirEOFEndsListing(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp })
	c := connected(t, s, nil)
	if _, err := c.ListDirectory(bg, "/docs"); err != nil {
		t.Fatal(err)
	}
	if n := s.procs[procReaddir].Load(); n != 1 {
		t.Errorf("%d READDIR calls for a one-page directory, want exactly 1 (eof honoured)", n)
	}
}

// The decision is remembered: a second listing does not retry READDIRPLUS.
func TestReaddirDecisionRemembered(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp })
	c := connected(t, s, nil)
	sortedNames(t, c, "/docs")
	first := s.procs[procReaddirplus].Load()
	sortedNames(t, c, "/many")
	if got := s.procs[procReaddirplus].Load(); got != first {
		t.Errorf("READDIRPLUS retried after NOTSUPP: %d -> %d", first, got)
	}
}

// Control: with a READDIRPLUS-capable server READDIR is never used.
func TestReaddirNotUsedWhenPlusWorks(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	sortedNames(t, c, "/docs")
	if n := s.procs[procReaddir].Load(); n != 0 {
		t.Errorf("READDIR used %d times against a READDIRPLUS server", n)
	}
}

// Wire codec for READDIR3res.
func TestDecodeReaddirEntries(t *testing.T) {
	var e encoder
	e.u32(0)
	e.boolean(false) // no dir attrs
	e.fixed([]byte{0, 0, 0, 0, 0, 0, 0, 7})
	for i, n := range []string{".", "x", "y"} {
		e.boolean(true)
		e.u64(uint64(10 + i))
		e.str(n)
		e.u64(uint64(i + 1))
	}
	e.boolean(false)
	e.boolean(true)
	pg, err := decodeReaddir(e.b)
	if err != nil || !pg.EOF || len(pg.Entries) != 3 || pg.Entries[2].Name != "y" || pg.Entries[2].Cookie != 3 || pg.Entries[1].Attr != nil || pg.Verf[7] != 7 {
		t.Fatalf("%+v %v", pg, err)
	}
	for cut := 0; cut < len(e.b); cut++ {
		if _, err := decodeReaddir(e.b[:cut]); err == nil {
			t.Fatalf("truncated at %d decoded", cut)
		}
	}
	args := encodeReaddir(Handle{1, 2}, 5, [8]byte{9}, 777)
	d := newDecoder(args)
	h, _ := d.opaque(64)
	ck, _ := d.u64()
	if string(h) != "\x01\x02" || ck != 5 || len(args) != 4+4+8+8+4 {
		t.Errorf("args %x", args)
	}
}
