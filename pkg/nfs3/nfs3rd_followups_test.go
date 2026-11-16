package nfs3

// UNIT-CLASS tests (hermetic in-process fake NFS server, fakeserver_test.go) for the NFS3RD review follow-ups
// m1 (READDIR vs READDIRPLUS entry types, concurrent fallback decision), n1 (directory-handle cache filled by the
// fallback), n2 (FallbackMaxEntries cap). Not evidence about a real server (that is the nfsemu EMULATOR leg).

import (
	"strings"
	"sync"
	"testing"
)

func TestNFS3RDm1_ReaddirTypesEqualReaddirplus(t *testing.T) {
	plus := connected(t, newFakeServer(t), nil)
	lp, err := plus.ListDirectory(bg, "/")
	if err != nil {
		t.Fatal(err)
	}
	s2 := newFakeServer(t)
	s2.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp })
	pl := connected(t, s2, nil)
	lr, err := pl.ListDirectory(bg, "/")
	if err != nil {
		t.Fatal(err)
	}
	if s2.procs[procReaddir].Load() == 0 {
		t.Fatal("fallback not exercised")
	}
	m := map[string]string{}
	for _, f := range lp {
		m[f.Name] = f.Mode.String()
	}
	if len(lr) != len(lp) {
		t.Fatalf("len %d vs %d", len(lr), len(lp))
	}
	sawLink := false
	for _, f := range lr {
		if m[f.Name] != f.Mode.String() {
			t.Errorf("%s mode via READDIR %s, via READDIRPLUS %s", f.Name, f.Mode, m[f.Name])
		}
		if f.Name == "link" {
			sawLink = true
			if f.Mode.String()[0] != 'L' {
				t.Errorf("symlink not reported as symlink: %s", f.Mode)
			}
		}
	}
	if !sawLink {
		t.Fatal("no symlink entry in fixture")
	}
}

func TestNFS3RDm1_ConcurrentFallbackDecision(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp })
	c := connected(t, s, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ListDirectory(bg, "/docs"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestNFS3RDn1_FallbackFillsDirHandleCache(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp })
	c := connected(t, s, nil)
	if _, err := c.ListDirectory(bg, "/"); err != nil {
		t.Fatal(err)
	}
	before := s.procs[procLookup].Load()
	// resolving /docs/a.txt looks the leaf up always; the intermediate "docs" only when its handle is not cached.
	if _, err := c.GetFileInfo(bg, "/docs/a.txt"); err != nil {
		t.Fatal(err)
	}
	if d := s.procs[procLookup].Load() - before; d != 1 {
		t.Errorf("%d LOOKUPs for /docs/a.txt after listing /, want 1 (directory handle of docs cached by the fallback)", d)
	}
}

func TestNFS3RDn2_FallbackMaxEntries(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp })
	c := connected(t, s, func(cfg *Config) { cfg.FallbackMaxEntries = 100 })
	_, err := c.ListDirectory(bg, "/many")
	if err == nil || !strings.Contains(err.Error(), "more than 100 entries") {
		t.Fatalf("err = %v", err)
	}
	if n := s.procs[procLookup].Load(); n > 101 {
		t.Errorf("%d LOOKUPs despite cap 100", n)
	}
	// READDIRPLUS is not affected by the fallback cap.
	s2 := newFakeServer(t)
	c2 := connected(t, s2, func(cfg *Config) { cfg.FallbackMaxEntries = 100 })
	if l, err := c2.ListDirectory(bg, "/many"); err != nil || len(l) != 250 {
		t.Fatalf("plus listing %d %v", len(l), err)
	}
	// Default (0): fallback lists all 250.
	s3 := newFakeServer(t)
	s3.set(func(o *fakeOpts) { o.PlusStatus = NFS3ErrNotSupp })
	c3 := connected(t, s3, nil)
	if l, err := c3.ListDirectory(bg, "/many"); err != nil || len(l) != 250 {
		t.Fatalf("default fallback listing %d %v", len(l), err)
	}
}
