package nfs3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
)

func connected(t *testing.T, s *fakeServer, mod func(*Config)) *Client {
	t.Helper()
	cfg := s.cfg()
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })
	return c
}

var bg = context.Background()

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{Export: "/x"}); err == nil {
		t.Error("empty host accepted")
	}
	if _, err := New(Config{Host: "h", Export: "x"}); err == nil {
		t.Error("relative export accepted")
	}
}

func TestConnectUsesPortmapperAndMounts(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	if !c.IsConnected() {
		t.Fatal("not connected")
	}
	if s.mntProcs[procMnt].Load() != 1 {
		t.Errorf("MNT calls: %d", s.mntProcs[procMnt].Load())
	}
	if s.procs[procFsinfo].Load() < 1 || c.FSInfo().RTPref != 32768 {
		t.Errorf("FSINFO not read: %+v", c.FSInfo())
	}
	if err := c.TestConnection(bg); err != nil {
		t.Fatal(err)
	}
	if err := c.Disconnect(bg); err != nil {
		t.Fatal(err)
	}
	if s.mntProcs[procUmnt].Load() != 1 {
		t.Errorf("UMNT calls: %d", s.mntProcs[procUmnt].Load())
	}
	if c.IsConnected() {
		t.Error("still connected after Disconnect")
	}
	if err := c.TestConnection(bg); !errors.Is(err, ErrNotConnected) {
		t.Errorf("after Disconnect: %v", err)
	}
}

func TestConnectErrors(t *testing.T) {
	s := newFakeServer(t)
	cfg := s.cfg()
	cfg.Export = "/nope"
	c, _ := New(cfg)
	var me *MountError
	if err := c.Connect(bg); !errors.As(err, &me) || me.Status != mnt3ErrNoEnt {
		t.Errorf("unknown export: %v", err)
	}
	s.set(func(o *fakeOpts) { o.NFSNotListed = true })
	c, _ = New(s.cfg())
	if err := c.Connect(bg); !errors.Is(err, ErrProgramNotRegistered) {
		t.Errorf("NFS not registered: %v", err)
	}
	s.set(func(o *fakeOpts) { o.NFSNotListed = false; o.AuthFlavors = []uint32{390003} })
	c, _ = New(s.cfg())
	if err := c.Connect(bg); !errors.Is(err, ErrAuthFlavor) {
		t.Errorf("krb-only export: %v", err)
	}
	s.set(func(o *fakeOpts) { o.AuthFlavors = nil; o.RPCDeny = 2 })
	c, _ = New(s.cfg())
	var re *RPCError
	if err := c.Connect(bg); !errors.As(err, &re) || re.Low != 2 {
		t.Errorf("rpc mismatch: %v", err)
	}
	// Closed port: precise dial error, no hang.
	cfg = s.cfg()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg.PortmapPort = port(l)
	l.Close()
	c, _ = New(cfg)
	if err := c.Connect(bg); err == nil {
		t.Error("connect to closed portmapper succeeded")
	}
}

func TestExports(t *testing.T) {
	s := newFakeServer(t)
	c, _ := New(s.cfg())
	ex, err := c.Exports(bg)
	if err != nil || len(ex) != 1 || ex[0].Path != "/export" || ex[0].Groups[0] != "10.0.0.0/8" {
		t.Fatalf("%+v %v", ex, err)
	}
}

func TestGetFileInfo(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	fi, err := c.GetFileInfo(bg, "/docs/a.txt")
	if err != nil || fi.Name != "a.txt" || fi.Size != 6 || fi.IsDir || fi.Path != "/docs/a.txt" || fi.Mode.Perm() != 0o644 {
		t.Fatalf("%+v %v", fi, err)
	}
	if fi.ModTime.Nanosecond() != 123456789 {
		t.Errorf("nanoseconds lost: %v", fi.ModTime)
	}
	for _, p := range []string{"/", "", ".", "//"} {
		r, err := c.GetFileInfo(bg, p)
		if err != nil || !r.IsDir || r.Path != "/" {
			t.Errorf("root via %q: %+v %v", p, r, err)
		}
	}
	d, err := c.GetFileInfo(bg, "docs/")
	if err != nil || !d.IsDir || d.Name != "docs" {
		t.Errorf("relative dir: %+v %v", d, err)
	}
	u, err := c.GetFileInfo(bg, "/ünï.txt")
	if err != nil || u.Size != 12 {
		t.Errorf("unicode: %+v %v", u, err)
	}
	l, err := c.GetFileInfo(bg, "/link")
	if err != nil || l.Mode&os.ModeSymlink == 0 {
		t.Errorf("symlink not reported: %+v %v", l, err)
	}
	_, err = c.GetFileInfo(bg, "/docs/missing")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	ok, err := c.FileExists(bg, "/docs/missing")
	if ok || err != nil {
		t.Errorf("FileExists(missing) = %v, %v", ok, err)
	}
	ok, err = c.FileExists(bg, "/docs/b.txt")
	if !ok || err != nil {
		t.Errorf("FileExists(b.txt) = %v, %v", ok, err)
	}
	if _, err = c.GetFileInfo(bg, "/docs/a.txt/x"); err == nil {
		t.Error("path through a file succeeded")
	}
	deep, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt")
	if err != nil || deep.Size != 4 {
		t.Errorf("deep: %+v %v", deep, err)
	}
}

func TestPathConfinement(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	for _, p := range []string{"..", "/..", "/docs/../..", "docs/../../x", "/a/../b", "\x00"} {
		if _, err := c.GetFileInfo(bg, p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("%q accepted: %v", p, err)
		}
		if _, err := c.ListDirectory(bg, p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("list %q accepted: %v", p, err)
		}
		if _, err := c.ReadFile(bg, p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("read %q accepted: %v", p, err)
		}
	}
}

func names(l []*client.FileInfo) []string {
	var o []string
	for _, f := range l {
		o = append(o, f.Name)
	}
	return o
}

func TestListDirectory(t *testing.T) {
	s := newFakeServer(t)
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
		t.Fatalf("root listing %v\nwant %v", got, want)
	}
	for _, f := range l {
		if f.Name == "." || f.Name == ".." {
			t.Errorf("dot entry leaked: %s", f.Name)
		}
		if f.Name == "docs" && (!f.IsDir || f.Path != "/docs") {
			t.Errorf("docs %+v", f)
		}
		if f.Name == "big.bin" && f.Size != 3<<20+13 {
			t.Errorf("big size %d", f.Size)
		}
	}
	// One READDIRPLUS carried every attribute: zero LOOKUP/GETATTR per entry.
	if n := s.procs[procLookup].Load(); n != 0 {
		t.Errorf("listing issued %d LOOKUPs; READDIRPLUS should supply attributes", n)
	}
	if _, err = c.ListDirectory(bg, "/docs/a.txt"); err == nil {
		t.Error("listing a file succeeded")
	}
}

func TestListDirectoryPagingWithCookieVerifier(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PageEntries = 17 })
	c := connected(t, s, nil)
	before := s.procs[procReaddirplus].Load()
	l, err := c.ListDirectory(bg, "/many")
	if err != nil || len(l) != 250 {
		t.Fatalf("%d entries, %v", len(l), err)
	}
	pages := s.procs[procReaddirplus].Load() - before
	if pages < 250/17 {
		t.Errorf("only %d pages for 250 entries at 17 per page", pages)
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

func TestListDirectoryByteBudgetPaging(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.DirCount = 1000 }) // ~8 entries per page in the fake
	l, err := c.ListDirectory(bg, "/many")
	if err != nil || len(l) != 250 {
		t.Fatalf("%d, %v", len(l), err)
	}
}

func TestBadCookieRestartsListing(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PageEntries = 40; o.BadCookieOnce = true })
	c := connected(t, s, nil)
	l, err := c.ListDirectory(bg, "/many")
	if err != nil || len(l) != 250 {
		t.Fatalf("%d, %v", len(l), err)
	}
}

func TestListWithoutAttributesFallsBackToLookup(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.OmitAttrs = true; o.OmitHandles = true })
	c := connected(t, s, nil)
	l, err := c.ListDirectory(bg, "/docs")
	if err != nil || len(l) != 2 {
		t.Fatalf("%v %v", names(l), err)
	}
	for _, f := range l {
		if f.Size == 0 || f.ModTime.IsZero() {
			t.Errorf("attributes not recovered: %+v", f)
		}
	}
	if s.procs[procLookup].Load() < 2 {
		t.Error("no LOOKUP fallback happened")
	}
}

func TestListingNotProgressing(t *testing.T) {
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
			e.boolean(false) // no entries
			e.boolean(false) // and not EOF
			return e.b
		}
	})
	if _, err := c.ListDirectory(bg, "/many"); !errors.Is(err, ErrNotProgressing) {
		t.Fatalf("%v", err)
	}
}

func readAll(t *testing.T, c *Client, p string) []byte {
	t.Helper()
	r, err := c.ReadFile(bg, p)
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}

func TestReadFileLargeAndSmall(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	want := s.byID[s.root.kids[3].id].data // big.bin
	if s.root.kids[3].name != "big.bin" {
		t.Fatal("fixture order changed")
	}
	got := readAll(t, c, "/big.bin")
	if sha256.Sum256(got) != sha256.Sum256(want) || len(got) != len(want) {
		t.Fatalf("big.bin differs: %d vs %d bytes", len(got), len(want))
	}
	if string(readAll(t, c, "/docs/a.txt")) != "alpha\n" {
		t.Error("a.txt")
	}
	if len(readAll(t, c, "/empty.txt")) != 0 {
		t.Error("empty.txt")
	}
	if string(readAll(t, c, "/ünï.txt")) != "unicode name" {
		t.Error("unicode")
	}
	if _, err := c.ReadFile(bg, "/docs"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("read dir: %v", err)
	}
	if _, err := c.ReadFile(bg, "/link"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("read symlink: %v", err)
	}
	if _, err := c.ReadFile(bg, "/docs/zzz"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("read missing: %v", err)
	}
}

func TestReadShortReadsAreResumed(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.MaxRead = 1000 })
	c := connected(t, s, func(c *Config) { c.ReadSize = 16384 })
	got := readAll(t, c, "/big.bin")
	if !bytes.Equal(got, s.root.kids[3].data) {
		t.Fatalf("short-read assembly differs (%d bytes)", len(got))
	}
}

func TestReadSeekAndRange(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.ReadSize = 4096 })
	data := s.root.kids[3].data
	f, err := c.OpenSeekable(bg, "/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 100)
	if p, err := f.Seek(1<<20+7, io.SeekStart); err != nil || p != 1<<20+7 {
		t.Fatal(p, err)
	}
	if _, err := io.ReadFull(f, buf); err != nil || !bytes.Equal(buf, data[1<<20+7:1<<20+107]) {
		t.Fatalf("after seek: %v", err)
	}
	if p, _ := f.Seek(-50, io.SeekEnd); p != int64(len(data))-50 {
		t.Fatal("SeekEnd", p)
	}
	rest, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(rest, data[len(data)-50:]) {
		t.Fatalf("tail: %v len=%d", err, len(rest))
	}
	if p, _ := f.Seek(10, io.SeekStart); p != 10 {
		t.Fatal(p)
	}
	if p, _ := f.Seek(5, io.SeekCurrent); p != 15 {
		t.Fatal(p)
	}
	if _, err := f.Seek(-1, io.SeekStart); err == nil {
		t.Error("negative seek accepted")
	}
	r, err := c.ReadRange(bg, "/big.bin", 12345, 200000)
	if err != nil || !bytes.Equal(r, data[12345:212345]) {
		t.Fatalf("range: %v (%d)", err, len(r))
	}
	r, err = c.ReadRange(bg, "/big.bin", int64(len(data))-10, 1000)
	if err != nil || len(r) != 10 {
		t.Fatalf("range past EOF: %v (%d)", err, len(r))
	}
	if _, err = c.ReadRange(bg, "/big.bin", -1, 5); err == nil {
		t.Error("negative offset accepted")
	}
	if _, err = c.ReadRange(bg, "/big.bin", 0, MaxRangeBytes+1); err == nil {
		t.Error("oversize range accepted")
	}
}

func TestReadPipelinesOutOfOrderReplies(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.Shuffle = true })
	c := connected(t, s, func(c *Config) { c.ReadSize = 8192; c.MaxPipeline = 8 })
	got := readAll(t, c, "/big.bin")
	if !bytes.Equal(got, s.root.kids[3].data) {
		t.Fatal("out-of-order replies corrupted the stream")
	}
	// Pipelining actually happened: more than one READ was outstanding at once.
	if m := s.maxInflight.Load(); m < 2 {
		t.Errorf("max in-flight READs %d: the reader is not pipelining", m)
	}
}

func TestAccessAndReadOnly(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	m, err := c.Access(bg, "/docs/a.txt", Access3Read|Access3Modify|Access3Delete)
	if err != nil || m != Access3Read {
		t.Fatalf("access mask %x %v", m, err)
	}
	// Every mutating method refuses locally.
	reqs := s.procs[procNull].Load() + s.procs[procGetattr].Load() + s.procs[procLookup].Load()
	for name, err := range map[string]error{
		"WriteFile":       c.WriteFile(bg, "/x", strings.NewReader("data")),
		"DeleteFile":      c.DeleteFile(bg, "/docs/a.txt"),
		"CopyFile":        c.CopyFile(bg, "/docs/a.txt", "/y"),
		"CreateDirectory": c.CreateDirectory(bg, "/z"),
		"DeleteDirectory": c.DeleteDirectory(bg, "/docs"),
	} {
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := s.procs[procNull].Load() + s.procs[procGetattr].Load() + s.procs[procLookup].Load(); got != reqs {
		t.Errorf("a refused mutation reached the wire (%d -> %d calls)", reqs, got)
	}
	// Server-side proof: after a full workflow no write procedure was ever called.
	_, _ = c.ListDirectory(bg, "/")
	_ = readAll(t, c, "/docs/b.txt")
	if n := s.writeProcCalls(); n != 0 {
		t.Fatalf("server saw %d write-class procedure calls", n)
	}
	allowed := map[int]bool{procNull: true, procGetattr: true, procLookup: true, procAccess: true, procRead: true, procReaddirplus: true, procFsinfo: true}
	for p := range s.procs {
		if s.procs[p].Load() > 0 && !allowed[p] {
			t.Errorf("procedure %d was called", p)
		}
	}
	if c.GetProtocol() != "nfs3" {
		t.Error(c.GetProtocol())
	}
	if cfg, ok := c.GetConfig().(Config); !ok || cfg.Dial != nil || cfg.Host != "127.0.0.1" {
		t.Errorf("GetConfig %+v", c.GetConfig())
	}
}

// TestNoWriteProcedureCompiledIn parses the package sources and requires the
// set of procedure constants to be exactly the read procedures.
func TestNoWriteProcedureCompiledIn(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				if vs, ok := n.(*ast.ValueSpec); ok {
					for _, id := range vs.Names {
						if strings.HasPrefix(id.Name, "proc") {
							found[id.Name] = true
						}
					}
				}
				return true
			})
		}
	}
	want := []string{"procNull", "procGetattr", "procLookup", "procAccess", "procRead", "procReaddirplus", "procFsinfo",
		"procMntNull", "procMnt", "procUmnt", "procMntExport", "procPmapGetport"}
	var got []string
	for k := range found {
		got = append(got, k)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("procedure constants %v, want exactly %v", got, want)
	}
	// And no exported method name suggests a mutation beyond the interface refusals.
	typ := reflect.TypeOf(&Client{})
	refused := map[string]bool{"WriteFile": true, "DeleteFile": true, "CopyFile": true, "CreateDirectory": true, "DeleteDirectory": true}
	for i := 0; i < typ.NumMethod(); i++ {
		n := typ.Method(i).Name
		for _, w := range []string{"Write", "Create", "Delete", "Remove", "Rename", "Mkdir", "Rmdir", "Symlink", "Link", "Setattr", "Commit", "Put"} {
			if strings.Contains(n, w) && !refused[n] {
				t.Errorf("unexpected mutating-looking method %s", n)
			}
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.Shuffle = true })
	c := connected(t, s, func(c *Config) { c.ReadSize = 65536 })
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 4 {
			case 0:
				if l, err := c.ListDirectory(bg, "/many"); err != nil || len(l) != 250 {
					errs <- fmt.Errorf("list: %d %v", len(l), err)
				}
			case 1:
				if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil {
					errs <- err
				}
			case 2:
				if b := readAllNoT(c, "/big.bin"); len(b) != 3<<20+13 {
					errs <- fmt.Errorf("big: %d", len(b))
				}
			case 3:
				if _, err := c.FileExists(bg, "/nothing"); err != nil {
					errs <- err
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func readAllNoT(c *Client, p string) []byte {
	r, err := c.ReadFile(bg, p)
	if err != nil {
		return nil
	}
	defer r.Close()
	b, _ := io.ReadAll(r)
	return b
}

func TestAuthNullOnlyExportUsesAuthNone(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.AuthFlavors = []uint32{authNone} })
	c := connected(t, s, nil)
	if _, err := c.GetFileInfo(bg, "/docs/a.txt"); err != nil {
		t.Fatal(err)
	}
	if got := s.lastFlavor.Load(); got != authNone {
		t.Errorf("NFS calls used credential flavor %d, want AUTH_NONE for an AUTH_NULL-only export", got)
	}
	s.set(func(o *fakeOpts) { o.AuthFlavors = []uint32{authNone, authSys} })
	c2 := connected(t, s, nil)
	_, _ = c2.GetFileInfo(bg, "/docs")
	if got := s.lastFlavor.Load(); got != authSys {
		t.Errorf("flavor %d, want AUTH_SYS when both are offered", got)
	}
	// An EMPTY list (not nil) is really sent as zero flavors: AUTH_SYS is the default.
	s.set(func(o *fakeOpts) { o.AuthFlavors = []uint32{} })
	c3 := connected(t, s, nil)
	if _, err := c3.GetFileInfo(bg, "/docs"); err != nil {
		t.Fatal(err)
	}
	if got := s.lastFlavor.Load(); got != authSys {
		t.Errorf("flavor %d, want AUTH_SYS default for an empty flavor list", got)
	}
}

func TestReadChunkFollowsFSInfoButIsCapped(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.FSInfoRTPref = 8 << 20 }) // a server advertising an absurd preferred size
	c := connected(t, s, nil)
	_ = readAll(t, c, "/big.bin")
	if m := s.maxReadCount.Load(); m > 1<<20 {
		t.Errorf("READ of %d bytes requested: the 1 MiB ceiling was not applied", m)
	} else if m <= 32768 {
		t.Errorf("READ size %d: the FSINFO preference was ignored", m)
	}
}
