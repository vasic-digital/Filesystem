package decorators_test

// Round-2 review (WF19) regression tests: S6/S7 (what the read-only handle
// still hands out), S13 (typed nil) and T1 R01/R02 (read paths are forwarded).

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/local"
	"digital.vasic.filesystem/pkg/smb"
	"digital.vasic.filesystem/pkg/webdav"
)

// pathRec records the path arguments of the read methods.
type pathRec struct {
	*rec
	mu2   sync.Mutex
	paths map[string][]string
}

func newPathRec() *pathRec { return &pathRec{rec: newRec(), paths: map[string][]string{}} }

func (p *pathRec) note(op string, ps ...string) {
	p.mu2.Lock()
	p.paths[op] = ps
	p.mu2.Unlock()
}
func (p *pathRec) got(op string) []string { p.mu2.Lock(); defer p.mu2.Unlock(); return p.paths[op] }

func (p *pathRec) ReadFile(_ context.Context, path string) (io.ReadCloser, error) {
	p.note("ReadFile", path)
	return io.NopCloser(strings.NewReader("x")), nil
}
func (p *pathRec) GetFileInfo(_ context.Context, path string) (*client.FileInfo, error) {
	p.note("GetFileInfo", path)
	return &client.FileInfo{Name: "n"}, nil
}
func (p *pathRec) FileExists(_ context.Context, path string) (bool, error) {
	p.note("FileExists", path)
	return true, nil
}
func (p *pathRec) ListDirectory(_ context.Context, path string) ([]*client.FileInfo, error) {
	p.note("ListDirectory", path)
	return nil, nil
}

type pathRecSeek struct{ *pathRec }

func (p pathRecSeek) OpenSeekable(_ context.Context, path string) (client.ReadSeekCloser, error) {
	p.note("OpenSeekable", path)
	return nil, nil
}

// T1 R01/R02: each read method forwards the caller's path unchanged.
func TestReadOnly_ReadMethodsForwardThePathTheyWereGiven(t *testing.T) {
	t.Parallel()
	p := newPathRec()
	ro := decorators.ReadOnly(pathRecSeek{p})
	ctx := context.Background()
	rc, _ := ro.ReadFile(ctx, "/p/read")
	_ = rc.Close()
	_, _ = ro.GetFileInfo(ctx, "/p/info")
	_, _ = ro.FileExists(ctx, "/p/exists")
	_, _ = ro.ListDirectory(ctx, "/p/list")
	_, _ = ro.(client.SeekableClient).OpenSeekable(ctx, "/p/seek")
	for op, want := range map[string]string{"ReadFile": "/p/read", "GetFileInfo": "/p/info", "FileExists": "/p/exists",
		"ListDirectory": "/p/list", "OpenSeekable": "/p/seek"} {
		if got := p.got(op); len(got) != 1 || got[0] != want {
			t.Errorf("%s forwarded %v, want [%s]", op, got, want)
		}
	}
}

// S6: GetConfig is a redacted, detached copy for every protocol client shape.
func TestReadOnly_GetConfigIsRedactedAndDetached(t *testing.T) {
	t.Parallel()
	sc := &smb.Config{Host: "nas.invalid", Port: 445, Share: "media", Username: "u", Password: "DUMMY-NOT-A-SECRET", Domain: "d"}
	got, ok := decorators.ReadOnly(smb.NewSMBClient(sc)).GetConfig().(*smb.Config)
	if !ok || got.Password != "" || got.Host != "nas.invalid" || got.Share != "media" || got.Username != "u" || got.Port != 445 || got.Domain != "d" {
		t.Fatalf("smb: %+v", got)
	}
	got.Share = "admin$"
	if sc.Share != "media" || sc.Password == "" {
		t.Fatal("the copy reaches the inner config / the inner config was blanked")
	}
	wc := &webdav.Config{URL: "http://nas.invalid/dav", Username: "u", Password: "DUMMY-NOT-A-SECRET"}
	if g, ok := decorators.ReadOnly(webdav.NewWebDAVClient(wc)).GetConfig().(*webdav.Config); !ok || g.Password != "" || g.URL != wc.URL {
		t.Fatalf("webdav: %+v", g)
	}
	dir := t.TempDir()
	lcfg := &local.Config{BasePath: dir}
	g := decorators.ReadOnly(local.NewLocalClient(lcfg)).GetConfig().(*local.Config)
	g.BasePath = "/"
	if lcfg.BasePath != dir {
		t.Fatal("mutating the returned local config re-rooted the inner client")
	}
}

// S7 (RV22 + members): the stream handed out has no metadata mutators; reading,
// seeking and ReadAt still work.
func TestReadOnly_StreamsExposeOnlyReadingCapabilities(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(p, []byte("0123456789"), 0o640); err != nil {
		t.Fatal(err)
	}
	ro := decorators.ReadOnly(local.NewLocalClient(&local.Config{BasePath: dir}))
	ctx := context.Background()
	if err := ro.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	rc, err := ro.ReadFile(ctx, "keep.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	s, err := ro.(client.SeekableClient).OpenSeekable(ctx, "keep.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for name, st := range map[string]interface{}{"ReadFile": rc, "OpenSeekable": s} {
		if _, ok := st.(*os.File); ok {
			t.Errorf("%s returned the raw *os.File", name)
		}
		for what, probe := range map[string]bool{
			"Chmod":    func() bool { _, ok := st.(interface{ Chmod(os.FileMode) error }); return ok }(),
			"Chown":    func() bool { _, ok := st.(interface{ Chown(int, int) error }); return ok }(),
			"Truncate": func() bool { _, ok := st.(interface{ Truncate(int64) error }); return ok }(),
			"Write":    func() bool { _, ok := st.(io.Writer); return ok }(),
			"Fd":       func() bool { _, ok := st.(interface{ Fd() uintptr }); return ok }(),
			"Sync":     func() bool { _, ok := st.(interface{ Sync() error }); return ok }(),
		} {
			if probe {
				t.Errorf("%s: %s is reachable through the read-only stream", name, what)
			}
		}
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %v", st.Mode().Perm())
	}
	if sk, ok := rc.(io.Seeker); !ok {
		t.Error("ReadFile lost Seek")
	} else if _, err := sk.Seek(3, io.SeekStart); err != nil {
		t.Error(err)
	}
	b, _ := io.ReadAll(rc)
	if string(b) != "3456789" {
		t.Errorf("read %q", b)
	}
	if ra, ok := s.(io.ReaderAt); !ok {
		t.Error("OpenSeekable lost ReadAt")
	} else {
		buf := make([]byte, 3)
		if n, _ := ra.ReadAt(buf, 2); n != 3 || string(buf) != "234" {
			t.Errorf("ReadAt %q", buf)
		}
	}
	// the inner error path passes through unchanged
	if _, err := ro.ReadFile(ctx, "missing.txt"); err == nil {
		t.Error("missing file: no error")
	}
}
