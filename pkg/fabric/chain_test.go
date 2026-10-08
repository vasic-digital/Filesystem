package fabric_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/fabric"
	"digital.vasic.filesystem/pkg/local"
)

// The recommended chain over the REAL local client and a real directory.
func TestChain_RealLocalFilesystem(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "media"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "media", "a.txt"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	lc := local.NewLocalClient(&local.Config{BasePath: dir})
	sink := &fabric.CounterSink{}
	budget := mustBudget(t, 2, 1e6, nil)
	c := fabric.Chain(lc,
		func(c client.Client) client.Client { return fabric.Metered(c, sink, nil) },
		func(c client.Client) client.Client {
			return retrying(t, c, fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, Clock: newFakeClock()})
		},
		func(c client.Client) client.Client { return fabric.Limited(c, budget) },
		func(c client.Client) client.Client { return confined(t, c, "/media") },
		decorators.ReadOnly,
	)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := c.ListDirectory(ctx, "/media")
	if err != nil || len(list) != 1 || list[0].Name != "a.txt" {
		t.Fatalf("list: %v %v", list, err)
	}
	rc, err := c.ReadFile(ctx, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "0123456789" {
		t.Fatalf("read %q", b)
	}
	// seekable passes all the way through
	sc, ok := c.(client.SeekableClient)
	if !ok {
		t.Fatal("chain lost OpenSeekable")
	}
	s, err := sc.OpenSeekable(ctx, "/media/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Seek(5, io.SeekStart)
	tail, _ := io.ReadAll(s)
	_ = s.Close()
	if string(tail) != "56789" {
		t.Fatalf("seek read %q", tail)
	}
	// mutation: refused by ReadOnly, disk unchanged
	if err := c.WriteFile(ctx, "/media/new.txt", strings.NewReader("x")); !errors.Is(err, decorators.ErrReadOnly) {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "media", "new.txt")); !os.IsNotExist(err) {
		t.Fatal("file was created through a read-only chain")
	}
	// escape: refused by Confined, secret file untouched and unreadable
	if _, err := c.ReadFile(ctx, "/media/../secret.txt"); !errors.Is(err, fabric.ErrOutsideRoot) {
		t.Fatalf("escape: %v", err)
	}
	if err := c.DeleteFile(ctx, "/secret.txt"); !errors.Is(err, fabric.ErrOutsideRoot) {
		t.Fatalf("delete outside: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secret.txt")); err != nil {
		t.Fatal("secret.txt vanished")
	}
	if budget.Stats().InFlight != 0 {
		t.Fatalf("budget leak %+v", budget.Stats())
	}
	if sink.Snapshot(fabric.OpListDirectory).Calls != 1 || sink.Snapshot(fabric.OpReadFile).Bytes != 10 {
		t.Fatalf("metrics: list=%+v read=%+v", sink.Snapshot(fabric.OpListDirectory), sink.Snapshot(fabric.OpReadFile))
	}
}

// FuzzConfined: whatever the input, the inner client either is not called, or
// receives an absolute, clean path inside the root with no ".." segment.
func FuzzConfined(f *testing.F) {
	for _, s := range []string{"", "/", "a", "../..", "/data/media/../../etc", "\\\\x\\y", "a\x00b", "a\r\nDELE /data/b", "a\x1b[2J", "a\x7f", "a\tb", "/data/media/./a//b/", "/data/media2", "..\\..\\z", "%2e%2e/x", "a\u0085b", "a\u009b2J", "a\x85b", "a\x9b2J", "a\xff\xfeb", "/data/media/\u65e5\u672c"} {
		f.Add(s)
	}
	const root = "/data/media"
	f.Fuzz(func(t *testing.T, p string) {
		fc := newFk("p")
		c, err := fabric.Confined(fkSeek{fc}, root)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range fabric.AllOps() {
			if op.Paths() == 0 {
				continue
			}
			before := fc.total()
			err := invokeOp(t, c, op, p, root+"/x")
			if err != nil {
				if !errors.Is(err, fabric.ErrOutsideRoot) {
					t.Fatalf("%v(%q): unexpected error %v", op, p, err)
				}
				if fc.total() != before {
					t.Fatalf("%v(%q): refused but inner was called", op, p)
				}
				continue
			}
			got := fc.paths(op.String())[0]
			if !utf8.ValidString(got) {
				t.Fatalf("%v(%q): inner saw invalid UTF-8 %q", op, p, got)
			}
			for _, r := range got {
				if unicode.IsControl(r) { // round 3 (N6): C0, DEL and the C1 controls
					t.Fatalf("%v(%q): inner saw a control character in %q", op, p, got)
				}
			}
			if got != path.Clean(got) || !(got == root || strings.HasPrefix(got, root+"/")) || hasDotDot(got) {
				t.Fatalf("%v(%q): inner saw %q", op, p, got)
			}
		}
	})
}

func hasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return true
		}
	}
	return false
}
