//go:build nfs3fixture

package nfs3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests talk to a REAL, independently implemented NFSv3 server:
// willscott/go-nfs v0.0.4 (test/nfs3fixture). They run only with
//
//	go test -tags nfs3fixture ./pkg/nfs3/
//
// and the environment NFS3_FIXTURE_ADDR=host:port and NFS3_FIXTURE_MANIFEST=file,
// which test/nfs3fixture/run_integration.sh sets up.

type manifestEntry struct {
	Path   string `json:"path"`
	Dir    bool   `json:"dir"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Link   bool   `json:"symlink"`
}

func fixtureClient(t *testing.T) (*Client, []manifestEntry) {
	t.Helper()
	addr := os.Getenv("NFS3_FIXTURE_ADDR")
	mf := os.Getenv("NFS3_FIXTURE_MANIFEST")
	if addr == "" || mf == "" {
		t.Fatal("NFS3_FIXTURE_ADDR and NFS3_FIXTURE_MANIFEST must be set (see test/nfs3fixture/run_integration.sh)")
	}
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(ps)
	raw, err := os.ReadFile(mf)
	if err != nil {
		t.Fatal(err)
	}
	var m []manifestEntry
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Host: host, Export: "/", MountPort: p, NFSPort: p, UID: 1000, GID: 1000, CallTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg, 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect to go-nfs fixture: %v", err)
	}
	t.Cleanup(func() { _ = c.Disconnect(bg) })
	return c, m
}

func crawl(t *testing.T, c *Client, dir string, out map[string]manifestEntry) {
	l, err := c.ListDirectory(bg, dir)
	if err != nil {
		t.Fatalf("list %s: %v", dir, err)
	}
	for _, f := range l {
		e := manifestEntry{Path: f.Path, Dir: f.IsDir, Size: f.Size}
		if f.Mode&os.ModeSymlink != 0 {
			e = manifestEntry{Path: f.Path, Link: true}
		}
		out[f.Path] = e
		if f.IsDir {
			crawl(t, c, f.Path, out)
		}
	}
}

// TestGoNFSFullCrawlMatchesServerManifest is the independent-oracle test: the
// manifest was produced by the SERVER side from its own tree, the client's
// recursive READDIRPLUS crawl must reproduce it exactly (paths, types, sizes),
// and every file must read back with the server-computed SHA-256.
func TestGoNFSFullCrawlMatchesServerManifest(t *testing.T) {
	c, man := fixtureClient(t)
	got := map[string]manifestEntry{}
	crawl(t, c, "/", got)
	if len(got) != len(man) {
		t.Errorf("client crawl found %d entries, server manifest has %d", len(got), len(man))
	}
	var paths []string
	for _, m := range man {
		paths = append(paths, m.Path)
		g, ok := got[m.Path]
		if !ok {
			t.Errorf("missing from client crawl: %s", m.Path)
			continue
		}
		if g.Dir != m.Dir || g.Link != m.Link || (!m.Dir && !m.Link && g.Size != m.Size) {
			t.Errorf("%s: client %+v, server %+v", m.Path, g, m)
		}
		if !m.Dir && !m.Link {
			r, err := c.ReadFile(bg, m.Path)
			if err != nil {
				t.Errorf("open %s: %v", m.Path, err)
				continue
			}
			h := sha256.New()
			n, err := io.Copy(h, r)
			_ = r.Close()
			if err != nil || n != m.Size || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
				t.Errorf("%s: read %d bytes err=%v sha=%s want %d %s", m.Path, n, err, hex.EncodeToString(h.Sum(nil)), m.Size, m.SHA256)
			}
		}
	}
	sort.Strings(paths)
	if len(paths) < 260 {
		t.Fatalf("manifest too small (%d): fixture not the expected corpus", len(paths))
	}
}

func TestGoNFSReadRangeSeekAndLargeFile(t *testing.T) {
	c, _ := fixtureClient(t)
	whole := readAll(t, c, "/big.bin")
	if len(whole) != 3<<20+13 {
		t.Fatalf("big.bin %d bytes", len(whole))
	}
	r, err := c.ReadRange(bg, "/big.bin", 1<<20-5, 70000)
	if err != nil || !bytes.Equal(r, whole[1<<20-5:1<<20-5+70000]) {
		t.Fatalf("range: %v", err)
	}
	f, err := c.OpenSeekable(bg, "/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.Seek(-13, io.SeekEnd)
	tail, _ := io.ReadAll(f)
	if !bytes.Equal(tail, whole[len(whole)-13:]) {
		t.Error("tail differs")
	}
}

func TestGoNFSAttributesAndErrors(t *testing.T) {
	c, _ := fixtureClient(t)
	fi, err := c.GetFileInfo(bg, "/docs/a.txt")
	if err != nil || fi.Size != 6 || fi.IsDir {
		t.Fatalf("%+v %v", fi, err)
	}
	if _, err := c.GetFileInfo(bg, "/docs/none"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if _, err := c.ListDirectory(bg, "/docs/a.txt"); err == nil {
		t.Error("list of a file succeeded")
	}
	m, err := c.Access(bg, "/docs/a.txt", Access3Read)
	if err != nil {
		t.Fatalf("ACCESS on the real server: %v", err)
	}
	if m&Access3Read == 0 {
		t.Errorf("read access mask %x", m)
	}
	if fs := c.FSInfo(); fs.RTMax == 0 {
		t.Errorf("FSINFO %+v", fs)
	}
	if err := c.TestConnection(bg); err != nil {
		t.Error(err)
	}
	if err := c.WriteFile(bg, "/new", strings.NewReader("x")); !errors.Is(err, ErrReadOnly) {
		t.Error(err)
	}
}

// TestGoNFSAuthSysCredentialIsWellFormed is the independent oracle for AUTH_SYS, the flavor a
// Synology/knfsd NAS uses. The fixture on NFS3_FIXTURE_AUTHSYS_ADDR advertises AUTH_SYS and decodes
// every call's credential with go-nfs-client's XDR reader (test/nfs3fixture/authsys.go); a malformed
// credential closes the connection and is logged as VIOLATION. The client must work end to end, the
// log must hold OK lines (the positive control: a tap that saw nothing proves nothing) and no
// VIOLATION line.
func TestGoNFSAuthSysCredentialIsWellFormed(t *testing.T) {
	addr := os.Getenv("NFS3_FIXTURE_AUTHSYS_ADDR")
	logPath := os.Getenv("NFS3_FIXTURE_AUTHLOG")
	if addr == "" || logPath == "" {
		t.Skip("NFS3_FIXTURE_AUTHSYS_ADDR / NFS3_FIXTURE_AUTHLOG not set: the AUTH_SYS fixture only runs with the in-container run_integration.sh (honest SKIP, not a pass)")
	}
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(ps)
	c, err := New(Config{Host: host, Export: "/", MountPort: p, NFSPort: p, UID: 1000, GID: 1000, GIDs: []uint32{4, 24, 1000}, CallTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg, 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect to the AUTH_SYS fixture: %v", err)
	}
	defer c.Disconnect(bg)
	if c.cred().None {
		t.Fatal("the client chose AUTH_NONE although the export lists AUTH_SYS")
	}
	if fi, err := c.GetFileInfo(bg, "/docs/a.txt"); err != nil || fi.Size != 6 {
		t.Fatalf("%+v %v", fi, err)
	}
	if l, err := c.ListDirectory(bg, "/many"); err != nil || len(l) != 250 {
		t.Fatalf("listing: %d %v", len(l), err)
	}
	if got := readAll(t, c, "/docs/b.txt"); string(got) != "bravo bravo\n" {
		t.Fatalf("read: %q", got)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	if strings.Contains(log, "VIOLATION") {
		t.Fatalf("the independent decoder rejected a credential:\n%s", log)
	}
	ok := strings.Count(log, "OK prog=")
	if ok < 6 {
		t.Fatalf("instrument blind: only %d credentials were verified\n%s", ok, log)
	}
	for _, want := range []string{"prog=100005 proc=1 ", "prog=100003 proc=19 ", "prog=100003 proc=3 ", "prog=100003 proc=17 ", "prog=100003 proc=6 "} {
		if !strings.Contains(log, want) {
			t.Errorf("no verified credential for %q\n%s", want, log)
		}
	}
	if !strings.Contains(log, "gids=3") || !strings.Contains(log, "uid=1000 gid=1000 machine=catalogizer") {
		t.Errorf("the verified credentials do not carry the configured identity:\n%s", log)
	}
}

// TestGoNFSWorkflowLeavesTheTreeUnchanged re-reads the whole tree after the refused mutations and
// requires path, type, size and SHA-256 to equal the server-side manifest. What it proves is limited
// and stated: the five mutating methods are refused locally and never reach the wire (so this test
// cannot fail for a write regression by itself; the wire guarantee is the run-time allow-list and
// the server counters of the unit tests), and the READ path does not disturb the tree.
func TestGoNFSWorkflowLeavesTheTreeUnchanged(t *testing.T) {
	c, man := fixtureClient(t)
	for name, err := range map[string]error{
		"WriteFile":       c.WriteFile(bg, "/x", strings.NewReader("x")),
		"DeleteFile":      c.DeleteFile(bg, "/docs/a.txt"),
		"CreateDirectory": c.CreateDirectory(bg, "/newdir"),
		"DeleteDirectory": c.DeleteDirectory(bg, "/docs"),
		"CopyFile":        c.CopyFile(bg, "/docs/a.txt", "/docs/c.txt"),
	} {
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s: %v", name, err)
		}
	}
	got := map[string]manifestEntry{}
	crawl(t, c, "/", got)
	if len(got) != len(man) {
		t.Fatalf("entry count changed: %d vs %d", len(got), len(man))
	}
	for _, m := range man {
		g, ok := got[m.Path]
		if !ok {
			t.Errorf("missing after the workflow: %s", m.Path)
			continue
		}
		if g.Dir != m.Dir || g.Link != m.Link || (!m.Dir && !m.Link && g.Size != m.Size) {
			t.Errorf("%s changed: client %+v, server %+v", m.Path, g, m)
			continue
		}
		if m.Dir || m.Link {
			continue
		}
		r, err := c.ReadFile(bg, m.Path)
		if err != nil {
			t.Errorf("open %s: %v", m.Path, err)
			continue
		}
		h := sha256.New()
		n, err := io.Copy(h, r)
		_ = r.Close()
		if err != nil || n != m.Size || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
			t.Errorf("%s: content differs from the manifest (read %d bytes, err %v)", m.Path, n, err)
		}
	}
}
