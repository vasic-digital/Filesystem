package nfs3

// Killer tests, adopted verbatim from the WF19 review of this package
// (scratchpad/WF19-nfs3-artifacts/kill_test.go): each MUST PASS on the fixed package and MUST FAIL
// on the named reviewer mutant (tools/wf19_mutants.sh runs them mutant by mutant), proving that
// the mutant is not equivalent and the suite covers it.

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rawServer answers each record with handler(connIndex, callIndexOnConn, rec) -> records to write (nil = no reply).
func rawServer(t *testing.T, handler func(conn, call int, rec []byte) [][]byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var nconn atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			ci := int(nconn.Add(1))
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for call := 1; ; call++ {
					rec, err := readRecord(br, 1<<20)
					if err != nil {
						return
					}
					for _, out := range handler(ci, call, rec) {
						h := binary.BigEndian.AppendUint32(nil, 0x80000000|uint32(len(out)))
						if _, err := c.Write(append(h, out...)); err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func getattrOK(xid uint32) []byte {
	b := replyHdr(xid, msgAccepted, 0, 0, acceptSuccess)
	var e encoder
	e.u32(0)
	e.fattr(sampleAttr())
	return append(b, e.b...)
}

func rawClient(t *testing.T, addr string, mod func(*Config)) *Client {
	t.Helper()
	cfg := Config{Host: "127.0.0.1", Export: "/x", CallTimeout: 300 * time.Millisecond, RetryBackoff: time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.connected = true
	c.nfsAddr = addr
	t.Cleanup(c.dropAll)
	return c
}

// A01: a READDIRPLUS page that ends exactly with "..".
func TestKillA01PageEndingWithDotDot(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PageEntries = 2 })
	c := connected(t, s, nil)
	ctx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	l, err := c.ListDirectory(ctx, "/docs")
	if err != nil || len(l) != 2 {
		t.Fatalf("page boundary after '..': %v %v", names(l), err)
	}
}

// A02: an EMPTY (not nil) flavor list means AUTH_SYS.
func TestKillA02EmptyFlavorList(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.AuthFlavors = []uint32{} })
	c := connected(t, s, nil)
	if _, err := c.GetFileInfo(bg, "/docs"); err != nil || s.lastFlavor.Load() != authSys {
		t.Fatalf("empty flavor list: %v flavor %d", err, s.lastFlavor.Load())
	}
}

// A03: RPC SYSTEM_ERR is documented as transient.
func TestKillA03SystemErrRetried(t *testing.T) {
	addr := rawServer(t, func(conn, call int, rec []byte) [][]byte {
		xid := binary.BigEndian.Uint32(rec)
		if conn == 1 && call == 1 {
			return [][]byte{replyHdr(xid, msgAccepted, 0, 0, acceptSystemErr)}
		}
		return [][]byte{getattrOK(xid)}
	})
	c := rawClient(t, addr, nil)
	if _, err := c.callNFS(bg, procGetattr, encodeFH(Handle{1}), "GETATTR"); err != nil {
		t.Fatalf("SYSTEM_ERR not retried: %v", err)
	}
}

// A05: a CALL message from the server (backchannel) must not kill the connection.
func TestKillA05ServerCallIgnored(t *testing.T) {
	addr := rawServer(t, func(conn, call int, rec []byte) [][]byte {
		xid := binary.BigEndian.Uint32(rec)
		var e encoder
		e.u32(xid + 5000)
		e.u32(rpcCall)
		e.u32(2)
		return [][]byte{e.b, getattrOK(xid)}
	})
	c := rawClient(t, addr, func(c *Config) { c.MaxRetries = -1 })
	if _, err := c.callNFS(bg, procGetattr, encodeFH(Handle{1}), "GETATTR"); err != nil {
		t.Fatalf("server CALL broke the call: %v", err)
	}
}

// A06: opaque_auth body is at most 400 bytes (RFC 5531 section 8.2).
func TestKillA06VerifierLimit(t *testing.T) {
	var e encoder
	e.u32(7)
	e.u32(rpcReply)
	e.u32(msgAccepted)
	e.u32(1)
	e.opaque(make([]byte, 404))
	e.u32(acceptSuccess)
	if _, err := parseReply(e.b, 7, 1); !errors.Is(err, ErrProtocol) {
		t.Fatalf("404-byte verifier accepted: %v", err)
	}
}

// A07: a path through a regular file is refused locally and the file is never cached as a directory.
func TestKillA07PathThroughFileNotCached(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	_, err := c.GetFileInfo(bg, "/docs/a.txt/x")
	var ne *NFSError
	if !errors.As(err, &ne) || ne.Status != NFS3ErrNotDir {
		t.Fatalf("%v", err)
	}
	if _, ok := c.cached("/docs/a.txt"); ok {
		t.Fatal("a regular file was cached as a directory handle")
	}
}

// A08: a cached parent that became permanently stale (deleted and recreated) is dropped and the walk repeated.
func TestKillA08PersistentStaleParent(t *testing.T) {
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
	fi, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt")
	if err != nil || fi.Size != 8 {
		t.Fatalf("persistently stale cached parent not recovered: %+v %v", fi, err)
	}
}

// A09: a call that timed out is retried on a NEW connection (documented).
func TestKillA09TimeoutRetriedOnNewConnection(t *testing.T) {
	addr := rawServer(t, func(conn, call int, rec []byte) [][]byte {
		if conn == 1 {
			return nil // the first connection never answers
		}
		return [][]byte{getattrOK(binary.BigEndian.Uint32(rec))}
	})
	c := rawClient(t, addr, func(c *Config) { c.CallTimeout = 200 * time.Millisecond; c.MaxRetries = 1 })
	if _, err := c.callNFS(bg, procGetattr, encodeFH(Handle{1}), "GETATTR"); err != nil {
		t.Fatalf("timeout not retried on a fresh connection: %v", err)
	}
}

// A10: an explicit ReadSize above 1 MiB is capped.
func TestKillA10ReadSizeCapped(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.ReadSize = 4 << 20 })
	_ = readAll(t, c, "/big.bin")
	if m := s.maxReadCount.Load(); m > 1<<20 {
		t.Fatalf("READ of %d bytes", m)
	}
}

// A11: every RPC issued by the package names an allow-listed procedure identifier (no literal, no other name).
func TestKillA11OnlyAllowListedProcsReachTheWire(t *testing.T) {
	allowed := map[string]bool{"procNull": true, "procGetattr": true, "procLookup": true, "procAccess": true, "procRead": true,
		"procReaddirplus": true, "procFsinfo": true, "procMnt": true, "procUmnt": true, "procMntExport": true, "procPmapGetport": true,
		"proc": true} // "proc" = the forwarded parameter inside callNFS/oneShot/call themselves
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	argIdx := map[string]int{"callNFS": 1, "oneShot": 4, "call": 4}
	n := 0
	for _, p := range pkgs {
		for _, f := range p.Files {
			ast.Inspect(f, func(x ast.Node) bool {
				ce, ok := x.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				i, ok := argIdx[sel.Sel.Name]
				if !ok || len(ce.Args) <= i {
					return true
				}
				n++
				id, ok := ce.Args[i].(*ast.Ident)
				if !ok || !allowed[id.Name] {
					t.Errorf("%s: %s called with procedure %T %v", fset.Position(ce.Pos()), sel.Sel.Name, ce.Args[i], ce.Args[i])
				}
				return true
			})
		}
	}
	if n < 10 {
		t.Fatalf("instrument blind: only %d RPC call sites found", n)
	}
}

// A12: a name holding '/' is refused even when the server sent attributes (no LOOKUP fallback to fail for it).
func TestKillA12SlashNameRefusedWithAttrs(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, r []byte) []byte {
			if proc != procReaddirplus {
				return r
			}
			var e encoder
			e.u32(0)
			e.boolean(false)
			e.fixed(make([]byte, 8))
			e.boolean(true)
			e.u64(1)
			e.str("x/y")
			e.u64(3)
			e.boolean(true)
			e.fattr(sampleAttr())
			e.boolean(false)
			e.boolean(false)
			e.boolean(true)
			return e.b
		}
	})
	if _, err := c.ListDirectory(bg, "/docs"); !errors.Is(err, ErrBadXDR) {
		t.Fatalf("name with '/' accepted: %v", err)
	}
}

// A13: a cancelled call does not leave its xid pending.
func TestKillA13CancelledCallForgotten(t *testing.T) {
	addr := rawServer(t, func(conn, call int, rec []byte) [][]byte { return nil })
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	rc := newRPCConn(nc, authSysCred{}, 0, 1)
	defer rc.close()
	ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
	defer cancel()
	if _, err := rc.call(ctx, 5*time.Second, progNFS, 3, 0, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	rc.mu.Lock()
	n := len(rc.pending)
	rc.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d xids left pending after cancellation", n)
	}
}

// A14: NFS3ERR_PERM on the first NFS call (what Linux knfsd answers for an insecure source port) is an *AccessError.
func TestKillA14PermIsAccessError(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, r []byte) []byte {
			if proc == procFsinfo {
				var e encoder
				e.u32(NFS3ErrPerm)
				e.boolean(false)
				return e.b
			}
			return r
		}
	})
	c, _ := New(s.cfg())
	var ae *AccessError
	if err := c.Connect(bg); !errors.As(err, &ae) {
		t.Fatalf("NFS3ERR_PERM not an AccessError: %v", err)
	}
}

// A15: MaxEntries bounds a listing.
func TestKillA15MaxEntries(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(c *Config) { c.MaxEntries = 100 })
	if _, err := c.ListDirectory(bg, "/many"); err == nil || !strings.Contains(err.Error(), "more than 100") {
		t.Fatalf("MaxEntries not enforced: %v", err)
	}
}

// A16: NFS3ERR_BADHANDLE on a cached parent is handled like STALE.
func TestKillA16BadHandleRecovered(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil {
		t.Fatal(err)
	}
	var once atomic.Bool
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, r []byte) []byte {
			if proc == procLookup && once.CompareAndSwap(false, true) {
				var e encoder
				e.u32(NFS3ErrBadHandle)
				e.boolean(false)
				return e.b
			}
			return r
		}
	})
	if _, err := c.GetFileInfo(bg, "/deep/a/b/c/leaf.txt"); err != nil {
		t.Fatalf("BADHANDLE on a cached parent not recovered: %v", err)
	}
}

// A17: the MOUNT flavor count is bounded before allocation.
func TestKillA17FlavorLimit(t *testing.T) {
	var e encoder
	e.u32(0)
	e.opaque([]byte{1, 2, 3, 4})
	e.u32(flavorsMax + 1)
	for i := 0; i <= flavorsMax; i++ {
		e.u32(1)
	}
	if _, _, err := decodeMnt("/x", e.b); !errors.Is(err, ErrBadXDR) {
		t.Fatalf("%d flavors accepted: %v", flavorsMax+1, err)
	}
}

// A18: Seek clears a sticky read error so the reader is usable again.
func TestKillA18SeekClearsError(t *testing.T) {
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
		t.Fatal("expected the injected NFS3ERR_IO")
	}
	s.set(func(o *fakeOpts) { o.Corrupt = nil })
	if _, err := f.Seek(1, io.SeekStart); err != nil { // a DIFFERENT position: Seek resets the window
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "lpha\n" {
		t.Fatalf("after Seek: %q %v", b, err)
	}
}

func kfind(d *fnode, name string) *fnode {
	for _, k := range d.kids {
		if k.name == name {
			return k
		}
	}
	return nil
}
