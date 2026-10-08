package nfs3

// ADOPTED (fix-r3, constitution 11.4.276 D): the WF24 reviewer's nine killers, verbatim from WF24-nfs3-artifacts/wf24_kill_test.go. Each
// PASSES on the committed code (83c0ac1) by design and FAILS on its mutant N01 to N17 (tools/fixr3_mutants/N*.meta); N15's killer needs a
// reserved-port bind and SKIPs without one (the executed twin is TestFixR3DialPrivilegedSkipsBusyPorts in fixr3_test.go).

// WF24 killers: one targeted test per surviving WF24 mutant. Each MUST PASS on the committed package
// (negative control) and MUST FAIL on its mutant, which proves the mutant is not equivalent.

import (
	"context"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// N01 + N02: an entry whose GETATTR (attribute fallback, after a LOOKUP without attributes) answers STALE
// vanished between the listing and the GETATTR: it is skipped and counted, the listing succeeds.
func TestWF24KillN01N02GetattrLegVanishedEntry(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.OmitAttrs = true; o.OmitHandles = true })
	c := connected(t, s, nil)
	var listed atomic.Bool
	var getattrs atomic.Int64
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc == procReaddirplus {
				listed.Store(true)
			}
			if proc == procGetattr && listed.Load() && getattrs.Add(1) == 2 { // b.txt: deleted after its LOOKUP
				var e encoder
				e.u32(NFS3ErrStale)
				return e.b
			}
			return reply
		}
	})
	v0 := c.VanishedEntries()
	l, err := c.ListDirectory(bg, "/docs")
	if err != nil || len(l) != 1 || l[0].Name != "a.txt" {
		t.Fatalf("GETATTR-leg vanished entry: %v %v", names(l), err)
	}
	if c.VanishedEntries()-v0 != 1 {
		t.Fatalf("VanishedEntries +%d, want +1", c.VanishedEntries()-v0)
	}
}

// N03: the handle cache never grows past handleCacheMax entries.
func TestWF24KillN03HandleCacheBounded(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	for i := 0; i < handleCacheMax+50; i++ {
		c.remember("/d"+itoa(i), Handle("h"+itoa(i)))
	}
	c.mu.Lock()
	n := len(c.cache)
	c.mu.Unlock()
	if n > handleCacheMax {
		t.Fatalf("handle cache holds %d entries, bound is %d", n, handleCacheMax)
	}
}

// N08: MaxRetries=n means exactly n+1 attempts on a persistent transient error.
func TestWF24KillN08RetryCountIsExact(t *testing.T) {
	for _, tc := range []struct{ maxRetries, want int }{{-1, 1}, {1, 2}, {3, 4}} {
		var calls atomic.Int64
		addr := rawServer(t, func(conn, call int, rec []byte) [][]byte {
			calls.Add(1)
			return [][]byte{replyHdr(binary.BigEndian.Uint32(rec), msgAccepted, 0, 0, acceptSystemErr)}
		})
		c := rawClient(t, addr, func(c *Config) { c.MaxRetries = tc.maxRetries })
		if _, err := c.callNFS(bg, procGetattr, encodeFH(Handle{1}), "GETATTR"); err == nil {
			t.Fatal("SYSTEM_ERR forever: no error")
		}
		if got := calls.Load(); got != int64(tc.want) {
			t.Errorf("MaxRetries=%d: %d attempts, want %d", tc.maxRetries, got, tc.want)
		}
	}
}

// N10: MNT3ERR_PERM is an access refusal (*AccessError), like MNT3ERR_ACCES.
func TestWF24KillN10MountPermIsAccessError(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.MountStatus = mnt3ErrPerm })
	c, _ := New(s.cfg())
	var ae *AccessError
	if err := c.Connect(bg); !errors.As(err, &ae) || ae.Layer != "mount" {
		t.Fatalf("MNT3ERR_PERM: want a mount-layer *AccessError, got %v", err)
	}
}

// N11: an access error after the reserved-port retry says so (Privileged=true), so the hint does not
// tell the operator to try a reserved port that was already used.
func TestWF24KillN11PrivilegedFlagInAccessError(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) { o.PortOK = func(int) bool { return false } }) // refuses every source port
	cfg := s.cfg()
	cfg.TryPrivilegedPort = true
	cfg.Dial = func(ctx context.Context, network, addr string, privileged bool) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	c, _ := New(cfg)
	var ae *AccessError
	if err := c.Connect(bg); !errors.As(err, &ae) {
		t.Fatalf("want *AccessError, got %v", err)
	}
	if !ae.Privileged || !strings.Contains(ae.Error(), "already used a reserved source port") {
		t.Fatalf("after the reserved-port retry: Privileged=%v msg=%q", ae.Privileged, ae.Error())
	}
}

// N15: dialPrivileged skips a reserved port that is in use and binds the next one. Needs the right to bind
// a reserved port (run as root in the rootless container); otherwise an honest SKIP.
func TestWF24KillN15PrivilegedDialSkipsBusyPort(t *testing.T) {
	busy, err := net.Listen("tcp", ":1023")
	if err != nil {
		t.Skipf("cannot bind reserved port 1023 here (needs privilege): %v", err)
	}
	defer busy.Close()
	s := newFakeServer(t)
	conn, err := dialPrivileged(bg, s.pmLn.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("port 1023 busy: dialPrivileged gave up: %v", err)
	}
	defer conn.Close()
	if p := conn.LocalAddr().(*net.TCPAddr).Port; p >= 1023 || p < 512 {
		t.Fatalf("bound port %d, want a free reserved port below 1023", p)
	}
}

// N16: an export whose root is not a directory is refused at Connect.
func TestWF24KillN16NonDirectoryRootRefused(t *testing.T) {
	s := newFakeServer(t)
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, r []byte) []byte {
			if proc == procGetattr && len(r) >= 8 && binary.BigEndian.Uint32(r) == 0 {
				r = append([]byte(nil), r...)
				binary.BigEndian.PutUint32(r[4:8], uint32(TypeRegular))
			}
			return r
		}
	})
	c, _ := New(s.cfg())
	defer c.Disconnect(bg)
	if err := c.Connect(bg); err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("a regular-file export root was accepted: %v", err)
	}
	if c.IsConnected() {
		t.Fatal("client marked connected after a refused root")
	}
}

// N17: every RPC call site names an allow-listed VERSION too (the run-time allow-list does not key on it,
// so the version must be pinned at the call site): NFS v4 procedure 1 is COMPOUND, which carries writes.
func TestWF24KillN17CallSitesPinTheVersion(t *testing.T) {
	allowed := map[string]bool{"versNFS": true, "versMount": true, "versPortmap": true, "vers": true}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range pkgs {
		for _, f := range p.Files {
			ast.Inspect(f, func(x ast.Node) bool {
				ce, ok := x.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "call" || len(ce.Args) != 6 {
					return true
				}
				n++
				if id, ok := ce.Args[3].(*ast.Ident); !ok || !allowed[id.Name] {
					t.Errorf("%s: call with version %T %v", fset.Position(ce.Pos()), ce.Args[3], ce.Args[3])
				}
				return true
			})
		}
	}
	if n < 2 {
		t.Fatalf("instrument blind: %d rpcConn.call sites", n)
	}
}
