package ftp

// WF24 independent re-review probes, ADOPTED as permanent tests (fix round 3, constitution 11.4.276(D)): the reviewer's
// own instruments, verbatim, so that what the independent review measured can never silently regress.
//   TestWF24_R_*  re-run of a WF21 finding's probe scenario: PASS = the defect no longer reproduces (closed).
//   TestWF24_C_*  control needles: PASS = the instrument sees the correct behaviour where the code is right.
//   TestWF24_N5/N10/N12/N18  correct-behaviour probes that are also the killers of mutants NM02/NM09/NM01/NM10.
//   TestWF24_N8/N9  the two documented boundaries (a listing as a whole is bounded only by ctx; Disconnect aborts streams,
//                   not a stalled non-stream operation): they assert the DOCUMENTED behaviour so it cannot change silently.
// The reviewer's defect probes N1, N2, N3, N4, N6, N7, N13, N14, N15, N16, N17 asserted the DEFECT (they passed while it
// was present). Their scenarios are adopted in fix_r3_test.go with the assertion inverted to the correct behaviour: each
// one FAILS on the committed code 83c0ac1 and passes now (evidence: raw/fix-r3-red-*.txt).

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/fabric"
)

func wfSize(fi *client.FileInfo) any {
	if fi == nil {
		return nil
	}
	return fi.Size
}

// ================================ F1: deadlines ================================

func TestWF24_R_D1_NoBanner(t *testing.T) {
	for _, mode := range []string{TLSNone, TLSExplicit} {
		t.Run(mode+"/ctx", func(t *testing.T) {
			port, _ := silentServer(t, nil)
			cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: mode, TrustedLAN: true, PinStore: NewMemPinStore()}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			var cerr error
			start := time.Now()
			done := runAsync(func() { cerr = NewFTPClient(cfg).Connect(ctx) })
			require.True(t, returnedWithin(done, 2*time.Second))
			t.Logf("CLOSED-D1/%s ctx: returned in %v err=%v", mode, time.Since(start).Round(time.Millisecond), cerr)
			require.Error(t, cerr)
		})
		t.Run(mode+"/DialTimeout", func(t *testing.T) {
			port, _ := silentServer(t, nil)
			cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: mode, TrustedLAN: true, PinStore: NewMemPinStore(),
				DialTimeout: 300 * time.Millisecond, IOTimeout: 30 * time.Second}
			var cerr error
			start := time.Now()
			done := runAsync(func() { cerr = NewFTPClient(cfg).Connect(context.Background()) })
			require.True(t, returnedWithin(done, 2*time.Second))
			t.Logf("CLOSED-D1/%s DialTimeout: returned in %v class=%v err=%v", mode, time.Since(start).Round(time.Millisecond), fabric.Classify(cerr), cerr)
		})
	}
}

func TestWF24_C_C1_ServerClosesAtOnce(t *testing.T) {
	port, _ := silentServer(t, func(c net.Conn) { _ = c.Close() })
	cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: TLSNone, TrustedLAN: true}
	start := time.Now()
	err := NewFTPClient(cfg).Connect(context.Background())
	require.Error(t, err)
	require.Less(t, time.Since(start), 2*time.Second)
	t.Logf("CONTROL C1: %v class=%v", err, fabric.Classify(err))
}

func TestWF24_R_D2_TLSHandshakeUnanswered(t *testing.T) {
	port, _ := silentServer(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "220 hi\r\n")
		r := bufio.NewReader(c)
		line, _ := r.ReadString('\n')
		if strings.HasPrefix(strings.ToUpper(line), "AUTH") {
			_, _ = io.WriteString(c, "234 go ahead\r\n")
		}
		_, _ = io.Copy(io.Discard, r)
	})
	st := NewMemPinStore()
	require.NoError(t, st.Record(HostPort("127.0.0.1", port), genCertT(t)))
	for _, v := range []struct {
		name string
		dial time.Duration
		ctx  time.Duration
	}{{"DialTimeout", 300 * time.Millisecond, 0}, {"ctx", 30 * time.Second, 300 * time.Millisecond}} {
		cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", PinStore: st, DialTimeout: v.dial, IOTimeout: 30 * time.Second}
		ctx := context.Background()
		var cancel context.CancelFunc = func() {}
		if v.ctx > 0 {
			ctx, cancel = context.WithTimeout(ctx, v.ctx)
		}
		var cerr error
		start := time.Now()
		done := runAsync(func() { cerr = NewFTPClient(cfg).Connect(ctx) })
		require.True(t, returnedWithin(done, 2*time.Second), v.name)
		t.Logf("CLOSED-D2/%s: returned in %v err=%v", v.name, time.Since(start).Round(time.Millisecond), cerr)
		cancel()
	}
}

func TestWF24_R_D3_MLSDStall(t *testing.T) {
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 300 * time.Millisecond })
	s.setHook(stallHook(map[string]bool{"MLSD": true}, rch))
	var lerr error
	start := time.Now()
	done := runAsync(func() { _, lerr = c.ListDirectory(context.Background(), "/") })
	require.True(t, returnedWithin(done, 2*time.Second))
	t.Logf("CLOSED-D3: ListDirectory returned in %v err=%v class=%v IsConnected=%v", time.Since(start).Round(time.Millisecond), lerr, fabric.Classify(lerr), c.IsConnected())
	rel()
	s.setHook(nil)
	fi, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	t.Logf("CLOSED-D3: next caller works (size %v)", wfSize(fi))
}

func TestWF24_C_C3_RETRStall(t *testing.T) {
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 300 * time.Millisecond })
	s.setHook(stallHook(map[string]bool{"RETR": true}, rch))
	rc, err := c.ReadFile(ctx5(t), "a.txt")
	require.NoError(t, err)
	start := time.Now()
	_, rerr := rc.Read(make([]byte, 16))
	require.Error(t, rerr)
	require.Less(t, time.Since(start), 2*time.Second)
	t.Logf("CONTROL C3: %v in %v", rerr, time.Since(start).Round(time.Millisecond))
	rel()
	closed := runAsync(func() { _ = rc.Close() })
	require.True(t, returnedWithin(closed, 3*time.Second))
}

func TestWF24_R_D4_NoFinalReply(t *testing.T) {
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 400 * time.Millisecond })
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = io.WriteString(dc, "hello")
		_ = dc.Close()
		<-rch
		return true, false
	})
	rc, err := c.ReadFile(ctx5(t), "a.txt")
	require.NoError(t, err)
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	var cerr error
	start := time.Now()
	closed := runAsync(func() { cerr = rc.Close() })
	require.True(t, returnedWithin(closed, 2*time.Second))
	dctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	derr := c.Disconnect(dctx)
	t.Logf("CLOSED-D4: read %q; Close returned in %v err=%v; Disconnect(500ms)=%v", b, time.Since(start).Round(time.Millisecond), cerr, derr)
	require.Error(t, cerr)
	require.NoError(t, derr)
	rel()
}

// static members not exercised by the author: REST and PASV (EPSV disabled) muted
func TestWF24_R_F1_RESTAndPASVMuted(t *testing.T) {
	for _, v := range []string{"REST", "PASV"} {
		t.Run(v, func(t *testing.T) {
			s := newFakeServer(t)
			rch, _ := releaser(t)
			c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 300 * time.Millisecond; cfg.DisableEPSV = v == "PASV" })
			s.setHook(mute(map[string]bool{v: true}, rch))
			var err error
			start := time.Now()
			done := runAsync(func() {
				rc, e := c.ReadFileFrom(context.Background(), "big.bin", 10)
				if e == nil {
					_ = rc.Close()
				}
				err = e
			})
			require.True(t, returnedWithin(done, 2*time.Second))
			t.Logf("CLOSED-F1/%s muted: returned in %v err=%v IsConnected=%v", v, time.Since(start).Round(time.Millisecond), err, c.IsConnected())
			require.Error(t, err)
		})
	}
}

func TestWF24_R_F1_PoolConnectAndHealthTimeout(t *testing.T) {
	t.Run("ConnectTimeout", func(t *testing.T) {
		port, _ := silentServer(t, nil)
		cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: TLSNone, TrustedLAN: true}
		pool, err := NewWorkerPool(cfg, fabric.PoolOptions{MaxPerKey: 1, ConnectTimeout: 300 * time.Millisecond}, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 1}})
		require.NoError(t, err)
		defer pool.CloseAll()
		var gerr error
		start := time.Now()
		done := runAsync(func() {
			_, gerr = pool.GetClientContext(context.Background(), &client.StorageConfig{ID: "r", Protocol: "ftp"})
		})
		require.True(t, returnedWithin(done, 2*time.Second))
		t.Logf("CLOSED-F1 pool ConnectTimeout: borrow returned in %v err=%v", time.Since(start).Round(time.Millisecond), gerr)
		require.Error(t, gerr)
	})
	t.Run("HealthTimeout", func(t *testing.T) {
		s := newFakeServer(t)
		cfg := cfgFor(s, pinned(t, s))
		pool, err := NewWorkerPool(cfg, fabric.PoolOptions{MaxPerKey: 1, HealthTimeout: 300 * time.Millisecond}, ScanOptions{})
		require.NoError(t, err)
		defer pool.CloseAll()
		sc := &client.StorageConfig{ID: "r", Protocol: "ftp"}
		c1, err := pool.GetClientContext(ctx5(t), sc)
		require.NoError(t, err)
		require.NoError(t, pool.ReturnClient(c1))
		rch, rel := releaser(t)
		var once sync.Once
		s.setHook(func(ss *session, verb, arg string) (bool, bool) {
			if verb != "NOOP" {
				return false, true
			}
			stalled := false
			once.Do(func() { stalled = true })
			if stalled {
				<-rch
				return true, false
			}
			return false, true
		})
		start := time.Now()
		var c2 client.Client
		var gerr error
		done := runAsync(func() { c2, gerr = pool.GetClientContext(context.Background(), sc) })
		require.True(t, returnedWithin(done, 3*time.Second))
		t.Logf("CLOSED-F1 pool HealthTimeout: borrow over a muted NOOP returned in %v err=%v ctrlConns=%d", time.Since(start).Round(time.Millisecond), gerr, s.wfCtrl())
		require.NoError(t, gerr)
		_ = pool.ReturnClient(c2)
		rel()
	})
}

// ================================ F2: discipline, 421, desync ================================

func TestWF24_R_D5_421(t *testing.T) {
	pol := &fabric.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}
	s := newFakeServer(t)
	raw := NewFTPClient(cfgFor(s, pinned(t, s)))
	require.NoError(t, raw.Connect(ctx5(t)))
	s.setHook(once421("MLSD"))
	_, err := raw.ListDirectory(ctx5(t), "/")
	t.Logf("CLOSED-D5 raw: err=%v IsConnected=%v class=%v", err, raw.IsConnected(), fabric.Classify(err))
	require.Error(t, err)
	require.False(t, raw.IsConnected())
	_ = raw.Disconnect(context.Background())

	s2 := newFakeServer(t)
	sc, err := NewScanClient(cfgFor(s2, pinned(t, s2)), ScanOptions{Retry: pol})
	require.NoError(t, err)
	require.NoError(t, sc.Connect(ctx5(t)))
	defer sc.Disconnect(context.Background())
	s2.setHook(once421("MLSD"))
	got, err := sc.ListDirectory(ctx5(t), "/")
	t.Logf("CLOSED-D5 scan (MaxAttempts=2): entries=%d err=%v ctrlConns=%d", len(got), err, s2.wfCtrl())
	require.NoError(t, err)
}

func TestWF24_R_D6_ExtraReplyDesync(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprintf("extra226=%v", extra), func(t *testing.T) {
			s := newFakeServer(t)
			c := connected(t, s, nil)
			s.setHook(earlyCloseHook(s, extra))
			rc, err := c.ReadFile(ctx5(t), "a.txt")
			require.NoError(t, err)
			_, _ = rc.Read(make([]byte, 1))
			cerr := rc.Close()
			s.setHook(nil)
			_, e1 := c.GetFileInfo(ctx5(t), "a.txt")
			fi, e2 := c.GetFileInfo(ctx5(t), "sub/c.txt")
			ok, e3 := c.FileExists(ctx5(t), "missing.txt")
			t.Logf("D6 extra=%v: Close=%v; GetFileInfo(a.txt) err=%v; GetFileInfo(sub/c.txt) size=%v err=%v; FileExists(missing)=%v,%v; ctrlConns=%d",
				extra, cerr, e1, wfSize(fi), e2, ok, e3, s.wfCtrl())
			require.NoError(t, e1)
			require.NoError(t, e2)
			require.Equal(t, int64(2), fi.Size)
			require.False(t, ok)
			if extra {
				t.Logf("CLOSED-D6: c.txt's own metadata after the extra reply")
			} else {
				t.Logf("CONTROL C6")
			}
		})
	}
}

// ================================ F3: cancel / Disconnect between reads ================================

func TestWF24_R_D9_D9b(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		s := newFakeServer(t)
		rch, rel := releaser(t)
		c := connected(t, s, nil)
		s.setHook(slowHook(rch))
		ctx, cancel := context.WithCancel(context.Background())
		rc, err := c.ReadFile(ctx, "big.bin")
		require.NoError(t, err)
		_, err = io.ReadFull(rc, make([]byte, 1024))
		require.NoError(t, err)
		cancel()
		time.Sleep(200 * time.Millisecond)
		n, rerr := readFor(rc, time.Second)
		rel()
		_ = rc.Close()
		t.Logf("CLOSED-D9: after cancel %d more bytes, err=%v", n, rerr)
		require.Error(t, rerr)
		require.Less(t, n, 16*1024)
	})
	t.Run("disconnect", func(t *testing.T) {
		s := newFakeServer(t)
		rch, rel := releaser(t)
		c := connected(t, s, nil)
		s.setHook(slowHook(rch))
		rc, err := c.ReadFile(ctx5(t), "big.bin")
		require.NoError(t, err)
		_, err = io.ReadFull(rc, make([]byte, 1024))
		require.NoError(t, err)
		var derr error
		ddone := runAsync(func() { derr = c.Disconnect(ctx5(t)) })
		time.Sleep(200 * time.Millisecond)
		n, rerr := readFor(rc, time.Second)
		rel()
		_ = rc.Close()
		require.True(t, returnedWithin(ddone, 3*time.Second))
		t.Logf("CLOSED-D9b: after Disconnect %d more bytes, err=%v; Disconnect=%v; open ctrl=%v", n, rerr, derr, s.waitCtrl(0, 3*time.Second))
		require.Error(t, rerr)
		require.Less(t, n, 16*1024)
	})
}

// ================================ F4: seekable truncation ================================

func TestWF24_R_D8_SeekableTruncation(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(truncHook(s))
	sk, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	all, err := io.ReadAll(sk)
	_ = sk.Close()
	t.Logf("CLOSED-D8: OpenSeekable ReadAll got %d of 100000 bytes, err=%v", len(all), err)
	require.Error(t, err)
}

// ================================ F5: login phases ================================

func TestWF24_R_D11_D12_D23(t *testing.T) {
	t.Run("D11", func(t *testing.T) {
		s := newFakeServer(t)
		cfg := cfgFor(s, pinned(t, s))
		s.dropNext("PASS", 10)
		sc, err := NewScanClient(cfg, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond}})
		require.NoError(t, err)
		err = sc.Connect(ctx5(t))
		t.Logf("CLOSED-D11: PASS sent %d time(s), class=%v err=%v", s.count("PASS"), fabric.Classify(err), err)
		require.Equal(t, 1, s.count("PASS"))
	})
	t.Run("D12b_prot", func(t *testing.T) {
		s := newFakeServer(t)
		cfg := cfgFor(s, pinned(t, s))
		s.setHook(func(ss *session, verb, arg string) (bool, bool) {
			if verb == "PROT" {
				ss.reply("536 PROT P not supported")
				return true, true
			}
			return false, true
		})
		err := NewFTPClient(cfg).Connect(ctx5(t))
		t.Logf("CLOSED-D12b: class=%v err=%v", fabric.Classify(err), err)
		require.NotEqual(t, fabric.ClassAuth, fabric.Classify(err))
	})
	t.Run("D12c_opts", func(t *testing.T) {
		hook := func(ss *session, verb, arg string) (bool, bool) {
			if verb == "OPTS" {
				ss.reply("500 OPTS not understood")
				return true, true
			}
			return false, true
		}
		s := newFakeServer(t)
		s.legacyName = true
		s.setHook(hook)
		c := NewFTPClient(cfgFor(s, pinned(t, s)))
		require.NoError(t, c.Connect(ctx5(t)))
		got, err := c.ListDirectory(ctx5(t), "/")
		_ = c.Disconnect(context.Background())
		t.Logf("CLOSED-D12c TLS: entries=%d err=%v", len(got), err)
		require.ErrorIs(t, err, ErrUTF8Refused)
		s2 := newFakeServer(t)
		s2.tlsOn = false
		s2.setHook(hook)
		cfg2 := cfgFor(s2, nil)
		cfg2.TLSMode, cfg2.TrustedLAN = TLSNone, true
		err = NewFTPClient(cfg2).Connect(ctx5(t))
		t.Logf("CLOSED-D12c clear: connect err=%v", err)
		require.NoError(t, err)
	})
	t.Run("D23", func(t *testing.T) {
		s := newFakeServer(t)
		cfg := cfgFor(s, pinned(t, s))
		var mu sync.Mutex
		n := 0
		s.setHook(func(ss *session, verb, arg string) (bool, bool) {
			if verb != "USER" {
				return false, true
			}
			mu.Lock()
			n++
			first := n == 1
			mu.Unlock()
			if first {
				ss.reply("421 Too many connections (5) from this IP")
				return true, false
			}
			return false, true
		})
		pool, err := NewWorkerPool(cfg, fabric.PoolOptions{MaxPerKey: 2}, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 1}})
		require.NoError(t, err)
		defer pool.CloseAll()
		sc := &client.StorageConfig{ID: "root1", Protocol: "ftp"}
		_, err = pool.GetClientContext(ctx5(t), sc)
		t.Logf("D23 first borrow (no retry): class=%v err=%v", fabric.Classify(err), err)
		require.Error(t, err)
		require.Equal(t, fabric.ClassTransient, fabric.Classify(err))
		c2, err2 := pool.GetClientContext(ctx5(t), sc)
		t.Logf("CLOSED-D23: second borrow err=%v USER sent=%d (root not latched)", err2, s.count("USER"))
		require.NoError(t, err2)
		_ = pool.ReturnClient(c2)
	})
}

// ================================ F6: MLSD parsing (the D7 table) ================================

func TestWF24_R_D7_MLSD(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	lines := []string{
		"Type=cdir;Modify=20200517103000; .",
		"Type=file;Size=5;Modify=20200517103000; plain.txt",
		"type=file;size=7;modify=20200517103000; lower.txt",
		"Type=file;Size=10;Modify=20200517103000.123; frac.txt",
		"Type=Dir;Modify=20200517103000; UpperDir",
		"Type=OS.unix=symlink;Modify=20200517103000; link",
		"Type=file;Size=010;Modify=20200517103000; octal.txt",
		"Type=file;Size=08;Modify=20200517103000; badoctal.txt",
		"Type=cdir;Modify=20200517103000; data",
		"Type=file;Size=3;UNIX.group=Domain Users;Modify=20200517103000; spaced.txt",
		" nofacts.txt",
		"Type=file;Size=4;Modify=20200517103000;  two leading spaces.txt",
		"Type=file;Size=4;Modify=20200517103000; trailing dot.",
	}
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLSD" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = io.WriteString(dc, strings.Join(lines, "\r\n")+"\r\n")
		_ = dc.Close()
		ss.reply("226 done")
		return true, true
	})
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	by := map[string]*client.FileInfo{}
	for _, f := range got {
		by[f.Name] = f
	}
	t.Logf("D7: %d entries", len(got))
	assert.True(t, by["UpperDir"] != nil && by["UpperDir"].IsDir, "Type=Dir")
	assert.True(t, by["link"] != nil && by["link"].Mode == os.ModeSymlink, "symlink")
	assert.True(t, by["octal.txt"] != nil && by["octal.txt"].Size == 10, "decimal size")
	assert.True(t, by["badoctal.txt"] != nil && by["badoctal.txt"].Size == 8, "Size=08 kept")
	assert.Nil(t, by["data"], "cdir named data not a child")
	assert.True(t, by["spaced.txt"] != nil && by["spaced.txt"].Size == 3 && !by["spaced.txt"].ModTime.IsZero(), "fact value with a space")
	assert.NotNil(t, by["nofacts.txt"], "no-facts entry")
	assert.True(t, by["frac.txt"] != nil && by["frac.txt"].ModTime.Equal(t0.Add(123*time.Millisecond)))
	assert.NotNil(t, by[" two leading spaces.txt"])
	assert.NotNil(t, by["trailing dot."])
	t.Logf("CLOSED-D7 if no assertion above failed")
}

// ================================ F7: 550 ================================

func TestWF24_R_D18_Permission550(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if (verb == "MLST" || verb == "RETR") && arg == "/data/a.txt" {
			ss.reply("550 /data/a.txt: Permission denied")
			return true, true
		}
		return false, true
	})
	ok, err := c.FileExists(ctx5(t), "a.txt")
	_, rerr := c.ReadFile(ctx5(t), "a.txt")
	t.Logf("CLOSED-D18: FileExists=%v err=%v (IsPermission=%v); ReadFile err=%v (IsNotExist=%v)", ok, err, errors.Is(err, os.ErrPermission), rerr, errors.Is(rerr, os.ErrNotExist))
	require.Error(t, err)
	require.False(t, errors.Is(rerr, os.ErrNotExist))
}

// ================================ F8: degraded top-level stat ================================

func TestWF24_R_D10_DegradedStat(t *testing.T) {
	t.Run("root_with_Path", func(t *testing.T) {
		s := newFakeServer(t)
		s.mlst = false
		c := connected(t, s, func(cfg *Config) { cfg.AllowDegradedList = true })
		fi, err := c.GetFileInfo(ctx5(t), "/")
		ok, e2 := c.FileExists(ctx5(t), "/")
		t.Logf("CLOSED-D10a: GetFileInfo(/)=%+v err=%v FileExists=%v,%v", fi, err, ok, e2)
		require.NoError(t, err)
		require.True(t, ok)
	})
	t.Run("no_Path_home_data", func(t *testing.T) {
		s := newFakeServer(t)
		s.mlst = false
		s.setHome("/data")
		c := connected(t, s, func(cfg *Config) { cfg.AllowDegradedList = true; cfg.Path = "" })
		fi, err := c.GetFileInfo(ctx5(t), "a.txt")
		t.Logf("CLOSED-D10b: GetFileInfo(a.txt == /a.txt) err=%v size=%v; LIST commands=%v", err, wfSize(fi), s.commands())
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

// ================================ F10 / F12 / F13 / F14 / F15 ================================

func TestWF24_R_D13_Fmt(t *testing.T) {
	const secret = "S3cr3t-WF24-QQQ"
	v := Credential{Password: secret}
	cfg := &Config{Host: "h", Username: "u", Password: secret}
	pool, err := NewWorkerPool(cfg, fabric.PoolOptions{MaxPerKey: 1}, ScanOptions{})
	require.NoError(t, err)
	defer pool.CloseAll()
	sc, err := NewScanClient(cfg, ScanOptions{})
	require.NoError(t, err)
	outs := []string{fmt.Sprintf("%v %+v %#v", v, v, v), fmt.Sprintf("%+v %#v", scanFactory{cfg: cfg}, scanFactory{cfg: cfg}),
		fmt.Sprintf("%v %+v %#v", pool, pool, pool), fmt.Sprintf("%v %+v %#v", *cfg, *cfg, *cfg), fmt.Sprintf("%v %+v", sc, sc),
		fmt.Sprintf("%+v", NewFTPClient(cfg)), fmt.Sprintf("%+v", sc.GetConfig())}
	leaked := 0
	for i, o := range outs {
		if strings.Contains(o, secret) {
			leaked++
			t.Logf("leak in output %d", i)
		}
	}
	// control needle: the instrument sees the secret when it IS printed
	require.Contains(t, fmt.Sprintf("%s", secret), secret)
	t.Logf("CLOSED-D13 if 0: %d of %d fmt renderings contain the secret", leaked, len(outs))
	require.Zero(t, leaked)
}

func TestWF24_R_D15_IAC(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	_, _ = c.GetFileInfo(ctx5(t), "x\xff\xf4y")
	lone := 0
	for _, cmd := range s.commands() {
		if strings.Contains(strings.ReplaceAll(cmd, "\xff\xff", ""), "\xff") {
			lone++
		}
	}
	t.Logf("CLOSED-D15 if 0: commands with a lone 0xFF: %d (sent %q)", lone, s.commands()[len(s.commands())-1])
	require.Zero(t, lone)
}

func TestWF24_R_D16_D17_Bounds(t *testing.T) {
	t.Run("reply_default_cap", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, nil)
		s.setHook(func(ss *session, verb, arg string) (bool, bool) {
			if verb != "NOOP" {
				return false, true
			}
			w := bufio.NewWriterSize(ss.conn, 1<<16)
			fmt.Fprintf(w, "200-start\r\n")
			pad := strings.Repeat("x", 1000)
			for i := 0; i < 3000; i++ { // ~3 MB > the 1 MiB default
				fmt.Fprintf(w, " %s\r\n", pad)
			}
			fmt.Fprintf(w, "200 end\r\n")
			_ = w.Flush()
			return true, true
		})
		err := c.TestConnection(ctx5(t))
		t.Logf("CLOSED-D16: 3 MB reply under the default cap: %v", err)
		require.ErrorIs(t, err, ErrReplyTooLarge)
	})
	t.Run("listing_cap", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, func(cfg *Config) { cfg.MaxListEntries = 1000 })
		s.setHook(func(ss *session, verb, arg string) (bool, bool) {
			if verb != "MLSD" {
				return false, true
			}
			ss.reply("150 opening")
			dc, err := ss.openData()
			if err != nil {
				return true, true
			}
			w := bufio.NewWriterSize(dc, 1<<16)
			for i := 0; i < 5000; i++ {
				fmt.Fprintf(w, "Type=file;Size=1;Modify=20200517103000; f%07d\r\n", i)
			}
			_ = w.Flush()
			_ = dc.Close()
			ss.reply("226 done")
			return true, true
		})
		_, err := c.ListDirectory(ctx5(t), "/")
		t.Logf("CLOSED-D17 (a cap exists): %v", err)
		require.ErrorIs(t, err, ErrListingTooLarge)
	})
}

func TestWF24_R_D19_DisconnectTimeout(t *testing.T) {
	s := newFakeServer(t)
	c := NewFTPClient(cfgFor(s, pinned(t, s)))
	require.NoError(t, c.Connect(ctx5(t)))
	rc, err := c.ReadFile(ctx5(t), "a.txt")
	require.NoError(t, err)
	short, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() { time.Sleep(600 * time.Millisecond); _, _ = io.Copy(io.Discard, rc); _ = rc.Close() }()
	derr := c.Disconnect(short)
	closed := s.waitCtrl(0, 3*time.Second)
	t.Logf("CLOSED-D19: Disconnect=%v; server control connections reached 0 without a second Disconnect: %v", derr, closed)
	require.True(t, closed)
}

func TestWF24_R_D21_PinPort0(t *testing.T) {
	_, err := Pin(ctx5(t), NewMemPinStore(), "127.0.0.1", 0, Confirmation{Fingerprint: "SHA256:AA"})
	t.Logf("CLOSED-D21: %v", err)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "127.0.0.1:0")
}

func TestWF24_C_C20_Goroutines(t *testing.T) {
	s := newFakeServer(t)
	time.Sleep(100 * time.Millisecond)
	base := runtime.NumGoroutine()
	c := NewFTPClient(cfgFor(s, pinned(t, s)))
	require.NoError(t, c.Connect(ctx5(t)))
	for i := 0; i < 5; i++ {
		_, _ = c.ListDirectory(ctx5(t), "/")
		sk, err := c.OpenSeekable(ctx5(t), "big.bin")
		require.NoError(t, err)
		_, _ = sk.Seek(500, io.SeekStart)
		_, _ = sk.Read(make([]byte, 10))
		_ = sk.Close()
		ctx, cancel := context.WithCancel(context.Background())
		rc, err := c.ReadFile(ctx, "big.bin")
		require.NoError(t, err)
		_, _ = rc.Read(make([]byte, 10))
		cancel()
		_ = rc.Close()
	}
	require.NoError(t, c.Disconnect(ctx5(t)))
	time.Sleep(500 * time.Millisecond)
	after := runtime.NumGoroutine()
	t.Logf("CONTROL C20: goroutines base=%d after=%d", base, after)
	assert.LessOrEqual(t, after, base+2)
}

func TestWF24_C_C22_ReadOnlyScanPath(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	require.NoError(t, c.CreateDirectory(ctx5(t), "zz"))
	require.Equal(t, 1, s.count("MKD"), "needle: raw MKD is seen")
	s2 := newFakeServer(t)
	sc, err := NewScanClient(cfgFor(s2, pinned(t, s2)), ScanOptions{})
	require.NoError(t, err)
	require.NoError(t, sc.Connect(ctx5(t)))
	defer sc.Disconnect(context.Background())
	e := sc.CreateDirectory(ctx5(t), "zz")
	t.Logf("CONTROL C22: scan client MKD -> %v; MKD seen by server: %d", e, s2.count("MKD"))
	require.ErrorIs(t, e, decorators.ErrReadOnly)
	require.Zero(t, s2.count("MKD"))
	_, ok := sc.(client.SeekableClient)
	require.True(t, ok, "the scan client keeps OpenSeekable")
}

// ================================ NEW probes ================================

// N5 (correct-behaviour probe, the control for mutant NM02): a data connection presenting an UNPINNED certificate is refused.
func TestWF24_N5_DataChannelMITMRefused(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	other := genCert(t)
	var mu sync.Mutex
	var hsErr error
	served := false
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLSD" {
			return false, true
		}
		ss.reply("150 opening")
		if ss.pasv == nil {
			ss.reply("425 no")
			return true, true
		}
		if tl, ok := ss.pasv.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(5 * time.Second))
		}
		raw, err := ss.pasv.Accept()
		_ = ss.pasv.Close()
		ss.pasv = nil
		if err != nil {
			ss.reply("425 no")
			return true, true
		}
		tc := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{other}, MinVersion: tls.VersionTLS12})
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		herr := tc.Handshake()
		mu.Lock()
		hsErr = herr
		mu.Unlock()
		if herr == nil {
			served = true
			_, _ = io.WriteString(tc, "Type=file;Size=1;Modify=20200517103000; mitm.txt\r\n")
		}
		_ = tc.Close()
		ss.reply("226 done")
		return true, true
	})
	got, err := c.ListDirectory(ctx5(t), "/")
	mu.Lock()
	defer mu.Unlock()
	t.Logf("N5: client err=%v entries=%d; server-side handshake err=%v served=%v", err, len(got), hsErr, served)
	require.Error(t, err)
	require.False(t, served)
	var cve *tls.CertificateVerificationError
	var mm *CertMismatchError
	t.Logf("CONTROL N5 (data channel verifies the pin): x509=%v mismatch=%v", errors.As(err, &cve), errors.As(err, &mm))
}

// N8: a listing that drips one line every 200 ms is bounded only by ctx (IOTimeout bounds each read, not the transfer).
func TestWF24_N8_DrippingListing(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 500 * time.Millisecond })
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLSD" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		for i := 0; i < 15; i++ {
			if _, err := fmt.Fprintf(dc, "Type=file;Size=1;Modify=20200517103000; f%d\r\n", i); err != nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		_ = dc.Close()
		ss.reply("226 done")
		return true, true
	})
	start := time.Now()
	got, err := c.ListDirectory(context.Background(), "/")
	el := time.Since(start)
	t.Logf("N8: listing took %v with IOTimeout=500ms (%.1fx), entries=%d err=%v", el.Round(time.Millisecond), float64(el)/float64(500*time.Millisecond), len(got), err)
	require.NoError(t, err)
	require.Greater(t, el, 2*time.Second)
	t.Logf("DEFECT-REPRODUCED N8 (disclosed by the author): no whole-transfer bound other than ctx")
}

// N9: Disconnect does not abort an in-flight NON-stream operation (a stalled listing): it waits for IOTimeout.
func TestWF24_N9_DisconnectDoesNotAbortListing(t *testing.T) {
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 2 * time.Second })
	s.setHook(stallHook(map[string]bool{"MLSD": true}, rch))
	start := time.Now()
	var lerr error
	ldone := runAsync(func() { _, lerr = c.ListDirectory(context.Background(), "/") })
	time.Sleep(200 * time.Millisecond)
	short, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	derr := c.Disconnect(short)
	require.True(t, returnedWithin(ldone, 5*time.Second))
	el := time.Since(start)
	rel()
	t.Logf("N9: Disconnect=%v; the stalled listing returned after %v err=%v; open ctrl -> 0: %v", derr, el.Round(time.Millisecond), lerr, s.waitCtrl(0, 3*time.Second))
	require.Greater(t, el, time.Second)
	t.Logf("DEFECT-REPRODUCED N9 (documented scope: only streams are aborted): Disconnect cannot interrupt a stalled non-stream operation")
}

// N10 (control for NM09): USER answered with 230 logs in without sending PASS.
func TestWF24_N10_User230(t *testing.T) {
	s := newFakeServer(t)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "USER" {
			ss.authed = true
			ss.reply("230 logged in, no password needed")
			return true, true
		}
		return false, true
	})
	err := NewFTPClient(cfgFor(s, pinned(t, s))).Connect(ctx5(t))
	t.Logf("CONTROL N10: connect err=%v PASS sent=%d", err, s.count("PASS"))
	require.NoError(t, err)
	require.Zero(t, s.count("PASS"))
}

// N12 (control for NM01): a CR/LF in the configured base path never reaches the wire.
func TestWF24_N12_PathInjection(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	cfg.Path = "/data\r\nDELE /data/a.txt"
	err := NewFTPClient(cfg).Connect(ctx5(t))
	t.Logf("CONTROL N12: connect err=%v; DELE seen=%d", err, s.count("DELE"))
	require.Error(t, err)
	require.Zero(t, s.count("DELE"))
}

func (s *fakeServer) wfCtrl() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctrlConns
}

// N18 (control for NM10): bytes sent in clear text together with the 234 (STARTTLS response injection) are refused.
func TestWF24_N18_StartTLSInjectionRefused(t *testing.T) {
	s := newFakeServer(t)
	st := pinned(t, s)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "AUTH" {
			_, _ = io.WriteString(ss.conn, "234 AUTH TLS ok\r\n230 injected: logged in\r\n")
			return true, false
		}
		return false, true
	})
	err := NewFTPClient(cfgFor(s, st)).Connect(ctx5(t))
	t.Logf("CONTROL N18: connect err=%v USER sent=%d", err, s.count("USER"))
	require.ErrorIs(t, err, ErrProtocol)
	require.Zero(t, s.count("USER"))
}

// N15 control needle: the same instrument, no stray reply: every MLST answers for its own path.
func TestWF24_C_N15_NoStray(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	require.NoError(t, c.TestConnection(ctx5(t)))
	time.Sleep(400 * time.Millisecond)
	a, e1 := c.GetFileInfo(ctx5(t), "a.txt")
	fi, e2 := c.GetFileInfo(ctx5(t), "sub/c.txt")
	b, e3 := c.GetFileInfo(ctx5(t), "big.bin")
	t.Logf("CONTROL N15: sizes a=%v c=%v big=%v errs=%v %v %v", wfSize(a), wfSize(fi), wfSize(b), e1, e2, e3)
	require.Equal(t, int64(10), a.Size)
	require.Equal(t, int64(2), fi.Size)
	require.Equal(t, int64(100000), b.Size)
}
