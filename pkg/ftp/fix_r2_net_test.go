package ftp

// WF21 fix round 2 (11.4.276): the independent review's probes D1-D23 and controls C1-C23 are adopted here as
// PERMANENT tests that assert the CORRECT behaviour (each one failed against the pre-fix client; the defect probes
// asserted the defect). Reviewer-authored mutants MX01-MX28 have their killing tests below, named after them.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
)

// ---- helpers ------------------------------------------------------------------------------------------------------

func runAsync(f func()) <-chan struct{} {
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	return done
}

func returnedWithin(done <-chan struct{}, d time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func releaser(t *testing.T) (chan struct{}, func()) {
	ch := make(chan struct{})
	var once sync.Once
	rel := func() { once.Do(func() { close(ch) }) }
	t.Cleanup(rel)
	return ch, rel
}

// silentServer accepts TCP and then behaves per fn (nil = say nothing); release() closes everything.
func silentServer(t *testing.T, fn func(c net.Conn)) (int, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			if fn != nil {
				go fn(c)
			}
		}
	}()
	var once sync.Once
	rel := func() {
		once.Do(func() {
			_ = ln.Close()
			mu.Lock()
			for _, c := range conns {
				_ = c.Close()
			}
			mu.Unlock()
		})
	}
	t.Cleanup(rel)
	return ln.Addr().(*net.TCPAddr).Port, rel
}

type hookFn = func(ss *session, verb, arg string) (bool, bool)

// stallHook answers the transfer verbs with 150 and then holds the data connection open without sending a byte.
func stallHook(verbs map[string]bool, release <-chan struct{}) hookFn {
	return func(ss *session, verb, arg string) (bool, bool) {
		if !verbs[verb] {
			return false, true
		}
		ss.reply("150 opening data connection")
		dc, err := ss.openData()
		if err != nil {
			ss.reply("425 no data")
			return true, true
		}
		<-release
		_ = dc.Close()
		return true, false
	}
}

// mute makes the server swallow the listed verbs without ever answering (the control channel stalls).
func mute(verbs map[string]bool, release <-chan struct{}) hookFn {
	return func(ss *session, verb, arg string) (bool, bool) {
		if !verbs[verb] {
			return false, true
		}
		<-release
		return true, false
	}
}

// once421 answers the first occurrence of verb with 421 and closes the session.
func once421(verb string) hookFn {
	var mu sync.Mutex
	fired := false
	return func(ss *session, v, arg string) (bool, bool) {
		mu.Lock()
		defer mu.Unlock()
		if v != verb || fired {
			return false, true
		}
		fired = true
		ss.reply("421 Timeout - closing control connection")
		return true, false
	}
}

// slowHook streams 1 KiB chunks until released, then reports the abort.
func slowHook(release <-chan struct{}) hookFn {
	return func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		chunk := make([]byte, 1024)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-release:
				deadline = time.Now()
			default:
			}
			if _, err := dc.Write(chunk); err != nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		_ = dc.Close()
		ss.reply("426 aborted")
		return true, true
	}
}

func readFor(r io.Reader, d time.Duration) (int, error) {
	end := time.Now().Add(d)
	buf := make([]byte, 4096)
	total := 0
	for time.Now().Before(end) {
		n, err := r.Read(buf)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func fastCfg(s *fakeServer, st PinStore, d time.Duration) *Config {
	c := cfgFor(s, st)
	c.IOTimeout, c.DialTimeout = d, 5*time.Second
	return c
}

// ---- F1: deadlines on every phase (D1-D4 and the static members) ---------------------------------------------------

func TestDeadline_NoBanner_ConnectHonoursCtxAndDialTimeout_D1(t *testing.T) {
	for _, mode := range []string{TLSNone, TLSExplicit} {
		t.Run(mode+"/ctx", func(t *testing.T) {
			port, _ := silentServer(t, nil)
			cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: mode, TrustedLAN: true, PinStore: NewMemPinStore()}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			var cerr error
			start := time.Now()
			done := runAsync(func() { cerr = NewFTPClient(cfg).Connect(ctx) })
			require.True(t, returnedWithin(done, 3*time.Second), "Connect must give up when ctx ends (still blocked after %v)", time.Since(start))
			require.Error(t, cerr)
			assert.ErrorIs(t, cerr, context.DeadlineExceeded)
		})
		t.Run(mode+"/DialTimeout", func(t *testing.T) {
			port, _ := silentServer(t, nil)
			cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: mode, TrustedLAN: true, PinStore: NewMemPinStore(),
				DialTimeout: 300 * time.Millisecond, IOTimeout: 30 * time.Second}
			var cerr error
			done := runAsync(func() { cerr = NewFTPClient(cfg).Connect(context.Background()) })
			require.True(t, returnedWithin(done, 3*time.Second), "DialTimeout bounds the greeting")
			require.Error(t, cerr)
			assert.Equal(t, fabric.ClassTransient, fabric.Classify(cerr), "a silent server is a transient failure: %v", cerr)
		})
	}
}

func TestDeadline_C1_ServerClosesAtOnce_ConnectReturnsFast(t *testing.T) {
	port, _ := silentServer(t, func(c net.Conn) { _ = c.Close() })
	cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: TLSNone, TrustedLAN: true}
	start := time.Now()
	err := NewFTPClient(cfg).Connect(context.Background())
	require.Error(t, err)
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestDeadline_TLSHandshakeUnanswered_D2(t *testing.T) {
	port, _ := silentServer(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "220 hi\r\n")
		r := bufio.NewReader(c)
		line, _ := r.ReadString('\n')
		if strings.HasPrefix(strings.ToUpper(line), "AUTH") {
			_, _ = io.WriteString(c, "234 go ahead\r\n")
		}
		_, _ = io.Copy(io.Discard, r) // swallow the ClientHello, never answer
	})
	st := NewMemPinStore()
	require.NoError(t, st.Record(HostPort("127.0.0.1", port), genCertT(t)))
	cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", PinStore: st, DialTimeout: 400 * time.Millisecond, IOTimeout: 30 * time.Second}
	var cerr error
	start := time.Now()
	done := runAsync(func() { cerr = NewFTPClient(cfg).Connect(context.Background()) })
	require.True(t, returnedWithin(done, 3*time.Second), "DialTimeout bounds the TLS handshake (blocked %v)", time.Since(start))
	require.Error(t, cerr)
}

func TestDeadline_MLSDStall_ListDirectoryHonoursIOTimeoutAndCtx_D3(t *testing.T) {
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 300 * time.Millisecond })
	s.setHook(stallHook(map[string]bool{"MLSD": true}, rch))
	var lerr error
	start := time.Now()
	done := runAsync(func() { _, lerr = c.ListDirectory(ctx5(t), "/") })
	require.True(t, returnedWithin(done, 3*time.Second), "a stalled MLSD data connection must hit IOTimeout (blocked %v)", time.Since(start))
	require.Error(t, lerr)
	assert.False(t, c.IsConnected(), "a timed-out transfer leaves the connection unusable: it is dropped")
	// and the session is free for the next caller (D3 showed a second caller stuck behind the hang)
	rel()
	s.setHook(nil)
	_, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.Equal(t, 2, s.ctrlConns, "the next operation re-dialled")

	// the same with ctx: IOTimeout is long, the caller's deadline is short
	s2 := newFakeServer(t)
	rch2, _ := releaser(t)
	c2 := connected(t, s2, nil)
	s2.setHook(stallHook(map[string]bool{"MLSD": true}, rch2))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done = runAsync(func() { _, lerr = c2.ListDirectory(ctx, "/") })
	require.True(t, returnedWithin(done, 3*time.Second), "ctx ends a blocked listing")
	assert.ErrorIs(t, lerr, context.DeadlineExceeded)
}

func TestDeadline_C3_RETRStall_IOTimeoutHonoured(t *testing.T) {
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 300 * time.Millisecond })
	s.setHook(stallHook(map[string]bool{"RETR": true}, rch))
	rc, err := c.ReadFile(ctx5(t), "a.txt")
	require.NoError(t, err)
	start := time.Now()
	_, rerr := rc.Read(make([]byte, 16))
	require.Error(t, rerr)
	require.Less(t, time.Since(start), 3*time.Second)
	rel()
	closed := runAsync(func() { _ = rc.Close() })
	require.True(t, returnedWithin(closed, 5*time.Second))
}

func TestDeadline_NoFinalReply_CloseIsBounded_DisconnectStillWorks_D4(t *testing.T) {
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
		<-rch // never sends 226
		return true, false
	})
	rc, err := c.ReadFile(ctx5(t), "a.txt")
	require.NoError(t, err)
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, "hello", string(b))
	var cerr error
	closed := runAsync(func() { cerr = rc.Close() })
	require.True(t, returnedWithin(closed, 3*time.Second), "Close waits at most IOTimeout for the final reply")
	require.Error(t, cerr, "a transfer whose final reply never came cannot be confirmed")
	assert.False(t, c.IsConnected())
	dctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, c.Disconnect(dctx))
	rel()
}

// every control command is bounded, not only the data reads (the static members of F1)
func TestDeadline_EveryControlCommandIsBounded(t *testing.T) {
	type tc struct {
		verb string
		op   func(c *Client) error
	}
	cases := []tc{
		{"NOOP", func(c *Client) error { return c.TestConnection(ctx5(t)) }},
		{"MLST", func(c *Client) error { _, err := c.GetFileInfo(ctx5(t), "a.txt"); return err }},
		{"SIZE", func(c *Client) error { _, err := c.OpenSeekable(ctx5(t), "big.bin"); return err }},
		{"EPSV", func(c *Client) error { _, err := c.ListDirectory(ctx5(t), "/"); return err }},
		{"MKD", func(c *Client) error { return c.CreateDirectory(ctx5(t), "zz") }},
		{"DELE", func(c *Client) error { return c.DeleteFile(ctx5(t), "a.txt") }},
	}
	for _, k := range cases {
		t.Run(k.verb, func(t *testing.T) {
			s := newFakeServer(t)
			rch, _ := releaser(t)
			c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 300 * time.Millisecond })
			s.setHook(mute(map[string]bool{k.verb: true}, rch))
			var err error
			start := time.Now()
			done := runAsync(func() { err = k.op(c) })
			require.True(t, returnedWithin(done, 3*time.Second), "%s: the reply never came and nothing gave up (%v)", k.verb, time.Since(start))
			require.Error(t, err)
			assert.False(t, c.IsConnected(), "%s: a connection that timed out is dropped", k.verb)
		})
	}
	for _, verb := range []string{"USER", "PASS", "FEAT", "TYPE", "OPTS", "PBSZ", "PROT", "CWD", "PWD"} {
		t.Run("connect/"+verb, func(t *testing.T) {
			s := newFakeServer(t)
			cfg := fastCfg(s, pinned(t, s), 300*time.Millisecond)
			rch, _ := releaser(t)
			s.setHook(mute(map[string]bool{verb: true}, rch))
			var err error
			start := time.Now()
			done := runAsync(func() { err = NewFTPClient(cfg).Connect(ctx5(t)) })
			require.True(t, returnedWithin(done, 4*time.Second), "Connect hangs at %s (%v)", verb, time.Since(start))
			require.Error(t, err)
			if verb == "PASS" {
				assert.NotEqual(t, fabric.ClassTransient, fabric.Classify(err), "no reply after PASS must not be retried: %v", err)
			}
		})
	}
	t.Run("control_unstalled_verb_works", func(t *testing.T) {
		s := newFakeServer(t)
		rch, _ := releaser(t)
		c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 300 * time.Millisecond })
		s.setHook(mute(map[string]bool{"DELE": true}, rch))
		require.NoError(t, c.TestConnection(ctx5(t)))
	})
}

// A stream whose data read timed out is dropped by Close at once: nothing is awaited from a server that already stalled.
func TestStreamTimeout_CloseDoesNotWaitForTheFinalReply(t *testing.T) {
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = time.Second })
	s.setHook(stallHook(map[string]bool{"RETR": true}, rch))
	rc, err := c.ReadFile(ctx5(t), "a.txt")
	require.NoError(t, err)
	_, rerr := rc.Read(make([]byte, 8))
	require.Error(t, rerr, "the stalled data connection times out")
	start := time.Now()
	var cerr error
	closed := runAsync(func() { cerr = rc.Close() })
	require.True(t, returnedWithin(closed, 3*time.Second), "Close hangs waiting for a final reply that never comes")
	require.NoError(t, cerr)
	assert.Less(t, time.Since(start), 500*time.Millisecond, "Close must not wait another IOTimeout for a final reply on a connection that already failed")
	assert.False(t, c.IsConnected())
	rel()
}

func TestCancel_InterruptsBlockedControlCommand(t *testing.T) {
	s := newFakeServer(t)
	rch, _ := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 30 * time.Second })
	s.setHook(mute(map[string]bool{"MLST": true}, rch))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	var err error
	start := time.Now()
	done := runAsync(func() { _, err = c.GetFileInfo(ctx, "a.txt") })
	require.True(t, returnedWithin(done, 3*time.Second), "cancel must interrupt a blocked reply read (%v)", time.Since(start))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestDiscoverCert_StalledBanner_HonoursTimeout_MX11(t *testing.T) {
	port, _ := silentServer(t, nil)
	var err error
	start := time.Now()
	done := runAsync(func() { _, err = DiscoverCert(context.Background(), "127.0.0.1", port, 300*time.Millisecond) })
	require.True(t, returnedWithin(done, 3*time.Second), "DiscoverCert must honour its timeout (%v)", time.Since(start))
	require.Error(t, err)
	// ctx cancellation too
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()
	done = runAsync(func() { _, err = DiscoverCert(ctx, "127.0.0.1", port, 30*time.Second) })
	require.True(t, returnedWithin(done, 3*time.Second), "DiscoverCert must honour ctx")
	require.Error(t, err)
}

// ---- F2: reply discipline, 421, desync (D5, D6) --------------------------------------------------------------------

func earlyCloseHook(s *fakeServer, extra226 bool) hookFn {
	return func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" || arg != "/data/a.txt" {
			return false, true
		}
		f, _ := s.lookup(arg)
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = dc.Write(f.data)
		_ = dc.Close()
		ss.reply("426 Connection closed; transfer aborted.")
		if extra226 {
			ss.reply("226 Transfer complete.")
		}
		return true, true
	}
}

func TestDesync_ExtraReplyAfterEarlyClose_NeverAnswersAnotherCommand_D6(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprintf("extra226=%v", extra), func(t *testing.T) {
			s := newFakeServer(t)
			c := connected(t, s, nil)
			s.setHook(earlyCloseHook(s, extra))
			rc, err := c.ReadFile(ctx5(t), "a.txt")
			require.NoError(t, err)
			_, _ = rc.Read(make([]byte, 1))
			require.NoError(t, rc.Close(), "an early close is not an error")
			s.setHook(nil)
			fi, e2 := c.GetFileInfo(ctx5(t), "sub/c.txt")
			require.NoError(t, e2)
			assert.Equal(t, int64(2), fi.Size, "c.txt's own size, never a.txt's (10) from a stale reply")
			assert.True(t, fi.ModTime.Equal(t0.Add(72*time.Hour)))
			ok, e3 := c.FileExists(ctx5(t), "missing.txt")
			require.NoError(t, e3)
			assert.False(t, ok, "a missing file must not read as present")
			ok, _ = c.FileExists(ctx5(t), "a.txt")
			assert.True(t, ok)
			if extra {
				assert.Equal(t, 2, s.ctrlConns, "the out-of-step connection was dropped and the client re-dialled")
			} else {
				assert.Equal(t, 1, s.ctrlConns, "a server that answers an early close with ONE reply keeps its connection (no needless re-dial)")
			}
		})
	}
}

// Measured against the real pure-ftpd (fixture, TLS): a download closed early is answered with ONE reply, "150 <stats>",
// not with 226/426. That is a legal single reply: the connection stays, and the next commands are answered correctly.
func TestEarlyClose_PureFTPdStyleSingle150Reply_KeepsTheConnection(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" || arg != "/data/big.bin" {
			return false, true
		}
		f, _ := s.lookup(arg)
		ss.reply("150-Accepted data connection")
		ss.reply("150 %d.0 kbytes to download", len(f.data)/1024)
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = dc.Write(f.data)
		_ = dc.Close()
		ss.reply("150 0.001 seconds (measured here), 533.08 Mbytes per second")
		return true, true
	})
	rc, err := c.ReadFile(ctx5(t), "big.bin")
	require.NoError(t, err)
	_, err = io.ReadFull(rc, make([]byte, 10))
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	s.setHook(nil)
	fi, err := c.GetFileInfo(ctx5(t), "sub/c.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(2), fi.Size)
	assert.Equal(t, 1, s.ctrlConns, "one reply to the early close: nothing to re-dial for")
}

func TestDesync_UnsolicitedReplyIsNeverTakenForAnAnswer(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	first := true
	var mu sync.Mutex
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		mu.Lock()
		defer mu.Unlock()
		if verb == "NOOP" && first {
			first = false
			ss.reply("200 ok")
			ss.reply("226 stray reply nobody asked for")
			return true, true
		}
		return false, true
	})
	require.NoError(t, c.TestConnection(ctx5(t)))
	time.Sleep(100 * time.Millisecond)
	fi, err := c.GetFileInfo(ctx5(t), "sub/c.txt")
	if err == nil {
		assert.Equal(t, int64(2), fi.Size, "if the call succeeded it must be c.txt's own data")
	}
	fi, err = c.GetFileInfo(ctx5(t), "sub/c.txt")
	require.NoError(t, err, "the client recovered with a fresh connection")
	assert.Equal(t, int64(2), fi.Size)
}

func TestUnexpectedPositiveReply_DropsTheConnection(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "NOOP" {
			ss.reply("226 transfer complete") // positive, but not the answer to NOOP
			return true, true
		}
		return false, true
	})
	err := c.TestConnection(ctx5(t))
	require.ErrorIs(t, err, ErrProtocol)
	assert.False(t, c.IsConnected())
}

func TestReply421_MarksTheConnectionLost_RetryRecovers_D5(t *testing.T) {
	pol := &fabric.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}
	{ // control C5: a silent drop is recovered within 2 attempts
		s := newFakeServer(t)
		sc, err := NewScanClient(cfgFor(s, pinned(t, s)), ScanOptions{Retry: pol})
		require.NoError(t, err)
		require.NoError(t, sc.Connect(ctx5(t)))
		s.dropNext("MLSD", 1)
		_, err = sc.ListDirectory(ctx5(t), "/")
		require.NoError(t, err)
		_ = sc.Disconnect(context.Background())
	}
	s := newFakeServer(t)
	raw := NewFTPClient(cfgFor(s, pinned(t, s)))
	require.NoError(t, raw.Connect(ctx5(t)))
	s.setHook(once421("MLSD"))
	_, err := raw.ListDirectory(ctx5(t), "/")
	require.Error(t, err)
	assert.False(t, raw.IsConnected(), "421 means the server is closing: the connection is unusable")
	assert.Equal(t, fabric.ClassTransient, fabric.Classify(err))
	_ = raw.Disconnect(context.Background())

	s2 := newFakeServer(t)
	sc, err := NewScanClient(cfgFor(s2, pinned(t, s2)), ScanOptions{Retry: pol})
	require.NoError(t, err)
	require.NoError(t, sc.Connect(ctx5(t)))
	defer sc.Disconnect(context.Background())
	s2.setHook(once421("MLSD"))
	got, err := sc.ListDirectory(ctx5(t), "/")
	require.NoError(t, err, "a 421 costs one attempt, not the whole budget")
	assert.NotEmpty(t, got)
	assert.Equal(t, 2, s2.ctrlConns)
}

// ---- F3: cancellation and Disconnect between reads (D9, D9b, C9, MX01, MX02) ----------------------------------------

func TestCancelBetweenReads_IsHonoured_D9(t *testing.T) {
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
	time.Sleep(200 * time.Millisecond) // no Read in flight when the cancellation lands
	n, rerr := readFor(rc, time.Second)
	rel()
	_ = rc.Close()
	require.Error(t, rerr, "a cancelled context ends the stream")
	assert.ErrorIs(t, rerr, context.Canceled)
	assert.Less(t, n, 16*1024, "no more than what was already in flight may arrive after the cancellation")
}

func TestC9_CancelDuringBlockedRead_IsHonoured_MX02(t *testing.T) {
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 20 * time.Second })
	s.setHook(stallHook(map[string]bool{"RETR": true}, rch))
	ctx, cancel := context.WithCancel(context.Background())
	rc, err := c.ReadFile(ctx, "big.bin")
	require.NoError(t, err)
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	_, rerr := rc.Read(make([]byte, 10))
	el := time.Since(start)
	require.Error(t, rerr)
	require.Less(t, el, 2*time.Second, "the watcher must break a blocked Read (IOTimeout is 20 s here)")
	closeStart := time.Now()
	done := runAsync(func() { _ = rc.Close() })
	require.True(t, returnedWithin(done, 2*time.Second), "Close of a cancelled stream must not wait for a final reply that never comes (IOTimeout is 20 s here; waited %v)", time.Since(closeStart))
	rel()
}

func TestDisconnectBetweenReads_AbortsTheStream_D9b_MX01(t *testing.T) {
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
	time.Sleep(200 * time.Millisecond) // Disconnect aborts while no Read is in flight
	n, rerr := readFor(rc, time.Second)
	rel()
	_ = rc.Close()
	require.True(t, returnedWithin(ddone, 5*time.Second))
	require.NoError(t, derr)
	require.Error(t, rerr, "Disconnect ends the stream")
	assert.ErrorIs(t, rerr, ErrAborted)
	assert.Less(t, n, 16*1024)
	assert.True(t, s.waitCtrl(0, 3*time.Second), "the connection is closed")
}

// ---- F4: a transfer the server cut short is never a complete file (D8, C8, MX07) -----------------------------------

func truncHook(s *fakeServer) hookFn {
	return func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" || arg != "/data/big.bin" {
			return false, true
		}
		f, _ := s.lookup(arg)
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = dc.Write(f.data[:1000])
		_ = dc.Close()
		ss.reply("451 Requested action aborted: local error in processing")
		return true, true
	}
}

func TestSeekable_TruncatedTransfer_IsAnError_D8(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(truncHook(s))
	rc, err := c.ReadFile(ctx5(t), "big.bin") // control C8: ReadFile surfaces the abort at Close
	require.NoError(t, err)
	b, rerr := io.ReadAll(rc)
	cerr := rc.Close()
	require.NoError(t, rerr)
	assert.Len(t, b, 1000)
	require.Error(t, cerr, "C8/MX07: the 451 after a COMPLETE read is visible at Close")
	assert.Contains(t, cerr.Error(), "451")

	sk, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	all, err := io.ReadAll(sk)
	_ = sk.Close()
	require.Error(t, err, "OpenSeekable must not hand out %d bytes of a 100000-byte file as complete", len(all))
	assert.Len(t, all, 1000)
	assert.Contains(t, err.Error(), "451", "the server's own reason for giving up is reported, not a generic short read: %v", err)
}

func TestSeekable_ServerEndsEarlyWithA226_IsUnexpectedEOF(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" {
			return false, true
		}
		f, _ := s.lookup(arg)
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = dc.Write(f.data[:500])
		_ = dc.Close()
		ss.reply("226 Transfer complete.") // lies: 500 of 100000 bytes
		return true, true
	})
	sk, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	defer sk.Close()
	_, err = io.ReadAll(sk)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF, "fewer bytes than SIZE announced is an error even when the server says 226")
}

func TestReadFile_FullReadWith451_ClosesWithTheError_MX07(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" {
			return false, true
		}
		f, _ := s.lookup(arg)
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = dc.Write(f.data)
		_ = dc.Close()
		ss.reply("451 local error in processing")
		return true, true
	})
	rc, err := c.ReadFile(ctx5(t), "a.txt")
	require.NoError(t, err)
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "hello ftp\n", string(b))
	assert.Error(t, rc.Close(), "all bytes arrived but the server reports a failure: not a clean transfer")
}

// ---- F5: login phases (D11, D12, D23, MX06, MX09) --------------------------------------------------------------------

func TestLogin_USER421_IsTransient_NotAuth_PoolDoesNotLatch_D23(t *testing.T) {
	// control C23: a 421 banner is transient
	port, _ := silentServer(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "421 Too many connections (5) from this IP\r\n")
		_ = c.Close()
	})
	berr := NewFTPClient(&Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: TLSNone, TrustedLAN: true}).Connect(ctx5(t))
	require.Equal(t, fabric.ClassTransient, fabric.Classify(berr))

	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	s.setHook(once421("USER"))
	raw := NewFTPClient(cfg)
	err := raw.Connect(ctx5(t))
	require.Error(t, err)
	assert.Equal(t, fabric.ClassTransient, fabric.Classify(err), "421 at USER is RFC 959 'service closing, try again': %v", err)

	s2 := newFakeServer(t)
	cfg2 := cfgFor(s2, pinned(t, s2))
	var mu sync.Mutex
	n := 0
	s2.setHook(func(ss *session, verb, arg string) (bool, bool) {
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
	pool, err := NewWorkerPool(cfg2, fabric.PoolOptions{MaxPerKey: 2}, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond}})
	require.NoError(t, err)
	defer pool.CloseAll()
	sc := &client.StorageConfig{ID: "root1", Protocol: "ftp"}
	c, err := pool.GetClientContext(ctx5(t), sc)
	require.NoError(t, err, "the transient 421 is retried and the borrow succeeds")
	require.NoError(t, pool.ReturnClient(c))
	c2, err := pool.GetClientContext(ctx5(t), sc)
	require.NoError(t, err, "the root is not latched as a rejected login")
	require.NoError(t, pool.ReturnClient(c2))
	assert.Equal(t, 2, s2.count("USER"))
}

func TestLogin_NoReplyAfterPASS_IsNeverRetried_D11(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	s.dropNext("PASS", 10)
	sc, err := NewScanClient(cfg, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond}})
	require.NoError(t, err)
	err = sc.Connect(ctx5(t))
	require.Error(t, err)
	assert.Equal(t, 1, s.count("PASS"), "the password is sent once: a retry after an unanswered PASS risks a lockout")
	assert.Equal(t, fabric.ClassPermanent, fabric.Classify(err), "%v", err)
	assert.NotContains(t, err.Error(), "pw")
}

func TestLogin_PASSReplies_ClassifiedByCode(t *testing.T) {
	for code, want := range map[int]fabric.ErrorClass{530: fabric.ClassAuth, 430: fabric.ClassAuth, 534: fabric.ClassAuth, 535: fabric.ClassAuth,
		503: fabric.ClassPermanent, 421: fabric.ClassPermanent, 500: fabric.ClassPermanent} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			s := newFakeServer(t)
			s.loginCode = code
			if want == fabric.ClassPermanent { // neutral text: "Login incorrect" would (rightly) read as a credential failure
				s.setHook(func(ss *session, verb, arg string) (bool, bool) {
					if verb == "PASS" {
						ss.reply("%d Bad sequence of commands", code)
						return true, true
					}
					return false, true
				})
			}
			cfg := cfgFor(s, pinned(t, s))
			cfg.Resolver = mapResolver{"ref": "WRONG"}
			sc, err := NewScanClient(cfg, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond}})
			require.NoError(t, err)
			err = sc.Connect(ctx5(t))
			require.Error(t, err)
			assert.Equal(t, want, fabric.Classify(err), "%v", err)
			assert.Equal(t, 1, s.count("PASS"), "never resent")
		})
	}
}

func TestLogin_USER530_IsAuth(t *testing.T) {
	s := newFakeServer(t)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "USER" {
			ss.reply("530 User not allowed to log in")
			return true, true
		}
		return false, true
	})
	err := NewFTPClient(cfgFor(s, pinned(t, s))).Connect(ctx5(t))
	require.Error(t, err)
	assert.Equal(t, fabric.ClassAuth, fabric.Classify(err))
}

func TestLogin_ConfigRefusals_AreNotAuthFailures_D12(t *testing.T) {
	for _, verb := range []string{"PROT", "PBSZ", "TYPE"} {
		t.Run(verb, func(t *testing.T) {
			s := newFakeServer(t)
			cfg := cfgFor(s, pinned(t, s))
			s.setHook(func(ss *session, v, arg string) (bool, bool) {
				if v == verb {
					ss.reply("536 %s not supported", verb)
					return true, true
				}
				return false, true
			})
			err := NewFTPClient(cfg).Connect(ctx5(t))
			require.Error(t, err)
			assert.Equal(t, fabric.ClassPermanent, fabric.Classify(err), "a %s refusal after a good login is a configuration failure: %v", verb, err)
			assert.Contains(t, err.Error(), verb)
		})
	}
	t.Run("FEAT_refused_means_no_features", func(t *testing.T) {
		s := newFakeServer(t)
		s.tlsOn = false
		cfg := cfgFor(s, nil)
		cfg.TLSMode, cfg.TrustedLAN = TLSNone, true
		s.setHook(func(ss *session, v, arg string) (bool, bool) {
			if v == "FEAT" {
				ss.reply("500 FEAT not understood")
				return true, true
			}
			return false, true
		})
		c := NewFTPClient(cfg)
		require.NoError(t, c.Connect(ctx5(t)))
		defer c.Disconnect(context.Background())
		assert.True(t, c.Degraded(), "no FEAT, no MLST: degraded")
	})
	t.Run("tls_version_is_not_auth", func(t *testing.T) {
		s := newFakeServer(t)
		st := pinned(t, s)
		old := newFakeServer(t)
		old.cert = s.cert
		old.tlsOnly11 = true
		pins, _ := st.Lookup(HostPort("127.0.0.1", s.port()))
		require.NoError(t, st.Record(HostPort("127.0.0.1", old.port()), pins[0]))
		err := NewFTPClient(cfgFor(old, st)).Connect(ctx5(t))
		require.Error(t, err)
		assert.NotEqual(t, fabric.ClassAuth, fabric.Classify(err))
		assert.Zero(t, old.count("USER"))
	})
}

func TestLogin_OPTSUTF8Refused_ConnectsButNeverCataloguesGarbledNames_D12c(t *testing.T) {
	refuse := func(code int, text string) hookFn {
		return func(ss *session, verb, arg string) (bool, bool) {
			if verb == "OPTS" {
				ss.reply("%d %s", code, text)
				return true, true
			}
			return false, true
		}
	}
	t.Run("tls_garbled_names", func(t *testing.T) {
		s := newFakeServer(t)
		s.legacyName = true // Synology: 0x7f for every non-ASCII name until OPTS UTF8 ON
		cfg := cfgFor(s, pinned(t, s))
		s.setHook(refuse(500, "OPTS not understood"))
		c := NewFTPClient(cfg)
		require.NoError(t, c.Connect(ctx5(t)), "a refusal alone is not a login failure")
		defer c.Disconnect(context.Background())
		_, err := c.ListDirectory(ctx5(t), "/")
		require.ErrorIs(t, err, ErrUTF8Refused, "names garbled to 0x7f must never be catalogued")
		assert.Equal(t, fabric.ClassPermanent, fabric.Classify(err))
		assert.True(t, c.IsConnected(), "the listing was read to its end: the connection is fine")
	})
	t.Run("clear_garbled_names", func(t *testing.T) {
		s := newFakeServer(t)
		s.tlsOn = false
		s.legacyName = true
		cfg := cfgFor(s, nil)
		cfg.TLSMode, cfg.TrustedLAN = TLSNone, true
		s.setHook(refuse(500, "OPTS not understood"))
		c := NewFTPClient(cfg)
		require.NoError(t, c.Connect(ctx5(t)), "clear text: also not an authentication failure")
		defer c.Disconnect(context.Background())
		_, err := c.ListDirectory(ctx5(t), "/")
		require.ErrorIs(t, err, ErrUTF8Refused)
	})
	t.Run("pure_ftpd_style_504_with_valid_utf8_names_is_fine", func(t *testing.T) {
		s := newFakeServer(t) // legacyName false: the server really speaks UTF-8
		s.setHook(refuse(504, "Unknown command"))
		c := NewFTPClient(cfgFor(s, pinned(t, s)))
		require.NoError(t, c.Connect(ctx5(t)))
		defer c.Disconnect(context.Background())
		got, err := c.ListDirectory(ctx5(t), "/")
		require.NoError(t, err)
		var names []string
		for _, f := range got {
			names = append(names, f.Name)
		}
		assert.Contains(t, names, "Čšž_日本.txt")
	})
	t.Run("accepted_switch_never_checks_names", func(t *testing.T) {
		s := newFakeServer(t)
		s.legacyName = true
		c := connected(t, s, nil) // OPTS UTF8 ON accepted by the fake: names are real
		got, err := c.ListDirectory(ctx5(t), "/")
		require.NoError(t, err)
		assert.NotEmpty(t, got)
	})
	t.Run("202_already_utf8_is_accepted", func(t *testing.T) {
		s := newFakeServer(t)
		s.setHook(refuse(202, "UTF8 mode is always enabled"))
		c := NewFTPClient(cfgFor(s, pinned(t, s)))
		require.NoError(t, c.Connect(ctx5(t)))
		_ = c.Disconnect(context.Background())
	})
	t.Run("4yz_is_transient", func(t *testing.T) {
		s := newFakeServer(t)
		s.setHook(refuse(450, "try later"))
		err := NewFTPClient(cfgFor(s, pinned(t, s))).Connect(ctx5(t))
		require.Error(t, err)
		assert.Equal(t, fabric.ClassTransient, fabric.Classify(err))
	})
}

func TestLogin_NetworkFailureBeforePASS_StaysRetryable_MX06(t *testing.T) {
	s := newFakeServer(t)
	sc, err := NewScanClient(cfgFor(s, pinned(t, s)), ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond}})
	require.NoError(t, err)
	s.dropNext("USER", 1)
	require.NoError(t, sc.Connect(ctx5(t)), "a connection lost before any credential was sent is retried")
	defer sc.Disconnect(context.Background())
	assert.Equal(t, 2, s.ctrlConns)
}

func TestFailedLogin_SaysQuitAndClosesTheConnection_MX09(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	cfg.Resolver = mapResolver{"ref": "WRONG"}
	require.Error(t, NewFTPClient(cfg).Connect(ctx5(t)))
	assert.True(t, s.waitCtrl(0, 3*time.Second), "the control connection of a failed login must be closed")
	assert.GreaterOrEqual(t, s.count("QUIT"), 1, "and the client says goodbye")
}

// ---- F11: Disconnect (D19, C19, MX18, MX19) ---------------------------------------------------------------------

func TestDisconnect_SaysQuitAndClosesTheConnection_MX19(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	require.NoError(t, c.Disconnect(ctx5(t)))
	assert.True(t, s.waitCtrl(0, 3*time.Second), "the server must see the connection closed")
	assert.Equal(t, 1, s.count("QUIT"))
}

func TestLostConnection_IsClosed_NotLeaked_MX18(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "NOOP" {
			ss.reply("226 transfer complete") // out of step: the client must drop the connection
			return true, true
		}
		return false, true
	})
	require.Error(t, c.TestConnection(ctx5(t)))
	assert.True(t, s.waitCtrl(0, 3*time.Second), "a connection the client gave up on must be closed, not left open on the server")
}

func TestDisconnectTimeout_DoesNotLeakTheControlConnection_D19(t *testing.T) {
	s := newFakeServer(t)
	c := NewFTPClient(cfgFor(s, pinned(t, s)))
	require.NoError(t, c.Connect(ctx5(t)))
	rc, err := c.ReadFile(ctx5(t), "a.txt")
	require.NoError(t, err)
	short, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() { time.Sleep(600 * time.Millisecond); _, _ = io.Copy(io.Discard, rc); _ = rc.Close() }()
	derr := c.Disconnect(short)
	require.ErrorIs(t, derr, context.DeadlineExceeded)
	assert.True(t, s.waitCtrl(0, 3*time.Second), "once the holder lets go the connection is closed without a second Disconnect")
	assert.False(t, c.IsConnected())
	require.NoError(t, c.Disconnect(ctx5(t))) // C19: still idempotent
}

func TestDisconnectWithCancelledContext_StillClosesAnIdleConnection(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = c.Disconnect(ctx)
	assert.True(t, s.waitCtrl(0, 3*time.Second))
}

func TestConnectAfterTimedOutDisconnect_DoesNotOverwriteALiveConnection(t *testing.T) {
	s := newFakeServer(t)
	c := NewFTPClient(cfgFor(s, pinned(t, s)))
	require.NoError(t, c.Connect(ctx5(t)))
	rc, err := c.ReadFile(ctx5(t), "big.bin")
	require.NoError(t, err)
	short, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	require.Error(t, c.Disconnect(short))
	_ = rc.Close()
	require.NoError(t, c.Connect(ctx5(t)))
	defer c.Disconnect(context.Background())
	_, err = c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.True(t, s.waitCtrl(1, 3*time.Second), "exactly one connection is open: the old one was closed, the new one is live")
}

// ---- pins: MX04, MX05, MX12, MX28, F14, F15 --------------------------------------------------------------------

func genCASigned(t *testing.T, dns []string, ips []net.IP) (leaf tls.Certificate, caDER []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "fake-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err = x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano() + 1), Subject: pkix.Name{CommonName: "fake-leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: dns, IPAddresses: ips}
	der, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}, caDER
}

func TestTLS_CASignedLeaf_IsRefused_WhenOnlyTheCAIsPinned_MX04(t *testing.T) {
	s := newFakeServer(t)
	leaf, caDER := genCASigned(t, nil, []net.IP{net.ParseIP("127.0.0.1")})
	s.cert = leaf
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	st := NewMemPinStore()
	require.NoError(t, st.Record(HostPort("127.0.0.1", s.port()), CertPin{Fingerprint: Fingerprint(ca), ServerName: "127.0.0.1", CertDER: caDER}))
	err = NewFTPClient(cfgFor(s, st)).Connect(ctx5(t))
	var mm *CertMismatchError
	require.ErrorAs(t, err, &mm, "the chain verifies against the pinned CA, but the leaf is not a pinned certificate: the pin check refuses it")
	assert.Zero(t, s.count("USER"), "no credential was sent")
}

func TestTLS_PinnedServerName_IsUsedForVerification_MX05_MX12(t *testing.T) {
	s := newFakeServer(t)
	s.cert = genCertNames(t, []string{"nas.test"}, nil) // valid for a NAME only; we connect to 127.0.0.1
	st := NewMemPinStore()
	pin, err := Pin(ctx5(t), st, "127.0.0.1", s.port(), Confirmation{Fingerprint: certFingerprint(t, s.cert), ConfirmedBy: "o"})
	require.NoError(t, err)
	assert.Equal(t, "nas.test", pin.ServerName, "Pin records the name the certificate is valid for, not the dialled address")
	s.resetCounters()
	c := NewFTPClient(cfgFor(s, st))
	require.NoError(t, c.Connect(ctx5(t)), "SNI and verification use the pinned name")
	_ = c.Disconnect(context.Background())
}

func TestPin_ConfirmationThatIsOnlyAPrefix_IsRefused_MX28(t *testing.T) {
	s := newFakeServer(t)
	fp := certFingerprint(t, s.cert)
	for _, partial := range []string{fp[:len(fp)-3], "SHA256:" + NormalizeFingerprint(fp)[:8], fp + "00"} {
		st := NewMemPinStore()
		_, err := Pin(ctx5(t), st, "127.0.0.1", s.port(), Confirmation{Fingerprint: partial})
		require.ErrorIs(t, err, ErrPinNotConfirmed, partial)
		got, _ := st.Lookup(HostPort("127.0.0.1", s.port()))
		assert.Empty(t, got)
	}
}

func TestPin_PortZero_MeansTheFTPDefaultPort_F14(t *testing.T) {
	_, err := Pin(ctx5(t), NewMemPinStore(), "127.0.0.1", 0, Confirmation{Fingerprint: "SHA256:AA"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "127.0.0.1:0", "port 0 must dial 21 like Connect does")
	assert.Contains(t, err.Error(), "127.0.0.1:21")
	_, err = DiscoverCert(ctx5(t), "127.0.0.1", 0, time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "127.0.0.1:21")
}

func TestPin_SecondServerNameForTheSameHost_IsRefused_F15(t *testing.T) {
	s := newFakeServer(t)
	s.cert = genCertNames(t, []string{"new.test"}, nil)
	st := NewMemPinStore()
	hp := HostPort("127.0.0.1", s.port())
	require.NoError(t, st.Record(hp, CertPin{Fingerprint: "SHA256:00:11", ServerName: "old.test"}))
	_, err := Pin(ctx5(t), st, "127.0.0.1", s.port(), Confirmation{Fingerprint: certFingerprint(t, s.cert)})
	require.ErrorIs(t, err, ErrPinNameConflict)
	got, _ := st.Lookup(hp)
	assert.Len(t, got, 1, "nothing was recorded")
	// after the owner removed the old pin the rotation is accepted
	require.NoError(t, st.Remove(hp, "SHA256:00:11"))
	_, err = Pin(ctx5(t), st, "127.0.0.1", s.port(), Confirmation{Fingerprint: certFingerprint(t, s.cert)})
	require.NoError(t, err)
	// the same certificate pinned again is idempotent, not a conflict
	_, err = Pin(ctx5(t), st, "127.0.0.1", s.port(), Confirmation{Fingerprint: certFingerprint(t, s.cert)})
	require.NoError(t, err)
}

// ---- MX13, MX14, MX17 ------------------------------------------------------------------------------------------------

func TestDegraded_IsKnownRightAfterConnect_MX13(t *testing.T) {
	s := newFakeServer(t)
	s.mlst = false
	c := connected(t, s, func(cfg *Config) { cfg.AllowDegradedList = true })
	assert.True(t, c.Degraded(), "known at connect, before any listing")
	s2 := newFakeServer(t)
	c2 := connected(t, s2, nil)
	assert.False(t, c2.Degraded())
}

func TestDefaultRetryPolicy_IsThreeAttempts_MX17(t *testing.T) {
	p := ScanOptions{}.retry()
	assert.Equal(t, 3, p.MaxAttempts)
	assert.Equal(t, 200*time.Millisecond, p.BaseDelay)
	assert.Equal(t, 2*time.Second, p.MaxDelay)
	s := newFakeServer(t)
	sc, err := NewScanClient(cfgFor(s, pinned(t, s)), ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}})
	require.NoError(t, err)
	require.NoError(t, sc.Connect(ctx5(t)))
	defer sc.Disconnect(context.Background())
	s.dropNext("MLSD", 2)
	_, err = sc.ListDirectory(ctx5(t), "/")
	require.NoError(t, err, "two drops are survived by the third attempt")
	d, err := NewScanClient(cfgFor(s, pinned(t, s)), ScanOptions{}) // the default policy end to end
	require.NoError(t, err)
	require.NoError(t, d.Connect(ctx5(t)))
	defer d.Disconnect(context.Background())
	s.dropNext("MLSD", 2)
	_, err = d.ListDirectory(ctx5(t), "/")
	require.NoError(t, err, "the default policy retries")
}

// ---- MX03: the base directory is canonicalised with PWD ------------------------------------------------------------

func TestBaseDirectory_IsCanonicalisedWithPWD_MX03(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(cfg *Config) { cfg.Path = "/data/sub/.." })
	_, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.Contains(t, s.commands(), "MLST /data/a.txt", "paths are built on the server's own answer to PWD, not on the configured spelling")
	for _, cmd := range s.commands() {
		if strings.HasPrefix(cmd, "MLST ") {
			assert.NotContains(t, cmd, "/..", cmd)
		}
	}
}

// ---- F10 / F12 / F13 --------------------------------------------------------------------------------------------------

func TestSecret_NeverReachableThroughFmt_D13(t *testing.T) {
	const secret = "S3cr3t-WF21-XYZ"
	v := Credential{Password: secret}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		assert.NotContains(t, fmt.Sprintf(f, v), secret, "Credential value "+f)
		assert.NotContains(t, fmt.Sprintf(f, &v), secret, "Credential pointer "+f)
	}
	f := scanFactory{cfg: &Config{Host: "h", Username: "u", Password: secret}}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		assert.NotContains(t, fmt.Sprintf(verb, f), secret, "scanFactory "+verb)
		assert.NotContains(t, fmt.Sprintf(verb, &f), secret, "&scanFactory "+verb)
	}
	cfg := &Config{Host: "h", Username: "u", Password: secret}
	pool, err := NewWorkerPool(cfg, fabric.PoolOptions{MaxPerKey: 1}, ScanOptions{})
	require.NoError(t, err)
	defer pool.CloseAll()
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		assert.NotContains(t, fmt.Sprintf(verb, pool), secret, "worker pool "+verb)
	}
	cfg.Password = "changed-by-caller" // the pool kept its own copy
}

func TestIACByteInAPath_IsDoubled_F12(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	_, err := c.GetFileInfo(ctx5(t), "x\xff\xf4y")
	require.Error(t, err) // no such file; the point is what was sent
	assert.Contains(t, s.commands(), "MLST /data/x\xff\xff\xf4y", "RFC 854: a 0xFF data byte is sent as 0xFF 0xFF, never as a Telnet command")
	for _, cmd := range s.commands() {
		assert.NotContains(t, strings.ReplaceAll(cmd, "\xff\xff", ""), "\xff", "no lone IAC reaches the server: %q", cmd)
	}
}

func TestReplyAndListingSizeAreBounded_D16_D17(t *testing.T) {
	t.Run("reply", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, func(cfg *Config) { cfg.MaxReplyBytes = 8192 })
		s.setHook(func(ss *session, verb, arg string) (bool, bool) {
			if verb != "NOOP" {
				return false, true
			}
			w := bufio.NewWriterSize(ss.conn, 1<<16)
			fmt.Fprintf(w, "200-start\r\n")
			pad := strings.Repeat("x", 500)
			for i := 0; i < 400; i++ {
				fmt.Fprintf(w, " %s\r\n", pad)
			}
			fmt.Fprintf(w, "200 end\r\n")
			_ = w.Flush()
			return true, true
		})
		err := c.TestConnection(ctx5(t))
		require.ErrorIs(t, err, ErrReplyTooLarge)
		assert.False(t, c.IsConnected())
	})
	t.Run("reply_under_the_bound_is_fine", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, func(cfg *Config) { cfg.MaxReplyBytes = 8192 })
		s.setHook(func(ss *session, verb, arg string) (bool, bool) {
			if verb != "NOOP" {
				return false, true
			}
			ss.reply("200-start")
			for i := 0; i < 10; i++ {
				ss.reply(" line %d", i)
			}
			ss.reply("200 end")
			return true, true
		})
		require.NoError(t, c.TestConnection(ctx5(t)))
		assert.True(t, c.IsConnected())
	})
	listing := func(n int) hookFn {
		return func(ss *session, verb, arg string) (bool, bool) {
			if verb != "MLSD" {
				return false, true
			}
			ss.reply("150 opening")
			dc, err := ss.openData()
			if err != nil {
				return true, true
			}
			w := bufio.NewWriterSize(dc, 1<<16)
			for i := 0; i < n; i++ {
				fmt.Fprintf(w, "Type=file;Size=1;Modify=20200517103000; f%07d\r\n", i)
			}
			_ = w.Flush()
			_ = dc.Close()
			ss.reply("226 done")
			return true, true
		}
	}
	t.Run("listing", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, func(cfg *Config) { cfg.MaxListEntries = 1000 })
		s.setHook(listing(1500))
		_, err := c.ListDirectory(ctx5(t), "/")
		require.ErrorIs(t, err, ErrListingTooLarge)
		assert.False(t, c.IsConnected(), "the oversized transfer was abandoned: the connection is dropped")
		s.setHook(listing(900))
		got, err := c.ListDirectory(ctx5(t), "/")
		require.NoError(t, err)
		assert.Len(t, got, 900)
	})
	t.Run("long_line", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, nil)
		s.setHook(func(ss *session, verb, arg string) (bool, bool) {
			if verb != "MLSD" {
				return false, true
			}
			ss.reply("150 opening")
			dc, err := ss.openData()
			if err != nil {
				return true, true
			}
			_, _ = io.WriteString(dc, "Type=file;Size=1; "+strings.Repeat("n", 100000)+"\r\n")
			_ = dc.Close()
			return true, true
		})
		_, err := c.ListDirectory(ctx5(t), "/")
		require.ErrorIs(t, err, ErrListingIncomplete)
	})
}

// ---- C20: no goroutine is left behind by normal use, timeouts, cancellations and aborts ---------------------------

func TestGoroutinesReturnToBaseline_C20(t *testing.T) {
	s := newFakeServer(t)
	time.Sleep(100 * time.Millisecond)
	base := runtime.NumGoroutine()
	c := NewFTPClient(cfgFor(s, pinned(t, s)))
	require.NoError(t, c.Connect(ctx5(t)))
	for i := 0; i < 5; i++ {
		_, _ = c.ListDirectory(ctx5(t), "/")
		rc, err := c.ReadFile(ctx5(t), "big.bin")
		require.NoError(t, err)
		_, _ = rc.Read(make([]byte, 10))
		_ = rc.Close()
		sk, err := c.OpenSeekable(ctx5(t), "big.bin")
		require.NoError(t, err)
		_, _ = sk.Seek(500, io.SeekStart)
		_, _ = sk.Read(make([]byte, 10))
		_ = sk.Close()
		ctx, cancel := context.WithCancel(context.Background())
		rc, err = c.ReadFile(ctx, "big.bin")
		require.NoError(t, err)
		cancel()
		_ = rc.Close()
	}
	s.dropNext("MLSD", 1)
	_, _ = c.ListDirectory(ctx5(t), "/")
	_, _ = c.ListDirectory(ctx5(t), "/")
	require.NoError(t, c.Disconnect(ctx5(t)))
	time.Sleep(500 * time.Millisecond)
	after := runtime.NumGoroutine()
	assert.LessOrEqual(t, after, base+2, "goroutines base=%d after=%d", base, after)
	// control needle (11.4.273): the same counter DOES see a goroutine that is really there
	stop := make(chan struct{})
	b2 := runtime.NumGoroutine()
	go func() { <-stop }()
	time.Sleep(50 * time.Millisecond)
	a2 := runtime.NumGoroutine()
	close(stop)
	assert.Greater(t, a2, b2, "the instrument must see a goroutine that is really there")
}

func TestSlowDrippingReply_IsBoundedAsAWhole(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 500 * time.Millisecond })
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "NOOP" {
			return false, true
		}
		// every single read gets data well inside IOTimeout, but the reply as a whole never ends in time
		for i := 0; i < 40; i++ {
			if _, err := io.WriteString(ss.conn, "200-"); err != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
			if _, err := io.WriteString(ss.conn, "x\r\n"); err != nil {
				break
			}
		}
		return true, false
	})
	var err error
	start := time.Now()
	done := runAsync(func() { err = c.TestConnection(ctx5(t)) })
	require.True(t, returnedWithin(done, 3*time.Second), "a reply that drips on forever must hit IOTimeout as a whole (%v)", time.Since(start))
	require.Error(t, err)
	assert.False(t, c.IsConnected())
}

// ---- F1 (writes): a control write that cannot complete is bounded too ----------------------------------------------

func TestDeadline_ControlWriteStall_IsBounded(t *testing.T) {
	// a server that logs in and then stops reading: the huge CWD line fills the socket buffers and the write blocks
	port, _ := silentServer(t, func(c net.Conn) {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(4096) // a small receive window: the sender blocks after a few MiB instead of after tens of MiB (autotuning goes up to 32 MiB on this host)
		}
		r := bufio.NewReader(c)
		_, _ = io.WriteString(c, "220 hi\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch strings.ToUpper(strings.Fields(line)[0]) {
			case "USER":
				_, _ = io.WriteString(c, "331 pw\r\n")
			case "PASS":
				_, _ = io.WriteString(c, "230 ok\r\n")
			case "FEAT":
				_, _ = io.WriteString(c, "211 none\r\n")
			case "TYPE":
				_, _ = io.WriteString(c, "200 ok\r\n")
				time.Sleep(30 * time.Second) // never read the next line
				return
			}
		}
	})
	cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: TLSNone, TrustedLAN: true,
		Path: "/" + strings.Repeat("p", 8<<20), DialTimeout: 5 * time.Second, IOTimeout: 400 * time.Millisecond}
	var err error
	start := time.Now()
	done := runAsync(func() { err = NewFTPClient(cfg).Connect(context.Background()) })
	require.True(t, returnedWithin(done, 10*time.Second), "a blocked control write must hit IOTimeout (blocked %v)", time.Since(start))
	require.Error(t, err)
}

// ---- F2: bytes that arrive together with the previous reply are caught BEFORE the next command ---------------

func TestDesync_StrayReplyDeliveredWithTheAnswer_IsCaughtBeforeTheNextCommand(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	var mu sync.Mutex
	first := true
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "NOOP" {
			return false, true
		}
		mu.Lock()
		defer mu.Unlock()
		if first {
			first = false
			_, _ = io.WriteString(ss.conn, "200 ok\r\n200 stray, same code as the answer\r\n") // one write: both are buffered at once
			return true, true
		}
		ss.reply("200 ok")
		return true, true
	})
	require.NoError(t, c.TestConnection(ctx5(t)))
	err := c.TestConnection(ctx5(t))
	require.ErrorIs(t, err, ErrProtocol, "the stray reply, which has the SAME code as a NOOP answer, must not be taken for the answer to the next command")
	require.NoError(t, c.TestConnection(ctx5(t)), "and the client recovered on a fresh connection")
	assert.Equal(t, 2, s.ctrlConns)
}

// ---- F11: a connection left referenced but unusable is closed when the client re-dials -----------------------

func TestReDial_ClosesTheConnectionItReplaces(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	c.mu.Lock()
	old := c.p
	c.mu.Unlock()
	old.interrupt() // poisoned but still referenced (an interrupt that lands right after an operation finished)
	require.NoError(t, c.Connect(ctx5(t)), "Connect sees a poisoned connection and dials a new one")
	assert.True(t, s.waitCtrl(1, 3*time.Second), "exactly one connection stays open: the poisoned one was closed, not leaked")
	require.NoError(t, c.TestConnection(ctx5(t)))
}
