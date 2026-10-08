package sftp

// WF24 REVIEWER PROBES (independent re-review of fix-r2). Author-independent: every handler, raw peer and server variant below is
// written here; only the WF19 reviewer harness (startProbe/probeClient) and the plain read-only handlers are reused.
// Each probe asserts what the package doc / docs/testing/sftp-client.md CLAIMS; a FAIL is evidence of a defect.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gosftp "github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ---- own helpers ---------------------------------------------------------------------------------------------------

func wfU32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func wfStr(s string) []byte { return append(wfU32(uint32(len(s))), s...) }
func wfFrame(typ byte, parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return append(append(wfU32(uint32(1+len(b))), typ), b...)
}
func wfRdStr(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return ""
	}
	return string(b[4 : 4+n])
}

// wfEntry: one NAME entry with only the permissions attribute.
func wfEntry(name string, mode uint32) []byte {
	return append(append(wfStr(name), wfStr("longname "+name)...), append(wfU32(0x00000004), wfU32(mode)...)...)
}

func wfNames(id uint32, entries ...[]byte) []byte {
	var b []byte
	for _, e := range entries {
		b = append(b, e...)
	}
	return wfFrame(104, wfU32(id), wfU32(uint32(len(entries))), b)
}

func wfStatus(id, code uint32) []byte {
	return wfFrame(101, wfU32(id), wfU32(code), wfStr(""), wfStr(""))
}

// wfRaw answers INIT and hands every other request (type, id, body after id) to h; a nil reply is a stall.
func wfRaw(h func(typ byte, id uint32, body []byte) []byte) func(ssh.Channel) {
	return func(ch ssh.Channel) {
		defer ch.Close()
		for {
			var hdr [5]byte
			if _, err := io.ReadFull(ch, hdr[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(hdr[:4])
			if n < 1 || n > 1<<20 {
				return
			}
			body := make([]byte, n-1)
			if _, err := io.ReadFull(ch, body); err != nil {
				return
			}
			if hdr[4] == 1 {
				_, _ = ch.Write(wfFrame(2, wfU32(3)))
				continue
			}
			if len(body) < 4 {
				return
			}
			if r := h(hdr[4], binary.BigEndian.Uint32(body), body[4:]); r != nil {
				_, _ = ch.Write(r)
			}
		}
	}
}

// wfSlowList serves "List" one entry per 150 ms page.
type wfSlowList struct{ roHandlers }

type wfSlowAt struct{ ents []os.FileInfo }

func (l wfSlowAt) ListAt(f []os.FileInfo, off int64) (int, error) {
	time.Sleep(150 * time.Millisecond)
	if off >= int64(len(l.ents)) {
		return 0, io.EOF
	}
	f[0] = l.ents[off]
	return 1, nil
}

func (w wfSlowList) Filelist(r *gosftp.Request) (gosftp.ListerAt, error) {
	if r.Method == "List" && strings.HasSuffix(r.Filepath, "/d") {
		d, err := os.Open(r.Filepath)
		if err != nil {
			return nil, err
		}
		defer d.Close()
		fis, err := d.Readdir(-1)
		if err != nil {
			return nil, err
		}
		return wfSlowAt{fis}, nil
	}
	return w.roHandlers.Filelist(r)
}

// ---- N1: a cancelled ListDirectory on a HEALTHY (slow) server tears down the shared connection ---------------------

func TestWF24_N1_CancelledListingKillsSharedConnection(t *testing.T) {
	s := startProbe(t, probeOpts{fileList: wfSlowList{}})
	if err := os.MkdirAll(filepath.Join(s.Dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		_ = os.WriteFile(filepath.Join(s.Dir, "d", fmt.Sprintf("f%02d", i)), []byte("x"), 0o644)
	}
	big := bytes.Repeat([]byte("0123456789abcdef"), 256*1024) // 4 MiB
	_ = os.WriteFile(filepath.Join(s.Dir, "big"), big, 0o644)
	c := probeClient(s, nil) // defaults: CancelGrace 1s, MaxRetries 3
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx)           //nolint:errcheck
	rc, err := c.ReadFile(ctx, "big") // an unrelated stream (e.g. an HTTP video stream) on the same client
	if err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4096)
	if _, err := io.ReadFull(rc, head); err != nil {
		t.Fatal(err)
	}
	conns0 := s.conns.Load()
	lctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	start := time.Now()
	_, lerr := c.ListDirectory(lctx, "d") // 20 pages x 150 ms: ends at the 300 ms deadline
	el := time.Since(start)
	cancel()
	connectedAfter := c.IsConnected()
	rest, rerr := io.ReadAll(rc)
	_ = rc.Close()
	t.Logf("WF24-PROBE N1 list_err=%v list_elapsed=%v (grace=1s, so the guard never fired) connected_after_cancel=%v stream_err=%v stream_bytes_after=%d/%d conns_before=%d",
		lerr, el.Round(time.Millisecond), connectedAfter, rerr, len(rest), len(big)-4096, conns0)
	if !errors.Is(lerr, context.DeadlineExceeded) {
		t.Fatalf("control: the listing should end with the context deadline, got %v", lerr)
	}
	if !connectedAfter || rerr != nil {
		t.Errorf("DEFECT N1: a ListDirectory cancelled on a healthy server (returned by itself after %v, inside CancelGrace) dropped the shared connection; the unrelated stream failed: %v", el, rerr)
	}
}

// ---- N2: the MaxDirEntries budget does not reset while listings overlap ---------------------------------------------

func TestWF24_N2_ListingBudgetAccumulatesAcrossOverlappingListings(t *testing.T) {
	sixty := make([][]byte, 60)
	for i := range sixty {
		sixty[i] = wfEntry(fmt.Sprintf("e%02d", i), 0o100644)
	}
	newServer := func() *probeServer {
		var mu sync.Mutex
		reads := map[string]int{}
		var opens atomic.Int32
		return startProbe(t, probeOpts{raw: wfRaw(func(typ byte, id uint32, body []byte) []byte {
			switch typ {
			case 11: // OPENDIR
				if wfRdStr(body) == "/hang" {
					return wfFrame(102, wfU32(id), wfStr("H"))
				}
				return wfFrame(102, wfU32(id), wfStr(fmt.Sprintf("S%d", opens.Add(1))))
			case 12: // READDIR
				h := wfRdStr(body)
				if h == "H" {
					return nil // stall: the listing of /hang stays in flight
				}
				mu.Lock()
				k := reads[h]
				reads[h]++
				mu.Unlock()
				if k == 0 {
					return wfNames(id, sixty...)
				}
				return wfStatus(id, 1)
			case 4: // CLOSE
				return wfStatus(id, 0)
			}
			return wfStatus(id, 8)
		})})
	}
	mk := func(s *probeServer) *Client {
		return probeClient(s, func(cfg *Config) {
			cfg.Root = "/"
			cfg.MaxRetries = -1
			cfg.MaxDirEntries = 150
			cfg.CancelGrace = time.Minute
		})
	}
	ctx := context.Background()

	// control: three sequential listings of a 60-entry directory, nothing else in flight
	s1 := newServer()
	c1 := mk(s1)
	if err := c1.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	var ctrl []string
	for i := 0; i < 3; i++ {
		ents, err := c1.ListDirectory(ctx, "/small")
		ctrl = append(ctrl, fmt.Sprintf("n=%d err=%v", len(ents), err))
		if err != nil {
			t.Fatalf("control failed: %v", ctrl)
		}
	}
	_ = c1.Disconnect(ctx)

	// the same three listings while ONE other listing is in flight
	s2 := newServer()
	c2 := mk(s2)
	if err := c2.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	hctx, hcancel := context.WithCancel(ctx)
	hdone := make(chan error, 1)
	go func() { _, err := c2.ListDirectory(hctx, "/hang"); hdone <- err }()
	time.Sleep(300 * time.Millisecond)
	var got []string
	var firstErr error
	for i := 0; i < 3; i++ {
		ents, err := c2.ListDirectory(ctx, "/small")
		got = append(got, fmt.Sprintf("n=%d err=%v", len(ents), err))
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	var herr error
	received := false
	select {
	case herr = <-hdone:
		received = true
	case <-time.After(500 * time.Millisecond):
		herr = errors.New("(still in flight)")
	}
	connected := c2.IsConnected()
	hcancel()
	_ = c2.Disconnect(ctx)
	if !received {
		select {
		case <-hdone:
		case <-time.After(5 * time.Second):
			t.Error("the /hang listing did not end after cancel + Disconnect")
		}
	}
	t.Logf("WF24-PROBE N2 limit=150 control_sequential=%v with_one_overlapping_listing=%v hang_listing_err=%v connected_after=%v", ctrl, got, herr, connected)
	if firstErr != nil {
		t.Errorf("DEFECT N2: three listings of 60 entries each (limit 150) fail with %v once another listing overlaps them: the budget is not per listing and never resets while listings overlap; the fault also ended the shared connection (connected=%v) and failed the unrelated listing with %v",
			firstErr, connected, herr)
	}
}

// ---- N3: a server-supplied entry named "/" is returned with the listed directory's own Path --------------------------

func TestWF24_N3_SlashEntryPointsAtItsOwnDirectory(t *testing.T) {
	// one page with "/" (a directory) and "f", then EOF
	var page atomic.Int32
	s2 := startProbe(t, probeOpts{raw: wfRaw(func(typ byte, id uint32, body []byte) []byte {
		switch typ {
		case 11:
			page.Store(0)
			return wfFrame(102, wfU32(id), wfStr("D"))
		case 12:
			if page.Add(1) == 1 {
				return wfNames(id, wfEntry("/", 0o40755), wfEntry("f", 0o100644))
			}
			return wfStatus(id, 1)
		case 4:
			return wfStatus(id, 0)
		}
		return wfStatus(id, 8)
	})})
	c := probeClient(s2, func(cfg *Config) { cfg.Root = "/"; cfg.MaxRetries = -1 })
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	ents, err := c.ListDirectory(ctx, "/a")
	if err != nil {
		t.Fatal(err)
	}
	self := 0
	var desc []string
	for _, e := range ents {
		desc = append(desc, fmt.Sprintf("{Name:%q Path:%q IsDir:%v}", e.Name, e.Path, e.IsDir))
		if e.Path == "/a" {
			self++
		}
	}
	// what a recursive walker that descends into IsDir entries does with it
	visits := 0
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		if depth > 6 {
			return
		}
		if p == "/a" {
			visits++
		}
		es, err := c.ListDirectory(ctx, p)
		if err != nil {
			return
		}
		for _, e := range es {
			if e.IsDir {
				walk(e.Path, depth+1)
			}
		}
	}
	walk("/a", 0)
	t.Logf("WF24-PROBE N3 listing_of_/a=%v entries_whose_Path_is_the_listed_dir=%d naive_walk_visits_of_/a(depth cap 6)=%d", desc, self, visits)
	if self > 0 {
		t.Errorf("DEFECT N3: the server name %q became an entry whose Path is the listed directory itself (IsDir); a recursive scanner revisits /a until its own depth cap (%d visits)", "/", visits)
	}
}

// ---- N4: the end-of-file verification uses a hard-coded 3 s liveness timeout, not KeepAliveTimeout -------------------

// wfServer is a real ssh server with the real pkg/sftp request server; global requests are answered after replyDelay.
func wfServer(t *testing.T, replyDelay time.Duration) (*probeServer, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hk := newSigner(t)
	s := &probeServer{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Dir: t.TempDir(), Password: "wf24-pw", HostKey: hk, ln: ln}
	var globals atomic.Int32
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) == s.Password {
			return nil, nil
		}
		return nil, os.ErrPermission
	}}
	cfg.AddHostKey(hk)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var accepted []net.Conn
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			mu.Lock()
			accepted = append(accepted, nc)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer nc.Close()
				sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go func() {
					for r := range reqs {
						globals.Add(1)
						go func(r *ssh.Request) { time.Sleep(replyDelay); _ = r.Reply(false, nil) }(r)
					}
				}()
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "no")
						continue
					}
					ch, creqs, err := newCh.Accept()
					if err != nil {
						return
					}
					go func() {
						for r := range creqs {
							ok := r.Type == "subsystem" && strings.HasSuffix(string(r.Payload), "sftp")
							_ = r.Reply(ok, nil)
							if ok {
								h := roHandlers{}
								srv := gosftp.NewRequestServer(ch, gosftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h})
								_ = srv.Serve()
								_ = srv.Close()
								return
							}
						}
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range accepted {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return s, &globals
}

func TestWF24_N4_EOFVerificationIgnoresConfiguredKeepAliveTimeout(t *testing.T) {
	for _, delay := range []time.Duration{0, 4 * time.Second} {
		s, globals := wfServer(t, delay)
		_ = os.WriteFile(filepath.Join(s.Dir, "a.txt"), []byte("0123456789"), 0o644)
		c := probeClient(s, func(cfg *Config) {
			cfg.MaxRetries = -1
			cfg.KeepAliveInterval = -1              // no periodic keepalive: only the end-of-file check sends a global request
			cfg.KeepAliveTimeout = 60 * time.Second // the owner allows a slow link 60 s to answer
		})
		ctx := context.Background()
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		rc, err := c.ReadFile(ctx, "a.txt")
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		var buf bytes.Buffer
		n, cerr := io.Copy(&buf, rc) // the pipelined WriteTo path
		el := time.Since(start)
		_ = rc.Close()
		connected := c.IsConnected()
		t.Logf("WF24-PROBE N4 global_reply_delay=%v copy_n=%d content_ok=%v copy_err=%v elapsed=%v connected_after=%v global_requests_seen=%d",
			delay, n, buf.String() == "0123456789", cerr, el.Round(time.Millisecond), connected, globals.Load())
		if cerr != nil && delay > 0 {
			t.Errorf("DEFECT N4: a COMPLETE file read on a live server that answers global requests in %v (< KeepAliveTimeout 60s) was reported as %v and the shared connection was dropped (connected=%v)", delay, cerr, connected)
		}
		if delay == 0 && cerr != nil {
			t.Fatalf("control failed: %v", cerr)
		}
		_ = c.Disconnect(ctx)
	}
}

// ---- N6: an explicit Connect in flight is installed after a Disconnect that returned before it ---------------------

func TestWF24_N6_DisconnectDuringExplicitConnect(t *testing.T) {
	s := startProbe(t, probeOpts{})
	s.delay.Store(int64(700 * time.Millisecond))
	c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1 })
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- c.Connect(ctx) }()
	time.Sleep(250 * time.Millisecond)
	derr := c.Disconnect(ctx)
	cerr := <-done
	after := c.IsConnected()
	t.Logf("WF24-PROBE N6 disconnect_err=%v connect_err=%v connected_after_disconnect=%v", derr, cerr, after)
	if after {
		t.Logf("OBSERVATION N6: a Connect that was in flight when Disconnect returned installs its connection afterwards")
	}
	_ = c.Disconnect(ctx)
}

// ---- N7: the real HTTP streaming path (OpenSeekable + http.ServeContent) is not pipelined ----------------------------

type wfGauge struct{ cur, peak, reads atomic.Int32 }

type wfGaugeAt struct {
	f *os.File
	g *wfGauge
}

func (o *wfGaugeAt) ReadAt(p []byte, off int64) (int, error) {
	n := o.g.cur.Add(1)
	o.g.reads.Add(1)
	for {
		pk := o.g.peak.Load()
		if n <= pk || o.g.peak.CompareAndSwap(pk, n) {
			break
		}
	}
	time.Sleep(8 * time.Millisecond)
	o.g.cur.Add(-1)
	return o.f.ReadAt(p, off)
}
func (o *wfGaugeAt) Close() error { return o.f.Close() }

type wfGaugeGet struct{ g *wfGauge }

func (h wfGaugeGet) Fileread(r *gosftp.Request) (io.ReaderAt, error) {
	f, err := os.Open(r.Filepath)
	if err != nil {
		return nil, err
	}
	return &wfGaugeAt{f: f, g: h.g}, nil
}

func TestWF24_N7_ServeContentOverOpenSeekableIsNotPipelined(t *testing.T) {
	g := &wfGauge{}
	s := startProbe(t, probeOpts{fileGet: wfGaugeGet{g}})
	data := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	_ = os.WriteFile(filepath.Join(s.Dir, "f"), data, 0o644)
	c := probeClient(s, nil) // defaults: MaxPacket 32 KiB, 64 requests in flight
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck

	// the reference: ReadRange + io.Copy (what the guide's "HTTP Range streaming is pipelined too" measures)
	r, err := c.ReadRange(ctx, "f", 1000, 600_000)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	_, _ = io.Copy(io.Discard, r)
	rrEl := time.Since(t0)
	_ = r.Close()
	rrPeak, rrReads := g.peak.Load(), g.reads.Load()

	// the path catalog-api's stream handler uses: http.ServeContent over OpenSeekable, behind a real HTTP server
	g.peak.Store(0)
	g.reads.Store(0)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sk, err := c.OpenSeekable(req.Context(), "f")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer sk.Close()
		http.ServeContent(w, req, "f", time.Time{}, sk)
	}))
	defer hs.Close()
	req, _ := http.NewRequest("GET", hs.URL, nil)
	req.Header.Set("Range", "bytes=1000-600999")
	t1 := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	scEl := time.Since(t1)
	ok := bytes.Equal(body, data[1000:601000])
	t.Logf("WF24-PROBE N7 ReadRange+io.Copy: peak_concurrent_READs=%d reads=%d elapsed=%v | ServeContent(OpenSeekable): status=%d bytes_ok=%v peak_concurrent_READs=%d reads=%d elapsed=%v",
		rrPeak, rrReads, rrEl.Round(time.Millisecond), resp.StatusCode, ok, g.peak.Load(), g.reads.Load(), scEl.Round(time.Millisecond))
	if !ok {
		t.Fatalf("control: ServeContent returned wrong bytes")
	}
	if g.peak.Load() < 3 {
		t.Errorf("GAP N7: the HTTP Range path the consumer uses (http.ServeContent over OpenSeekable) keeps %d READ in flight (ReadRange+io.Copy: %d)", g.peak.Load(), rrPeak)
	}
}

// ---- N8: Close of a file whose connection died ----------------------------------------------------------------------

func TestWF24_N8_CloseAfterConnectionDeath(t *testing.T) {
	s := startProbe(t, probeOpts{})
	_ = os.WriteFile(filepath.Join(s.Dir, "a.txt"), []byte("abc"), 0o644)
	c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1 })
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	rc, err := c.ReadFile(ctx, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	killConnAndWait(c)
	cerr := rc.Close()
	t.Logf("WF24-PROBE N8 close_err_after_connection_death=%v (code comment: 'the handle died with its connection' -> nil)", cerr)
	_ = c.Disconnect(ctx)
}
