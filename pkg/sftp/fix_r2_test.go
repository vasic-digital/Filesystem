package sftp

// fix-r2: tests added for the findings of the independent review of round 1 (WF19-REVIEW-sftp.md) that the reviewer's probes
// (review_probes_test.go) do not cover, and one killing test for every reviewer mutant that survived round 1 (R01..R21, mapped in
// fix-r2-mutants.py and in the evidence README). All of them drive the real client against a real ssh server with the real
// pkg/sftp request server behind it, or against a raw sftp peer that scripts exact reply bytes.

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gosftp "github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// ---- raw sftp peer ---------------------------------------------------------------------------------------------

const (
	fxpOpen     = 3
	fxpClose    = 4
	fxpRead     = 5
	fxpFstat    = 8
	fxpOpendir  = 11
	fxpReaddir  = 12
	fxpRealpath = 16
	fxpStat     = 17
)

func statusFrame(id uint32, code uint32) []byte {
	return wireFrame(fxpStatus, u32b(id), u32b(code), strb(""), strb(""))
}

// rawSFTP speaks just enough SFTP v3 to script replies: INIT is answered, every other request goes to h (type, id, body after
// the id). A nil reply means "no answer" (a stall). Used as probeOpts.raw.
func rawSFTP(h func(typ byte, id uint32, body []byte) []byte) func(ssh.Channel) {
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
			if hdr[4] == 1 { // SSH_FXP_INIT
				_, _ = ch.Write(wireFrame(fxpVersion, u32b(3)))
				continue
			}
			if len(body) < 4 {
				return
			}
			if reply := h(hdr[4], binary.BigEndian.Uint32(body), body[4:]); reply != nil {
				_, _ = ch.Write(reply)
			}
		}
	}
}

func rootClient(s *probeServer, mut func(*Config)) *Client {
	return probeClient(s, func(cfg *Config) {
		cfg.Root = "/"
		cfg.MaxRetries = -1
		if mut != nil {
			mut(cfg)
		}
	})
}

// ---- SFTP-08: malformed replies never panic the process ---------------------------------------------------------

// handler that hands out a handle and a stat, and answers every READ with a DATA frame whose length field lies.
func lyingDataHandler() func(byte, uint32, []byte) []byte {
	return func(typ byte, id uint32, body []byte) []byte {
		switch typ {
		case fxpOpen:
			return wireFrame(fxpHandle, u32b(id), strb("h"))
		case fxpStat, fxpFstat:
			return wireFrame(fxpAttrs, u32b(id), attrsB(attrSize|attrPerms|attrACModTim, u64b(1<<20), u32b(0o100644), u32b(1), u32b(1)))
		case fxpRead:
			return wireFrame(fxpData, u32b(id), u32b(1<<20), []byte("0123456789")) // claims 1 MiB, carries 10 bytes
		case fxpClose:
			return statusFrame(id, 0)
		}
		return statusFrame(id, 8)
	}
}

// The pipelined read parses DATA replies in goroutines that pkg/sftp starts: before the wire validator this panicked there,
// where no recover() of this package can reach, and killed the whole process.
func TestRaw_MalformedDataInPipelinedReadIsAnErrorNotAProcessCrash(t *testing.T) {
	s := startProbe(t, probeOpts{raw: rawSFTP(lyingDataHandler())})
	c := rootClient(s, nil)
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	rc, err := c.ReadFile(ctx, "f")
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, rc) // WriteTo: the pipelined path
	_ = rc.Close()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMalformedReply)
	assert.False(t, IsTransient(err), "a hostile server answers the same way again: not retried")
}

func TestRaw_MalformedDataInSequentialReadIsAnError(t *testing.T) {
	s := startProbe(t, probeOpts{raw: rawSFTP(lyingDataHandler())})
	c := rootClient(s, nil)
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	rc, err := c.ReadFile(ctx, "f")
	require.NoError(t, err)
	_, err = rc.Read(make([]byte, 100))
	_ = rc.Close()
	assert.ErrorIs(t, err, ErrMalformedReply)
}

// A malformed reply costs the connection exactly once and never retries (retry budget left at the default here).
func TestRaw_MalformedReplyIsNotRetriedAndLeavesTheClientRecoverable(t *testing.T) {
	s := startProbe(t, probeOpts{raw: rawSFTP(func(typ byte, id uint32, body []byte) []byte { return wireFrame(fxpStatus, u32b(id)) })})
	c := rootClient(s, func(cfg *Config) { cfg.MaxRetries = 3 })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	before := s.conns.Load()
	_, err := c.GetFileInfo(ctx, "x")
	assert.ErrorIs(t, err, ErrMalformedReply)
	assert.Equal(t, before, s.conns.Load(), "no re-dial: a malformed reply is not transient")
	assert.False(t, c.IsConnected(), "the connection that carried it is gone")
}

// ---- SFTP-14: listing limit; R03: '.' and '..' filter -------------------------------------------------------------

func nameEntry(name string) []byte {
	return cat(strb(name), strb("-rw-r--r-- 1 u g 1 Jan 1 00:00 "+name), attrsB(attrPerms, u32b(0o100644)))
}

// NAME replies are built so that the frame length is right: wireFrame wraps (type, id, count) only, so the entries are
// appended and the length patched here.
func nameFrame(id uint32, entries ...string) []byte {
	var body []byte
	for _, e := range entries {
		body = append(body, nameEntry(e)...)
	}
	return wireFrame(fxpName, u32b(id), u32b(uint32(len(entries))), body)
}

func listingServer(t *testing.T, pages [][]string) *probeServer {
	t.Helper()
	return startProbe(t, probeOpts{raw: func(ch ssh.Channel) {
		var reads atomic.Int32
		rawSFTP(func(typ byte, id uint32, body []byte) []byte {
			switch typ {
			case fxpOpendir:
				return wireFrame(fxpHandle, u32b(id), strb("d"))
			case fxpReaddir:
				i := int(reads.Add(1)) - 1
				if i < len(pages) {
					return nameFrame(id, pages[i]...)
				}
				return statusFrame(id, 1)
			case fxpClose:
				return statusFrame(id, 0)
			}
			return statusFrame(id, 8)
		})(ch)
	}})
}

// R03: the client drops "." and ".." (also when the server sends them as the last element of a longer name).
func TestRaw_ListingDropsDotEntries(t *testing.T) {
	s := listingServer(t, [][]string{{".", "..", "x/..", "ok", "dir/sub"}})
	c := rootClient(s, nil)
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	ents, err := c.ListDirectory(ctx, "/")
	require.NoError(t, err)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name)
	}
	assert.Equal(t, []string{"ok", "sub"}, names)
}

func entries(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + strings.Repeat("x", i%7) + string(rune('a'+i%26))
	}
	return out
}

// SFTP-14: a server that keeps streaming NAME frames cannot grow the listing without bound.
func TestRaw_ListingLimit(t *testing.T) {
	pages := [][]string{entries("a", 100), entries("b", 100), entries("c", 100)}
	s := listingServer(t, pages)
	c := rootClient(s, func(cfg *Config) { cfg.MaxDirEntries = 150 })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	ents, err := c.ListDirectory(ctx, "/")
	require.Error(t, err, "300 entries against a limit of 150 (got %d)", len(ents))
	assert.ErrorIs(t, err, ErrDirTooLarge)
	assert.False(t, IsTransient(err))

	// within the limit, and with the limit disabled, the same listing works
	for _, limit := range []int{300, -1, 0} {
		c2 := rootClient(s, func(cfg *Config) { cfg.MaxDirEntries = limit })
		require.NoError(t, c2.Connect(ctx))
		ents, err = c2.ListDirectory(ctx, "/")
		require.NoError(t, err, "limit %d", limit)
		assert.Len(t, ents, 300, "limit %d", limit)
		_ = c2.Disconnect(ctx)
	}
}

// ---- SFTP-01: bounded calls --------------------------------------------------------------------------------------

// Seek(0, SeekEnd) asks the server for the size: a server that never answers must not hang the caller past its context.
func TestSeekEndHonoursContextOnHungServer(t *testing.T) {
	rel := make(chan struct{})
	s := startProbe(t, probeOpts{fileList: blockStatLister{release: rel}})
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "hang"), []byte("0123456789"), 0o644))
	c := probeClient(s, func(cfg *Config) { cfg.CancelGrace = 100 * time.Millisecond })
	require.NoError(t, c.Connect(context.Background()))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	sk, err := c.OpenSeekable(ctx, "hang")
	require.NoError(t, err)
	done := make(chan struct{})
	var serr error
	go func() { defer close(done); _, serr = sk.Seek(0, io.SeekEnd) }()
	ok := within3s(done)
	close(rel)
	<-done
	_ = sk.Close()
	assert.True(t, ok, "Seek(SeekEnd) stayed blocked on a server that does not answer STAT")
	assert.ErrorIs(t, serr, context.DeadlineExceeded)
	_ = c.Disconnect(context.Background())
}

// Closing a file on a server that never answers CLOSE is bounded by CloseTimeout.
type blockCloseReaderAt struct {
	f       *os.File
	release chan struct{}
}

func (b blockCloseReaderAt) ReadAt(p []byte, off int64) (int, error) { return b.f.ReadAt(p, off) }
func (b blockCloseReaderAt) Close() error                            { <-b.release; return b.f.Close() }

type blockCloseGet struct{ release chan struct{} }

func (g blockCloseGet) Fileread(r *gosftp.Request) (io.ReaderAt, error) {
	f, err := os.Open(r.Filepath)
	if err != nil {
		return nil, err
	}
	return blockCloseReaderAt{f: f, release: g.release}, nil
}

func TestCloseIsBoundedOnAStalledServer(t *testing.T) {
	rel := make(chan struct{})
	s := startProbe(t, probeOpts{fileGet: blockCloseGet{rel}})
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "f"), bytes.Repeat([]byte("z"), 100), 0o644))
	c := probeClient(s, func(cfg *Config) { cfg.CloseTimeout = 300 * time.Millisecond })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	rc, err := c.ReadFile(ctx, "f")
	require.NoError(t, err)
	p := make([]byte, 10)
	_, err = io.ReadFull(rc, p)
	require.NoError(t, err)
	done := make(chan struct{})
	start := time.Now()
	go func() { defer close(done); _ = rc.Close() }()
	ok := within3s(done)
	close(rel)
	<-done
	assert.True(t, ok, "Close stayed blocked > 3s on a server that never answers CLOSE (took %v)", time.Since(start))
	assert.False(t, c.IsConnected(), "the bounded close ended the connection that could not finish it")
	_ = c.Disconnect(ctx)
}

// A call whose context ends gets CancelGrace to finish by itself: cancelling one stream on a HEALTHY server does not take
// down the connection the other streams share.
func TestCancelOfOneStreamDoesNotKillTheSharedConnection(t *testing.T) {
	g := &gauge{}
	var closed atomic.Int32
	s := startProbe(t, probeOpts{fileGet: obsGet{g: g, delay: 2 * time.Millisecond, closed: &closed}})
	big := bytes.Repeat([]byte("0123456789abcdef"), 512*1024) // 8 MiB
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "a"), big, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "b"), big, 0o644))
	c := probeClient(s, func(cfg *Config) { cfg.MaxPacket = 4096; cfg.MaxConcurrentRequests = 8 })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck

	ra, err := c.ReadFile(ctx, "a")
	require.NoError(t, err)
	ctxB, cancelB := context.WithCancel(ctx)
	rb, err := c.ReadFile(ctxB, "b")
	require.NoError(t, err)

	var wg sync.WaitGroup
	var aSum, aErr, bErr = new(bytes.Buffer), error(nil), error(nil)
	wg.Add(2)
	go func() { defer wg.Done(); _, aErr = io.Copy(aSum, ra) }()
	go func() { defer wg.Done(); _, bErr = io.Copy(io.Discard, rb) }()
	time.Sleep(60 * time.Millisecond)
	cancelB()
	wg.Wait()
	_ = ra.Close()
	_ = rb.Close()
	assert.ErrorIs(t, bErr, context.Canceled)
	require.NoError(t, aErr, "stream A shares the connection with the cancelled stream B and must finish")
	assert.True(t, bytes.Equal(big, aSum.Bytes()), "stream A delivered every byte")
	assert.Equal(t, int32(1), s.conns.Load(), "no connection was dropped and re-dialled")
}

// R04: a file whose context ends is closed on the server although nobody calls Close.
func TestContextEndClosesTheRemoteFile(t *testing.T) {
	g := &gauge{}
	var closed atomic.Int32
	s := startProbe(t, probeOpts{fileGet: obsGet{g: g, closed: &closed}})
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "f"), []byte("abc"), 0o644))
	c := probeClient(s, nil)
	require.NoError(t, c.Connect(context.Background()))
	defer c.Disconnect(context.Background()) //nolint:errcheck
	ctx, cancel := context.WithCancel(context.Background())
	_, err := c.ReadFile(ctx, "f")
	require.NoError(t, err)
	require.Zero(t, closed.Load())
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	assert.Equal(t, int32(1), closed.Load(), "the server saw the CLOSE of the file whose context ended")
}

// ---- keepalive / half-open links -------------------------------------------------------------------------------------

// holeProxy forwards TCP to target until hole is set; then it swallows everything in both directions (a half-open link: the
// peer is still there for the OS, but nothing arrives).
type holeProxy struct {
	ln   net.Listener
	port int
	hole atomic.Bool
	mu   sync.Mutex
	cs   []net.Conn
}

func startHoleProxy(t *testing.T, target string) *holeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &holeProxy{ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.cs = append(p.cs, c, d)
			p.mu.Unlock()
			go p.pipe(d, c)
			go p.pipe(c, d)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		p.mu.Lock()
		for _, c := range p.cs {
			_ = c.Close()
		}
		p.mu.Unlock()
	})
	return p
}

func (p *holeProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !p.hole.Load() {
			_, _ = dst.Write(buf[:n])
		}
		if err != nil {
			_ = dst.Close()
			return
		}
	}
}

func proxiedClient(t *testing.T, s *testServer, p *holeProxy, mut func(*Config)) *Client {
	t.Helper()
	st := NewMemPinStore()
	require.NoError(t, st.Record(HostPort("127.0.0.1", p.port), HostKeyPin{KeyType: s.HostKey.PublicKey().Type(), Fingerprint: Fingerprint(s.HostKey.PublicKey()), ConfirmedBy: "test"}))
	cfg := &Config{Host: "127.0.0.1", Port: p.port, Username: "alice", CredentialRef: "ref", Root: s.Dir,
		Resolver: mapResolver{"ref": {Password: s.Password}}, PinStore: st, MaxRetries: -1, DialTimeout: 5 * time.Second}
	if mut != nil {
		mut(cfg)
	}
	return NewSFTPClient(cfg)
}

func TestKeepaliveEndsACallOnAHalfOpenLink(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	p := startHoleProxy(t, s.Addr)
	c := proxiedClient(t, s, p, func(cfg *Config) {
		cfg.KeepAliveInterval = 100 * time.Millisecond
		cfg.KeepAliveTimeout = 300 * time.Millisecond
	})
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	_, err := c.GetFileInfo(ctx, "a.txt")
	require.NoError(t, err, "control: the link works before the hole")
	p.hole.Store(true)
	done := make(chan error, 1)
	go func() { _, err := c.GetFileInfo(context.Background(), "a.txt"); done <- err }() // no context deadline at all
	select {
	case err := <-done:
		require.Error(t, err)
		assert.True(t, IsTransient(err), "a dead link is a connection loss: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("a call on a half-open link stayed blocked > 10s although the keepalive is 100ms/300ms")
	}
	assert.False(t, c.IsConnected())
}

func TestKeepaliveCanBeDisabled(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	p := startHoleProxy(t, s.Addr)
	c := proxiedClient(t, s, p, func(cfg *Config) { cfg.KeepAliveInterval = -1 })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	_, err := c.GetFileInfo(ctx, "a.txt")
	require.NoError(t, err)
	p.hole.Store(true)
	done := make(chan error, 1)
	go func() { _, err := c.GetFileInfo(context.Background(), "a.txt"); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("keepalive disabled, yet the call ended on its own: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}
	disc := make(chan error, 1)
	go func() { disc <- c.Disconnect(ctx) }()
	select {
	case err := <-disc:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Disconnect hung on a half-open link (it closed the sftp session, which waits for the dead connection, before the ssh connection)")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Disconnect did not end the blocked call")
	}
}

// ---- dial bounds (R05, R06) ----------------------------------------------------------------------------------------

// silentListener accepts TCP connections and never writes or reads.
func silentListener(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var mu sync.Mutex
	var cs []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			cs = append(cs, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range cs {
			_ = c.Close()
		}
		mu.Unlock()
	})
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

func silentClient(t *testing.T, mut func(*Config)) *Client {
	host, port := silentListener(t)
	st := NewMemPinStore()
	require.NoError(t, st.Record(HostPort(host, port), HostKeyPin{KeyType: "ssh-ed25519", Fingerprint: Fingerprint(newSigner(t).PublicKey())}))
	cfg := &Config{Host: host, Port: port, Username: "u", CredentialRef: "r", Resolver: mapResolver{"r": {Password: "pw"}}, PinStore: st, MaxRetries: -1}
	mut(cfg)
	return NewSFTPClient(cfg)
}

func TestDialTimeoutBoundsTheHandshake(t *testing.T) {
	c := silentClient(t, func(cfg *Config) { cfg.DialTimeout = 400 * time.Millisecond })
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- c.Connect(context.Background()) }() // no context deadline
	select {
	case err := <-done:
		require.Error(t, err)
		assert.Less(t, time.Since(start), 5*time.Second)
	case <-time.After(8 * time.Second):
		t.Fatal("DialTimeout did not bound the SSH handshake")
	}
}

func TestContextCancelEndsTheHandshake(t *testing.T) {
	c := silentClient(t, func(cfg *Config) { cfg.DialTimeout = time.Minute })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Connect(ctx) }()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling the context did not end the SSH handshake")
	}
}

// SFTP-18: Discover/Pin honour their context after the TCP connect.
func TestDiscoverAllHonoursContextAfterConnect(t *testing.T) {
	host, port := silentListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := DiscoverAll(ctx, host, port, 0); done <- err }() // default 15 s per key family
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(4 * time.Second):
		t.Fatal("DiscoverAll ignored its context while the server was silent")
	}
}

// ---- pipelining is measured, not assumed (R01, R02, SFTP-15) ------------------------------------------------------------

type gauge struct{ cur, peak atomic.Int32 }

func (g *gauge) enter() {
	n := g.cur.Add(1)
	for {
		p := g.peak.Load()
		if n <= p || g.peak.CompareAndSwap(p, n) {
			return
		}
	}
}
func (g *gauge) leave() { g.cur.Add(-1) }

type obsReaderAt struct {
	f      *os.File
	g      *gauge
	delay  time.Duration
	closed *atomic.Int32
}

func (o *obsReaderAt) ReadAt(p []byte, off int64) (int, error) {
	o.g.enter()
	defer o.g.leave()
	time.Sleep(o.delay)
	return o.f.ReadAt(p, off)
}
func (o *obsReaderAt) Close() error {
	if o.closed != nil {
		o.closed.Add(1)
	}
	return o.f.Close()
}

type obsGet struct {
	g      *gauge
	delay  time.Duration
	closed *atomic.Int32
}

func (h obsGet) Fileread(r *gosftp.Request) (io.ReaderAt, error) {
	f, err := os.Open(r.Filepath)
	if err != nil {
		return nil, err
	}
	return &obsReaderAt{f: f, g: h.g, delay: h.delay, closed: h.closed}, nil
}

func pipelineServer(t *testing.T) (*probeServer, *gauge, []byte) {
	t.Helper()
	g := &gauge{}
	s := startProbe(t, probeOpts{fileGet: obsGet{g: g, delay: 8 * time.Millisecond}})
	data := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "f"), data, 0o644))
	return s, g, data
}

// onlyWriter hides any ReaderFrom of the destination, so io.Copy has to use the source's WriteTo or its own 32 KiB buffer.
type onlyWriter struct{ io.Writer }

func TestPipelinedReadKeepsSeveralRequestsInFlight(t *testing.T) {
	s, g, data := pipelineServer(t)
	// default packet size (32 KiB): a plain Read of 32 KiB is ONE request, so concurrency can only come from the WriteTo path
	c := probeClient(s, func(cfg *Config) { cfg.MaxConcurrentRequests = 16 })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	rc, err := c.ReadFile(ctx, "f")
	require.NoError(t, err)
	var buf bytes.Buffer
	_, err = io.Copy(onlyWriter{&buf}, rc)
	_ = rc.Close()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, buf.Bytes()))
	assert.GreaterOrEqual(t, g.peak.Load(), int32(3), "the server saw %d concurrent READs: the read path is not pipelined", g.peak.Load())
}

func TestRangedReadIsPipelinedToo(t *testing.T) {
	s, g, data := pipelineServer(t)
	c := probeClient(s, func(cfg *Config) { cfg.MaxPacket = 4096; cfg.MaxConcurrentRequests = 16 })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	rc, err := c.ReadRange(ctx, "f", 1000, 600_000)
	require.NoError(t, err)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, rc)
	_ = rc.Close()
	require.NoError(t, err)
	assert.Equal(t, int64(600_000), n)
	assert.True(t, bytes.Equal(data[1000:601_000], buf.Bytes()))
	assert.GreaterOrEqual(t, g.peak.Load(), int32(3), "ranged reads (HTTP Range) were serialised: %d concurrent READs", g.peak.Load())

	// the range edges: past the end, exactly the end, zero length
	for _, tc := range []struct {
		off, ln int64
		want    []byte
	}{
		{int64(len(data)) - 5, 100, data[len(data)-5:]},
		{int64(len(data)), 10, nil},
		{10, 0, nil},
	} {
		r, err := c.ReadRange(ctx, "f", tc.off, tc.ln)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		_ = r.Close()
		assert.True(t, bytes.Equal(tc.want, got), "off %d len %d: got %d bytes", tc.off, tc.ln, len(got))
		r, err = c.ReadRange(ctx, "f", tc.off, tc.ln) // and through WriteTo
		require.NoError(t, err)
		var b2 bytes.Buffer
		_, err = io.Copy(&b2, r)
		require.NoError(t, err)
		_ = r.Close()
		assert.True(t, bytes.Equal(tc.want, b2.Bytes()), "WriteTo off %d len %d", tc.off, tc.ln)
	}
}

// ---- small killers for the remaining round-1 survivors ------------------------------------------------------------------

// R07: Disconnect releases the connection (not only the flag).
func TestDisconnectReleasesTheConnection(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, nil)
	sc := sshOf(c)
	require.NotNil(t, sc)
	require.NoError(t, c.Disconnect(context.Background()))
	waited := make(chan struct{})
	go func() { _ = sc.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("Disconnect left the ssh connection open")
	}
	assert.False(t, heldConn(c))
}

// recordingResolver hands out credentials it keeps a pointer to, so the test can look at them after the client used them.
type recordingResolver struct {
	cred *Credential
}

func (r *recordingResolver) Resolve(context.Context, string) (*Credential, error) { return r.cred, nil }

// R08: the client overwrites the key and passphrase bytes it was handed, and drops the password.
func TestClientWipesWhatTheResolverHandedOver(t *testing.T) {
	s := startServer(t)
	pemKey, pub := marshalKey(t, []byte("pp-wipe"))
	s.AuthKey = pub
	rec := &recordingResolver{cred: &Credential{PrivateKeyPEM: append([]byte(nil), pemKey...), Passphrase: []byte("pp-wipe"), Password: "unused-pw"}}
	c := NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "ref", Root: s.Dir, Resolver: rec, PinStore: s.pinned(), MaxRetries: -1})
	require.NoError(t, c.Connect(context.Background()))
	defer c.Disconnect(context.Background()) //nolint:errcheck
	assert.Equal(t, make([]byte, len(pemKey)), rec.cred.PrivateKeyPEM, "key bytes zeroed")
	assert.Equal(t, make([]byte, len("pp-wipe")), rec.cred.Passphrase, "passphrase bytes zeroed")
	assert.Empty(t, rec.cred.Password)
}

// R10: TestConnection refuses a root that is not a directory.
func TestTestConnectionRefusesAFileAsRoot(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "ref", Root: filepath.Join(s.Dir, "a.txt"),
		Resolver: mapResolver{"ref": {Password: s.Password}}, PinStore: s.pinned(), MaxRetries: -1})
	err := c.TestConnection(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

// R11: ListDirectory ends at the context between round trips of a SLOW (not stalled) server, without waiting for the grace.
type slowLister struct {
	roHandlers
	delay time.Duration
}

type slowListerAt struct {
	ents  []os.FileInfo
	delay time.Duration
}

func (l slowListerAt) ListAt(f []os.FileInfo, off int64) (int, error) {
	time.Sleep(l.delay)
	if off >= int64(len(l.ents)) {
		return 0, io.EOF
	}
	f[0] = l.ents[off] // one entry per page
	return 1, nil
}

func (s slowLister) Filelist(r *gosftp.Request) (gosftp.ListerAt, error) {
	if r.Method == "List" {
		d, err := os.Open(r.Filepath)
		if err != nil {
			return nil, err
		}
		defer d.Close()
		fis, err := d.Readdir(-1)
		if err != nil {
			return nil, err
		}
		return slowListerAt{ents: fis, delay: s.delay}, nil
	}
	return s.roHandlers.Filelist(r)
}

func TestListDirectoryStopsAtTheContextOnASlowServer(t *testing.T) {
	s := startProbe(t, probeOpts{fileList: slowLister{delay: 120 * time.Millisecond}})
	for i := 0; i < 40; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(s.Dir, strings.Repeat("f", 1+i%5)+string(rune('a'+i%26))+string(rune('A'+i/26))), nil, 0o644))
	}
	c := probeClient(s, func(cfg *Config) { cfg.CancelGrace = time.Minute }) // the grace must not be what ends the call
	require.NoError(t, c.Connect(context.Background()))
	defer c.Disconnect(context.Background()) //nolint:errcheck
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.ListDirectory(ctx, "/")
	el := time.Since(start)
	require.Error(t, err, "40 pages at 120 ms cannot finish inside 400 ms")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, el, 2500*time.Millisecond, "the listing ran on to the end (%v) instead of stopping at the context", el)
}

// R13: the negative-offset guard comes before any connection is needed.
func TestReadRangeNegativeOffsetIsRefusedUpFront(t *testing.T) {
	c := NewSFTPClient(&Config{})
	_, err := c.ReadRange(context.Background(), "a", -1, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "negative offset")
	assert.NotErrorIs(t, err, ErrNotConnected)
}

// R16: a path that escapes the root is an error, never "does not exist".
func TestFileExistsReportsAnEscapeAsAnError(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, nil)
	ok, err := c.FileExists(context.Background(), "../outside")
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrPathEscape)
	ok, err = c.FileExists(context.Background(), "nope")
	assert.NoError(t, err)
	assert.False(t, ok)
}

// R19: the root is named "/".
func TestGetFileInfoRootIsNamedSlash(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, nil)
	fi, err := c.GetFileInfo(context.Background(), "/")
	require.NoError(t, err)
	assert.Equal(t, "/", fi.Name)
	assert.Equal(t, "/", fi.Path)
	assert.True(t, fi.IsDir)
}

// R20: the containment check refuses what it cannot verify, but still lets "does not exist" through as not-exist.
func TestContainmentFailsClosedButReportsNotExist(t *testing.T) {
	s := startProbe(t, probeOpts{fileList: failRealPathLister{}})
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "evil-file"), []byte("x"), 0o644))
	c := probeClient(s, nil)
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	_, err := c.GetFileInfo(ctx, "evil-file")
	require.Error(t, err, "RealPath failed for this path: the call is refused")
	assert.Contains(t, err.Error(), "cannot verify")
	_, err = c.GetFileInfo(ctx, "missing")
	assert.ErrorIs(t, err, os.ErrNotExist)
	ok, err := c.FileExists(ctx, "missing")
	assert.NoError(t, err)
	assert.False(t, ok)
}

// R21: a STATUS EOF reply to a request neither tears the connection down nor is retried (probe P6 shows the damage; this is
// the unit-level statement of the classification).
func TestStatusEOFIsNotAConnectionLoss(t *testing.T) {
	assert.False(t, isConnectionLoss(io.EOF))
	assert.False(t, IsTransient(&serverStatus{err: io.EOF}))
	assert.True(t, IsTransient(io.EOF), "io.EOF as a handshake/dial failure is still transient")
}

// Concurrent callers on one client with lost connections: no data race, every call succeeds.
func TestConcurrentCallsAfterLossAreRaceFreeAndSucceed(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, func(cfg *Config) { cfg.MaxRetries = 3 })
	killConn(c)
	var wg sync.WaitGroup
	errs := make([]error, 16)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				_, errs[i] = c.ListDirectory(context.Background(), "/")
			case 1:
				_, errs[i] = c.GetFileInfo(context.Background(), "a.txt")
			default:
				var rc io.ReadCloser
				if rc, errs[i] = c.ReadFile(context.Background(), "a.txt"); errs[i] == nil {
					_, errs[i] = io.Copy(io.Discard, rc)
					_ = rc.Close()
				}
			}
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		assert.NoError(t, e, "call %d", i)
	}
}

// pkg/sftp renders the write error of a closed channel as io.EOF; a read or copy that ends on a dead connection must not look
// like the end of the file (it would be a silently truncated file).
func TestReadOnADeadConnectionIsNeverAnEOF(t *testing.T) {
	s := startServer(t)
	big := bytes.Repeat([]byte("0123456789abcdef"), 64*1024)
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "big"), big, 0o644))
	for i := 0; i < 8; i++ {
		c := connected(t, s, func(cfg *Config) { cfg.MaxRetries = -1 })
		rc, err := c.ReadFile(context.Background(), "big")
		require.NoError(t, err)
		killConnAndWait(c)
		if i%2 == 0 {
			n, err := io.Copy(io.Discard, rc)
			require.Error(t, err, "iteration %d: a copy on a dead connection ended cleanly after %d bytes", i, n)
			assert.True(t, IsTransient(err), "%v", err)
		} else {
			_, err := rc.Read(make([]byte, 1024))
			require.Error(t, err, "iteration %d", i)
			assert.NotEqual(t, io.EOF, err, "iteration %d: a read on a dead connection reported the end of the file", i)
		}
		_ = rc.Close()
	}
}

// SFTP-12 x real OpenSSH: a WRONG password against a server that advertises keyboard-interactive without a device is still an
// AuthError (not a protocol error), is not retried, and costs one connection.
func TestWrongPasswordIsAnAuthErrorEvenWhenKeyboardInteractiveIsAdvertised(t *testing.T) {
	s := startProbe(t, probeOpts{kbdNoDevice: true})
	c := probeClient(s, func(cfg *Config) {
		cfg.MaxRetries = 5
		cfg.RetryBase = 2 * time.Second
		cfg.Resolver = mapResolver{"r": {Password: "definitely-wrong"}}
	})
	start := time.Now()
	err := c.Connect(context.Background())
	var ae *AuthError
	require.ErrorAs(t, err, &ae)
	assert.Less(t, time.Since(start), 2*time.Second, "no backoff happened: the failure was not retried")
	assert.Equal(t, int32(1), s.conns.Load())
	assert.NotContains(t, err.Error(), "definitely-wrong")
	// and the right password still works on the same kind of server
	c = probeClient(s, nil)
	require.NoError(t, c.Connect(context.Background()))
	_ = c.Disconnect(context.Background())
}

// R15: a host key refusal reaches the caller as the typed error ITSELF (not wrapped in the handshake error x/crypto builds around
// it), so callers that type-assert, and the message the owner reads, carry the fingerprint without ssh library noise.
func TestHostKeyRefusalIsReturnedAsTheTypedErrorItself(t *testing.T) {
	s := startServer(t)
	mk := func(st PinStore) *Client {
		return NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "ref", Root: s.Dir,
			Resolver: mapResolver{"ref": {Password: s.Password}}, PinStore: st, MaxRetries: -1})
	}
	err := mk(NewMemPinStore()).Connect(context.Background())
	unk, ok := err.(*UnknownHostKeyError)
	require.True(t, ok, "an unpinned host must be refused with the *UnknownHostKeyError itself, got %T: %v", err, err)
	assert.Equal(t, Fingerprint(s.HostKey.PublicKey()), unk.Fingerprint)
	assert.NotContains(t, err.Error(), "handshake")

	other := NewMemPinStore()
	require.NoError(t, other.Record(HostPort(s.Host, s.Port), HostKeyPin{KeyType: "ssh-ed25519", Fingerprint: Fingerprint(newSigner(t).PublicKey())}))
	err = mk(other).Connect(context.Background())
	_, ok = err.(*HostKeyMismatchError)
	require.True(t, ok, "a changed key must be refused with the *HostKeyMismatchError itself, got %T: %v", err, err)
}

// N19: when the guard closes the connection of a stuck request/response call, the caller gets the CONTEXT error (not the connection
// loss the close produced, which would be retried as transient).
func TestStuckRequestReturnsTheContextError(t *testing.T) {
	rel := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(rel) }) }
	defer release() // also on t.Fatal: the stalled server handler must be released or the probe's cleanup waits for it
	s := startProbe(t, probeOpts{fileList: blockStatLister{release: rel}})
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "hang"), []byte("x"), 0o644))
	c := probeClient(s, func(cfg *Config) { cfg.CancelGrace = 100 * time.Millisecond })
	require.NoError(t, c.Connect(context.Background()))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.GetFileInfo(ctx, "hang"); done <- err }()
	var err error
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("GetFileInfo stayed blocked")
	}
	release()
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, IsTransient(err), "a cancelled call is never retried")
	_ = c.Disconnect(context.Background())
}
