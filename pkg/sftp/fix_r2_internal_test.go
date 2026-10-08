package sftp

// White-box tests of fix-r2 (they look at unexported symbols that only exist after the fix, so on the pre-fix tree they do not
// compile; the black-box counterparts in fix_r2_test.go carry the behavioural RED).

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gosftp "github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// R18: the backoff doubles up to its cap.
func TestBackoffIsExponentialAndCapped(t *testing.T) {
	c := NewSFTPClient(&Config{MaxRetries: 5, RetryBase: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	var delays []time.Duration
	c.backoffHook = func(d time.Duration) {
		delays = append(delays, d)
		if len(delays) == 4 {
			cancel() // enough observed; do not actually wait seconds
		}
	}
	err := c.retry(ctx, func() error { return io.ErrUnexpectedEOF })
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []time.Duration{time.Second, 2 * time.Second, 2 * time.Second, 2 * time.Second}, delays, "doubling, capped at maxRetryDelay")
	c2 := NewSFTPClient(&Config{MaxRetries: 3, RetryBase: time.Millisecond})
	var d2 []time.Duration
	c2.backoffHook = func(d time.Duration) { d2 = append(d2, d) }
	_ = c2.retry(context.Background(), func() error { return io.ErrUnexpectedEOF })
	assert.Equal(t, []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond}, d2)
}

// SFTP-12 helper-level: the keyboard-interactive answerer answers echo-off password prompts only, within bounds.
func TestKbdAnswer(t *testing.T) {
	f := kbdAnswer("PW")
	ans, err := f("", "", []string{"Password: "}, []bool{false})
	require.NoError(t, err)
	assert.Equal(t, []string{"PW"}, ans)
	_, err = kbdAnswer("PW")("", "", []string{"Username: "}, []bool{true})
	assert.Error(t, err, "an echoed prompt is not a password prompt")
	_, err = kbdAnswer("PW")("", "", make([]string, 5), make([]bool, 5))
	assert.Error(t, err, "too many questions")
	g := kbdAnswer("PW")
	for i := 0; i < 3; i++ {
		_, err = g("", "", nil, nil)
		require.NoError(t, err)
	}
	_, err = g("", "", nil, nil)
	assert.Error(t, err, "a server that keeps asking is cut off after 3 rounds")
	ans, err = kbdAnswer("PW")("", "", nil, nil)
	require.NoError(t, err)
	assert.Empty(t, ans, "an information-only round is answered with nothing")
}

// R20 (white-box half): a client that does not know its resolved root refuses instead of letting the check pass.
func TestCheckWithinRefusesWhenTheResolvedRootIsUnknown(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, nil)
	c.mu.Lock()
	cn := c.cur
	c.mu.Unlock()
	cn.rootReal = ""
	assert.ErrorIs(t, c.checkWithin(cn.sftp, cn, s.Dir+"/a.txt"), ErrPathEscape)
	assert.ErrorIs(t, c.checkWithin(cn.sftp, cn, s.Dir+"/missing"), ErrPathEscape, "unknown root refuses before any server round trip")
}

// N08: a panic in the calling goroutine becomes a protocol fault that ends the connection.
func TestProtectTurnsAPanicIntoAFaultAndClosesTheConnection(t *testing.T) {
	s := startServer(t)
	c := connected(t, s, nil)
	c.mu.Lock()
	cn := c.cur
	c.mu.Unlock()
	err := protect(cn, func() error {
		var m map[string]int
		m["x"] = 1 // nil map write: panics
		return nil
	})
	assert.ErrorIs(t, err, ErrMalformedReply)
	assert.False(t, IsTransient(err))
	assert.ErrorIs(t, cn.faultErr(), ErrMalformedReply)
	waited := make(chan struct{})
	go func() { _ = cn.ssh.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("the connection that produced a panic was left open")
	}
}

func TestIsAuthFailure(t *testing.T) {
	assert.True(t, isAuthFailure(errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain")))
	assert.True(t, isAuthFailure(errors.New("ssh: handshake failed: ssh: unexpected message type 51 (expected 60)")))
	assert.False(t, isAuthFailure(errors.New("ssh: handshake failed: EOF")))
	assert.False(t, isAuthFailure(errors.New("ssh: unexpected message type 52 (expected 60)")))
}

// A file created with a context that has already ended is closed by the context's AfterFunc, which can run before newFile has
// stored the stop function: that must neither panic (nil func) nor race (run with -race).
func TestNewFileWithAnAlreadyEndedContext(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, nil)
	c.mu.Lock()
	cn := c.cur
	c.mu.Unlock()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ { // several goroutines at once widen the scheduling window the defect needs
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 250; i++ {
				f, err := cn.sftp.Open(filepath.Join(s.Dir, "a.txt"))
				if !assert.NoError(t, err) {
					return
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				fl := c.newFile(ctx, cn, f)
				time.Sleep(time.Millisecond) // let the AfterFunc goroutine run Close first, as it can in production
				assert.NoError(t, fl.Close())
				_, err = fl.Read(make([]byte, 4))
				assert.ErrorIs(t, err, context.Canceled)
			}
		}()
	}
	wg.Wait()
}

// N09/N15: the same io.EOF is a server reply on a live connection and a lost connection on a dead one (pkg/sftp reports both as
// io.EOF); run() tells them apart with a keepalive round trip. Deterministic: the error is injected, the connection state is real.
func TestRunClassifiesIOEOFByTheStateOfTheConnection(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, func(cfg *Config) { cfg.MaxRetries = -1 })
	c.mu.Lock()
	cn := c.cur
	c.mu.Unlock()
	ctx := context.Background()

	err := c.run(ctx, cn, func() error { return io.EOF })
	var st *serverStatus
	require.ErrorAs(t, err, &st, "a live connection: io.EOF is a reply")
	assert.False(t, errors.Is(err, io.EOF))
	assert.False(t, IsTransient(err))
	assert.True(t, c.IsConnected(), "the connection is untouched")

	require.NoError(t, cn.ssh.Close())
	select {
	case <-cn.dead:
	case <-time.After(3 * time.Second):
		t.Fatal("connection did not end")
	}
	err = c.run(ctx, cn, func() error { return io.EOF })
	assert.ErrorIs(t, err, gosftp.ErrSSHFxConnectionLost, "a dead connection: io.EOF is a lost connection")
	assert.True(t, IsTransient(err))
	assert.False(t, c.IsConnected())
}

// N16/N17: an EOF (or a clean copy) on a dead connection is not the end of the file.
func TestFileReadAndCopyVerifyTheConnectionBeforeReportingTheEnd(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, func(cfg *Config) { cfg.MaxRetries = -1 })
	ctx := context.Background()
	rc, err := c.ReadFile(ctx, "a.txt") // "hello sftp", 10 bytes
	require.NoError(t, err)
	fl := rc.(*file)
	p := make([]byte, 64)
	n, err := fl.Read(p)
	require.True(t, err == nil || err == io.EOF)
	if err == nil {
		_, err = fl.Read(p)
	}
	require.Equal(t, io.EOF, err, "on a LIVE connection the end of the file is a plain io.EOF (n=%d)", n)
	_ = fl.Close()

	// the same file, the connection dies before the reads: the reads must not report a clean end
	for _, copyPath := range []bool{false, true} {
		c2 := connected(t, s, func(cfg *Config) { cfg.MaxRetries = -1 })
		c2.mu.Lock()
		cn2 := c2.cur
		c2.mu.Unlock()
		rc2, err := c2.ReadFile(ctx, "a.txt")
		require.NoError(t, err)
		require.NoError(t, cn2.ssh.Close())
		select {
		case <-cn2.dead:
		case <-time.After(3 * time.Second):
			t.Fatal("connection did not end")
		}
		f2 := rc2.(*file)
		if copyPath {
			wt, ok := rc2.(io.WriterTo)
			require.True(t, ok, "the reader must keep its WriteTo: it is the pipelined path io.Copy uses")
			_, err = wt.WriteTo(io.Discard)
		} else {
			_, err = f2.Read(make([]byte, 64))
		}
		require.Error(t, err, "copyPath=%v: a dead connection ended cleanly", copyPath)
		assert.NotEqual(t, io.EOF, err, "copyPath=%v", copyPath)
		_ = f2.Close()
	}
}

// L01: a listing that "succeeds" while the connection has ended (pkg/sftp maps the write error of a closed channel to a clean
// end of the listing, so the entries may be partial) is refused as a lost connection.
func TestListingOnAConnectionThatEndedDuringItIsRefused(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, func(cfg *Config) { cfg.MaxRetries = -1 })
	c.listHook = func(cn *conn) {
		_ = cn.ssh.Close()
		select {
		case <-cn.dead:
		case <-time.After(3 * time.Second):
		}
	}
	ents, err := c.ListDirectory(context.Background(), "/")
	require.Error(t, err, "got %d entries from a connection that ended", len(ents))
	assert.ErrorIs(t, err, gosftp.ErrSSHFxConnectionLost)
	assert.True(t, IsTransient(err))
	c.listHook = nil
	ents, err = c.ListDirectory(context.Background(), "/") // and the client recovers on the next call
	require.NoError(t, err)
	assert.NotEmpty(t, ents)
}

// N09/N21: alive() against a connection object whose "dead" signal never fires (so only the keepalive request itself can tell):
// a closed transport fails the request at once, a live one answers, a silent one times out.
func TestAliveProbesTheTransport(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, nil)
	c.mu.Lock()
	cn := c.cur
	c.mu.Unlock()
	blind := &conn{ssh: cn.ssh, dead: make(chan struct{})} // never closed: the fast path cannot answer
	assert.True(t, blind.alive(), "a live connection answers the keepalive")
	require.NoError(t, cn.ssh.Close())
	assert.False(t, blind.alive(), "a closed transport fails the keepalive request at once")
}

func TestAliveTimesOutOnASilentPeer(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	p := startHoleProxy(t, s.Addr)
	c := proxiedClient(t, s, p, nil)
	require.NoError(t, c.Connect(context.Background()))
	defer c.Disconnect(context.Background()) //nolint:errcheck
	c.mu.Lock()
	cn := c.cur
	c.mu.Unlock()
	cn.aliveTimeout = 300 * time.Millisecond // alive() is bounded by KeepAliveTimeout (fix-r3), which the connection carries
	p.hole.Store(true)
	start := time.Now()
	assert.False(t, cn.alive(), "a peer that stopped answering is not alive")
	assert.Less(t, time.Since(start), 2*time.Second)
}

// N16/N17 (deterministic wiring test): Read consults alive() when it sees io.EOF and WriteTo when it ends cleanly. The probe is
// replaced by "dead" on a LIVE connection, so a plain end of file is then reported as a lost connection.
func TestReadAndWriteToConsultTheConnectionBeforeReportingTheEnd(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	for _, copyPath := range []bool{false, true} {
		c := connected(t, s, func(cfg *Config) { cfg.MaxRetries = -1 })
		c.mu.Lock()
		cn := c.cur
		c.mu.Unlock()
		rc, err := c.ReadFile(context.Background(), "a.txt")
		require.NoError(t, err)
		asked := 0
		cn.probe = func() bool { asked++; return false }
		if copyPath {
			_, err = rc.(io.WriterTo).WriteTo(io.Discard)
		} else {
			p := make([]byte, 64)
			_, err = rc.Read(p) // 10 bytes then the server's EOF
			if err == nil {
				_, err = rc.Read(p)
			}
		}
		assert.Positive(t, asked, "copyPath=%v: the end was reported without asking the connection", copyPath)
		assert.ErrorIs(t, err, gosftp.ErrSSHFxConnectionLost, "copyPath=%v", copyPath)
		assert.False(t, c.IsConnected(), "copyPath=%v: the connection that could not vouch for the end is dropped", copyPath)
		_ = rc.Close()
		// control: a probe that says "alive" leaves a plain end of file alone
		c2 := connected(t, s, func(cfg *Config) { cfg.MaxRetries = -1 })
		c2.mu.Lock()
		c2.cur.probe = func() bool { return true }
		c2.mu.Unlock()
		rc2, err := c2.ReadFile(context.Background(), "a.txt")
		require.NoError(t, err)
		if copyPath {
			n, err := rc2.(io.WriterTo).WriteTo(io.Discard)
			require.NoError(t, err)
			assert.Equal(t, int64(10), n)
		} else {
			b, err := io.ReadAll(rc2)
			require.NoError(t, err)
			assert.Equal(t, "hello sftp", string(b))
		}
		_ = rc2.Close()
	}
}
