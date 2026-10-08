package sftp

// fix-r3: tests for the findings of the WF24 re-review that are not pinned by an adopted reviewer file (wf24_*_test.go, byte-identical
// copies of the reviewer's probes and discriminators). Black-box where the behaviour can be observed from outside, white-box for the
// pure decision functions and the accessors.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	gosftp "github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/fabric"
)

// ---- class C: error classification, one truth table ------------------------------------------------------------------------

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// Every error value that can reach run / file.call / acquire / retry: pkg/sftp errors and their %w wraps, x/crypto handshake errors,
// net/os/syscall errors, both context errors and their wraps, and every sentinel of this package.
func TestClassification_TruthTable(t *testing.T) {
	wrap := func(e error) error { return fmt.Errorf("sftp: stat x: %w", e) }
	rows := []struct {
		name            string
		err             error
		loss, transient bool
	}{
		{"conn lost", gosftp.ErrSSHFxConnectionLost, true, true},
		{"conn lost wrapped", wrap(gosftp.ErrSSHFxConnectionLost), true, true},
		{"no connection", gosftp.ErrSSHFxNoConnection, true, true},
		{"unexpected EOF", io.ErrUnexpectedEOF, true, true},
		{"net closed", net.ErrClosed, true, true},
		{"ECONNRESET", syscall.ECONNRESET, true, true},
		{"EPIPE", wrap(syscall.EPIPE), true, true},
		{"os deadline", os.ErrDeadlineExceeded, true, true},
		{"net timeout", &net.OpError{Op: "read", Err: timeoutErr{}}, true, true},
		{"net timeout wrapped", wrap(&net.OpError{Op: "read", Err: timeoutErr{}}), true, true},
		{"io.EOF (needs the probe)", io.EOF, false, true},
		{"wrapped io.EOF", wrap(io.EOF), false, true},
		{"server status wrapper", &serverStatus{err: io.EOF}, false, false},
		{"ECONNREFUSED", syscall.ECONNREFUSED, false, true},
		{"context canceled", context.Canceled, false, false},
		{"context deadline", context.DeadlineExceeded, false, false},
		{"context deadline wrapped", wrap(context.DeadlineExceeded), false, false},
		{"context canceled wrapped", wrap(context.Canceled), false, false},
		{"deadline inside a net.OpError", &net.OpError{Op: "read", Err: context.DeadlineExceeded}, false, false},
		{"not exist", os.ErrNotExist, false, false},
		{"permission", wrap(os.ErrPermission), false, false},
		{"exists", os.ErrExist, false, false},
		{"ErrReadOnly", ErrReadOnly, false, false},
		{"ErrPathEscape", wrap(ErrPathEscape), false, false},
		{"ErrNotConnected", ErrNotConnected, false, false},
		{"ErrMalformedReply", fmt.Errorf("%w: x", ErrMalformedReply), false, false},
		{"ErrDirTooLarge", fmt.Errorf("%w: x", ErrDirTooLarge), false, false},
		{"ErrDisconnected", ErrDisconnected, false, false},
		{"ErrInvalidConfig", fmt.Errorf("%w: x", ErrInvalidConfig), false, false},
		{"ErrCredentialUnavailable", fmt.Errorf("%w: x", ErrCredentialUnavailable), false, false},
		{"ErrNoPinStore", ErrNoPinStore, false, false},
		{"AuthError", &AuthError{User: "u", Host: "h", Err: errors.New("ssh: unable to authenticate")}, false, false},
		{"UnknownHostKeyError", &UnknownHostKeyError{Host: "h"}, false, false},
		{"HostKeyMismatchError", &HostKeyMismatchError{Host: "h"}, false, false},
		{"handshake failure", errors.New("ssh: handshake failed: read tcp: connection reset"), false, false},
		{"status failure", &gosftp.StatusError{Code: 4}, false, false},
		{"plain error", errors.New("boom"), false, false},
	}
	for _, r := range rows {
		loss, tr, ctxe := isConnectionLoss(r.err), IsTransient(r.err), isCtxErr(r.err)
		assert.Equal(t, r.loss, loss, "%s: isConnectionLoss", r.name)
		assert.Equal(t, r.transient, tr, "%s: IsTransient", r.name)
		// the invariants, over the whole table
		if loss {
			assert.True(t, tr, "%s: every connection loss is transient", r.name)
		}
		if ctxe {
			assert.False(t, loss, "%s: a context error is never a connection loss", r.name)
			assert.False(t, tr, "%s: a context error is never transient", r.name)
		}
		// the drop decision, with the context alive and with the context ended
		alive := callDisposition(nil, r.err)
		ended := callDisposition(context.Canceled, r.err)
		switch {
		case ctxe:
			assert.Equal(t, dispReturn, alive, "%s: with a live context the error just goes back", r.name)
			assert.Equal(t, dispCtxOnly, ended, "%s: pkg/sftp gave up by itself: the connection is NOT dropped", r.name)
		case loss:
			assert.Equal(t, dispDropErr, alive, r.name)
			assert.Equal(t, dispDropCtx, ended, r.name)
		case errors.Is(r.err, io.EOF):
			assert.Equal(t, dispProbe, alive, r.name)
			assert.Equal(t, dispProbe, ended, r.name)
		default:
			assert.Equal(t, dispReturn, alive, r.name)
			assert.Equal(t, dispReturn, ended, r.name)
		}
	}
}

// ---- S09: a wrapped io.EOF (the send error of a dead channel) is handled the same way everywhere --------------------------------

func TestFile_CloseAndSeekOnADeadConnectionAreDeterministic(t *testing.T) {
	s := startProbe(t, probeOpts{})
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "a.txt"), bytes.Repeat([]byte("x"), 4096), 0o644))
	for i := 0; i < 40; i++ {
		c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1; cfg.KeepAliveInterval = -1 })
		require.NoError(t, c.Connect(context.Background()))
		rc, err := c.OpenSeekable(context.Background(), "a.txt")
		require.NoError(t, err)
		killConnAndWait(c)
		_, serr := rc.Seek(0, io.SeekEnd)
		require.Error(t, serr, "iteration %d", i)
		assert.True(t, isConnectionLoss(serr), "iteration %d: Seek on a dead connection is a connection loss, got %v", i, serr)
		assert.False(t, errors.Is(serr, io.EOF), "iteration %d: not an end of file: %v", i, serr)
		assert.NoError(t, rc.Close(), "iteration %d: the handle died with its connection", i)
		_ = c.Disconnect(context.Background())
	}
}

// ---- class L: one liveness policy ---------------------------------------------------------------------------------------------

func TestLivenessAccessors(t *testing.T) {
	c := NewSFTPClient(&Config{})
	assert.Equal(t, DefaultKeepAliveTimeout, c.livenessTimeout())
	assert.Equal(t, 7*time.Second, NewSFTPClient(&Config{KeepAliveTimeout: 7 * time.Second}).livenessTimeout())
	assert.Equal(t, DefaultKeepAliveTimeout, NewSFTPClient(&Config{KeepAliveTimeout: -1}).livenessTimeout())

	// V02: the keepalive is ON by default, with the documented period; a negative interval turns it off
	iv, ok := c.keepaliveInterval()
	assert.True(t, ok)
	assert.Equal(t, DefaultKeepAliveInterval, iv)
	_, ok = NewSFTPClient(&Config{KeepAliveInterval: -1}).keepaliveInterval()
	assert.False(t, ok)
	iv, ok = NewSFTPClient(&Config{KeepAliveInterval: 5 * time.Second}).keepaliveInterval()
	assert.True(t, ok)
	assert.Equal(t, 5*time.Second, iv)
}

// V15: the ranged read window is MaxPacket x MaxConcurrentRequests, capped at 4 MiB.
func TestReadWindow(t *testing.T) {
	assert.Equal(t, DefaultMaxPacket*DefaultMaxConcurrentRequests, NewSFTPClient(&Config{}).readWindow())
	assert.Equal(t, 2<<20, NewSFTPClient(&Config{}).readWindow())
	assert.Equal(t, 4<<20, NewSFTPClient(&Config{MaxPacket: 32768, MaxConcurrentRequests: 1000}).readWindow(), "capped at 4 MiB")
	assert.Equal(t, maxReadWindow, NewSFTPClient(&Config{MaxPacket: 32768, MaxConcurrentRequests: 129}).readWindow())
	assert.Equal(t, 8*1024, NewSFTPClient(&Config{MaxPacket: 1024, MaxConcurrentRequests: 8}).readWindow())
}

// S04: the question asked after an end of file is bounded by KeepAliveTimeout, not by a constant. A reply that takes longer than the
// configured bound IS a dead link as far as the owner said; one that takes less is not.
func TestEndOfFileLivenessFollowsKeepAliveTimeout(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		delay   time.Duration
		wantErr bool
	}{
		{"slow link allowed more than 3 s", 8 * time.Second, 3500 * time.Millisecond, false},
		{"owner allows only 300 ms", 300 * time.Millisecond, 2 * time.Second, true},
	} {
		s, _ := wfServer(t, tc.delay)
		require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "a.txt"), []byte("0123456789"), 0o644))
		c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1; cfg.KeepAliveInterval = -1; cfg.KeepAliveTimeout = tc.timeout })
		require.NoError(t, c.Connect(context.Background()))
		rc, err := c.ReadFile(context.Background(), "a.txt")
		require.NoError(t, err)
		start := time.Now()
		_, cerr := io.Copy(io.Discard, rc)
		el := time.Since(start)
		_ = rc.Close()
		if tc.wantErr {
			assert.ErrorIs(t, cerr, gosftp.ErrSSHFxConnectionLost, tc.name)
			assert.Less(t, el, 1500*time.Millisecond, "%s: gave up at the configured bound, not later", tc.name)
		} else {
			assert.NoError(t, cerr, tc.name)
			assert.True(t, c.IsConnected(), tc.name)
		}
		_ = c.Disconnect(context.Background())
	}
}

// ---- class B: listing accounting -----------------------------------------------------------------------------------------------

// S03: a listing over its budget fails ALONE: the connection stays up, the next listing works, and the error is not transient.
func TestListingOverBudgetFailsOnlyThatListing(t *testing.T) {
	s := listingServer(t, [][]string{entries("a", 100), entries("b", 100), entries("c", 100)})
	c := rootClient(s, func(cfg *Config) { cfg.MaxDirEntries = 150 })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	_, err := c.ListDirectory(ctx, "/")
	require.ErrorIs(t, err, ErrDirTooLarge)
	assert.False(t, IsTransient(err))
	assert.True(t, c.IsConnected(), "the connection that carried the oversize listing stays up")
	assert.EqualValues(t, 1, s.conns.Load(), "no re-dial happened")
	ents, err := c.ListDirectory(ctx, "/") // the scripted server hands out its third page now: 100 entries, within the budget
	require.NoError(t, err, "the same client lists again")
	assert.Len(t, ents, 100)
}

// S03 end to end with the real request server: an oversize listing does not touch a stream that is open on the same connection.
func TestOversizeListingDoesNotDisturbAStream(t *testing.T) {
	s := startProbe(t, probeOpts{})
	require.NoError(t, os.MkdirAll(filepath.Join(s.Dir, "many"), 0o755))
	for i := 0; i < 400; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "many", fmt.Sprintf("f%03d", i)), nil, 0o644))
	}
	big := bytes.Repeat([]byte("0123456789abcdef"), 128*1024) // 2 MiB
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "big"), big, 0o644))
	c := probeClient(s, func(cfg *Config) { cfg.MaxDirEntries = 100; cfg.MaxRetries = -1 })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	rc, err := c.ReadFile(ctx, "big")
	require.NoError(t, err)
	head := make([]byte, 1000)
	_, err = io.ReadFull(rc, head)
	require.NoError(t, err)
	_, err = c.ListDirectory(ctx, "many")
	require.ErrorIs(t, err, ErrDirTooLarge)
	rest, err := io.ReadAll(rc)
	require.NoError(t, err, "the stream on the same connection finished")
	_ = rc.Close()
	assert.Equal(t, big, append(head, rest...))
	assert.EqualValues(t, 1, s.conns.Load())
	ents, err := c.ListDirectory(ctx, "/")
	require.NoError(t, err, "a small listing still works")
	assert.Len(t, ents, 2)
}

// S08: names that are not file names are dropped (a NUL byte; "/" is covered by the adopted probe N3).
func TestListingDropsImplausibleNames(t *testing.T) {
	s := listingServer(t, [][]string{{"a\x00b", "ok", "/", ""}})
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
	assert.Equal(t, []string{"ok"}, names)
	for _, n := range []string{"", ".", "..", "/", "a/b", "a\x00b"} {
		assert.False(t, plausibleName(n), "%q", n)
	}
	for _, n := range []string{"a", "a b", ".hidden", "..x", "é", `x\y`} {
		assert.True(t, plausibleName(n), "%q", n)
	}
}

// ---- S10: Disconnect wins over a Connect in flight ----------------------------------------------------------------------------

func TestDisconnectDuringConnectWins(t *testing.T) {
	s := startProbe(t, probeOpts{})
	s.delay.Store(int64(700 * time.Millisecond))
	c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1 })
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- c.Connect(ctx) }()
	time.Sleep(250 * time.Millisecond)
	require.NoError(t, c.Disconnect(ctx))
	cerr := <-done
	assert.ErrorIs(t, cerr, ErrDisconnected)
	assert.False(t, IsTransient(cerr))
	assert.False(t, c.IsConnected(), "a Connect that was in flight must not install its connection after Disconnect returned")
	// control: Disconnect followed by a NEW Connect is a normal sequence
	s.delay.Store(0)
	require.NoError(t, c.Connect(ctx))
	assert.True(t, c.IsConnected())
	_ = c.Disconnect(ctx)
}

// ---- S14: a configuration that can never work is refused before any traffic -------------------------------------------------------

func TestMaxPacketAboveWhatPkgSftpAcceptsIsRefusedUpFront(t *testing.T) {
	s := startProbe(t, probeOpts{})
	c := probeClient(s, func(cfg *Config) { cfg.MaxPacket = 65536; cfg.MaxRetries = 3 })
	err := c.Connect(context.Background())
	require.ErrorIs(t, err, ErrInvalidConfig)
	assert.False(t, IsTransient(err), "never retried")
	assert.EqualValues(t, 0, s.conns.Load(), "no connection was attempted")
	c2 := probeClient(s, func(cfg *Config) { cfg.MaxPacket = MaxPacketLimit })
	require.NoError(t, c2.Connect(context.Background()), "the limit itself works")
	_ = c2.Disconnect(context.Background())
}

// ---- class E: the typed auth contract with pkg/fabric --------------------------------------------------------------------------------

func TestAuthContractWithFabric(t *testing.T) {
	isAuth := func(err error) bool { return fabric.Classify(err) == fabric.ClassAuth }
	for _, e := range []error{
		&AuthError{User: "u", Host: "h", Err: errors.New("ssh: unable to authenticate, attempted methods [none password]")},
		&AuthError{User: "u", Host: "h", Err: errors.New("ssh: unexpected message type 51 (expected 60)")}, // no text marker at all
		&AuthError{User: "u", Host: "h"}, // nothing underneath
		fmt.Errorf("pool: connect nas: %w", &AuthError{User: "u", Host: "h", Err: errors.New("x")}),
	} {
		assert.True(t, errors.Is(e, fabric.ErrAuth), "%v", e)
		assert.True(t, isAuth(e), "fabric.Classify must report auth for %v", e)
		assert.False(t, IsTransient(e))
	}
	// every other typed error / sentinel this package exports is NOT an authentication failure
	for _, e := range []error{
		&UnknownHostKeyError{Host: "h"}, &HostKeyMismatchError{Host: "h"}, ErrNoPinStore, ErrReadOnly, ErrPathEscape, ErrNotConnected, ErrDisconnected,
		ErrInvalidConfig, ErrMalformedReply, ErrDirTooLarge, fmt.Errorf("%w: x", ErrCredentialUnavailable), ErrPinNotConfirmed,
	} {
		assert.False(t, errors.Is(e, fabric.ErrAuth), "%v", e)
		assert.False(t, isAuth(e), "%v", e)
	}
}

// The two real shapes of a wrong password, against real ssh servers: the plain rejection and the keyboard-interactive failure.
func TestWrongPasswordIsFabricAuthInBothShapes(t *testing.T) {
	for _, kbd := range []bool{false, true} {
		s := startProbe(t, probeOpts{kbdNoDevice: kbd})
		c := probeClient(s, func(cfg *Config) {
			cfg.MaxRetries = -1
			cfg.Resolver = mapResolver{"r": {Password: "definitely-wrong"}}
		})
		err := c.Connect(context.Background())
		var ae *AuthError
		require.ErrorAs(t, err, &ae, "kbd=%v: %v", kbd, err)
		assert.ErrorIs(t, err, fabric.ErrAuth, "kbd=%v", kbd)
		assert.Equal(t, fabric.ClassAuth, fabric.Classify(err), "kbd=%v", kbd)
	}
}

// ---- S07: the read-ahead --------------------------------------------------------------------------------------------------------

func randBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	_, _ = rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// Sequential reads of every shape return the file byte for byte.
func TestReadAheadSequentialReadsAreByteIdentical(t *testing.T) {
	s := startProbe(t, probeOpts{})
	data := randBytes(1_300_000+17, 1)
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "f"), data, 0o644))
	c := probeClient(s, nil)
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	for _, size := range []int{1, 100, 1000, 32 * 1024, 33_000, 70_000, 300_000, 3 << 20} {
		rc, err := c.OpenSeekable(ctx, "f")
		require.NoError(t, err)
		var got bytes.Buffer
		buf := make([]byte, size)
		for {
			n, err := rc.Read(buf)
			got.Write(buf[:n])
			if err == io.EOF {
				break
			}
			require.NoError(t, err, "size %d", size)
			if size == 1 && got.Len() > 5000 { // 1-byte reads: enough to cross the read-ahead start
				break
			}
		}
		_ = rc.Close()
		if size == 1 {
			assert.Equal(t, data[:got.Len()], got.Bytes(), "size %d", size)
			continue
		}
		assert.Equal(t, data, got.Bytes(), "size %d", size)
	}
}

// Model test: random Read / Seek sequences (biased to sequential reads so the read-ahead runs) against the file held in memory.
func TestReadAheadAgainstAModel(t *testing.T) {
	s := startProbe(t, probeOpts{})
	data := randBytes(400_000+123, 2)
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "f"), data, 0o644))
	c := probeClient(s, nil)
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	for seed := int64(1); seed <= 12; seed++ {
		rng := rand.New(rand.NewSource(seed))
		rc, err := c.OpenSeekable(ctx, "f")
		require.NoError(t, err)
		pos := int64(0)
		size := int64(len(data))
		var log []string
		for op := 0; op < 120; op++ {
			if rng.Intn(10) < 7 { // a Read
				p := make([]byte, 1+rng.Intn(70_000))
				n, err := rc.Read(p)
				log = append(log, fmt.Sprintf("read(%d)=%d,%v@%d", len(p), n, err, pos))
				require.True(t, n >= 0 && n <= len(p), "seed %d: %v", seed, log)
				if pos >= size { // at or past the end (a Seek may go beyond it): nothing to read
					require.Equal(t, 0, n, "seed %d: %v", seed, log)
					require.Equal(t, io.EOF, err, "seed %d: %v", seed, log)
					continue
				}
				end := pos + int64(n)
				if end > size {
					t.Fatalf("seed %d: read past the end: %v", seed, log)
				}
				require.Equal(t, data[pos:end], p[:n], "seed %d: bytes differ: %v", seed, log)
				pos = end
				switch {
				case err == io.EOF:
					require.Equal(t, size, pos, "seed %d: EOF before the end: %v", seed, log)
				case err != nil:
					t.Fatalf("seed %d: %v: %v", seed, err, log)
				case n == 0:
					t.Fatalf("seed %d: (0, nil) read: %v", seed, log)
				}
				continue
			}
			var off int64
			var whence int
			switch rng.Intn(3) {
			case 0:
				whence, off = io.SeekStart, int64(rng.Intn(int(size)+500))
			case 1:
				whence = io.SeekCurrent
				off = int64(rng.Intn(80_000)) - pos
				if rng.Intn(2) == 0 {
					off = int64(rng.Intn(5)) // small forward moves: inside the buffer
				}
			default:
				whence, off = io.SeekEnd, -int64(rng.Intn(int(size)))
			}
			want := off
			if whence == io.SeekCurrent {
				want = pos + off
			} else if whence == io.SeekEnd {
				want = size + off
			}
			got, err := rc.Seek(off, whence)
			log = append(log, fmt.Sprintf("seek(%d,%d)=%d,%v want %d", off, whence, got, err, want))
			require.NoError(t, err, "seed %d: %v", seed, log)
			require.Equal(t, want, got, "seed %d: %v", seed, log)
			pos = got
		}
		_ = rc.Close()
	}
}

// A connection that dies in the middle of a read-ahead stream is a lost connection, never an end of file that looks complete.
func TestReadAheadOnADyingConnectionIsNotAnEOF(t *testing.T) {
	s := startProbe(t, probeOpts{})
	data := randBytes(1<<20, 3)
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "f"), data, 0o644))
	c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1; cfg.KeepAliveInterval = -1 })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	rc, err := c.ReadFile(ctx, "f")
	require.NoError(t, err)
	p := make([]byte, 32*1024)
	for i := 0; i < 4; i++ { // two plain reads, then the read-ahead starts
		_, err := io.ReadFull(rc, p)
		require.NoError(t, err)
	}
	killConnAndWait(c)
	rest, err := io.ReadAll(rc)
	_ = rc.Close()
	require.Error(t, err, "got %d more bytes and a clean end of a 1 MiB file whose connection died", len(rest))
	assert.True(t, isConnectionLoss(err), "%v", err)
	assert.Less(t, len(rest)+4*len(p), len(data))
}

// The end of the file is verified against the connection after a fill too (the fill may carry data and the end together).
func TestReadAheadEndOfFileConsultsTheConnection(t *testing.T) {
	s := startProbe(t, probeOpts{})
	data := randBytes(200_000, 4)
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "f"), data, 0o644))
	var asked atomic.Int32
	c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1 })
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	c.mu.Lock()
	c.cur.probe = func() bool { asked.Add(1); return true }
	c.mu.Unlock()
	rc, err := c.ReadFile(ctx, "f")
	require.NoError(t, err)
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, data, b)
	assert.Positive(t, asked.Load(), "the end of the file was reported without asking the connection")
	n, err := rc.Read(make([]byte, 10))
	assert.Equal(t, 0, n)
	assert.Equal(t, io.EOF, err, "the end of the file is sticky")
	_ = rc.Close()
}

// A Seek inside the bytes already buffered by the read-ahead moves inside the buffer (no request), a SeekCurrent outside it is sent
// as an absolute position (the sftp file itself is AHEAD of the logical position by the buffered bytes).
func TestReadAheadSeekInsideAndOutsideTheBuffer(t *testing.T) {
	s := startProbe(t, probeOpts{})
	data := randBytes(600_000, 5)
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "f"), data, 0o644))
	c := probeClient(s, nil)
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	rc, err := c.OpenSeekable(ctx, "f")
	require.NoError(t, err)
	defer rc.Close() //nolint:errcheck
	p := make([]byte, 32*1024)
	for i := 0; i < 3; i++ { // two plain reads, the third one starts the read-ahead (64 KiB fetched, 32 KiB buffered)
		_, err := io.ReadFull(rc, p)
		require.NoError(t, err)
	}
	pos, err := rc.Seek(0, io.SeekCurrent)
	require.NoError(t, err)
	require.EqualValues(t, 3*32*1024, pos)
	pos, err = rc.Seek(5000, io.SeekCurrent) // inside the buffer
	require.NoError(t, err)
	require.EqualValues(t, 3*32*1024+5000, pos)
	q := make([]byte, 100)
	_, err = io.ReadFull(rc, q)
	require.NoError(t, err)
	assert.Equal(t, data[pos:pos+100], q, "the read after a seek inside the buffer starts at the new position")
	pos, err = rc.Seek(-50_000, io.SeekCurrent) // outside (behind) the buffer: an absolute seek on the server
	require.NoError(t, err)
	require.EqualValues(t, 3*32*1024+5000+100-50_000, pos)
	_, err = io.ReadFull(rc, q)
	require.NoError(t, err)
	assert.Equal(t, data[pos:pos+100], q)
}

// Read followed by WriteTo (io.Copy of the rest) loses nothing: the bytes the read-ahead already fetched are written first.
func TestReadAheadThenWriteToLosesNothing(t *testing.T) {
	s := startProbe(t, probeOpts{})
	data := randBytes(700_001, 6)
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "f"), data, 0o644))
	c := probeClient(s, nil)
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	rc, err := c.ReadFile(ctx, "f")
	require.NoError(t, err)
	defer rc.Close() //nolint:errcheck
	p := make([]byte, 32*1024)
	for i := 0; i < 5; i++ {
		_, err := io.ReadFull(rc, p)
		require.NoError(t, err)
	}
	var rest bytes.Buffer
	n, err := rc.(io.WriterTo).WriteTo(&rest)
	require.NoError(t, err)
	assert.EqualValues(t, len(data)-5*len(p), n)
	assert.Equal(t, data[5*len(p):], rest.Bytes())
}

// highWater records the furthest byte any READ request asked for.
type highWater struct{ max atomic.Int64 }

type hwAt struct {
	f *os.File
	h *highWater
}

func (o *hwAt) ReadAt(p []byte, off int64) (int, error) {
	end := off + int64(len(p))
	for {
		cur := o.h.max.Load()
		if end <= cur || o.h.max.CompareAndSwap(cur, end) {
			break
		}
	}
	return o.f.ReadAt(p, off)
}
func (o *hwAt) Close() error { return o.f.Close() }

type hwGet struct{ h *highWater }

func (g hwGet) Fileread(r *gosftp.Request) (io.ReaderAt, error) {
	f, err := os.Open(r.Filepath)
	if err != nil {
		return nil, err
	}
	return &hwAt{f: f, h: g.h}, nil
}

// A bounded range never reads beyond its end (the read-ahead is for open-ended streams), however it is consumed.
func TestBoundedRangeNeverReadsBeyondItsEnd(t *testing.T) {
	h := &highWater{}
	s := startProbe(t, probeOpts{fileGet: hwGet{h}})
	data := randBytes(1<<20, 7)
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "f"), data, 0o644))
	c := probeClient(s, nil)
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	defer c.Disconnect(ctx) //nolint:errcheck
	r, err := c.ReadRange(ctx, "f", 1000, 150_000)
	require.NoError(t, err)
	var got bytes.Buffer
	buf := make([]byte, 10_000) // ranged.Read: many small reads, the read-ahead pattern
	for {
		n, err := r.Read(buf)
		got.Write(buf[:n])
		if err != nil {
			require.Equal(t, io.EOF, err)
			break
		}
	}
	_ = r.Close()
	assert.Equal(t, data[1000:151_000], got.Bytes())
	assert.LessOrEqual(t, h.max.Load(), int64(151_000), "no READ asked for a byte beyond offset+length")
}
