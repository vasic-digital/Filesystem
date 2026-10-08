//go:build integration

package ftp

// Integration tests: a REAL pure-ftpd (clear text + explicit FTPS), started by scripts/test-infra/ftps_fixture.sh. No fake of any kind.
// The launcher passes the server address, the user, the password (through the credential_ref "fixture", i.e. FTP_CRED_FIXTURE_PASSWORD), the
// SHA-256 of the generated certificate (computed outside, with openssl: the owner's confirmation) and the expected content values.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"
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

type fixture struct {
	host, user, fp, bSHA string
	port                 int
	bSize                int64
	aMtime, cMtime       int64
}

func env(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("integration test needs %s (run through scripts/test-infra/ftps_fixture.sh)", k)
	}
	return v
}

func load(t *testing.T) fixture {
	t.Helper()
	p, _ := strconv.Atoi(env(t, "FTP_TEST_PORT"))
	bs, _ := strconv.ParseInt(env(t, "FTP_TEST_B_SIZE"), 10, 64)
	am, _ := strconv.ParseInt(env(t, "FTP_TEST_A_MTIME"), 10, 64)
	cm, _ := strconv.ParseInt(env(t, "FTP_TEST_C_MTIME"), 10, 64)
	return fixture{host: env(t, "FTP_TEST_HOST"), port: p, user: env(t, "FTP_TEST_USER"), fp: env(t, "FTP_TEST_CERT_FP"),
		bSHA: env(t, "FTP_TEST_B_SHA256"), bSize: bs, aMtime: am, cMtime: cm}
}

func (f fixture) cfg(st PinStore) *Config {
	return &Config{Host: f.host, Port: f.port, Username: f.user, CredentialRef: "fixture", PinStore: st,
		DialTimeout: 10 * time.Second, IOTimeout: 30 * time.Second}
}

func (f fixture) pinned(t *testing.T) PinStore {
	t.Helper()
	st := NewMemPinStore()
	_, err := Pin(ictx(t), st, f.host, f.port, Confirmation{Fingerprint: f.fp, ConfirmedBy: "fixture-launcher"})
	require.NoError(t, err)
	return st
}

func ictx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestIntegrationSelftest(t *testing.T) {
	f := load(t)
	d, err := DiscoverCert(ictx(t), f.host, f.port, 10*time.Second)
	require.NoError(t, err)
	assert.Equal(t, f.fp, d.Fingerprint, "the server presents the certificate the launcher generated")
}

func TestIntegration_ExplicitFTPS_ListStatReadResume(t *testing.T) {
	f := load(t)
	c := NewFTPClient(f.cfg(f.pinned(t)))
	require.NoError(t, c.Connect(ictx(t)))
	defer c.Disconnect(context.Background())

	got, err := c.ListDirectory(ictx(t), "/")
	require.NoError(t, err)
	by := map[string]*client.FileInfo{}
	for _, e := range got {
		by[e.Name] = e
	}
	require.Contains(t, by, "a.txt")
	require.Contains(t, by, "sub")
	assert.True(t, by["sub"].IsDir)
	assert.Equal(t, int64(10), by["a.txt"].Size)
	assert.Equal(t, f.aMtime, by["a.txt"].ModTime.Unix(), "MLSD modify fact, not a fabricated time")
	assert.Contains(t, by, "Čšž_日本.txt", "non-ASCII name survives (OPTS UTF8 ON)")
	assert.False(t, c.Degraded(), "pure-ftpd offers MLSD")
	assert.NotContains(t, by, ".")
	assert.NotContains(t, by, "..")

	fi, err := c.GetFileInfo(ictx(t), "sub/deep/c.txt")
	require.NoError(t, err)
	assert.Equal(t, f.cMtime, fi.ModTime.Unix())
	assert.Equal(t, int64(2), fi.Size)
	ok, err := c.FileExists(ictx(t), "nope.txt")
	require.NoError(t, err)
	assert.False(t, ok)

	rc, err := c.ReadFile(ictx(t), "sub/b.bin")
	require.NoError(t, err)
	h := sha256.New()
	n, err := io.Copy(h, rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, f.bSize, n)
	assert.Equal(t, f.bSHA, hex.EncodeToString(h.Sum(nil)))

	// resume: the tail from an offset equals the tail of the whole file
	full := sha256.New()
	r0, err := c.ReadFile(ictx(t), "sub/b.bin")
	require.NoError(t, err)
	head := make([]byte, 700000)
	_, err = io.ReadFull(r0, head)
	require.NoError(t, err)
	full.Write(head)
	_, err = io.Copy(full, r0)
	require.NoError(t, err)
	require.NoError(t, r0.Close(), "a complete read ends with a 226 on the real server")
	assert.Equal(t, f.bSHA, hex.EncodeToString(full.Sum(nil)), "head + the rest of the same stream reproduce the file")

	tail := sha256.New()
	r1, err := c.ReadFileFrom(ictx(t), "sub/b.bin", 700000)
	require.NoError(t, err)
	tn, err := io.Copy(tail, r1)
	require.NoError(t, err)
	require.NoError(t, r1.Close())
	assert.Equal(t, f.bSize-700000, tn)

	sk, err := c.OpenSeekable(ictx(t), "sub/b.bin")
	require.NoError(t, err)
	_, err = sk.Seek(700000, io.SeekStart)
	require.NoError(t, err)
	th := sha256.New()
	_, err = io.Copy(th, sk)
	require.NoError(t, err)
	require.NoError(t, sk.Close())
	assert.Equal(t, hex.EncodeToString(tail.Sum(nil)), hex.EncodeToString(th.Sum(nil)), "REST via ReadFileFrom == REST via OpenSeekable")

	// head + tail == whole
	rest := sha256.New()
	rest.Write(head)
	r2, err := c.ReadFileFrom(ictx(t), "sub/b.bin", 700000)
	require.NoError(t, err)
	_, err = io.Copy(rest, r2)
	require.NoError(t, err)
	require.NoError(t, r2.Close())
	assert.Equal(t, f.bSHA, hex.EncodeToString(rest.Sum(nil)), "bytes before the offset + the resumed tail reproduce the file")
}

// countingResolver counts how many times the password was fetched: one fetch = one login attempt.
type countingResolver struct {
	mu sync.Mutex
	n  int
	pw string
}

func (r *countingResolver) Resolve(_ context.Context, _ string) (*Credential, error) {
	r.mu.Lock()
	r.n++
	r.mu.Unlock()
	return &Credential{Password: r.pw}, nil
}

func (r *countingResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// WF21 T3: against the REAL server a wrong password is one attempt (a counted password fetch), never retried.
func TestIntegration_WrongPassword_IsExactlyOneAttempt(t *testing.T) {
	f := load(t)
	bad := f.cfg(f.pinned(t))
	cr := &countingResolver{pw: "definitely-wrong"}
	bad.Resolver = cr
	sc, err := NewScanClient(bad, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond}})
	require.NoError(t, err)
	err = sc.Connect(ictx(t))
	require.Error(t, err)
	assert.Equal(t, fabric.ClassAuth, fabric.Classify(err))
	assert.Equal(t, 1, cr.count(), "one login attempt for a rejected password, not %d", cr.count())
}

// WF21 F2 (the open question of the review: what does the real server send when a download is closed early?). Whatever
// it sends, the next commands must be answered correctly.
func TestIntegration_EarlyClose_KeepsTheControlChannelInStep(t *testing.T) {
	f := load(t)
	c := NewFTPClient(f.cfg(f.pinned(t)))
	require.NoError(t, c.Connect(ictx(t)))
	defer c.Disconnect(context.Background())
	for i := 0; i < 3; i++ {
		rc, err := c.ReadFile(ictx(t), "sub/b.bin")
		require.NoError(t, err)
		_, err = io.ReadFull(rc, make([]byte, 10))
		require.NoError(t, err)
		require.NoError(t, rc.Close(), "an early close is not an error")
		fi, err := c.GetFileInfo(ictx(t), "sub/deep/c.txt")
		require.NoError(t, err)
		assert.Equal(t, int64(2), fi.Size, "c.txt's own size after an early close (round %d)", i)
		assert.Equal(t, f.cMtime, fi.ModTime.Unix())
		ok, err := c.FileExists(ictx(t), "nope.txt")
		require.NoError(t, err)
		assert.False(t, ok)
	}
	c.mu.Lock()
	kept := c.p != nil && !c.p.isBroken()
	c.mu.Unlock()
	t.Logf("real server after an early close: control connection kept=%v (false means the server answered with more than one reply and the client re-dialled)", kept)
}

func TestIntegration_Seekable_WholeFileAndSeeks_NoTruncation(t *testing.T) {
	f := load(t)
	c := NewFTPClient(f.cfg(f.pinned(t)))
	require.NoError(t, c.Connect(ictx(t)))
	defer c.Disconnect(context.Background())
	sk, err := c.OpenSeekable(ictx(t), "sub/b.bin")
	require.NoError(t, err)
	h := sha256.New()
	n, err := io.Copy(h, sk)
	require.NoError(t, err)
	assert.Equal(t, f.bSize, n)
	assert.Equal(t, f.bSHA, hex.EncodeToString(h.Sum(nil)))
	require.NoError(t, sk.Close())
	// the reference reads use a SECOND client: an open seekable stream holds its client's session until the next Seek or Close
	ref := NewFTPClient(f.cfg(f.pinned(t)))
	require.NoError(t, ref.Connect(ictx(t)))
	defer ref.Disconnect(context.Background())
	sk, err = c.OpenSeekable(ictx(t), "sub/b.bin")
	require.NoError(t, err)
	defer sk.Close()
	for _, off := range []int64{0, 1, 65536, 500000, f.bSize - 100, 4096} {
		want := make([]byte, 100)
		r, err := ref.ReadFileFrom(ictx(t), "sub/b.bin", off)
		require.NoError(t, err)
		_, err = io.ReadFull(r, want)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		_, err = sk.Seek(off, io.SeekStart)
		require.NoError(t, err)
		got := make([]byte, 100)
		_, err = io.ReadFull(sk, got)
		require.NoError(t, err)
		assert.Equal(t, want, got, "seek to %d", off)
	}
}

func TestIntegration_CancelledContext_EndsATransferPromptly_AndTheClientRecovers(t *testing.T) {
	f := load(t)
	cfg := f.cfg(f.pinned(t))
	c := NewFTPClient(cfg)
	require.NoError(t, c.Connect(ictx(t)))
	defer c.Disconnect(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	rc, err := c.ReadFile(ctx, "sub/b.bin")
	require.NoError(t, err)
	_, err = io.ReadFull(rc, make([]byte, 1000))
	require.NoError(t, err)
	cancel()
	start := time.Now()
	_, rerr := io.Copy(io.Discard, rc)
	_ = rc.Close()
	require.Error(t, rerr)
	assert.Less(t, time.Since(start), 5*time.Second)
	fi, err := c.GetFileInfo(ictx(t), "a.txt") // the next operation re-dials
	require.NoError(t, err)
	assert.Equal(t, int64(10), fi.Size)
}

func TestIntegration_Disconnect_ClosesAndReconnectWorks(t *testing.T) {
	f := load(t)
	c := NewFTPClient(f.cfg(f.pinned(t)))
	require.NoError(t, c.Connect(ictx(t)))
	require.NoError(t, c.Disconnect(ictx(t)))
	assert.False(t, c.IsConnected())
	_, err := c.ListDirectory(ictx(t), "/")
	require.ErrorIs(t, err, ErrNotConnected)
	require.NoError(t, c.Connect(ictx(t)))
	defer c.Disconnect(context.Background())
	l, err := c.ListDirectory(ictx(t), "/")
	require.NoError(t, err)
	assert.NotEmpty(t, l)
}

func TestIntegration_Refusals(t *testing.T) {
	f := load(t)
	// unknown certificate: refused, with the fingerprint
	err := NewFTPClient(f.cfg(NewMemPinStore())).Connect(ictx(t))
	var u *UnknownCertError
	require.ErrorAs(t, err, &u)
	assert.Equal(t, f.fp, u.Fingerprint)
	// wrong owner confirmation: nothing recorded
	st := NewMemPinStore()
	_, err = Pin(ictx(t), st, f.host, f.port, Confirmation{Fingerprint: "SHA256:00:11"})
	require.ErrorIs(t, err, ErrPinNotConfirmed)
	pins, _ := st.Lookup(HostPort(f.host, f.port))
	assert.Empty(t, pins)
	// a pin of some other certificate: changed certificate refused
	st2 := NewMemPinStore()
	other := genCertT(t)
	require.NoError(t, st2.Record(HostPort(f.host, f.port), other))
	err = NewFTPClient(f.cfg(st2)).Connect(ictx(t))
	var m *CertMismatchError
	require.ErrorAs(t, err, &m)
	assert.Equal(t, f.fp, m.Presented)
	// clear text: refused by default, allowed on a trusted LAN
	cfg := f.cfg(nil)
	cfg.TLSMode = TLSNone
	require.ErrorIs(t, NewFTPClient(cfg).Connect(ictx(t)), ErrClearTextRefused)
	cfg.TrustedLAN = true
	c := NewFTPClient(cfg)
	require.NoError(t, c.Connect(ictx(t)))
	defer c.Disconnect(context.Background())
	l, err := c.ListDirectory(ictx(t), "/")
	require.NoError(t, err)
	assert.NotEmpty(t, l)
	// wrong password: classified auth, one attempt
	bad := f.cfg(f.pinned(t))
	bad.Resolver = mapResolver{"fixture": "definitely-wrong"}
	sc, err := NewScanClient(bad, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond}})
	require.NoError(t, err)
	err = sc.Connect(ictx(t))
	require.Error(t, err)
	assert.Equal(t, fabric.ClassAuth, fabric.Classify(err))
}

func TestIntegration_ScanPath_ReadOnly_WorkerPool(t *testing.T) {
	f := load(t)
	pool, err := NewWorkerPool(f.cfg(f.pinned(t)), fabric.PoolOptions{MaxPerKey: 3}, ScanOptions{})
	require.NoError(t, err)
	defer pool.CloseAll()
	sc := &client.StorageConfig{ID: "fixture-root", Protocol: "ftp"}
	var cs []client.Client
	for i := 0; i < 3; i++ {
		c, err := pool.GetClientContext(ictx(t), sc)
		require.NoError(t, err)
		cs = append(cs, c)
	}
	var wg sync.WaitGroup
	for _, c := range cs {
		wg.Add(1)
		go func(c client.Client) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				l, err := c.ListDirectory(ictx(t), "/sub")
				assert.NoError(t, err)
				assert.NotEmpty(t, l)
			}
			// every mutation is refused; the launcher proves afterwards that the served tree is unchanged
			assert.ErrorIs(t, c.DeleteFile(ictx(t), "a.txt"), decorators.ErrReadOnly)
			assert.ErrorIs(t, c.WriteFile(ictx(t), "new.txt", strings.NewReader("x")), decorators.ErrReadOnly)
			assert.ErrorIs(t, c.CreateDirectory(ictx(t), "newdir"), decorators.ErrReadOnly)
			assert.ErrorIs(t, c.DeleteDirectory(ictx(t), "sub"), decorators.ErrReadOnly)
			assert.ErrorIs(t, c.CopyFile(ictx(t), "a.txt", "b.txt"), decorators.ErrReadOnly)
		}(c)
	}
	wg.Wait()
	for _, c := range cs {
		require.NoError(t, pool.ReturnClient(c))
	}
}
