package sftp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	gosftp "github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"digital.vasic.filesystem/pkg/client"
)

// ---- pure unit tests (no network) --------------------------------------------------------------------------

func TestConfine_Table(t *testing.T) {
	c := NewSFTPClient(&Config{Root: "/srv/data"})
	cases := []struct {
		in      string
		logical string
		remote  string
		escape  bool
	}{
		{"", "/", "/srv/data", false},
		{"/", "/", "/srv/data", false},
		{"a/b", "/a/b", "/srv/data/a/b", false},
		{"/a/./b//c", "/a/b/c", "/srv/data/a/b/c", false},
		{"a/../b", "/b", "/srv/data/b", false},
		{"a\\b", "/a\\b", "/srv/data/a\\b", false}, // a backslash is an ordinary name byte on a POSIX server (SFTP-07)
		{"..", "", "", true},
		{"../etc/passwd", "", "", true},
		{"a/../../etc", "", "", true},
		{"/../x", "", "", true},
		{"a/b/../../..", "", "", true},
		{"a\x00b", "", "", true},
	}
	for _, tc := range cases {
		l, r, err := c.confine(tc.in)
		if tc.escape {
			require.Error(t, err, tc.in)
			assert.ErrorIs(t, err, ErrPathEscape, tc.in)
			continue
		}
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.logical, l, tc.in)
		assert.Equal(t, tc.remote, r, tc.in)
	}
}

func TestConfine_DefaultRootIsSlash(t *testing.T) {
	c := NewSFTPClient(&Config{})
	_, r, err := c.confine("x/y")
	require.NoError(t, err)
	assert.Equal(t, "/x/y", r)
}

func TestWithin(t *testing.T) {
	assert.True(t, within("/srv/data", "/srv/data"))
	assert.True(t, within("/srv/data", "/srv/data/a"))
	assert.False(t, within("/srv/data", "/srv/database"), "prefix of a sibling is not inside")
	assert.False(t, within("/srv/data", "/srv"))
	assert.True(t, within("/", "/anything"))
}

func TestFingerprintFormat(t *testing.T) {
	s := newSigner(t)
	fp := Fingerprint(s.PublicKey())
	assert.True(t, strings.HasPrefix(fp, "SHA256:"))
	assert.NotContains(t, fp, "=", "OpenSSH prints the fingerprint without padding")
	assert.Equal(t, fp, Fingerprint(s.PublicKey()))
	assert.NotEqual(t, fp, Fingerprint(newSigner(t).PublicKey()))
}

func TestHostPortNormalisation(t *testing.T) {
	assert.Equal(t, "nas.example:22", HostPort("NAS.Example", 0))
	assert.Equal(t, "nas.example:2222", HostPort("nas.example", 2222))
}

func TestHostKeyCallback_UnknownMismatchMatch(t *testing.T) {
	good := newSigner(t).PublicKey()
	other := newSigner(t).PublicKey()
	var refusal error

	cb := hostKeyCallback("h:22", nil, &refusal)
	err := cb("h:22", nil, good)
	var unk *UnknownHostKeyError
	require.ErrorAs(t, err, &unk)
	assert.Equal(t, Fingerprint(good), unk.Fingerprint)
	assert.Equal(t, err, refusal)

	refusal = nil
	pins := []HostKeyPin{{KeyType: good.Type(), Fingerprint: Fingerprint(good)}}
	cb = hostKeyCallback("h:22", pins, &refusal)
	require.NoError(t, cb("h:22", nil, good))
	assert.NoError(t, refusal)

	err = cb("h:22", nil, other)
	var mis *HostKeyMismatchError
	require.ErrorAs(t, err, &mis)
	assert.Equal(t, Fingerprint(other), mis.Presented)
	assert.Equal(t, []string{Fingerprint(good)}, mis.Pinned)
}

func TestHostKeyAlgorithmsFollowPinnedType(t *testing.T) {
	got := hostKeyAlgorithms([]HostKeyPin{{KeyType: "ssh-ed25519"}, {KeyType: "ssh-rsa"}, {KeyType: "ssh-ed25519"}})
	assert.Equal(t, []string{"ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"}, got)
	assert.Empty(t, hostKeyAlgorithms(nil))
}

func TestMemPinStore(t *testing.T) {
	s := NewMemPinStore()
	require.NoError(t, s.Record("h:22", HostKeyPin{Fingerprint: "SHA256:a"}))
	require.NoError(t, s.Record("h:22", HostKeyPin{Fingerprint: "SHA256:a"})) // idempotent
	require.NoError(t, s.Record("h:22", HostKeyPin{Fingerprint: "SHA256:b"}))
	pins, _ := s.Lookup("h:22")
	assert.Len(t, pins, 2)
	require.NoError(t, s.Remove("h:22", "SHA256:a"))
	pins, _ = s.Lookup("h:22")
	require.Len(t, pins, 1)
	assert.Equal(t, "SHA256:b", pins[0].Fingerprint)
	pins, _ = s.Lookup("other:22")
	assert.Empty(t, pins)
}

func TestFilePinStore_PersistsWith0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pins.json")
	s := NewFilePinStore(p)
	pins, err := s.Lookup("h:22")
	require.NoError(t, err)
	assert.Empty(t, pins, "absent file = no pins")

	require.NoError(t, s.Record("h:22", HostKeyPin{KeyType: "ssh-ed25519", Fingerprint: "SHA256:x", ConfirmedBy: "owner"}))
	st, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())

	s2 := NewFilePinStore(p) // a fresh instance reads the file
	pins, err = s2.Lookup("h:22")
	require.NoError(t, err)
	require.Len(t, pins, 1)
	assert.Equal(t, "owner", pins[0].ConfirmedBy)

	require.NoError(t, s2.Remove("h:22", "SHA256:x"))
	pins, _ = s.Lookup("h:22")
	assert.Empty(t, pins)
}

func TestFilePinStore_CorruptFileIsAnErrorNotNoPins(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pins.json")
	require.NoError(t, os.WriteFile(p, []byte("{not json"), 0o600))
	s := NewFilePinStore(p)
	_, err := s.Lookup("h:22")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "corrupt")
	// and a Record must not overwrite the corrupt file (that would drop real pins)
	assert.Error(t, s.Record("h:22", HostKeyPin{Fingerprint: "SHA256:z"}))
	b, _ := os.ReadFile(p)
	assert.Equal(t, "{not json", string(b))
}

func TestCredential_Redaction(t *testing.T) {
	c := &Credential{Password: "hunter2-secret", PrivateKeyPEM: []byte("KEYMATERIAL"), Passphrase: []byte("pp-secret")}
	for _, s := range []string{c.String(), fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprintf("%s", c)} {
		assert.NotContains(t, s, "hunter2")
		assert.NotContains(t, s, "KEYMATERIAL")
		assert.NotContains(t, s, "pp-secret")
	}
	assert.True(t, (&Credential{}).Empty())
	assert.False(t, c.Empty())
	c.wipe()
	assert.Empty(t, c.Password)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, c.PrivateKeyPEM)
}

func TestEnvCredentialResolver(t *testing.T) {
	env := map[string]string{"SFTP_CRED_NAS_1_PASSWORD": "pw1", "SFTP_CRED_NAS_1_PRIVATE_KEY": "PEM"}
	r := EnvCredentialResolver{Getenv: func(k string) string { return env[k] }}
	c, err := r.Resolve(context.Background(), "NAS_1")
	require.NoError(t, err)
	assert.Equal(t, "pw1", c.Password)
	assert.Equal(t, "PEM", string(c.PrivateKeyPEM))

	_, err = r.Resolve(context.Background(), "missing")
	require.ErrorIs(t, err, ErrCredentialUnavailable)
	assert.Contains(t, err.Error(), "SFTP_CRED_missing_PASSWORD", "names the variable")
	_, err = r.Resolve(context.Background(), "  ")
	assert.ErrorIs(t, err, ErrCredentialUnavailable)
}

// SFTP-16: the mapping ref -> variable names is injective. Punctuation is refused, case is significant: a secret set for
// one ref can never be read through another.
func TestEnvCredentialResolver_NoCollisions(t *testing.T) {
	env := map[string]string{"SFTP_CRED_NAS_1_PASSWORD": "secret-of-NAS_1"}
	r := EnvCredentialResolver{Getenv: func(k string) string { return env[k] }}
	for _, ref := range []string{"nas-1", "nas.1", "NAS.1", "NAS 1", "nas/1", "nas_1", "Nas_1", "nas_1_"} {
		c, err := r.Resolve(context.Background(), ref)
		if c != nil {
			t.Errorf("ref %q read the variables of NAS_1: password %q", ref, c.Password)
		}
		assert.ErrorIs(t, err, ErrCredentialUnavailable, ref)
	}
	c, err := r.Resolve(context.Background(), "NAS_1")
	require.NoError(t, err)
	assert.Equal(t, "secret-of-NAS_1", c.Password)
	// rejected refs say why and name no secret
	_, err = r.Resolve(context.Background(), "nas-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "letters, digits")
	assert.NotContains(t, err.Error(), "secret-of")
}

func TestIsTransient_Table(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"eof", io.EOF, true},
		{"unexpected eof", io.ErrUnexpectedEOF, true},
		{"conn reset", fmt.Errorf("read: %w", syscall.ECONNRESET), true},
		{"conn refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{"epipe", syscall.EPIPE, true},
		{"net closed", net.ErrClosed, true},
		{"deadline", os.ErrDeadlineExceeded, true},
		{"auth", &AuthError{User: "u", Host: "h", Err: errors.New("x")}, false},
		{"unknown host key", &UnknownHostKeyError{}, false},
		{"mismatch host key", &HostKeyMismatchError{}, false},
		{"not exist", fmt.Errorf("stat: %w", os.ErrNotExist), false},
		{"permission", fmt.Errorf("open: %w", os.ErrPermission), false},
		{"read only", ErrReadOnly, false},
		{"escape", ErrPathEscape, false},
		{"no creds", fmt.Errorf("x: %w", ErrCredentialUnavailable), false},
		{"canceled", context.Canceled, false},
		{"ctx deadline", context.DeadlineExceeded, false},
		{"random", errors.New("something else"), false},
		// SFTP-05 / R12: only a timeout of a net.Error is transient; a DNS "no such host" is not
		{"dns not found", &net.DNSError{Err: "no such host", Name: "nas.example", IsNotFound: true}, false},
		{"net timeout", &net.DNSError{Err: "i/o timeout", Name: "nas.example", IsTimeout: true}, true},
		{"server status eof", &serverStatus{err: io.EOF}, false},
		{"malformed reply", fmt.Errorf("x: %w", ErrMalformedReply), false},
		{"dir too large", fmt.Errorf("x: %w", ErrDirTooLarge), false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, IsTransient(tc.err), tc.name)
	}
}

// SFTP-05 (c): the two predicates may not disagree: a connection loss is always transient, and a server reply never is a loss.
func TestClassification_LossImpliesTransient(t *testing.T) {
	errs := []error{
		nil, io.EOF, io.ErrUnexpectedEOF, net.ErrClosed, syscall.ECONNRESET, syscall.EPIPE, syscall.ECONNREFUSED, os.ErrDeadlineExceeded,
		gosftp.ErrSSHFxConnectionLost, gosftp.ErrSSHFxNoConnection, &serverStatus{err: io.EOF},
		&net.DNSError{IsNotFound: true}, &net.DNSError{IsTimeout: true}, &net.OpError{Op: "read", Err: syscall.ECONNRESET},
		fmt.Errorf("wrapped: %w", gosftp.ErrSSHFxConnectionLost), errors.New("other"), os.ErrNotExist, ErrPathEscape,
	}
	for _, e := range errs {
		if isConnectionLoss(e) {
			assert.True(t, IsTransient(e), "connection loss %v must be transient", e)
		}
	}
	assert.False(t, isConnectionLoss(io.EOF), "a STATUS EOF reply is not a lost connection")
	assert.False(t, isConnectionLoss(&serverStatus{err: io.EOF}))
	assert.False(t, isConnectionLoss(&net.DNSError{IsNotFound: true}))
	assert.True(t, isConnectionLoss(gosftp.ErrSSHFxConnectionLost))
}

func TestRetry_BoundedAndTransientOnly(t *testing.T) {
	c := NewSFTPClient(&Config{MaxRetries: 3, RetryBase: time.Millisecond})
	calls := 0
	err := c.retry(context.Background(), func() error { calls++; return io.EOF })
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 4, calls, "1 attempt + 3 retries")

	calls = 0
	err = c.retry(context.Background(), func() error { calls++; return &AuthError{Err: errors.New("no")} })
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "auth failure is not retried")

	calls = 0
	err = c.retry(context.Background(), func() error {
		calls++
		if calls < 3 {
			return io.ErrUnexpectedEOF
		}
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 3, calls)

	c2 := NewSFTPClient(&Config{MaxRetries: -1, RetryBase: time.Millisecond})
	calls = 0
	_ = c2.retry(context.Background(), func() error { calls++; return io.EOF })
	assert.Equal(t, 1, calls, "negative disables retry")
}

func TestRetry_ContextCancelStopsBackoff(t *testing.T) {
	c := NewSFTPClient(&Config{MaxRetries: 10, RetryBase: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.retry(ctx, func() error { return io.EOF }) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("retry did not stop on cancel")
	}
}

func TestMutatorsAreImpossible_NoConnectionNeeded(t *testing.T) {
	c := NewSFTPClient(&Config{})
	ctx := context.Background()
	assert.ErrorIs(t, c.WriteFile(ctx, "/a", strings.NewReader("x")), ErrReadOnly)
	assert.ErrorIs(t, c.DeleteFile(ctx, "/a"), ErrReadOnly)
	assert.ErrorIs(t, c.CopyFile(ctx, "/a", "/b"), ErrReadOnly)
	assert.ErrorIs(t, c.CreateDirectory(ctx, "/d"), ErrReadOnly)
	assert.ErrorIs(t, c.DeleteDirectory(ctx, "/d"), ErrReadOnly)
}

func TestGetConfigHasNoSecret(t *testing.T) {
	c := NewSFTPClient(&Config{Host: "h", Username: "u", CredentialRef: "ref-1", Root: "/r",
		Resolver: mapResolver{"ref-1": {Password: "TOPSECRET-pw"}}, PinStore: NewMemPinStore()})
	b, err := json.Marshal(c.GetConfig())
	require.NoError(t, err)
	assert.NotContains(t, string(b), "TOPSECRET")
	assert.Contains(t, string(b), `"read_only":true`)
	assert.Contains(t, string(b), `"credential_ref":"ref-1"`)
	assert.NotContains(t, c.String(), "TOPSECRET")
	assert.Equal(t, "sftp", c.GetProtocol())
}

func TestToInfo_NoFabricatedMtime(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(p, []byte("abc"), 0o644))
	fi, _ := os.Stat(p)
	got := toInfo("/f", fi)
	assert.Equal(t, int64(3), got.Size)
	assert.False(t, got.ModTime.IsZero(), "a real mtime is kept")

	require.NoError(t, os.Chtimes(p, time.Unix(0, 0), time.Unix(0, 0)))
	fi, _ = os.Stat(p)
	assert.True(t, toInfo("/f", fi).ModTime.IsZero(), "epoch 0 means 'server sent none': reported as unknown, not 1970")
}

func TestNotConnectedOperationsFail(t *testing.T) {
	c := NewSFTPClient(&Config{})
	_, err := c.ListDirectory(context.Background(), "/")
	assert.ErrorIs(t, err, ErrNotConnected)
	_, err = c.ReadFile(context.Background(), "/a")
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.False(t, c.IsConnected())
}

func TestConnectRefusesWithoutPinStoreOrCredential(t *testing.T) {
	c := NewSFTPClient(&Config{Host: "127.0.0.1", Port: 1, Username: "u", CredentialRef: "r"})
	assert.ErrorIs(t, c.Connect(context.Background()), ErrNoPinStore)

	c = NewSFTPClient(&Config{Host: "127.0.0.1", Port: 1, Username: "u", PinStore: NewMemPinStore(), Resolver: mapResolver{}})
	err := c.Connect(context.Background())
	assert.ErrorIs(t, err, ErrCredentialUnavailable, "no credential_ref")
}

// ---- in-process real ssh+sftp server tests ------------------------------------------------------------------

func seed(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub", "deep"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello sftp"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "b.bin"), bytes.Repeat([]byte("0123456789"), 1000), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "deep", "c.txt"), []byte("c"), 0o644))
	old := time.Date(2020, 5, 17, 10, 30, 0, 0, time.UTC)
	require.NoError(t, os.Chtimes(filepath.Join(dir, "a.txt"), old, old))
}

func connected(t *testing.T, s *testServer, mutate func(*Config)) *Client {
	t.Helper()
	cfg := &Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "ref", Root: s.Dir,
		Resolver: mapResolver{"ref": {Password: s.Password}}, PinStore: s.pinned(), RetryBase: time.Millisecond, DialTimeout: 5 * time.Second}
	if mutate != nil {
		mutate(cfg)
	}
	c := NewSFTPClient(cfg)
	require.NoError(t, c.Connect(context.Background()))
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })
	return c
}

func TestServer_ListReadStat(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, nil)
	ctx := context.Background()
	assert.True(t, c.IsConnected())
	require.NoError(t, c.TestConnection(ctx))

	ents, err := c.ListDirectory(ctx, "/")
	require.NoError(t, err)
	names := map[string]*client.FileInfo{}
	for _, e := range ents {
		names[e.Name] = e
	}
	require.Contains(t, names, "a.txt")
	require.Contains(t, names, "sub")
	assert.NotContains(t, names, ".")
	assert.NotContains(t, names, "..")
	assert.Equal(t, int64(10), names["a.txt"].Size)
	assert.False(t, names["a.txt"].IsDir)
	assert.True(t, names["sub"].IsDir)
	assert.Equal(t, "/a.txt", names["a.txt"].Path)
	assert.True(t, names["a.txt"].ModTime.Equal(time.Date(2020, 5, 17, 10, 30, 0, 0, time.UTC)), "attribute mtime comes from the server entry: %v", names["a.txt"].ModTime)

	sub, err := c.ListDirectory(ctx, "sub")
	require.NoError(t, err)
	assert.Len(t, sub, 2)

	rc, err := c.ReadFile(ctx, "/a.txt")
	require.NoError(t, err)
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, "hello sftp", string(b))

	fi, err := c.GetFileInfo(ctx, "sub/b.bin")
	require.NoError(t, err)
	assert.Equal(t, int64(10000), fi.Size)
	ok, err := c.FileExists(ctx, "sub/b.bin")
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = c.FileExists(ctx, "nope")
	require.NoError(t, err)
	assert.False(t, ok)
	_, err = c.GetFileInfo(ctx, "nope")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// NOTE (review SFTP-10): this test proves byte equality of the three read shapes only; that the read path is really pipelined is
// measured by TestPipelinedReadKeepsSeveralRequestsInFlight / TestRangedReadIsPipelinedToo (a server-side gauge of concurrent READs).
func TestServer_PipelinedCopyAndRange(t *testing.T) {
	s := startServer(t)
	big := make([]byte, 3*1024*1024+17)
	_, _ = rand.Read(big)
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "big"), big, 0o644))
	c := connected(t, s, func(cfg *Config) { cfg.MaxPacket = 4096; cfg.MaxConcurrentRequests = 16 })
	ctx := context.Background()

	rc, err := c.ReadFile(ctx, "big")
	require.NoError(t, err)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, rc) // takes the pipelined WriteTo path
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, int64(len(big)), n)
	assert.True(t, bytes.Equal(big, buf.Bytes()))

	r, err := c.ReadRange(ctx, "big", 1000, 500)
	require.NoError(t, err)
	part, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	assert.True(t, bytes.Equal(big[1000:1500], part))

	r, err = c.ReadRange(ctx, "big", int64(len(big))-10, -1)
	require.NoError(t, err)
	tail, _ := io.ReadAll(r)
	_ = r.Close()
	assert.True(t, bytes.Equal(big[len(big)-10:], tail))

	sk, err := c.OpenSeekable(ctx, "big")
	require.NoError(t, err)
	_, err = sk.Seek(2_000_000, io.SeekStart)
	require.NoError(t, err)
	seg := make([]byte, 64)
	_, err = io.ReadFull(sk, seg)
	require.NoError(t, err)
	require.NoError(t, sk.Close())
	assert.True(t, bytes.Equal(big[2_000_000:2_000_064], seg))
}

// NOTE (review SFTP-10): the cancel here happens BETWEEN two reads, where the ctx pre-check answers. Cancellation of a call that is blocked on
// the server is covered by TestReview_P1/P8/P11, TestSeekEndHonoursContextOnHungServer and TestContextEndClosesTheRemoteFile.
func TestServer_ContextCancelStopsRead(t *testing.T) {
	s := startServer(t)
	big := make([]byte, 8*1024*1024)
	require.NoError(t, os.WriteFile(filepath.Join(s.Dir, "big"), big, 0o644))
	c := connected(t, s, nil)
	ctx, cancel := context.WithCancel(context.Background())
	rc, err := c.ReadFile(ctx, "big")
	require.NoError(t, err)
	defer rc.Close()
	p := make([]byte, 1024)
	_, err = rc.Read(p)
	require.NoError(t, err)
	cancel()
	_, err = rc.Read(p)
	assert.ErrorIs(t, err, context.Canceled)

	// a cancelled context never even starts the call
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	_, err = c.ListDirectory(cctx, "/")
	assert.ErrorIs(t, err, context.Canceled)
}

func TestServer_HostKey_UnknownRefused_ThenPinned(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	store := NewMemPinStore()
	mk := func() *Client {
		return NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "ref", Root: s.Dir,
			Resolver: mapResolver{"ref": {Password: s.Password}}, PinStore: store, RetryBase: time.Millisecond})
	}
	// 1. unknown host: refused, and NO credential reaches the server (zero auth attempts)
	c := mk()
	err := c.Connect(context.Background())
	var unk *UnknownHostKeyError
	require.ErrorAs(t, err, &unk)
	assert.Equal(t, Fingerprint(s.HostKey.PublicKey()), unk.Fingerprint)
	assert.Equal(t, int32(0), s.authAttempts.Load(), "the password was never offered to an unpinned host")
	assert.Equal(t, int32(1), s.conns.Load(), "an unknown host key is not retried")

	// 2. Pin without the owner's confirmation: refused, nothing recorded
	_, err = Pin(context.Background(), store, s.Host, s.Port, Confirmation{})
	assert.ErrorIs(t, err, ErrPinNotConfirmed)
	_, err = Pin(context.Background(), store, s.Host, s.Port, Confirmation{Owner: "alice", Fingerprint: "SHA256:wrong"})
	assert.ErrorIs(t, err, ErrPinNotConfirmed)
	pins, _ := store.Lookup(HostPort(s.Host, s.Port))
	assert.Empty(t, pins)
	assert.Equal(t, int32(0), s.authAttempts.Load())

	// 3. Pin with the matching fingerprint: recorded with the owner
	pin, err := Pin(context.Background(), store, s.Host, s.Port, Confirmation{Owner: "owner-1", Fingerprint: unk.Fingerprint})
	require.NoError(t, err)
	assert.Equal(t, "owner-1", pin.ConfirmedBy)
	assert.Equal(t, unk.Fingerprint, pin.Fingerprint)

	// 4. now it connects
	c = mk()
	require.NoError(t, c.Connect(context.Background()))
	ents, err := c.ListDirectory(context.Background(), "/")
	require.NoError(t, err)
	assert.NotEmpty(t, ents)
	_ = c.Disconnect(context.Background())
}

func TestServer_HostKey_ChangedKeyRefused(t *testing.T) {
	s := startServer(t)
	store := NewMemPinStore()
	other := newSigner(t)
	require.NoError(t, store.Record(HostPort(s.Host, s.Port), HostKeyPin{
		KeyType: other.PublicKey().Type(), Fingerprint: Fingerprint(other.PublicKey()), ConfirmedBy: "owner"}))
	c := NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "ref", Root: s.Dir,
		Resolver: mapResolver{"ref": {Password: s.Password}}, PinStore: store, RetryBase: time.Millisecond})
	err := c.Connect(context.Background())
	var mis *HostKeyMismatchError
	require.ErrorAs(t, err, &mis)
	assert.Equal(t, Fingerprint(s.HostKey.PublicKey()), mis.Presented)
	assert.Equal(t, []string{Fingerprint(other.PublicKey())}, mis.Pinned)
	assert.Equal(t, int32(0), s.authAttempts.Load(), "no credential is sent to a host whose key changed")
	assert.Equal(t, int32(1), s.conns.Load(), "a changed key is not retried")
	assert.False(t, c.IsConnected())
}

func TestServer_AuthFailureNotRetried_NoSecretInError(t *testing.T) {
	s := startServer(t)
	c := NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "ref", Root: s.Dir,
		Resolver: mapResolver{"ref": {Password: "WRONG-PASSWORD-xyz"}}, PinStore: s.pinned(), MaxRetries: 5, RetryBase: time.Millisecond})
	err := c.Connect(context.Background())
	var ae *AuthError
	require.ErrorAs(t, err, &ae)
	assert.False(t, IsTransient(err))
	assert.Equal(t, int32(1), s.conns.Load(), "exactly one connection: auth failure is never retried")
	assert.NotContains(t, err.Error(), "WRONG-PASSWORD-xyz")
	assert.NotContains(t, err.Error(), s.Password)
}

func TestServer_TransientConnectRetriedThenSucceeds(t *testing.T) {
	s := startServer(t)
	s.dropFirst.Store(2)
	c := connected(t, s, func(cfg *Config) { cfg.MaxRetries = 4 })
	assert.True(t, c.IsConnected())
	assert.Equal(t, int32(3), s.conns.Load(), "two dropped connections, the third succeeds")
}

func TestServer_TransientRetryIsBounded(t *testing.T) {
	s := startServer(t)
	s.dropFirst.Store(100)
	c := NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "ref", Root: s.Dir,
		Resolver: mapResolver{"ref": {Password: s.Password}}, PinStore: s.pinned(), MaxRetries: 2, RetryBase: time.Millisecond})
	err := c.Connect(context.Background())
	require.Error(t, err)
	assert.Equal(t, int32(3), s.conns.Load(), "1 attempt + 2 retries, then it gives up")
}

func TestServer_PathConfinement(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside"), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(s.Dir, "escape")))
	require.NoError(t, os.Symlink("a.txt", filepath.Join(s.Dir, "inside-link")))
	c := connected(t, s, nil)
	ctx := context.Background()

	for _, bad := range []string{"..", "../x", "sub/../../x", "/../../etc/passwd"} {
		_, err := c.ReadFile(ctx, bad)
		assert.ErrorIs(t, err, ErrPathEscape, bad)
		_, err = c.ListDirectory(ctx, bad)
		assert.ErrorIs(t, err, ErrPathEscape, bad)
		_, err = c.GetFileInfo(ctx, bad)
		assert.ErrorIs(t, err, ErrPathEscape, bad)
	}
	// a symlink inside the root that points outside is refused on the server-resolved path
	_, err := c.ReadFile(ctx, "escape/secret.txt")
	assert.ErrorIs(t, err, ErrPathEscape)
	_, err = c.ListDirectory(ctx, "escape")
	assert.ErrorIs(t, err, ErrPathEscape)
	// a symlink that stays inside works
	rc, err := c.ReadFile(ctx, "inside-link")
	require.NoError(t, err)
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	assert.Equal(t, "hello sftp", string(b))
}

func TestServer_ListingReportsSymlinkAsLink(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	require.NoError(t, os.Symlink("a.txt", filepath.Join(s.Dir, "ln")))
	c := connected(t, s, nil)
	ents, err := c.ListDirectory(context.Background(), "/")
	require.NoError(t, err)
	for _, e := range ents {
		if e.Name == "ln" {
			assert.True(t, e.Mode&os.ModeSymlink != 0, "symlink mode kept: %v", e.Mode)
			return
		}
	}
	t.Fatal("ln not listed")
}

func TestServer_WritesImpossibleEvenWithWritablePermissions(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, nil)
	ctx := context.Background()
	assert.ErrorIs(t, c.WriteFile(ctx, "new.txt", strings.NewReader("x")), ErrReadOnly)
	assert.ErrorIs(t, c.DeleteFile(ctx, "a.txt"), ErrReadOnly)
	assert.ErrorIs(t, c.CreateDirectory(ctx, "d"), ErrReadOnly)
	_, err := os.Stat(filepath.Join(s.Dir, "new.txt"))
	assert.True(t, os.IsNotExist(err), "nothing was created on the server")
	_, err = os.Stat(filepath.Join(s.Dir, "a.txt"))
	assert.NoError(t, err, "nothing was deleted on the server")
}

// NOTE (review SFTP-10): asserts state; that Disconnect releases the connection is TestDisconnectReleasesTheConnection, and that a re-dial
// racing Disconnect does not undo it is TestReview_P4_DisconnectDuringRedial.
func TestServer_DisconnectedClientDoesNotSilentlyReconnect(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, nil)
	require.NoError(t, c.Disconnect(context.Background()))
	assert.False(t, c.IsConnected())
	_, err := c.ListDirectory(context.Background(), "/")
	assert.ErrorIs(t, err, ErrNotConnected)
	require.NoError(t, c.Connect(context.Background()), "an explicit Connect works again")
	_, err = c.ListDirectory(context.Background(), "/")
	assert.NoError(t, err)
}

func TestServer_LostConnectionIsRedialled(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	c := connected(t, s, func(cfg *Config) { cfg.MaxRetries = 3 })
	// kill the live connection under the client
	killConn(c)
	ents, err := c.ListDirectory(context.Background(), "/")
	require.NoError(t, err, "the transient connection loss is retried on a fresh connection")
	assert.NotEmpty(t, ents)
	assert.GreaterOrEqual(t, s.conns.Load(), int32(2))
}

func TestServer_TestConnectionConnectsAndDisconnects(t *testing.T) {
	s := startServer(t)
	c := NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "ref", Root: s.Dir,
		Resolver: mapResolver{"ref": {Password: s.Password}}, PinStore: s.pinned()})
	require.NoError(t, c.TestConnection(context.Background()))
	assert.False(t, c.IsConnected(), "a client that was not connected is left not connected")

	bad := NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "ref", Root: filepath.Join(s.Dir, "missing"),
		Resolver: mapResolver{"ref": {Password: s.Password}}, PinStore: s.pinned(), SkipSymlinkCheck: true})
	assert.Error(t, bad.TestConnection(context.Background()), "a missing root fails the test")
}

func marshalKey(t *testing.T, pass []byte) (pemBytes []byte, pub ssh.PublicKey) {
	t.Helper()
	pubK, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var blk *pem.Block
	if pass == nil {
		blk, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", pass)
	}
	require.NoError(t, err)
	sp, err := ssh.NewPublicKey(pubK)
	require.NoError(t, err)
	return pem.EncodeToMemory(blk), sp
}

func TestServer_KeyAuth(t *testing.T) {
	s := startServer(t)
	seed(t, s.Dir)
	pemKey, pub := marshalKey(t, nil)
	s.AuthKey = pub
	c := NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "k", Root: s.Dir,
		Resolver: mapResolver{"k": {PrivateKeyPEM: pemKey}}, PinStore: s.pinned(), RetryBase: time.Millisecond})
	require.NoError(t, c.Connect(context.Background()))
	_, err := c.ListDirectory(context.Background(), "/")
	require.NoError(t, err)
	_ = c.Disconnect(context.Background())

	// the wrong key is an authentication failure, not retried
	wrongPEM, _ := marshalKey(t, nil)
	before := s.conns.Load()
	c = NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "k", Root: s.Dir,
		Resolver: mapResolver{"k": {PrivateKeyPEM: wrongPEM}}, PinStore: s.pinned(), MaxRetries: 4, RetryBase: time.Millisecond})
	err = c.Connect(context.Background())
	var ae *AuthError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, before+1, s.conns.Load())
}

func TestServer_KeyWithPassphrase(t *testing.T) {
	s := startServer(t)
	pemKey, pub := marshalKey(t, []byte("pp-123"))
	s.AuthKey = pub
	mk := func(pp string) *Client {
		return NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "k", Root: s.Dir,
			Resolver: mapResolver{"k": {PrivateKeyPEM: pemKey, Passphrase: []byte(pp)}}, PinStore: s.pinned(), RetryBase: time.Millisecond})
	}
	require.NoError(t, mk("pp-123").Connect(context.Background()))
	err := mk("wrong-pp").Connect(context.Background())
	require.ErrorIs(t, err, ErrCredentialUnavailable)
	assert.NotContains(t, err.Error(), "wrong-pp")
	assert.NotContains(t, err.Error(), "pp-123")
}

func TestServer_GarbageKeyIsRedacted(t *testing.T) {
	s := startServer(t)
	c := NewSFTPClient(&Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "k", Root: s.Dir,
		Resolver: mapResolver{"k": {PrivateKeyPEM: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nGARBAGE-MATERIAL\n-----END OPENSSH PRIVATE KEY-----")}},
		PinStore: s.pinned()})
	err := c.Connect(context.Background())
	require.ErrorIs(t, err, ErrCredentialUnavailable)
	assert.NotContains(t, err.Error(), "GARBAGE-MATERIAL")
}

func TestDiscoverDoesNotAuthenticate(t *testing.T) {
	s := startServer(t)
	d, err := Discover(context.Background(), s.Host, s.Port, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, Fingerprint(s.HostKey.PublicKey()), d.Fingerprint)
	assert.Equal(t, int32(0), s.authAttempts.Load())
	_, err = Discover(context.Background(), "127.0.0.1", 1, time.Second)
	assert.Error(t, err)
}

func TestDiscoverAll_ReturnsEveryKeyFamilyTheServerHolds(t *testing.T) {
	s := startServer(t)
	all, err := DiscoverAll(context.Background(), s.Host, s.Port, 5*time.Second)
	require.NoError(t, err)
	require.Len(t, all, 1, "the in-process server holds one ed25519 key; other families are skipped")
	assert.Equal(t, "ssh-ed25519", all[0].KeyType)
	assert.Equal(t, int32(0), s.authAttempts.Load())
}

func TestPin_RefusesEmptyOwnerOrFingerprint(t *testing.T) {
	s := startServer(t)
	st := NewMemPinStore()
	fp := Fingerprint(s.HostKey.PublicKey())
	_, err := Pin(context.Background(), st, s.Host, s.Port, Confirmation{Owner: "", Fingerprint: fp})
	assert.ErrorIs(t, err, ErrPinNotConfirmed)
	_, err = Pin(context.Background(), st, s.Host, s.Port, Confirmation{Owner: "o", Fingerprint: ""})
	assert.ErrorIs(t, err, ErrPinNotConfirmed)
	_, err = Pin(context.Background(), nil, s.Host, s.Port, Confirmation{Owner: "o", Fingerprint: fp})
	assert.ErrorIs(t, err, ErrNoPinStore)
	pins, _ := st.Lookup(HostPort(s.Host, s.Port))
	assert.Empty(t, pins)
}
