//go:build integration

package sftp

// Integration tests against a REAL OpenSSH server (internal-sftp, chroot, read-only data volume) started by
// scripts/test-infra/sftp_fixture.sh. They are compiled only with -tags integration and fail (never skip) when the
// fixture environment is missing: a green run without the server would be a bluff.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	gosftp "github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type fixtureEnv struct {
	Host, User, Password, Root, HostFP, KeyFile, BSha string
	Port                                              int
	BSize, AMtime                                     int64
}

func fixture(t *testing.T) fixtureEnv {
	t.Helper()
	get := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			t.Fatalf("fixture variable %s is not set: run through scripts/test-infra/sftp_fixture.sh (this test never skips)", k)
		}
		return v
	}
	port, err := strconv.Atoi(get("SFTP_TEST_PORT"))
	require.NoError(t, err)
	bsize, _ := strconv.ParseInt(get("SFTP_TEST_B_SIZE"), 10, 64)
	am, _ := strconv.ParseInt(get("SFTP_TEST_A_MTIME"), 10, 64)
	return fixtureEnv{
		Host: get("SFTP_TEST_HOST"), Port: port, User: get("SFTP_TEST_USER"), Password: get("SFTP_TEST_PASSWORD"),
		Root: get("SFTP_TEST_ROOT"), HostFP: get("SFTP_TEST_HOSTKEY_FP_ED25519"), KeyFile: get("SFTP_TEST_KEY_FILE"),
		BSha: get("SFTP_TEST_B_SHA256"), BSize: bsize, AMtime: am,
	}
}

func (f fixtureEnv) pinnedStore(t *testing.T) *MemPinStore {
	t.Helper()
	st := NewMemPinStore()
	// the owner confirmation: the fingerprint was computed OUTSIDE the container from the public key file
	_, err := Pin(context.Background(), st, f.Host, f.Port, Confirmation{Owner: "fixture-owner", Fingerprint: f.HostFP})
	require.NoError(t, err)
	return st
}

func (f fixtureEnv) client(t *testing.T, st PinStore, cred Credential, mutate func(*Config)) *Client {
	t.Helper()
	cfg := &Config{Host: f.Host, Port: f.Port, Username: f.User, CredentialRef: "fx", Root: f.Root,
		Resolver: mapResolver{"fx": cred}, PinStore: st, RetryBase: 50 * time.Millisecond, DialTimeout: 20 * time.Second}
	if mutate != nil {
		mutate(cfg)
	}
	return NewSFTPClient(cfg)
}

func connectedFx(t *testing.T, f fixtureEnv) *Client {
	t.Helper()
	c := f.client(t, f.pinnedStore(t), Credential{Password: f.Password}, nil)
	require.NoError(t, c.Connect(context.Background()))
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })
	return c
}

func TestIntegrationSelftest(t *testing.T) {
	f := fixture(t)
	all, err := DiscoverAll(context.Background(), f.Host, f.Port, 20*time.Second)
	require.NoError(t, err)
	found := false
	for _, d := range all {
		if d.Fingerprint == f.HostFP {
			found = true
			assert.Equal(t, "ssh-ed25519", d.KeyType)
		}
	}
	assert.True(t, found, "the ed25519 key the server presents is the one generated outside the container: %v", all)
	assert.GreaterOrEqual(t, len(all), 2, "OpenSSH holds ed25519 and rsa host keys")
	c := connectedFx(t, f)
	require.NoError(t, c.TestConnection(context.Background()))
	fmt.Println("selftest: connected to OpenSSH, host key pinned and verified")
}

func TestIntegration_ListingAndAttributes(t *testing.T) {
	f := fixture(t)
	c := connectedFx(t, f)
	ctx := context.Background()
	ents, err := c.ListDirectory(ctx, "/")
	require.NoError(t, err)
	by := map[string]int{}
	for i, e := range ents {
		by[e.Name] = i
	}
	for _, n := range []string{"a.txt", "sub", "escape", "inside-link"} {
		require.Contains(t, by, n, "listing %v", by)
	}
	a := ents[by["a.txt"]]
	assert.Equal(t, int64(len("hello sftp\n")), a.Size)
	assert.Equal(t, f.AMtime, a.ModTime.Unix(), "mtime is the server attribute, not fabricated")
	assert.True(t, ents[by["sub"]].IsDir)
	assert.True(t, ents[by["escape"]].Mode&os.ModeSymlink != 0, "symlinks are listed as links")
	sub, err := c.ListDirectory(ctx, "sub")
	require.NoError(t, err)
	names := map[string]bool{}
	for _, e := range sub {
		names[e.Name] = true
	}
	assert.True(t, names["b.bin"] && names["deep"], "%v", names)
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestIntegration_ReadWholeAndRanged(t *testing.T) {
	f := fixture(t)
	c := connectedFx(t, f)
	ctx := context.Background()
	rc, err := c.ReadFile(ctx, "sub/b.bin")
	require.NoError(t, err)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, rc) // pipelined path
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, f.BSize, n)
	assert.Equal(t, f.BSha, sha(buf.Bytes()), "content equals the seeded file")

	r, err := c.ReadRange(ctx, "sub/b.bin", 4096, 8192)
	require.NoError(t, err)
	part, err := io.ReadAll(r)
	require.NoError(t, err)
	_ = r.Close()
	assert.True(t, bytes.Equal(buf.Bytes()[4096:4096+8192], part), "ranged read returns exactly that range")

	sk, err := c.OpenSeekable(ctx, "sub/b.bin")
	require.NoError(t, err)
	_, err = sk.Seek(-100, io.SeekEnd)
	require.NoError(t, err)
	tail, err := io.ReadAll(sk)
	require.NoError(t, err)
	_ = sk.Close()
	assert.True(t, bytes.Equal(buf.Bytes()[len(buf.Bytes())-100:], tail))

	fi, err := c.GetFileInfo(ctx, "sub/b.bin")
	require.NoError(t, err)
	assert.Equal(t, f.BSize, fi.Size)
	_, err = c.GetFileInfo(ctx, "missing")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestIntegration_HostKey_UnknownRefusedUntilPinned_ChangedRefused(t *testing.T) {
	f := fixture(t)
	// unknown: refused before any credential is sent
	empty := NewMemPinStore()
	c := f.client(t, empty, Credential{Password: f.Password}, nil)
	err := c.Connect(context.Background())
	var unk *UnknownHostKeyError
	require.ErrorAs(t, err, &unk)
	assert.True(t, len(unk.Fingerprint) > 10 && unk.Fingerprint[:7] == "SHA256:", "the refusal carries the presented fingerprint for the owner to compare")

	// pin refused without the right confirmation
	_, err = Pin(context.Background(), empty, f.Host, f.Port, Confirmation{Owner: "o", Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	assert.ErrorIs(t, err, ErrPinNotConfirmed)

	// changed: a pin of another key for this host is a mismatch
	wrong := NewMemPinStore()
	other := newSigner(t)
	require.NoError(t, wrong.Record(HostPort(f.Host, f.Port), HostKeyPin{KeyType: other.PublicKey().Type(), Fingerprint: Fingerprint(other.PublicKey()), ConfirmedBy: "o"}))
	c = f.client(t, wrong, Credential{Password: f.Password}, nil)
	err = c.Connect(context.Background())
	var mis *HostKeyMismatchError
	require.ErrorAs(t, err, &mis)
	assert.Equal(t, f.HostFP, mis.Presented)
	assert.False(t, c.IsConnected())
}

func TestIntegration_AuthFailureNotRetried(t *testing.T) {
	f := fixture(t)
	c := f.client(t, f.pinnedStore(t), Credential{Password: "definitely-wrong-" + f.Password[:4]}, func(cfg *Config) {
		cfg.MaxRetries = 5
		cfg.RetryBase = 3 * time.Second // five retries would take >= 3s+6s+...: a single attempt takes far less
	})
	start := time.Now()
	err := c.Connect(context.Background())
	el := time.Since(start)
	var ae *AuthError
	require.ErrorAs(t, err, &ae)
	assert.Less(t, el, 3*time.Second, "no backoff happened: the failure was not retried")
	assert.NotContains(t, err.Error(), f.Password)
}

func TestIntegration_KeyAuth(t *testing.T) {
	f := fixture(t)
	pemKey, err := os.ReadFile(f.KeyFile)
	require.NoError(t, err)
	c := f.client(t, f.pinnedStore(t), Credential{PrivateKeyPEM: pemKey}, nil)
	require.NoError(t, c.Connect(context.Background()))
	defer c.Disconnect(context.Background())
	ents, err := c.ListDirectory(context.Background(), "/")
	require.NoError(t, err)
	assert.NotEmpty(t, ents)
}

func TestIntegration_WritesImpossible(t *testing.T) {
	f := fixture(t)
	c := connectedFx(t, f)
	ctx := context.Background()
	assert.ErrorIs(t, c.WriteFile(ctx, "w.txt", bytes.NewReader([]byte("x"))), ErrReadOnly)
	assert.ErrorIs(t, c.DeleteFile(ctx, "a.txt"), ErrReadOnly)
	assert.ErrorIs(t, c.CreateDirectory(ctx, "newdir"), ErrReadOnly)
	assert.ErrorIs(t, c.CopyFile(ctx, "a.txt", "copy.txt"), ErrReadOnly)
	assert.ErrorIs(t, c.DeleteDirectory(ctx, "sub"), ErrReadOnly)
	ok, err := c.FileExists(ctx, "w.txt")
	require.NoError(t, err)
	assert.False(t, ok, "nothing was created")
	ok, err = c.FileExists(ctx, "a.txt")
	require.NoError(t, err)
	assert.True(t, ok, "nothing was deleted")
}

// The fixture itself is read-only server side (defence in depth): a raw sftp session of the same user cannot write.
func TestIntegration_FixtureVolumeIsReadOnlyServerSide(t *testing.T) {
	f := fixture(t)
	hp := net.JoinHostPort(f.Host, strconv.Itoa(f.Port))
	pins := f.pinnedStore(t)
	pl, _ := pins.Lookup(HostPort(f.Host, f.Port))
	var refusal error
	conn, err := ssh.Dial("tcp", hp, &ssh.ClientConfig{User: f.User, Auth: []ssh.AuthMethod{ssh.Password(f.Password)},
		HostKeyAlgorithms: hostKeyAlgorithms(pl), HostKeyCallback: hostKeyCallback(hp, pl, &refusal), Timeout: 20 * time.Second})
	require.NoError(t, err)
	defer conn.Close()
	raw, err := gosftp.NewClient(conn)
	require.NoError(t, err)
	defer raw.Close()
	w, err := raw.OpenFile(f.Root+"/raw-write.txt", os.O_WRONLY|os.O_CREATE)
	if err == nil {
		_, err = w.Write([]byte("x"))
		if cerr := w.Close(); err == nil {
			err = cerr
		}
	}
	assert.Error(t, err, "the server refuses the write: the volume is mounted read-only")
	_, serr := raw.Stat(f.Root + "/raw-write.txt")
	assert.True(t, os.IsNotExist(serr), "no file was created on the volume")
}

func TestIntegration_PathConfinement(t *testing.T) {
	f := fixture(t)
	c := connectedFx(t, f)
	ctx := context.Background()
	_, err := c.ReadFile(ctx, "../etc/passwd")
	assert.ErrorIs(t, err, ErrPathEscape)
	// "escape" -> ".." lands on the chroot root, which is outside Root (/data): refused after server-side resolution
	_, err = c.ListDirectory(ctx, "escape")
	assert.ErrorIs(t, err, ErrPathEscape)
	_, err = c.GetFileInfo(ctx, "escape")
	assert.ErrorIs(t, err, ErrPathEscape)
	// a path that goes through the link but RESOLVES back inside the root is allowed: the check is on the resolved path
	back, err := c.ReadFile(ctx, "escape/data/a.txt")
	require.NoError(t, err)
	_ = back.Close()
	// a symlink that stays inside the root is fine
	rc, err := c.ReadFile(ctx, "inside-link")
	require.NoError(t, err)
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	assert.Equal(t, "hello sftp\n", string(b))
}

// NOTE (review SFTP-10): the cancel here happens between reads (the ctx pre-check answers); a call blocked on the server is covered by the unit
// probes TestReview_P1/P8/P11 and TestContextEndClosesTheRemoteFile.
func TestIntegration_ContextCancelMidRead(t *testing.T) {
	f := fixture(t)
	c := connectedFx(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	rc, err := c.ReadFile(ctx, "sub/b.bin")
	require.NoError(t, err)
	defer rc.Close()
	p := make([]byte, 512)
	_, err = io.ReadFull(rc, p)
	require.NoError(t, err)
	cancel()
	_, err = io.Copy(io.Discard, rc)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestIntegration_TransientDialFailureRetriedThenGivesUp(t *testing.T) {
	f := fixture(t)
	// nothing listens on this port: connection refused is transient, retried a bounded number of times, then reported
	c := NewSFTPClient(&Config{Host: "127.0.0.1", Port: 9, Username: f.User, CredentialRef: "fx", Resolver: mapResolver{"fx": {Password: f.Password}},
		PinStore: NewMemPinStore(), MaxRetries: 2, RetryBase: 20 * time.Millisecond, DialTimeout: 2 * time.Second})
	start := time.Now()
	err := c.Connect(context.Background())
	require.Error(t, err)
	assert.True(t, IsTransient(err), "%v", err)
	assert.GreaterOrEqual(t, time.Since(start), 40*time.Millisecond, "two backoff sleeps happened")
}
