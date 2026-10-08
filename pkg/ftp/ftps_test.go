package ftp

// PA-04 unit tests: explicit FTPS, certificate pinning, clear-text refusal, MLSD/MLST attributes, UTF-8, REST resume,
// session safety, auth-failure classification, credential handling and the read-only scan path. They run against
// the in-process server of fakeserver_test.go (unit tests only); integration_test.go runs the same behaviours
// against a real pure-ftpd.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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

type mapResolver map[string]string

func (m mapResolver) Resolve(_ context.Context, ref string) (*Credential, error) {
	if v, ok := m[ref]; ok {
		return &Credential{Password: v}, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrCredentialUnavailable, ref)
}

func ctx5(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

// pinned returns a store holding the pin of s, obtained through the real discovery and owner-confirmation path.
func pinned(t *testing.T, s *fakeServer) *MemPinStore {
	t.Helper()
	st := NewMemPinStore()
	_, err := Pin(ctx5(t), st, "127.0.0.1", s.port(), Confirmation{Fingerprint: certFingerprint(t, s.cert), ConfirmedBy: "test-owner"})
	require.NoError(t, err)
	s.resetCounters()
	return st
}

func cfgFor(s *fakeServer, st PinStore) *Config {
	return &Config{Host: "127.0.0.1", Port: s.port(), Username: "u", CredentialRef: "ref", Resolver: mapResolver{"ref": "pw"},
		Path: "/data", PinStore: st, DialTimeout: 5 * time.Second, IOTimeout: 5 * time.Second}
}

func connected(t *testing.T, s *fakeServer, mut func(*Config)) *Client {
	t.Helper()
	cfg := cfgFor(s, pinned(t, s))
	if mut != nil {
		mut(cfg)
	}
	c := NewFTPClient(cfg)
	require.NoError(t, c.Connect(ctx5(t)))
	t.Cleanup(func() {
		// bounded: a client that leaked its session must fail the test, not hang the suite
		bg, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = c.Disconnect(bg)
	})
	return c
}

// ---- explicit FTPS -----------------------------------------------------------------------------------------

func TestFTPS_CommandOrder_AuthTLS_Login_UTF8_PBSZ_PROT(t *testing.T) {
	s := newFakeServer(t)
	connected(t, s, nil)
	auth, user, pass := s.index("AUTH"), s.index("USER"), s.index("PASS")
	opts, pbsz, prot := s.index("OPTS"), s.index("PBSZ"), s.index("PROT")
	require.True(t, auth >= 0 && user > auth, "AUTH TLS must precede the first credential: %v", s.commands())
	assert.True(t, pass > user)
	assert.True(t, opts > pass, "OPTS UTF8 ON right after login: %v", s.commands())
	assert.Contains(t, s.commands(), "OPTS UTF8 ON")
	assert.True(t, pbsz > pass && prot > pbsz, "PBSZ 0 then PROT P after login: %v", s.commands())
	assert.Contains(t, s.commands(), "PBSZ 0")
	assert.Contains(t, s.commands(), "PROT P")
	for _, c := range s.commands() {
		assert.NotContains(t, c, "pw", "the password must not be recorded in clear: %q", c)
	}
}

func TestFTPS_DataChannelIsEncrypted_AndSessionIsResumed(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	for i := 0; i < 3; i++ {
		_, err := c.ListDirectory(ctx5(t), "/")
		require.NoError(t, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	assert.Equal(t, 3, s.dataTLS, "every data connection must be TLS (PROT P)")
	assert.Zero(t, s.dataClear, "no clear-text data connection")
	assert.GreaterOrEqual(t, s.resumed, 1, "the TLS session cache must resume the control session on data connections")
}

func TestTLSConfig_MinVersion12_NoInsecureSkipVerify_SessionCache(t *testing.T) {
	cfg := newTLSConfig("h", nil)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.False(t, cfg.InsecureSkipVerify)
	assert.NotNil(t, cfg.ClientSessionCache)
	assert.NotNil(t, cfg.RootCAs)
	assert.NotNil(t, cfg.VerifyConnection)
}

func TestFTPS_TLS11ServerIsRefused(t *testing.T) {
	s := newFakeServer(t)
	st := pinned(t, s)
	// a second server that only speaks TLS 1.1
	old := newFakeServer(t)
	old.cert = s.cert
	old.tlsOnly11 = true
	cfg := cfgFor(old, st)
	// the pin is stored under the first server's port: store it for the second one too
	pins, _ := st.Lookup(HostPort("127.0.0.1", s.port()))
	require.NoError(t, st.Record(HostPort("127.0.0.1", old.port()), pins[0]))
	err := NewFTPClient(cfg).Connect(ctx5(t))
	require.Error(t, err)
	assert.Zero(t, old.count("USER"), "no credential may be sent over TLS < 1.2")
}

// ---- certificate pinning -----------------------------------------------------------------------------------

func TestPin_UnknownCertificate_Refused_NoCredentialSent(t *testing.T) {
	s := newFakeServer(t)
	err := NewFTPClient(cfgFor(s, NewMemPinStore())).Connect(ctx5(t))
	var u *UnknownCertError
	require.ErrorAs(t, err, &u)
	assert.Equal(t, certFingerprint(t, s.cert), u.Fingerprint, "the refusal carries the fingerprint the owner must confirm")
	assert.Zero(t, s.count("USER")+s.count("PASS"), "credentials must not reach an unverified server: %v", s.commands())
}

func TestPin_ChangedCertificate_Refused_NoCredentialSent(t *testing.T) {
	s := newFakeServer(t)
	st := pinned(t, s)
	s.mu.Lock()
	s.cert, s.tcfg = genCert(t), nil // the server now presents a different certificate
	s.mu.Unlock()
	err := NewFTPClient(cfgFor(s, st)).Connect(ctx5(t))
	var m *CertMismatchError
	require.ErrorAs(t, err, &m)
	assert.Equal(t, certFingerprint(t, s.cert), m.Presented)
	assert.Len(t, m.Pinned, 1)
	assert.Zero(t, s.count("USER")+s.count("PASS"), "credentials must not reach a server whose certificate changed")
}

func TestPin_RequiresMatchingOwnerConfirmation(t *testing.T) {
	s := newFakeServer(t)
	st := NewMemPinStore()
	_, err := Pin(ctx5(t), st, "127.0.0.1", s.port(), Confirmation{Fingerprint: certFingerprint(t, genCert(t))})
	require.ErrorIs(t, err, ErrPinNotConfirmed)
	pins, _ := st.Lookup(HostPort("127.0.0.1", s.port()))
	assert.Empty(t, pins, "a wrong confirmation records nothing")
	_, err = Pin(ctx5(t), st, "127.0.0.1", s.port(), Confirmation{})
	require.ErrorIs(t, err, ErrPinNotConfirmed)
}

func TestPin_ConfirmationAcceptsEveryFingerprintSpelling(t *testing.T) {
	s := newFakeServer(t)
	fp := certFingerprint(t, s.cert)
	for _, spelling := range []string{fp, strings.ToLower(fp), strings.TrimPrefix(fp, "SHA256:"), strings.ReplaceAll(strings.TrimPrefix(fp, "SHA256:"), ":", "")} {
		st := NewMemPinStore()
		_, err := Pin(ctx5(t), st, "127.0.0.1", s.port(), Confirmation{Fingerprint: spelling})
		assert.NoError(t, err, spelling)
	}
}

func TestPin_NoPinStore_Refused(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, nil)
	err := NewFTPClient(cfg).Connect(ctx5(t))
	require.ErrorIs(t, err, ErrNoPinStore)
	assert.Zero(t, s.ctrlConns, "nothing is dialled without a pin store")
}

func TestFilePinStore_PersistsWith0600_AndRefusesCorruptFile(t *testing.T) {
	s := newFakeServer(t)
	p := filepath.Join(t.TempDir(), "pins.json")
	st := NewFilePinStore(p)
	_, err := Pin(ctx5(t), st, "127.0.0.1", s.port(), Confirmation{Fingerprint: certFingerprint(t, s.cert), ConfirmedBy: "o"})
	require.NoError(t, err)
	fi, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	// a fresh store object reads the same pin and a client connects with it
	c := NewFTPClient(cfgFor(s, NewFilePinStore(p)))
	require.NoError(t, c.Connect(ctx5(t)))
	_ = c.Disconnect(context.Background())
	// remove, then a corrupt file is an error, not "no pins"
	require.NoError(t, os.WriteFile(p, []byte("{not json"), 0o600))
	_, err = NewFilePinStore(p).Lookup("x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "corrupt")
	require.Error(t, NewFilePinStore(p).Record("x", CertPin{Fingerprint: "SHA256:00"}))
	raw, _ := os.ReadFile(p)
	assert.Equal(t, "{not json", string(raw), "a corrupt pin file must not be overwritten")
}

func TestPinStore_RemoveAndIdempotentRecord(t *testing.T) {
	for name, st := range map[string]PinStore{"mem": NewMemPinStore(), "file": NewFilePinStore(filepath.Join(t.TempDir(), "p.json"))} {
		t.Run(name, func(t *testing.T) {
			pin := CertPin{Fingerprint: "SHA256:AA:BB", ServerName: "h"}
			require.NoError(t, st.Record("h:21", pin))
			require.NoError(t, st.Record("h:21", CertPin{Fingerprint: "sha256:aabb"}))
			got, _ := st.Lookup("h:21")
			assert.Len(t, got, 1, "same fingerprint in another spelling is not a second pin")
			require.NoError(t, st.Remove("h:21", "SHA256:AA:BB"))
			got, _ = st.Lookup("h:21")
			assert.Empty(t, got)
		})
	}
}

// ---- clear text -------------------------------------------------------------------------------------------

func TestClearText_RefusedByDefault_NoConnectionAttempted(t *testing.T) {
	s := newFakeServer(t)
	s.tlsOn = false
	cfg := cfgFor(s, NewMemPinStore())
	cfg.TLSMode = TLSNone
	err := NewFTPClient(cfg).Connect(ctx5(t))
	require.ErrorIs(t, err, ErrClearTextRefused)
	assert.Zero(t, s.ctrlConns, "the refusal happens before any connection")
}

func TestClearText_AllowedOnTrustedLAN(t *testing.T) {
	s := newFakeServer(t)
	s.tlsOn = false
	cfg := cfgFor(s, nil)
	cfg.TLSMode = TLSNone
	cfg.TrustedLAN = true
	c := NewFTPClient(cfg)
	require.NoError(t, c.Connect(ctx5(t)))
	defer c.Disconnect(context.Background())
	_, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	assert.Zero(t, s.count("AUTH"))
	s.mu.Lock()
	defer s.mu.Unlock()
	assert.Equal(t, 1, s.dataClear)
}

func TestTLSMode_Unknown_Refused(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, NewMemPinStore())
	cfg.TLSMode = "implicit"
	require.ErrorIs(t, NewFTPClient(cfg).Connect(ctx5(t)), ErrUnsupportedTLSMode)
	assert.Zero(t, s.ctrlConns)
}

func TestExplicitTLS_ServerWithoutAuthTLS_NeverFallsBackToClearText(t *testing.T) {
	s := newFakeServer(t)
	st := pinned(t, s)
	s.tlsOn = false
	err := NewFTPClient(cfgFor(s, st)).Connect(ctx5(t))
	require.Error(t, err)
	assert.Zero(t, s.count("USER"), "a server that refuses AUTH TLS must not get the password in clear text")
}

// ---- attributes ------------------------------------------------------------------------------------------

func TestList_MLSD_ExactMtimes_NoDotEntries(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	byName := map[string]*client.FileInfo{}
	for _, f := range got {
		byName[f.Name] = f
	}
	require.Contains(t, byName, "a.txt")
	assert.True(t, byName["a.txt"].ModTime.Equal(t0), "mtime comes from the Modify fact: %v", byName["a.txt"].ModTime)
	assert.Equal(t, int64(10), byName["a.txt"].Size)
	assert.False(t, byName["a.txt"].IsDir)
	assert.True(t, byName["sub"].IsDir)
	assert.True(t, byName["sub"].ModTime.Equal(t0.Add(48*time.Hour)))
	assert.Equal(t, "/a.txt", byName["a.txt"].Path)
	assert.NotContains(t, byName, ".")
	assert.NotContains(t, byName, "..")
	assert.False(t, c.Degraded())
	assert.Zero(t, s.count("LIST"), "MLSD must be used when offered")
	assert.Equal(t, 1, s.count("MLSD"))
}

func TestList_NoModifyFact_MtimeIsZero_NotNow(t *testing.T) {
	s := newFakeServer(t)
	s.noModify = true
	c := connected(t, s, nil)
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	require.NotEmpty(t, got)
	for _, f := range got {
		assert.True(t, f.ModTime.IsZero(), "%s: an mtime the server did not send must be the zero time, got %v", f.Name, f.ModTime)
	}
	fi, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.True(t, fi.ModTime.IsZero())
}

func TestList_NoMLST_Refused_ByDefault(t *testing.T) {
	s := newFakeServer(t)
	s.mlst = false
	c := connected(t, s, nil)
	_, err := c.ListDirectory(ctx5(t), "/")
	require.ErrorIs(t, err, ErrNoMLSD)
	assert.Zero(t, s.count("LIST")+s.count("MLSD"), "a refused degraded listing must not even send LIST")
	_, err = c.GetFileInfo(ctx5(t), "a.txt")
	require.ErrorIs(t, err, ErrNoMLSD)
	assert.True(t, c.IsConnected(), "a refusal is not a connection failure")
}

func TestList_NoMLST_DegradedMode_Flagged_NoFabricatedMtime(t *testing.T) {
	s := newFakeServer(t)
	s.mlst = false
	c := connected(t, s, func(cfg *Config) { cfg.AllowDegradedList = true })
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	assert.True(t, c.Degraded(), "LIST fallback must be flagged")
	require.NotEmpty(t, got)
	names := map[string]bool{}
	for _, f := range got {
		names[f.Name] = true
		assert.True(t, f.ModTime.IsZero(), "%s: LIST times are not trustworthy, so unknown", f.Name)
	}
	assert.True(t, names["a.txt"] && names["sub"])
	assert.Equal(t, 1, s.count("LIST"))
	fi, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(10), fi.Size)
	assert.True(t, fi.ModTime.IsZero())
}

func TestGetFileInfo_UsesMLST_ServerMtime_NotNow(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	before := time.Now()
	fi, err := c.GetFileInfo(ctx5(t), "sub/c.txt")
	require.NoError(t, err)
	assert.True(t, fi.ModTime.Equal(t0.Add(72*time.Hour)), "got %v", fi.ModTime)
	assert.True(t, fi.ModTime.Before(before.Add(-24*time.Hour)), "must not be time.Now()")
	assert.Equal(t, "c.txt", fi.Name)
	assert.Equal(t, int64(2), fi.Size)
	assert.False(t, fi.IsDir)
	assert.Equal(t, 1, s.count("MLST"))
	assert.Zero(t, s.count("MDTM"), "no per-file MDTM round trip")
	d, err := c.GetFileInfo(ctx5(t), "sub")
	require.NoError(t, err)
	assert.True(t, d.IsDir)
}

func TestFileExists_NotFound_IsFalseNotError(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	ok, err := c.FileExists(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = c.FileExists(ctx5(t), "missing.txt")
	require.NoError(t, err)
	assert.False(t, ok)
	_, err = c.GetFileInfo(ctx5(t), "missing.txt")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestUTF8_NamesSurviveBecauseOptsUTF8OnIsSent(t *testing.T) {
	s := newFakeServer(t)
	s.legacyName = true // like the Synology hosts: 0x7f for every non-ASCII name unless OPTS UTF8 ON
	c := connected(t, s, nil)
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	var names []string
	for _, f := range got {
		names = append(names, f.Name)
	}
	assert.Contains(t, names, "Čšž_日本.txt")
	assert.Less(t, s.index("OPTS"), s.index("MLSD"), "OPTS UTF8 ON before the first listing")
	rc, err := c.ReadFile(ctx5(t), "Čšž_日本.txt")
	require.NoError(t, err)
	b, _ := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	assert.Equal(t, "utf8", string(b))
}

// ---- reads, resume ----------------------------------------------------------------------------------------

func TestReadFile_Content_AndSessionReleasedOnClose(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	rc, err := c.ReadFile(ctx5(t), "a.txt")
	require.NoError(t, err)
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, "hello ftp\n", string(b))
	require.NoError(t, rc.Close(), "Close is idempotent")
	ok, err := c.FileExists(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.True(t, ok, "the session is free again after Close")
}

func TestReadFileFrom_SendsREST_AndReturnsTheTail(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	rc, err := c.ReadFileFrom(ctx5(t), "big.bin", 99000)
	require.NoError(t, err)
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Contains(t, s.commands(), "REST 99000")
	assert.Equal(t, seqBytes(100000)[99000:], b)
	_, err = c.ReadFileFrom(ctx5(t), "big.bin", -1)
	assert.Error(t, err)
}

func TestOpenSeekable_SeekResumesWithREST(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	want := seqBytes(100000)
	r, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	buf := make([]byte, 10)
	_, err = io.ReadFull(r, buf)
	require.NoError(t, err)
	assert.Equal(t, want[:10], buf)
	pos, err := r.Seek(50000, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(50000), pos)
	_, err = io.ReadFull(r, buf)
	require.NoError(t, err)
	assert.Equal(t, want[50000:50010], buf)
	pos, err = r.Seek(-5, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(99995), pos)
	tail, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, want[99995:], tail)
	n, err := r.Read(buf)
	assert.Zero(t, n)
	assert.ErrorIs(t, err, io.EOF)
	_, err = r.Seek(-1, io.SeekStart)
	assert.Error(t, err)
	require.NoError(t, r.Close())
	assert.Contains(t, s.commands(), "REST 50000")
	assert.Contains(t, s.commands(), "REST 99995")
	ok, err := c.FileExists(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.True(t, ok, "session free after the seeker closed")
	_, err = c.OpenSeekable(ctx5(t), "missing.bin")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// ---- session safety ----------------------------------------------------------------------------------------

func TestConcurrentUse_OneControlConnection_NoInterleaving(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				switch (i + j) % 3 {
				case 0:
					l, err := c.ListDirectory(ctx5(t), "/")
					if err == nil && len(l) < 4 {
						err = fmt.Errorf("short listing %d", len(l))
					}
					errs <- err
				case 1:
					rc, err := c.ReadFile(ctx5(t), "big.bin")
					if err == nil {
						var b []byte
						b, err = io.ReadAll(rc)
						if err == nil && !bytes.Equal(b, seqBytes(100000)) {
							err = errors.New("corrupt content")
						}
						if e := rc.Close(); err == nil {
							err = e
						}
					}
					errs <- err
				default:
					fi, err := c.GetFileInfo(ctx5(t), "a.txt")
					if err == nil && fi.Size != 10 {
						err = errors.New("wrong size")
					}
					errs <- err
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, 1, s.ctrlConns, "one client = one control connection, however many goroutines")
}

func TestBusySession_WaitsAndHonoursContext(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	rc, err := c.ReadFile(ctx5(t), "big.bin") // holds the session
	require.NoError(t, err)
	short, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.ListDirectory(short, "/")
	require.ErrorIs(t, err, context.DeadlineExceeded, "a second command waits for the session and gives up with its context")
	assert.Less(t, time.Since(start), 3*time.Second)
	require.NoError(t, rc.Close())
	_, err = c.ListDirectory(ctx5(t), "/")
	assert.NoError(t, err)
}

func TestCancelledContext_SendsNothing(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	n := len(s.commands())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.ListDirectory(ctx, "/")
	require.ErrorIs(t, err, context.Canceled)
	assert.Len(t, s.commands(), n)
}

func TestDisconnect_AbortsOpenStream_AndNeverRedials(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	rc, err := c.ReadFile(ctx5(t), "big.bin")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- c.Disconnect(ctx5(t)) }()
	_, _ = io.Copy(io.Discard, rc) // the aborted stream ends
	_ = rc.Close()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Disconnect did not complete")
	}
	assert.False(t, c.IsConnected())
	_, err = c.ListDirectory(ctx5(t), "/")
	assert.ErrorIs(t, err, ErrNotConnected, "a disconnected client never re-dials implicitly")
	assert.Equal(t, 1, s.ctrlConns)
}

func TestLostConnection_IsRedialled_ByRetrying(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	rc, err := NewScanClient(cfg, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}})
	require.NoError(t, err)
	require.NoError(t, rc.Connect(ctx5(t)))
	defer rc.Disconnect(context.Background())
	s.dropNext("MLSD", 1) // the server kills the control connection while we list
	got, err := rc.ListDirectory(ctx5(t), "/")
	require.NoError(t, err, "a transient failure on a read is retried")
	assert.NotEmpty(t, got)
	assert.Equal(t, 2, s.ctrlConns, "re-dialled once")
	assert.Equal(t, 2, s.count("MLSD"))
}

// ---- authentication ---------------------------------------------------------------------------------------

func TestAuthFailure_IsClassifiedAuth_AndNeverRetried(t *testing.T) {
	for _, code := range []int{530, 430, 534, 535} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			s := newFakeServer(t)
			s.loginCode = code
			cfg := cfgFor(s, pinned(t, s))
			cfg.Resolver = mapResolver{"ref": "WRONG"}
			rc, err := NewScanClient(cfg, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond}})
			require.NoError(t, err)
			err = rc.Connect(ctx5(t))
			require.Error(t, err)
			assert.Equal(t, fabric.ClassAuth, fabric.Classify(err))
			assert.ErrorIs(t, err, fabric.ErrAuth)
			assert.Equal(t, 1, s.count("PASS"), "a failed login is attempted exactly once: %v", s.commands())
			assert.NotContains(t, err.Error(), "WRONG")
		})
	}
}

func TestAuthFailure_ThroughPool_IsNotRetried(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	cfg.Resolver = mapResolver{"ref": "WRONG"}
	pool, err := NewWorkerPool(cfg, fabric.PoolOptions{MaxPerKey: 2}, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond}})
	require.NoError(t, err)
	defer pool.CloseAll()
	_, err = pool.GetClientContext(ctx5(t), &client.StorageConfig{ID: "root1"})
	require.Error(t, err)
	assert.Equal(t, fabric.ClassAuth, fabric.Classify(err))
	assert.Equal(t, 1, s.count("PASS"))
}

// ---- credentials ------------------------------------------------------------------------------------------

func TestCredential_NeverInConfigStringErrorsOrLogs(t *testing.T) {
	const secret = "S3cr3t-Pa55w0rd-XYZ"
	s := newFakeServer(t)
	s.pass = secret
	cfg := cfgFor(s, pinned(t, s))
	cfg.Resolver = mapResolver{"ref": secret}
	cfg.Password = secret // an inline password too: it must not show in any rendering of the config
	c := NewFTPClient(cfg)
	require.NoError(t, c.Connect(ctx5(t)))
	defer c.Disconnect(context.Background())
	for _, v := range []any{c, c.GetConfig(), cfg, &Credential{Password: secret}, &cfg} {
		for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
			assert.NotContains(t, fmt.Sprintf(f, v), secret, f)
		}
	}
	// wrong password: the error and the server log must not hold either password
	cfg2 := cfgFor(s, pinned(t, s))
	cfg2.Resolver = mapResolver{"ref": "wrong-pw-ABC"}
	err := NewFTPClient(cfg2).Connect(ctx5(t))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "wrong-pw-ABC")
	assert.NotContains(t, err.Error(), secret)
	for _, line := range s.commands() {
		assert.NotContains(t, line, secret)
	}
}

func TestCredential_MissingRef_NoNetwork(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	cfg.CredentialRef = "unknown"
	ctrl := s.ctrlConns
	err := NewFTPClient(cfg).Connect(ctx5(t))
	require.ErrorIs(t, err, ErrCredentialUnavailable)
	assert.Equal(t, ctrl, s.ctrlConns, "nothing is dialled without a credential")
	cfg.CredentialRef, cfg.Password, cfg.Username = "", "", "bob"
	require.ErrorIs(t, NewFTPClient(cfg).Connect(ctx5(t)), ErrCredentialUnavailable)
}

func TestEnvCredentialResolver(t *testing.T) {
	env := map[string]string{"FTP_CRED_NAS_1_PASSWORD": "pw1"}
	r := EnvCredentialResolver{Getenv: func(k string) string { return env[k] }}
	cr, err := r.Resolve(context.Background(), "nas-1")
	require.NoError(t, err)
	assert.Equal(t, "pw1", cr.Password)
	_, err = r.Resolve(context.Background(), "other")
	require.ErrorIs(t, err, ErrCredentialUnavailable)
	assert.Contains(t, err.Error(), "FTP_CRED_OTHER_PASSWORD", "names the variable")
	_, err = r.Resolve(context.Background(), " ")
	require.ErrorIs(t, err, ErrCredentialUnavailable)
	assert.Equal(t, "Credential(redacted)", (&Credential{Password: "x"}).String())
}

func TestInlinePassword_Deprecated_StillWorks_ButNotJSONSerialised(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	cfg.CredentialRef, cfg.Resolver, cfg.Password = "", nil, "pw"
	c := NewFTPClient(cfg)
	require.NoError(t, c.Connect(ctx5(t)))
	_ = c.Disconnect(context.Background())
	// the struct tag keeps the secret out of any JSON dump of the config
	assert.NotContains(t, strings.ToLower(mustJSON(t, cfg)), "password")
}

// ---- paths --------------------------------------------------------------------------------------------------

func TestConfine_RefusesEscapeAndControlCharacters_BeforeAnyCommand(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	n := len(s.commands())
	for _, p := range []string{"../etc/passwd", "a/../../x", "..", "a\r\nDELE b", "x\x00y", "a\nb"} {
		_, err := c.ReadFile(ctx5(t), p)
		assert.ErrorIs(t, err, ErrPathEscape, "%q", p)
		_, err = c.ListDirectory(ctx5(t), p)
		assert.ErrorIs(t, err, ErrPathEscape, "%q", p)
		_, err = c.GetFileInfo(ctx5(t), p)
		assert.ErrorIs(t, err, ErrPathEscape, "%q", p)
	}
	assert.Len(t, s.commands(), n, "an escape attempt sends nothing to the server")
	for p, want := range map[string]string{"a/./b": "/data/a/b", "a/b/..": "/data/a", "": "/data", "/": "/data", "//x//y": "/data/x/y"} {
		assert.Equal(t, want, c.resolvePath(p), p)
	}
}

// ---- read-only scan path and worker pool ------------------------------------------------------------------

func TestScanClient_IsReadOnly_MutationsNeverReachTheServer(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	sc, err := NewScanClient(cfg, ScanOptions{})
	require.NoError(t, err)
	require.NoError(t, sc.Connect(ctx5(t)))
	defer sc.Disconnect(context.Background())
	ctx := ctx5(t)
	assert.ErrorIs(t, sc.WriteFile(ctx, "x", strings.NewReader("data")), decorators.ErrReadOnly)
	assert.ErrorIs(t, sc.DeleteFile(ctx, "a.txt"), decorators.ErrReadOnly)
	assert.ErrorIs(t, sc.CopyFile(ctx, "a.txt", "b.txt"), decorators.ErrReadOnly)
	assert.ErrorIs(t, sc.CreateDirectory(ctx, "d"), decorators.ErrReadOnly)
	assert.ErrorIs(t, sc.DeleteDirectory(ctx, "sub"), decorators.ErrReadOnly)
	for _, v := range []string{"STOR", "APPE", "DELE", "MKD", "RMD", "RNFR", "RNTO"} {
		assert.Zero(t, s.count(v), v)
	}
	_, isSeek := sc.(client.SeekableClient)
	assert.True(t, isSeek, "the read-only wrapper keeps OpenSeekable")
	got, err := sc.ListDirectory(ctx, "/")
	require.NoError(t, err)
	assert.NotEmpty(t, got)
}

func TestWorkerPool_OneControlConnectionPerWorker(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	pool, err := NewWorkerPool(cfg, fabric.PoolOptions{MaxPerKey: 3}, ScanOptions{})
	require.NoError(t, err)
	defer pool.CloseAll()
	sc := &client.StorageConfig{ID: "root1", Protocol: "ftp"}
	var clients []client.Client
	for i := 0; i < 3; i++ {
		c, err := pool.GetClientContext(ctx5(t), sc)
		require.NoError(t, err)
		clients = append(clients, c)
	}
	_, err = pool.GetClient(sc)
	require.ErrorIs(t, err, fabric.ErrPoolExhausted, "the per-root bound is the server's per-IP connection cap")
	var wg sync.WaitGroup
	for _, c := range clients {
		wg.Add(1)
		go func(c client.Client) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				l, err := c.ListDirectory(ctx5(t), "/")
				assert.NoError(t, err)
				assert.NotEmpty(t, l)
			}
		}(c)
	}
	wg.Wait()
	assert.Equal(t, 3, s.ctrlConns)
	s.mu.Lock()
	assert.Equal(t, 3, s.maxCtrl, "three workers = three concurrent control connections")
	s.mu.Unlock()
	for _, c := range clients {
		require.NoError(t, pool.ReturnClient(c))
	}
	c, err := pool.GetClientContext(ctx5(t), sc)
	require.NoError(t, err)
	assert.Equal(t, 3, s.ctrlConns, "a returned connection is reused, not re-dialled")
	require.NoError(t, pool.ReturnClient(c))
}

func TestScanClient_HostBudgetBoundsConcurrentReads(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	b, err := fabric.NewHostBudget(fabric.BudgetConfig{MaxConcurrent: 1, MaxReqPerSec: 1000})
	require.NoError(t, err)
	sc, err := NewScanClient(cfg, ScanOptions{Budget: b})
	require.NoError(t, err)
	require.NoError(t, sc.Connect(ctx5(t)))
	defer sc.Disconnect(context.Background())
	rc, err := sc.ReadFile(ctx5(t), "a.txt")
	require.NoError(t, err)
	short, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err = sc.ListDirectory(short, "/")
	require.Error(t, err, "the slot of the open stream is held")
	require.NoError(t, rc.Close())
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// ---- the (non-scan) mutation methods of the raw client, discovery and pin helpers --------------------------

func (s *fakeServer) has(p string) (fakeFile, bool) { return s.lookup(p) }

func TestRawClient_Mutations_WriteCopyMkdirDelete(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	ctx := ctx5(t)
	require.NoError(t, c.WriteFile(ctx, "new/up.txt", strings.NewReader("uploaded")))
	f, ok := s.has("/data/new/up.txt")
	require.True(t, ok)
	assert.Equal(t, "uploaded", string(f.data))
	require.NoError(t, c.CopyFile(ctx, "a.txt", "copy.txt"))
	f, ok = s.has("/data/copy.txt")
	require.True(t, ok)
	assert.Equal(t, "hello ftp\n", string(f.data))
	require.NoError(t, c.CreateDirectory(ctx, "made"))
	_, ok = s.has("/data/made")
	assert.True(t, ok)
	require.NoError(t, c.DeleteDirectory(ctx, "made"))
	require.NoError(t, c.DeleteFile(ctx, "copy.txt"))
	_, ok = s.has("/data/copy.txt")
	assert.False(t, ok)
	assert.Error(t, c.DeleteFile(ctx, "copy.txt"), "deleting a missing file is the server's 550")
	assert.True(t, c.IsConnected(), "a protocol error does not drop the connection")
	for _, bad := range []string{"../x"} {
		assert.ErrorIs(t, c.WriteFile(ctx, bad, strings.NewReader("x")), ErrPathEscape)
		assert.ErrorIs(t, c.DeleteFile(ctx, bad), ErrPathEscape)
		assert.ErrorIs(t, c.CreateDirectory(ctx, bad), ErrPathEscape)
		assert.ErrorIs(t, c.DeleteDirectory(ctx, bad), ErrPathEscape)
		assert.ErrorIs(t, c.CopyFile(ctx, bad, "y"), ErrPathEscape)
	}
}

func TestDiscoverCert_Errors(t *testing.T) {
	s := newFakeServer(t)
	s.tlsOn = false
	_, err := DiscoverCert(ctx5(t), "127.0.0.1", s.port(), time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not offer explicit TLS")
	_, err = DiscoverCert(ctx5(t), "127.0.0.1", 1, time.Second) // nothing listens
	require.Error(t, err)
	_, err = Pin(ctx5(t), nil, "127.0.0.1", s.port(), Confirmation{Fingerprint: "x"})
	require.ErrorIs(t, err, ErrNoPinStore)
}

func TestServerNameFor(t *testing.T) {
	mk := func(dns []string, ips []net.IP) *x509.Certificate {
		x, err := x509.ParseCertificate(genCertNames(t, dns, ips).Certificate[0])
		require.NoError(t, err)
		return x
	}
	n, err := serverNameFor(mk([]string{"nas.local"}, nil), "nas.local")
	require.NoError(t, err)
	assert.Equal(t, "nas.local", n, "the host itself when the certificate is valid for it")
	n, err = serverNameFor(mk([]string{"nas.local"}, nil), "10.0.0.5")
	require.NoError(t, err)
	assert.Equal(t, "nas.local", n, "the certificate's own DNS name when the host (an IP) is not covered")
	_, err = serverNameFor(mk(nil, nil), "10.0.0.5")
	require.Error(t, err, "a certificate that names nothing cannot be verified")
}

func TestErrorTexts_AndHostPort(t *testing.T) {
	assert.Contains(t, (&UnknownCertError{Host: "h", Fingerprint: "SHA256:AA"}).Error(), "SHA256:AA")
	e := (&CertMismatchError{Host: "h", Presented: "SHA256:BB", Pinned: []string{"SHA256:AA"}}).Error()
	assert.Contains(t, e, "CHANGED")
	assert.Contains(t, e, "SHA256:AA")
	assert.Equal(t, "nas:21", HostPort("NAS", 0))
	assert.Equal(t, "nas:2121", HostPort("NAS", 2121))
	assert.Equal(t, []string{"ftp"}, scanFactory{}.SupportedProtocols())
}

func TestFilePinStore_RemoveAndMissingFile(t *testing.T) {
	st := NewFilePinStore(filepath.Join(t.TempDir(), "none.json"))
	got, err := st.Lookup("h:21")
	require.NoError(t, err)
	assert.Empty(t, got, "a missing file is simply no pins")
	require.NoError(t, st.Remove("h:21", "SHA256:AA"))
	require.NoError(t, st.Record("h:21", CertPin{Fingerprint: "SHA256:AA"}))
	require.NoError(t, st.Record("h:21", CertPin{Fingerprint: "SHA256:BB"}))
	require.NoError(t, st.Remove("h:21", "SHA256:AA"))
	got, _ = st.Lookup("h:21")
	require.Len(t, got, 1)
	assert.Equal(t, "SHA256:BB", got[0].Fingerprint)
	bad := NewFilePinStore(filepath.Join(t.TempDir(), "nodir", "p.json"))
	assert.Error(t, bad.Record("h:21", CertPin{Fingerprint: "SHA256:CC"}), "an unwritable store is an error, not a silent no-pin")
}

func TestMapTLSError_ExpiredPinnedCertificate_IsNotReportedAsChanged(t *testing.T) {
	x, err := x509.ParseCertificate(genCert(t).Certificate[0])
	require.NoError(t, err)
	pin := CertPin{Fingerprint: Fingerprint(x), ServerName: "127.0.0.1", CertDER: x.Raw}
	expired := &tls.CertificateVerificationError{UnverifiedCertificates: []*x509.Certificate{x}, Err: x509.CertificateInvalidError{Cert: x, Reason: x509.Expired}}
	m, mapped := mapTLSError(expired, "h", []CertPin{pin})
	assert.True(t, mapped)
	var mm *CertMismatchError
	assert.False(t, errors.As(m, &mm), "an expired but pinned certificate keeps its real cause")
	// the same chain against a pin of ANOTHER certificate is a changed certificate
	other := genCertT(t)
	m, _ = mapTLSError(expired, "h", []CertPin{other})
	assert.True(t, errors.As(m, &mm))
	// and with no pin at all it is an unknown certificate
	m, _ = mapTLSError(expired, "h", nil)
	var uc *UnknownCertError
	assert.True(t, errors.As(m, &uc))
	assert.Equal(t, Fingerprint(x), uc.Fingerprint)
}

func genCertT(t *testing.T) CertPin {
	t.Helper()
	crt := genCert(t)
	return CertPin{Fingerprint: certFingerprint(t, crt), ServerName: "x", CertDER: crt.Certificate[0]}
}
