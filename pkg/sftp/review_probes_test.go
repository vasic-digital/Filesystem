package sftp

// REVIEWER PROBES (WF19, independent review of round 1), adopted verbatim as permanent regression tests (fix-r2).
// Author-independent: own server, own handlers. Each probe asserts the behaviour the package/doc CLAIMS; a FAIL of a probe
// is a defect. Probes never hang the run: every blocked call is bounded by a watchdog and released afterwards.
// Deviations from the reviewer's file (each one stated): (1) the places that reached into the client's private connection
// fields use killConn/heldConn (helpers_test.go); (2) P6 creates the file "eofme" so that the STAT (the request the probe is
// about) is still reached now that the containment check fails closed on a path the server cannot resolve.

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
	"golang.org/x/crypto/ssh"
)

type probeOpts struct {
	fileGet  gosftp.FileReader
	fileList gosftp.FileLister
	noServe  bool
	raw      func(ch ssh.Channel)
	kbdOnly  bool
	// kbdNoDevice: password login works, and keyboard-interactive is ADVERTISED but answered with a plain failure (what OpenSSH
	// does without a PAM/BSD-auth device); added in fix-r2 after a real OpenSSH showed the client's handling of it.
	kbdNoDevice bool
}

type probeServer struct {
	Host     string
	Port     int
	Dir      string
	Password string
	HostKey  ssh.Signer
	conns    atomic.Int32
	delay    atomic.Int64
	ln       net.Listener
	mu       sync.Mutex
	accepted []net.Conn
	wg       sync.WaitGroup
	once     sync.Once
}

func startProbe(t *testing.T, o probeOpts) *probeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &probeServer{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Dir: t.TempDir(), Password: "probe-pw-1", HostKey: newSigner(t), ln: ln}
	cfg := &ssh.ServerConfig{}
	if o.kbdOnly {
		cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := ch("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans) == 1 && ans[0] == s.Password {
				return nil, nil
			}
			return nil, os.ErrPermission
		}
	} else {
		if o.kbdNoDevice {
			cfg.KeyboardInteractiveCallback = func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				return nil, os.ErrPermission
			}
		}
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == s.Password {
				return nil, nil
			}
			return nil, os.ErrPermission
		}
	}
	cfg.AddHostKey(s.HostKey)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			s.mu.Lock()
			s.accepted = append(s.accepted, c)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				if d := s.delay.Load(); d > 0 {
					time.Sleep(time.Duration(d))
				}
				s.serve(c, cfg, o)
			}()
		}
	}()
	t.Cleanup(s.shutdown)
	return s
}

func (s *probeServer) shutdown() {
	s.once.Do(func() {
		_ = s.ln.Close()
		s.mu.Lock()
		for _, c := range s.accepted {
			_ = c.Close()
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
}

func (s *probeServer) serve(conn net.Conn, cfg *ssh.ServerConfig, o probeOpts) {
	defer conn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for r := range creqs {
				ok := r.Type == "subsystem" && strings.HasSuffix(string(r.Payload), "sftp")
				_ = r.Reply(ok, nil)
				if !ok {
					continue
				}
				switch {
				case o.noServe:
					for range creqs { //nolint:revive // hold the channel, never answer
					}
					return
				case o.raw != nil:
					o.raw(ch)
					return
				default:
					h := gosftp.Handlers{FileGet: roHandlers{}, FilePut: roHandlers{}, FileCmd: roHandlers{}, FileList: roHandlers{}}
					if o.fileGet != nil {
						h.FileGet = o.fileGet
					}
					if o.fileList != nil {
						h.FileList = o.fileList
					}
					srv := gosftp.NewRequestServer(ch, h)
					_ = srv.Serve()
					_ = srv.Close()
					return
				}
			}
		}()
	}
}

func probeClient(s *probeServer, mut func(*Config)) *Client {
	st := NewMemPinStore()
	_ = st.Record(HostPort(s.Host, s.Port), HostKeyPin{KeyType: s.HostKey.PublicKey().Type(), Fingerprint: Fingerprint(s.HostKey.PublicKey()), ConfirmedBy: "review"})
	cfg := &Config{Host: s.Host, Port: s.Port, Username: "alice", CredentialRef: "r", Root: s.Dir,
		Resolver: mapResolver{"r": {Password: s.Password}}, PinStore: st, RetryBase: time.Millisecond, DialTimeout: 5 * time.Second}
	if mut != nil {
		mut(cfg)
	}
	return NewSFTPClient(cfg)
}

func within3s(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	case <-time.After(3 * time.Second):
		return false
	}
}

// ---- handlers ------------------------------------------------------------------------------------------------

type blockStatLister struct {
	roHandlers
	release chan struct{}
}

func (b blockStatLister) Filelist(r *gosftp.Request) (gosftp.ListerAt, error) {
	if r.Method == "Stat" && strings.HasSuffix(r.Filepath, "/hang") {
		<-b.release
	}
	if r.Method == "List" && strings.HasSuffix(r.Filepath, "/hangdir") {
		return blockingLister{b.release}, nil
	}
	return b.roHandlers.Filelist(r)
}

type blockingLister struct{ release chan struct{} }

func (l blockingLister) ListAt([]os.FileInfo, int64) (int, error) { <-l.release; return 0, io.EOF }

type eofStatLister struct{ roHandlers }

func (e eofStatLister) Filelist(r *gosftp.Request) (gosftp.ListerAt, error) {
	if r.Method == "Stat" && strings.HasSuffix(r.Filepath, "/eofme") {
		return nil, io.EOF
	}
	return e.roHandlers.Filelist(r)
}

type failRealPathLister struct{ roHandlers }

func (f failRealPathLister) RealPath(p string) (string, error) {
	if strings.Contains(p, "evil") {
		return "", os.ErrPermission
	}
	return f.roHandlers.RealPath(p)
}

type blockingReaderAt struct{ release chan struct{} }

func (b blockingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off == 0 {
		for i := range p {
			p[i] = 'A'
		}
		return len(p), nil
	}
	<-b.release
	return 0, io.EOF
}

type blockingGet struct{ release chan struct{} }

func (g blockingGet) Fileread(r *gosftp.Request) (io.ReaderAt, error) {
	if strings.HasSuffix(r.Filepath, "/slow") {
		return blockingReaderAt{g.release}, nil
	}
	return os.Open(r.Filepath)
}

func writePkt(w io.Writer, typ byte, payload []byte) {
	b := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(b, uint32(1+len(payload)))
	b[4] = typ
	copy(b[5:], payload)
	_, _ = w.Write(b)
}

// rawMalformedStatus answers INIT correctly, then every request with a STATUS that carries only the request id
// (4 bytes; RFC draft-ietf-secsh-filexfer-02 section 7 requires id + code + message + language).
func rawMalformedStatus(ch ssh.Channel) {
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
			writePkt(ch, 2, []byte{0, 0, 0, 3}) // SSH_FXP_VERSION 3
			continue
		}
		if len(body) < 4 {
			return
		}
		writePkt(ch, 101, body[:4]) // SSH_FXP_STATUS, id only
	}
}

// ---- probes --------------------------------------------------------------------------------------------------

// P1: package doc "Context cancellation closes the file or the connection that the call is blocked on".
func TestReview_P1_StatHonoursContextOnHungServer(t *testing.T) {
	rel := make(chan struct{})
	s := startProbe(t, probeOpts{fileList: blockStatLister{release: rel}})
	if err := os.WriteFile(filepath.Join(s.Dir, "hang"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := probeClient(s, nil)
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	var err error
	start := time.Now()
	go func() { defer close(done); _, err = c.GetFileInfo(ctx, "hang") }()
	ok := within3s(done)
	close(rel)
	<-done
	t.Logf("REVIEW-PROBE P1 returned_within_3s=%v elapsed=%v err=%v", ok, time.Since(start).Round(time.Millisecond), err)
	if !ok {
		t.Errorf("DEFECT P1: GetFileInfo with a 300ms context stayed blocked > 3s on a server that does not answer STAT")
	}
	_ = c.Disconnect(context.Background())
}

// P2: Connect(ctx) must end when ctx ends, also after the ssh handshake (sftp INIT never answered).
func TestReview_P2_ConnectHonoursContextWhenInitUnanswered(t *testing.T) {
	s := startProbe(t, probeOpts{noServe: true})
	c := probeClient(s, func(cfg *Config) { cfg.Root = "/"; cfg.MaxRetries = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	var err error
	start := time.Now()
	go func() { defer close(done); err = c.Connect(ctx) }()
	ok := within3s(done)
	s.shutdown()
	<-done
	t.Logf("REVIEW-PROBE P2 returned_within_3s=%v elapsed=%v err=%v", ok, time.Since(start).Round(time.Millisecond), err)
	if !ok {
		t.Errorf("DEFECT P2: Connect with a 300ms context stayed blocked > 3s (server completed ssh auth but never answered SSH_FXP_INIT)")
	}
}

// P3: TestConnection on a client whose connection was LOST (caller had connected it) must not leave it disconnected.
func TestReview_P3_TestConnectionOnLostConnection(t *testing.T) {
	s := startProbe(t, probeOpts{})
	if err := os.WriteFile(filepath.Join(s.Dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, withTC := range []bool{false, true} {
		c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1 })
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		killConn(c) // the network drops the connection under the client
		_, lerr := c.GetFileInfo(ctx, "a.txt")
		tcErr := error(nil)
		if withTC {
			tcErr = c.TestConnection(ctx)
		}
		_, err := c.ListDirectory(ctx, "/")
		t.Logf("REVIEW-PROBE P3 with_TestConnection=%v first_op_err=%v testconn_err=%v list_err=%v connected_after=%v", withTC, lerr != nil, tcErr, err, c.IsConnected())
		if !withTC && err != nil {
			t.Fatalf("control failed: a lost connection should be re-dialled: %v", err)
		}
		if withTC && err != nil {
			t.Errorf("DEFECT P3: after a health check (TestConnection) on a lost connection the caller's client is permanently disconnected: %v", err)
		}
		_ = c.Disconnect(ctx)
	}
}

// P4: "A client that the caller disconnected is not re-dialled": Disconnect racing an in-flight re-dial.
func TestReview_P4_DisconnectDuringRedial(t *testing.T) {
	s := startProbe(t, probeOpts{})
	ctx := context.Background()
	c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1 })
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	killConn(c)
	_, _ = c.GetFileInfo(ctx, "x") // marks the connection lost
	s.delay.Store(int64(700 * time.Millisecond))
	done := make(chan struct{})
	var lerr error
	go func() { defer close(done); _, lerr = c.ListDirectory(ctx, "/") }()
	time.Sleep(250 * time.Millisecond)
	derr := c.Disconnect(ctx)
	<-done
	res := c.IsConnected()
	held := heldConn(c)
	t.Logf("REVIEW-PROBE P4 disconnect_err=%v list_err=%v connected_after_disconnect=%v ssh_conn_held=%v", derr, lerr, res, held)
	if res || held {
		t.Errorf("DEFECT P4: Disconnect during an implicit re-dial is undone: the client is connected again and holds a live ssh connection")
	}
	_ = c.Disconnect(ctx)
}

// P5: a file whose NAME contains a backslash (legal on POSIX servers) must be readable by the Path the listing returned.
func TestReview_P5_BackslashNameReadsAnotherFile(t *testing.T) {
	s := startProbe(t, probeOpts{})
	if err := os.MkdirAll(filepath.Join(s.Dir, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(s.Dir, "x", "y"), []byte("OTHER-FILE"), 0o644)
	_ = os.WriteFile(filepath.Join(s.Dir, `x\y`), []byte("BACKSLASH-FILE"), 0o644)
	c := probeClient(s, nil)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	ents, err := c.ListDirectory(ctx, "/")
	if err != nil {
		t.Fatal(err)
	}
	var p string
	for _, e := range ents {
		if e.Name == `x\y` {
			p = e.Path
		}
	}
	if p == "" {
		t.Fatalf("control failed: listing does not contain the backslash name")
	}
	rc, err := c.ReadFile(ctx, p)
	var got []byte
	if err == nil {
		got, _ = io.ReadAll(rc)
		_ = rc.Close()
	}
	t.Logf("REVIEW-PROBE P5 listed_path=%q read_err=%v content=%q", p, err, got)
	if string(got) != "BACKSLASH-FILE" {
		t.Errorf("DEFECT P5: reading the path the listing returned for %q yields %q (err %v), not the file's own content", `x\y`, got, err)
	}
}

// P6: one SSH_FX_EOF status reply to a STAT must not tear down the shared connection (and its open streams) nor re-dial.
func TestReview_P6_EOFStatusTearsDownConnection(t *testing.T) {
	s := startProbe(t, probeOpts{fileList: eofStatLister{}})
	big := bytes.Repeat([]byte("0123456789abcdef"), 256*1024) // 4 MiB
	_ = os.WriteFile(filepath.Join(s.Dir, "big"), big, 0o644)
	_ = os.WriteFile(filepath.Join(s.Dir, "eofme"), []byte("x"), 0o644) // deviation (2)
	c := probeClient(s, nil)                                            // default MaxRetries 3
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	rc, err := c.ReadFile(ctx, "big")
	if err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4096)
	if _, err := io.ReadFull(rc, head); err != nil {
		t.Fatal(err)
	}
	before := s.conns.Load()
	_, serr := c.GetFileInfo(ctx, "eofme")
	redials := s.conns.Load() - before
	rest, rerr := io.ReadAll(rc)
	_ = rc.Close()
	t.Logf("REVIEW-PROBE P6 stat_err=%v transient=%v redials=%d open_stream_err=%v stream_bytes_after=%d/%d", serr, IsTransient(serr), redials, rerr, len(rest), len(big)-4096)
	if redials > 0 || rerr != nil {
		t.Errorf("DEFECT P6: a single SSH_FX_EOF status reply caused %d re-dials and broke an unrelated open stream (%v)", redials, rerr)
	}
}

// P7: a malformed (short) STATUS reply from the (pinned) server must be an error, never a panic of the caller.
func TestReview_P7_MalformedStatusPanics(t *testing.T) {
	s := startProbe(t, probeOpts{raw: rawMalformedStatus})
	c := probeClient(s, func(cfg *Config) { cfg.Root = "/"; cfg.MaxRetries = -1 })
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	var pv any
	var err error
	func() {
		defer func() { pv = recover() }()
		_, err = c.GetFileInfo(ctx, "x")
	}()
	t.Logf("REVIEW-PROBE P7 panic=%v err=%v", pv, err)
	if pv != nil {
		t.Errorf("DEFECT P7: a 4-byte SSH_FXP_STATUS reply panicked the calling goroutine: %v", pv)
	}
}

// P8: package doc: cancellation closes the file "that the call is blocked on" -> an in-flight Read must end on cancel.
func TestReview_P8_CancelUnblocksInFlightRead(t *testing.T) {
	rel := make(chan struct{})
	s := startProbe(t, probeOpts{fileGet: blockingGet{rel}})
	_ = os.WriteFile(filepath.Join(s.Dir, "slow"), make([]byte, 1<<20), 0o644)
	c := probeClient(s, nil)
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	rc, err := c.ReadFile(ctx, "slow")
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 1024)
	if n, err := rc.Read(p); err != nil || n != 1024 {
		t.Fatalf("control read: %d %v", n, err)
	}
	done := make(chan struct{})
	var rerr error
	go func() { defer close(done); _, rerr = rc.Read(p) }()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	cancel()
	ok := within3s(done)
	close(rel)
	<-done
	_ = rc.Close()
	t.Logf("REVIEW-PROBE P8 returned_within_3s_of_cancel=%v elapsed=%v err=%v", ok, time.Since(start).Round(time.Millisecond), rerr)
	if !ok {
		t.Errorf("DEFECT P8: cancelling the context did not end a Read blocked on the server (file Close waits for the Read's lock)")
	}
	_ = c.Disconnect(context.Background())
}

// P9: compatibility: a server that offers password login only as keyboard-interactive (common on NAS/PAM setups).
func TestReview_P9_KeyboardInteractiveOnlyServer(t *testing.T) {
	s := startProbe(t, probeOpts{kbdOnly: true})
	c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1 })
	err := c.Connect(context.Background())
	var ae *AuthError
	t.Logf("REVIEW-PROBE P9 connect_err=%v is_AuthError=%v", err, err != nil && asAuth(err, &ae))
	if err != nil {
		t.Errorf("GAP P9: correct password refused by a keyboard-interactive-only server: %v", err)
	}
	_ = c.Disconnect(context.Background())
}

func asAuth(err error, ae **AuthError) bool {
	for e := err; e != nil; {
		if a, ok := e.(*AuthError); ok {
			*ae = a
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// P10: concurrent operations after one connection loss: how many new connections are opened (thundering herd)?
func TestReview_P10_ConcurrentRedialStorm(t *testing.T) {
	s := startProbe(t, probeOpts{})
	_ = os.WriteFile(filepath.Join(s.Dir, "a.txt"), []byte("a"), 0o644)
	c := probeClient(s, nil)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	killConn(c)
	before := s.conns.Load()
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, errs[i] = c.ListDirectory(ctx, "/") }(i)
	}
	wg.Wait()
	nerr := 0
	for _, e := range errs {
		if e != nil {
			nerr++
		}
	}
	redials := s.conns.Load() - before
	t.Logf("REVIEW-PROBE P10 concurrent_ops=8 new_connections=%d failed_ops=%d", redials, nerr)
	if redials > 1 {
		t.Errorf("DEFECT P10: one connection loss under 8 concurrent operations opened %d new ssh connections (no single-flight re-dial)", redials)
	}
}

// P11: the one context-aware call (ListDirectory -> ReadDirContext) on a server that does not answer READDIR.
func TestReview_P11_ListDirectoryHonoursContextOnHungServer(t *testing.T) {
	rel := make(chan struct{})
	s := startProbe(t, probeOpts{fileList: blockStatLister{release: rel}})
	_ = os.MkdirAll(filepath.Join(s.Dir, "hangdir"), 0o755)
	c := probeClient(s, nil)
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	var err error
	start := time.Now()
	go func() { defer close(done); _, err = c.ListDirectory(ctx, "hangdir") }()
	ok := within3s(done)
	close(rel)
	<-done
	t.Logf("REVIEW-PROBE P11 returned_within_3s=%v elapsed=%v err=%v", ok, time.Since(start).Round(time.Millisecond), err)
	if !ok {
		t.Errorf("DEFECT P11: ListDirectory with a 300ms context stayed blocked > 3s on a server that does not answer READDIR")
	}
	_ = c.Disconnect(context.Background())
}

// P12: the symlink containment check must fail CLOSED when the server cannot resolve the path.
func TestReview_P12_ContainmentFailsOpenOnRealPathError(t *testing.T) {
	s := startProbe(t, probeOpts{fileList: failRealPathLister{}})
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("OUTSIDE-SECRET"), 0o644)
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(s.Dir, "evil")); err != nil {
		t.Fatal(err)
	}
	c := probeClient(s, nil)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	rc, err := c.ReadFile(ctx, "evil")
	var got []byte
	if err == nil {
		got, _ = io.ReadAll(rc)
		_ = rc.Close()
	}
	t.Logf("REVIEW-PROBE P12 read_err=%v content=%q", err, got)
	if err == nil {
		t.Errorf("DEFECT P12: when RealPath fails the containment check is skipped and a symlink to outside the root is read: %q", got)
	}
}
