package sftp

// WF24 discriminators: one behavioural test per surviving reviewer mutant, to show the survivor is NOT equivalent (the test must
// PASS on the committed code and FAIL on the mutant). Each is a candidate killing test for the author.

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gosftp "github.com/pkg/sftp"
)

// V01: the handshake deadline must not stay on a connection that outlives DialTimeout.
func TestWF24D_V01_ConnectionOutlivesDialTimeout(t *testing.T) {
	s := startProbe(t, probeOpts{})
	_ = os.WriteFile(filepath.Join(s.Dir, "a.txt"), []byte("a"), 0o644)
	c := probeClient(s, func(cfg *Config) { cfg.DialTimeout = time.Second; cfg.MaxRetries = -1; cfg.KeepAliveInterval = -1 })
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	time.Sleep(1600 * time.Millisecond)
	if _, err := c.GetFileInfo(ctx, "a.txt"); err != nil {
		t.Errorf("a connection used %v after a 1 s DialTimeout failed: %v", 1600*time.Millisecond, err)
	}
}

// V03: a waiter of the single-flight re-dial whose own context is fine must not inherit the dialer's context error.
func TestWF24D_V03_WaiterDoesNotInheritTheDialersContextError(t *testing.T) {
	s := startProbe(t, probeOpts{})
	_ = os.WriteFile(filepath.Join(s.Dir, "a.txt"), []byte("a"), 0o644)
	c := probeClient(s, nil)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	killConnAndWait(c)
	_, _ = c.GetFileInfo(ctx, "missing-x") // marks the connection lost and re-dials once (fast, no delay yet)
	killConnAndWait(c)
	s.delay.Store(int64(700 * time.Millisecond))
	// A becomes the dialer with a 300 ms context; B waits for A's flight with a background context
	actx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	aDone := make(chan error, 1)
	go func() { _, err := c.GetFileInfo(actx, "a.txt"); aDone <- err }()
	time.Sleep(100 * time.Millisecond)
	_, berr := c.GetFileInfo(ctx, "a.txt")
	aerr := <-aDone
	t.Logf("dialer_err=%v waiter_err=%v", aerr, berr)
	if berr != nil {
		t.Errorf("the waiter (background context) failed because the dialer's context ended: %v", berr)
	}
}

// V04: TestConnection on a client whose connection was lost repairs it and leaves it connected (guide, Re-dial row).
func TestWF24D_V04_TestConnectionRepairsALostClient(t *testing.T) {
	s := startProbe(t, probeOpts{})
	c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1 })
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	killConnAndWait(c)
	_, _ = c.GetFileInfo(ctx, "x") // marks it lost
	if c.IsConnected() {
		t.Fatal("control: the client should be lost now")
	}
	if err := c.TestConnection(ctx); err != nil {
		t.Fatal(err)
	}
	if !c.IsConnected() {
		t.Errorf("TestConnection on a lost client left it disconnected (the guide: 'uses and repairs that connection and leaves it connected')")
	}
}

// V06: a call whose context ended but that returned by itself inside the grace must not have the connection dropped later.
type wfSlowReadAt struct{ f *os.File }

func (r wfSlowReadAt) ReadAt(p []byte, off int64) (int, error) {
	time.Sleep(150 * time.Millisecond)
	return r.f.ReadAt(p, off)
}
func (r wfSlowReadAt) Close() error { return r.f.Close() }

type wfSlowGet struct{}

func (wfSlowGet) Fileread(r *gosftp.Request) (io.ReaderAt, error) {
	f, err := os.Open(r.Filepath)
	if err != nil {
		return nil, err
	}
	return wfSlowReadAt{f}, nil
}

func TestWF24D_V06_GraceTimerIsDisarmedWhenTheCallReturns(t *testing.T) {
	s := startProbe(t, probeOpts{fileGet: wfSlowGet{}})
	_ = os.WriteFile(filepath.Join(s.Dir, "f"), bytes.Repeat([]byte("z"), 1<<16), 0o644)
	c := probeClient(s, func(cfg *Config) { cfg.CancelGrace = 400 * time.Millisecond; cfg.MaxRetries = -1 })
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	rctx, cancel := context.WithCancel(ctx)
	rc, err := c.ReadFile(rctx, "f")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = rc.Read(make([]byte, 1024)) }() // one READ, 150 ms on the server
	time.Sleep(50 * time.Millisecond)
	cancel() // ends while the READ is in flight: the guard arms the 400 ms grace timer
	<-done   // the READ comes back by itself after ~100 ms, well inside the grace
	_ = rc.Close()
	time.Sleep(700 * time.Millisecond)
	if !c.IsConnected() {
		t.Errorf("the connection was dropped after a call that had already returned inside its grace")
	}
}

// V18: Connect on a connected client releases the connection it replaces.
func TestWF24D_V18_ReConnectReleasesTheOldConnection(t *testing.T) {
	s := startProbe(t, probeOpts{})
	c := probeClient(s, nil)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	old := sshOf(c)
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	w := make(chan struct{})
	go func() { _ = old.Wait(); close(w) }()
	select {
	case <-w:
	case <-time.After(3 * time.Second):
		t.Errorf("the replaced ssh connection is still open (leak)")
	}
}

// V27: the Path of an entry of a NESTED directory includes that directory.
func TestWF24D_V27_NestedListingPath(t *testing.T) {
	s := startProbe(t, probeOpts{})
	_ = os.MkdirAll(filepath.Join(s.Dir, "sub", "deep"), 0o755)
	_ = os.WriteFile(filepath.Join(s.Dir, "sub", "deep", "c.txt"), []byte("c"), 0o644)
	c := probeClient(s, nil)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx) //nolint:errcheck
	ents, err := c.ListDirectory(ctx, "sub/deep")
	if err != nil || len(ents) != 1 {
		t.Fatalf("%v %d", err, len(ents))
	}
	if ents[0].Path != "/sub/deep/c.txt" {
		t.Errorf("nested entry Path = %q", ents[0].Path)
	}
	rc, err := c.ReadFile(ctx, ents[0].Path)
	if err != nil {
		t.Errorf("the listed Path does not read: %v", err)
		return
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if strings.TrimSpace(string(b)) != "c" {
		t.Errorf("read %q", b)
	}
}
