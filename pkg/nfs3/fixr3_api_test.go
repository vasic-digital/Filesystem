package nfs3

// Tests of the third fix pass that need internals which did not exist at the committed code (83c0ac1): the leg parameter of vanishedErr, the
// version in the allow-list key, the injectable reserved-port bind, the context-aware remount semaphore. Their RED on the committed package is
// the compile error plus the revert mutants (fix-r3-mutants.txt); fixr3_test.go holds the tests that compile there.

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ---- class A: the leg decides what STALE means ----

func TestFixR3VanishedErrDependsOnTheLeg(t *testing.T) {
	nfs := func(st uint32) error { return &NFSError{Op: "X", Status: st} }
	for _, tc := range []struct {
		name         string
		err          error
		lookup, attr bool
	}{
		{"NOENT", nfs(NFS3ErrNoEnt), true, true},
		{"STALE", nfs(NFS3ErrStale), false, true},
		{"BADHANDLE", nfs(NFS3ErrBadHandle), false, true},
		{"ACCES", nfs(NFS3ErrAcces), false, false},
		{"JUKEBOX", nfs(NFS3ErrJukebox), false, false},
		{"wrapped STALE", errors.Join(errors.New("ctx"), nfs(NFS3ErrStale)), false, true},
		{"not an NFS error", errors.New("boom"), false, false},
		{"nil", nil, false, false},
	} {
		if got := vanishedErr(tc.err, legLookup); got != tc.lookup {
			t.Errorf("%s on the LOOKUP leg: %v, want %v", tc.name, got, tc.lookup)
		}
		if got := vanishedErr(tc.err, legGetattr); got != tc.attr {
			t.Errorf("%s on the GETATTR leg: %v, want %v", tc.name, got, tc.attr)
		}
	}
	if vanishedErr(nfs(NFS3ErrNoEnt), attrLeg(99)) {
		t.Error("an unknown leg was treated as vanished: the safe answer is false")
	}
}

// ---- class D: the allow-list key is (program, version, procedure) ----

func TestFixR3AllowListKeysCarryTheRightVersion(t *testing.T) {
	want := map[uint32]uint32{progPortmap: versPortmap, progMount: versMount, progNFS: versNFS}
	if len(allowedCalls) != 11 {
		t.Errorf("%d allowed procedures, want 11 (portmap GETPORT; MOUNT MNT UMNT EXPORT; NFS NULL GETATTR LOOKUP ACCESS READ READDIRPLUS FSINFO)", len(allowedCalls))
	}
	for k := range allowedCalls {
		if v, ok := want[k.prog]; !ok || k.vers != v {
			t.Errorf("allow-list entry %+v: version %d, want %d", k, k.vers, v)
		}
	}
}

// Every allowed procedure is refused when it is called with any OTHER version of its program, and nothing reaches the server.
func TestFixR3AllowedProcedureWithAnotherVersionIsRefused(t *testing.T) {
	var reached atomic.Int64
	addr := rawServer(t, func(conn, call int, rec []byte) [][]byte { reached.Add(1); return nil })
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	rc := newRPCConn(nc, authSysCred{}, 0, 1)
	defer rc.close()
	n := 0
	for k := range allowedCalls {
		for _, v := range []uint32{k.vers + 1, k.vers - 1, 0, 4} {
			if v == k.vers {
				continue
			}
			n++
			if _, err := rc.call(bg, time.Second, k.prog, v, k.proc, nil); !errors.Is(err, ErrReadOnly) {
				t.Errorf("%+v called as version %d: %v, want ErrReadOnly", k, v, err)
			}
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n < 30 || reached.Load() != 0 {
		t.Errorf("%d refusals checked, %d records reached the server (want >= 30 and 0)", n, reached.Load())
	}
}

// ---- class C: the remount is serialised by a semaphore that honours the context ----

func TestFixR3RemountWaiterHonoursItsContext(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	c.remountSem <- struct{}{} // another remount is running
	ctx, cancel := context.WithTimeout(bg, 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- c.remount(ctx) }()
	var err error
	select {
	case err = <-done:
	case <-time.After(3 * time.Second):
		<-c.remountSem // release the semaphore so that the blocked goroutine ends
		t.Fatalf("a waiter for the remount ignored its context (still blocked after 3 s)")
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("a waiter for the remount ignored its context: err=%v after %v", err, time.Since(start))
	}
	<-c.remountSem // positive control: with the semaphore free the same call succeeds
	if err := c.remount(bg); err != nil {
		t.Fatalf("control: remount with a free semaphore: %v", err)
	}
	if len(c.remountSem) != 0 {
		t.Error("the semaphore is still held after a remount")
	}
}

// A stale walk whose remount is interrupted by the caller's context reports the context, not the stale handle.
func TestFixR3ResolveReportsTheContextWhenTheRemountIsCancelled(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.set(func(o *fakeOpts) {
		o.Corrupt = func(proc uint32, reply []byte) []byte {
			if proc == procLookup {
				var e encoder
				e.u32(NFS3ErrStale)
				e.boolean(false)
				return e.b
			}
			return reply
		}
	})
	c.remountSem <- struct{}{} // the remount can not start
	ctx, cancel := context.WithTimeout(bg, 150*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.GetFileInfo(ctx, "/docs/a.txt"); done <- err }()
	var err error
	select {
	case err = <-done:
	case <-time.After(3 * time.Second):
		<-c.remountSem
		t.Fatal("GetFileInfo ignored its context while waiting for the remount")
	}
	<-c.remountSem
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the context error, got %v", err)
	}
}

// ---- class T (TN5, N15): the reserved-port loop is executed through an injected bind ----

type portPipe struct{ net.Conn }

func TestFixR3DialPrivilegedSkipsBusyPorts(t *testing.T) {
	var tried []int
	conn, err := dialPrivilegedFrom(bg, func(ctx context.Context, port int) (net.Conn, error) {
		tried = append(tried, port)
		if port > 1020 {
			return nil, &net.OpError{Op: "dial", Err: syscall.EADDRINUSE}
		}
		a, _ := net.Pipe()
		return portPipe{a}, nil
	})
	if err != nil {
		t.Fatalf("ports 1023..1021 busy: dialPrivilegedFrom gave up: %v", err)
	}
	conn.Close()
	want := []int{1023, 1022, 1021, 1020}
	if len(tried) != len(want) {
		t.Fatalf("tried %v, want %v", tried, want)
	}
	for i := range want {
		if tried[i] != want[i] {
			t.Fatalf("tried %v, want %v (descending from 1023)", tried, want)
		}
	}
}

func TestFixR3DialPrivilegedPermissionRefusalIsUnavailable(t *testing.T) {
	for _, no := range []error{syscall.EACCES, syscall.EPERM} {
		var tries int
		_, err := dialPrivilegedFrom(bg, func(ctx context.Context, port int) (net.Conn, error) {
			tries++
			return nil, &net.OpError{Op: "dial", Err: no}
		})
		if !errors.Is(err, ErrPrivilegedPortUnavailable) || tries != 1 {
			t.Errorf("%v: err=%v after %d tries, want ErrPrivilegedPortUnavailable after 1", no, err, tries)
		}
	}
}

func TestFixR3DialPrivilegedGivesUpAfterTheBudgetAndOnOtherErrors(t *testing.T) {
	var tries int
	_, err := dialPrivilegedFrom(bg, func(ctx context.Context, port int) (net.Conn, error) {
		tries++
		return nil, &net.OpError{Op: "dial", Err: syscall.EADDRINUSE}
	})
	if err == nil || tries != 64 {
		t.Errorf("every port busy: err=%v after %d tries, want an error after exactly 64", err, tries)
	}
	boom := errors.New("connection refused by the peer")
	tries = 0
	_, err = dialPrivilegedFrom(bg, func(ctx context.Context, port int) (net.Conn, error) {
		tries++
		return nil, boom
	})
	if !errors.Is(err, boom) || tries != 1 {
		t.Errorf("an unrelated dial error: err=%v after %d tries, want it returned after 1", err, tries)
	}
	ctx, cancel := context.WithCancel(bg)
	cancel()
	tries = 0
	_, err = dialPrivilegedFrom(ctx, func(ctx context.Context, port int) (net.Conn, error) {
		tries++
		return nil, &net.OpError{Op: "dial", Err: syscall.EADDRINUSE}
	})
	if !errors.Is(err, context.Canceled) || tries != 0 {
		t.Errorf("a cancelled context: err=%v after %d tries, want context.Canceled after 0", err, tries)
	}
}

// ---- class C / I2: the READs of a stale read-ahead are cancelled ----

// silentReader returns a reader with `window` READs in flight against a server that never answers, and those futures.
func silentReader(t *testing.T, window int) (*fileReader, []*future) {
	t.Helper()
	addr := rawServer(t, func(conn, call int, rec []byte) [][]byte { return nil })
	c := rawClient(t, addr, func(c *Config) { c.CallTimeout = 30 * time.Second; c.MaxRetries = -1 })
	rctx, cancel := context.WithCancel(bg)
	t.Cleanup(cancel)
	r := &fileReader{c: c, ctx: rctx, cancel: cancel, fh: Handle("h"), size: 1 << 20, chunk: 64 << 10, window: window, limit: math.MaxInt64}
	r.restartRamp()
	r.cw = window
	r.topUp()
	futs := append([]*future(nil), r.q...)
	if len(futs) != window {
		t.Fatalf("setup: %d READs in flight, want %d", len(futs), window)
	}
	return r, futs
}

func requireCancelled(t *testing.T, what string, futs []*future) {
	t.Helper()
	for i, f := range futs {
		select {
		case res := <-f.ch:
			if !errors.Is(res.err, context.Canceled) {
				t.Errorf("%s: READ %d finished with %v, want context.Canceled", what, i, res.err)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("%s: READ %d is still in flight", what, i)
		}
	}
}

// The three ways the read-ahead becomes stale besides a Seek: a failed READ (sticky error) and the end of the file. Both cancel what is in flight.
func TestFixR3StaleReadAheadIsCancelledOnErrorAndOnEndOfFile(t *testing.T) {
	r, futs := silentReader(t, 3)
	r.mu.Lock()
	_ = r.fail(errors.New("a READ failed"))
	r.mu.Unlock()
	requireCancelled(t, "fail", futs)

	r2, futs2 := silentReader(t, 3)
	r2.mu.Lock()
	r2.truncateAt(100)
	size, next := r2.size, r2.next
	r2.mu.Unlock()
	requireCancelled(t, "truncateAt", futs2)
	if size != 100 || next != 100 || len(r2.q) != 0 {
		t.Errorf("truncateAt(100): size=%d next=%d queued=%d", size, next, len(r2.q))
	}
}

// ---- class C / W7: the order "fail the connection, then release the write slot" is observable ----

// The failing writer is held at the start of fail() (rpcConn.failHook, set only by tests). With the slot still held, a caller that waits for it can not
// write; with the slot already released (mutant F17) it writes within the window and the half record is followed by a second record.
func TestFixR3FailedWriterKeepsTheSlotUntilTheConnectionIsFailed(t *testing.T) {
	var held atomic.Int64
	halfWriteTrial(t, 0, func(rc *rpcConn, fc *failingConn) {
		var once sync.Once
		rc.failHook = func() {
			once.Do(func() {
				held.Add(1)
				deadline := time.Now().Add(300 * time.Millisecond)
				for fc.writeCount() < 2 && time.Now().Before(deadline) { // the window in which a released slot would let B write
					time.Sleep(200 * time.Microsecond)
				}
			})
		}
	})
	if held.Load() != 1 {
		t.Fatalf("instrument blind: the failing writer was never held at the start of fail() (%d)", held.Load())
	}
}
