package ftp

// Fix round 3 (WF24, constitution 11.4.276): class K3 (a transfer's end is closed through the early-close path / waits as
// long as an IOTimeout), K4 (limits that contradict each other), K5 (state published by a concurrent operation).
// The reviewer's scenarios N3, N4, N6 and N16 are adopted with the assertion inverted to the correct behaviour.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withEarlyCloseWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := earlyCloseWait
	earlyCloseWait = d
	t.Cleanup(func() { earlyCloseWait = old })
}

// G4 (reviewer N16 inverted): all SIZE bytes arrive, then 451. ReadFile reports it, so must OpenSeekable.
func TestR3_K3a_SeekerAtSize_ReportsTheNegativeFinalReply_G4(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" || arg != "/data/big.bin" {
			return false, true
		}
		f, _ := s.lookup(arg)
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = dc.Write(f.data)
		_ = dc.Close()
		ss.reply("451 Requested action aborted: local error in processing")
		return true, true
	})
	rc, err := c.ReadFile(ctx5(t), "big.bin")
	require.NoError(t, err)
	b1, _ := io.ReadAll(rc)
	cerr := rc.Close()
	require.Error(t, cerr, "CONTROL: ReadFile reports the 451")
	assert.Len(t, b1, 100000)

	sk, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	b2, serr := io.ReadAll(sk)
	_ = sk.Close()
	require.Error(t, serr, "all the bytes arrived but the transfer was reported as failed: not a clean, complete file")
	assert.Contains(t, serr.Error(), "451")
	assert.Len(t, b2, 100000)
}

// K3.a: a seeker that reads exactly SIZE bytes with ReadFull (no EOF seen by the caller) still releases the session
// (mutant NM13: the stream stayed open) and the final reply was consumed in step.
func TestR3_K3a_SeekerAtSize_ReleasesTheSession_NM13(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	sk, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	defer sk.Close()
	_, err = io.ReadFull(sk, make([]byte, 100000))
	require.NoError(t, err)
	short, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fi, err := c.GetFileInfo(short, "a.txt")
	require.NoError(t, err, "the session is free right after the last announced byte")
	assert.Equal(t, int64(10), fi.Size)
	assert.Equal(t, 1, s.wfCtrl(), "the control channel stayed in step: no re-dial")
}

// K3.a: a server that sends all bytes and does NOT close the data connection nor answer: the seeker neither hangs for a
// whole IOTimeout nor loses the bytes.
func TestR3_K3a_SeekerAtSize_ServerKeepsTheDataConnectionOpen_IsBounded(t *testing.T) {
	withEarlyCloseWait(t, 300*time.Millisecond)
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 5 * time.Second })
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" || arg != "/data/big.bin" {
			return false, true
		}
		f, _ := s.lookup(arg)
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = dc.Write(f.data)
		<-rch // never closes, never answers
		_ = dc.Close()
		return true, false
	})
	sk, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	start := time.Now()
	b, err := io.ReadAll(sk)
	el := time.Since(start)
	require.NoError(t, err)
	require.Len(t, b, 100000)
	_ = sk.Close()
	assert.Less(t, el, 2500*time.Millisecond, "bounded by earlyCloseWait (twice), not by the 5 s IOTimeout: %v", el)
	rel()
}

// G5: pure-ftpd sometimes never answers a download that was closed after a few bytes (measured: the whole IOTimeout).
// The early close is bounded; the connection is dropped, not waited for, and the next operation works.
func TestR3_K3b_EarlyClose_NeverAnswered_IsBoundedByEarlyCloseWait_G5(t *testing.T) {
	withEarlyCloseWait(t, 300*time.Millisecond)
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 5 * time.Second })
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" || arg != "/data/big.bin" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = dc.Write(make([]byte, 1000))
		<-rch // the final reply never comes
		_ = dc.Close()
		return true, false
	})
	rc, err := c.ReadFile(ctx5(t), "big.bin")
	require.NoError(t, err)
	_, err = io.ReadFull(rc, make([]byte, 10))
	require.NoError(t, err)
	start := time.Now()
	cerr := rc.Close()
	el := time.Since(start)
	require.NoError(t, cerr, "an early close is not an error, whatever the server does")
	assert.Less(t, el, 2*time.Second, "the early close waited %v: it must not wait for the 5 s IOTimeout", el)
	assert.False(t, c.IsConnected(), "an unanswered early close drops the connection")
	rel()
	s.setHook(nil)
	fi, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(10), fi.Size)
}

// K3.b with a Seek: the drop of the old stream is the early close.
func TestR3_K3b_SeekDrop_NeverAnswered_IsBounded(t *testing.T) {
	withEarlyCloseWait(t, 300*time.Millisecond)
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, func(cfg *Config) { cfg.IOTimeout = 5 * time.Second })
	var mu sync.Mutex
	n := 0
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "RETR" || arg != "/data/big.bin" {
			return false, true
		}
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if !first {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = dc.Write(make([]byte, 1000))
		<-rch
		_ = dc.Close()
		return true, false
	})
	sk, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	defer sk.Close()
	_, err = io.ReadFull(sk, make([]byte, 10))
	require.NoError(t, err)
	start := time.Now()
	_, err = sk.Seek(50000, io.SeekStart)
	require.NoError(t, err)
	got := make([]byte, 100)
	_, err = io.ReadFull(sk, got)
	el := time.Since(start)
	require.NoError(t, err)
	assert.Equal(t, seqBytes(100000)[50000:50100], got)
	assert.Less(t, el, 3*time.Second, "the seek cost %v", el)
	rel()
}

// ---- K4 -----------------------------------------------------------------------------------------------------------

// G7: a byte budget per listing (the entry cap alone allowed 1,048,576 lines of 16 KiB).
func TestR3_K4a_ListingByteBudget_G7(t *testing.T) {
	require.Equal(t, 256<<20, DefaultMaxListBytes)
	s := newFakeServer(t)
	c := connected(t, s, func(cfg *Config) { cfg.MaxListBytes = 1 << 20 })
	pad := strings.Repeat("n", 8000)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLSD" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		w := bufio.NewWriterSize(dc, 1<<16)
		for i := 0; i < 500; i++ { // 4 MB in all
			fmt.Fprintf(w, "Type=file;Size=1;Modify=20200517103000; %06d%s\r\n", i, pad)
		}
		_ = w.Flush()
		_ = dc.Close()
		ss.reply("226 done")
		return true, true
	})
	_, err := c.ListDirectory(ctx5(t), "/")
	require.ErrorIs(t, err, ErrListingTooLarge)
	assert.False(t, c.IsConnected(), "an over-budget listing drops the connection")
}

func TestR3_K4a_ListingUnderTheBudget_IsFine_NM17(t *testing.T) {
	require.Equal(t, 1<<20, DefaultMaxListEntries)
	s := newFakeServer(t)
	c := connected(t, s, nil) // default limits
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLSD" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		w := bufio.NewWriterSize(dc, 1<<16)
		for i := 0; i < 1500; i++ { // more than 1024: a default of 1<<10 would refuse this
			fmt.Fprintf(w, "Type=file;Size=1;Modify=20200517103000; f%07d\r\n", i)
		}
		_ = w.Flush()
		_ = dc.Close()
		ss.reply("226 done")
		return true, true
	})
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	assert.Len(t, got, 1500)
}

// G8 (reviewer N6 inverted): every name a listing can return can be stat'ed.
func TestR3_K4b_LongName_ListedAndStatted_G8(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	long := strings.Repeat("d", 4200)
	huge := strings.Repeat("e", 12000)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		switch verb {
		case "MLST":
			ss.reply("250-Listing %s", arg)
			ss.reply(" Type=file;Size=1;Modify=20200517103000; %s", arg)
			ss.reply("250 End")
			return true, true
		case "MLSD":
			ss.reply("150 opening")
			dc, err := ss.openData()
			if err != nil {
				return true, true
			}
			_, _ = io.WriteString(dc, "Type=file;Size=1;Modify=20200517103000; "+long+"\r\n")
			_, _ = io.WriteString(dc, "Type=file;Size=1;Modify=20200517103000; "+huge+"\r\n")
			_ = dc.Close()
			ss.reply("226 done")
			return true, true
		}
		return false, true
	})
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, name := range []string{long, huge} {
		fi, err := c.GetFileInfo(ctx5(t), name)
		require.NoError(t, err, "a name of %d bytes that the listing returned must be stat-able", len(name))
		assert.Equal(t, name, fi.Name)
		assert.True(t, c.IsConnected())
	}
}

// G12: the connect budget starts BEFORE the dial. A slow dial eats from DialTimeout, it does not add to it.
func TestR3_K4c_DialTimeoutIsOneBudget_G12(t *testing.T) {
	old := dialTCP
	t.Cleanup(func() { dialTCP = old })
	dialTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		time.Sleep(250 * time.Millisecond) // a slow TCP connect
		return old(ctx, d, addr)
	}
	port, _ := silentServer(t, nil)
	before := time.Now()
	p, err := dialProto(context.Background(), "127.0.0.1", port, protoOpts{dialTimeout: 500 * time.Millisecond, ioTimeout: time.Second, maxReply: 1 << 20}, nil)
	require.NoError(t, err)
	defer p.hardClose()
	assert.WithinDuration(t, before.Add(500*time.Millisecond), p.phaseEnd, 80*time.Millisecond,
		"the phase budget ends DialTimeout after the START of the connect, not after the dial: %v", p.phaseEnd.Sub(before))
}

// NM15: the connect phase ends. An operation issued after DialTimeout has elapsed must still work on the same connection.
func TestR3_NM15_OperationsAfterTheConnectBudget_StayOnTheSameConnection(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(cfg *Config) { cfg.DialTimeout = 300 * time.Millisecond })
	time.Sleep(450 * time.Millisecond)
	fi, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(10), fi.Size)
	_, err = c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	assert.Equal(t, 1, s.wfCtrl(), "no re-dial: the connect-phase deadline was lifted at the end of the connect")
}

// ---- K5 -----------------------------------------------------------------------------------------------------------

// G6 (reviewer N3 inverted): a timed-out Disconnect while another operation re-dials leaves nothing connected.
func TestR3_K5_DisconnectDuringReDial_WinsOverTheNewConnection_G6(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	c.mu.Lock()
	old := c.p
	c.mu.Unlock()
	old.interrupt() // the next operation re-dials
	inUSER := make(chan struct{})
	var once sync.Once
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "USER" {
			once.Do(func() { close(inUSER); time.Sleep(700 * time.Millisecond) })
		}
		return false, true
	})
	var opErr error
	opDone := runAsync(func() { _, opErr = c.GetFileInfo(ctx5(t), "a.txt") })
	select {
	case <-inUSER:
	case <-time.After(5 * time.Second):
		t.Fatal("the re-dial never reached USER")
	}
	short, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	derr := c.Disconnect(short)
	require.ErrorIs(t, derr, context.DeadlineExceeded)
	require.True(t, returnedWithin(opDone, 5*time.Second))
	require.ErrorIs(t, opErr, ErrNotConnected, "the operation that was connecting when Disconnect ran does not get a live connection")
	assert.False(t, c.IsConnected())
	assert.True(t, s.waitCtrl(0, 3*time.Second), "the re-dialled connection was closed, not published")
	_, err := c.GetFileInfo(ctx5(t), "sub/c.txt")
	require.ErrorIs(t, err, ErrNotConnected, "Disconnect never re-dials implicitly")
}

// An explicit Connect that races a Disconnect: the Disconnect wins; a LATER explicit Connect works.
func TestR3_K5_ExplicitConnectRacingDisconnect_DisconnectWins(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	c := NewFTPClient(cfg)
	inUSER := make(chan struct{})
	var once sync.Once
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "USER" {
			once.Do(func() { close(inUSER); time.Sleep(600 * time.Millisecond) })
		}
		return false, true
	})
	var cerr error
	cdone := runAsync(func() { cerr = c.Connect(ctx5(t)) })
	<-inUSER
	short, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, c.Disconnect(short), context.DeadlineExceeded)
	require.True(t, returnedWithin(cdone, 5*time.Second))
	require.ErrorIs(t, cerr, ErrNotConnected)
	assert.False(t, c.IsConnected())
	assert.True(t, s.waitCtrl(0, 3*time.Second))
	s.setHook(nil)
	require.NoError(t, c.Connect(ctx5(t)), "an explicit Connect AFTER the Disconnect is fine")
	assert.True(t, c.IsConnected())
	_ = c.Disconnect(ctx5(t))
}

var _ = errors.New
