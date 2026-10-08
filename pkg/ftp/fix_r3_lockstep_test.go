package ftp

// Fix round 3 (WF24 re-review, constitution 11.4.276): class K1 - the command/reply lock-step is checked on ONE shape
// only. Every member of the class has a test here; the reviewer's scenario N15 (G1) and N14 (G11) are adopted with the
// assertion inverted to the correct behaviour (each FAILS on the committed code 83c0ac1).

import (
	"errors"
	"io"
	"net/textproto"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
)

func resetLoginBackoffs() {
	loginBackoffs.mu.Lock()
	loginBackoffs.until = map[string]time.Time{}
	loginBackoffs.mu.Unlock()
}

// K1.b / G1: a same-code reply that arrives AFTER the client returned (it sits in the kernel buffer, not in bufio) is
// found by the zero-wait check before the next command; no later MLST is answered one behind.
func TestR3_K1b_LateSameCodeStray_IsCaughtBeforeTheNextCommand_G1(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	var mu sync.Mutex
	first := true
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "NOOP" {
			return false, true
		}
		mu.Lock()
		f := first
		first = false
		mu.Unlock()
		ss.reply("200 ok")
		if f {
			time.Sleep(150 * time.Millisecond) // the client has its answer and returned
			ss.reply("250 stray reply nobody asked for")
		}
		return true, true
	})
	require.NoError(t, c.TestConnection(ctx5(t)))
	time.Sleep(400 * time.Millisecond) // the stray is in the kernel buffer, not in bufio
	_, e1 := c.GetFileInfo(ctx5(t), "a.txt")
	require.Error(t, e1, "the stray must be found before MLST is sent")
	assert.ErrorIs(t, e1, ErrProtocol)
	assert.Equal(t, fabric.ClassTransient, fabric.Classify(e1), "the connection is dropped: a retry runs on a fresh, in-step one (G11)")
	fi, e2 := c.GetFileInfo(ctx5(t), "sub/c.txt")
	require.NoError(t, e2)
	assert.Equal(t, int64(2), fi.Size, "c.txt's own size, not a.txt's")
	assert.True(t, fi.ModTime.Equal(t0.Add(72*time.Hour)), "c.txt's own mtime: %v", fi.ModTime)
	fi3, e3 := c.GetFileInfo(ctx5(t), "big.bin")
	require.NoError(t, e3)
	assert.Equal(t, int64(100000), fi3.Size)
	assert.Equal(t, 2, s.wfCtrl(), "exactly one re-dial")
}

// K1.b the stray arrives between the command and its answer: the shape check poisons instead of shifting every later reply.
func TestR3_K1b_StrayBeforeTheMLSTAnswer_PoisonsInsteadOfShifting(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	var mu sync.Mutex
	first := true
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLST" {
			return false, true
		}
		mu.Lock()
		f := first
		first = false
		mu.Unlock()
		if f {
			ss.reply("250 stray reply nobody asked for") // taken for the answer: a single line, no entry
		}
		return false, true // then the real answer follows
	})
	_, e1 := c.GetFileInfo(ctx5(t), "a.txt")
	require.Error(t, e1)
	assert.False(t, c.IsConnected(), "an answer of the wrong shape drops the connection")
	fi, e2 := c.GetFileInfo(ctx5(t), "sub/c.txt")
	require.NoError(t, e2)
	assert.Equal(t, int64(2), fi.Size)
	fi3, e3 := c.GetFileInfo(ctx5(t), "big.bin")
	require.NoError(t, e3)
	assert.Equal(t, int64(100000), fi3.Size)
}

// K1.c / K1.d: MLST with no entry, with several, or describing another file: every one drops the connection, none leaves
// a lag behind.
func TestR3_K1cd_MLSTShapeAndPathname_AreChecked(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  error
	}{
		{"no_entry", []string{"250-Listing", "250 End"}, ErrListingIncomplete},
		{"two_entries", []string{"250-Listing", " Type=file;Size=1; one", " Type=file;Size=2; two", "250 End"}, ErrListingIncomplete},
		{"empty_entry_line", []string{"250-Listing", "", "250 End"}, ErrListingIncomplete},
		{"another_file", []string{"250-Listing", " Type=file;Size=77;Modify=20200517103000; /data/other.txt", "250 End"}, ErrProtocol},
		{"another_file_relative", []string{"250-Listing", " Type=file;Size=77;Modify=20200517103000; other.txt", "250 End"}, ErrProtocol},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeServer(t)
			c := connected(t, s, nil)
			s.setHook(func(ss *session, verb, arg string) (bool, bool) {
				if verb != "MLST" {
					return false, true
				}
				for _, l := range tc.lines {
					ss.reply("%s", l)
				}
				return true, true
			})
			_, err := c.GetFileInfo(ctx5(t), "a.txt")
			require.ErrorIs(t, err, tc.want)
			assert.False(t, c.IsConnected(), "the reply may be somebody else's answer: the connection is dropped")
			s.setHook(nil)
			fi, err := c.GetFileInfo(ctx5(t), "sub/c.txt")
			require.NoError(t, err)
			assert.Equal(t, int64(2), fi.Size)
			assert.Equal(t, 2, s.wfCtrl())
		})
	}
}

// The pathname check must not refuse a server that spells the path its own way (no false refusal, 11.4.201).
func TestR3_K1d_MLSTPathname_LenientWhereServersDiffer(t *testing.T) {
	for _, tc := range []struct {
		server, remote string
		want           bool
	}{
		{"/data/a.txt", "/data/a.txt", true},
		{"a.txt", "/data/a.txt", true},
		{"/virtual/root/a.txt", "/data/a.txt", true},
		{"/data/A.TXT", "/data/a.txt", true},
		{"/data/sub/", "/data/sub", true},
		{"", "/data/a.txt", true},
		{".", "/data/a.txt", true},
		{"/", "/data/a.txt", true},
		{"/data/b.txt", "/data/a.txt", false},
		{"b.txt", "/data/a.txt", false},
		{"/data/a.txt.bak", "/data/a.txt", false},
	} {
		assert.Equal(t, tc.want, mlstNameMatches(tc.server, tc.remote), "%q vs %q", tc.server, tc.remote)
	}
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLST" {
			return false, true
		}
		ss.reply("250-Listing")
		ss.reply(" Type=file;Size=10;Modify=20200517103000; /some/where/else/A.TXT")
		ss.reply("250 End")
		return true, true
	})
	fi, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err, "same last component, other spelling of the directory part: accepted")
	assert.Equal(t, int64(10), fi.Size)
	assert.True(t, c.IsConnected())
}

// K1.e: a 213 whose text is not a size.
func TestR3_K1e_UnreadableSIZE_DropsTheConnection(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "SIZE" {
			return false, true
		}
		ss.reply("213 garbage")
		return true, true
	})
	_, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.ErrorIs(t, err, ErrProtocol)
	assert.False(t, c.IsConnected())
	s.setHook(nil)
	sk, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	_ = sk.Close()
}

// K1.f: a 257 whose text holds no quoted name (at connect).
func TestR3_K1f_UnreadablePWD_FailsTheConnect_AsAViolation(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "PWD" {
			return false, true
		}
		ss.reply("257 no quotes at all")
		return true, true
	})
	err := NewFTPClient(cfg).Connect(ctx5(t))
	require.ErrorIs(t, err, ErrProtocol)
}

// K1.g: a 229 whose text holds no port. Not a fall-back to PASV: the reply is unreadable, the lock-step is in doubt.
func TestR3_K1g_UnreadableEPSV_DropsTheConnection_NoPASVFallback(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "EPSV" {
			return false, true
		}
		ss.reply("229 Entering Extended Passive Mode (no port here)")
		return true, true
	})
	_, err := c.ListDirectory(ctx5(t), "/")
	require.ErrorIs(t, err, ErrProtocol)
	assert.False(t, c.IsConnected())
	assert.Zero(t, s.count("PASV"), "no silent fall-back after an unreadable 229")
	s.setHook(nil)
	_, err = c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
}

// RFC 2428: the EPSV delimiter is ANY printable character; reading only "|" would turn a legal reply into a violation.
func TestR3_K1g_EPSVDelimiters_AreTheRFCOnes(t *testing.T) {
	for _, tc := range []struct {
		line string
		port int
		ok   bool
	}{
		{"229 Entering Extended Passive Mode (|||2021|)", 2021, true},
		{"229 Entering Extended Passive Mode (!!!2021!)", 2021, true},
		{"229 EPSV ok (###65535#)", 65535, true},
		{"229 Extended Passive mode OK (|||30000|)", 30000, true},
		{"229 (|||0|)", 0, false},
		{"229 (|||65536|)", 0, false},
		{"229 (|||x|)", 0, false},
		{"229 (|!|2021|)", 0, false},
		{"229 (!!!2021|)", 0, false},
		{"229 no port", 0, false},
		{"|||2021|", 2021, true}, // lenient: no parentheses
	} {
		port, ok := parseEPSV(tc.line)
		assert.Equal(t, tc.ok, ok, tc.line)
		if tc.ok {
			assert.Equal(t, tc.port, port, tc.line)
		}
	}
}

// K1.i: a second reply right behind the final reply of a COMPLETE transfer.
func TestR3_K1i_ReplyBehindTheFinalReply_NegativeOneIsTheVerdict(t *testing.T) {
	oldWait := postTransferWait
	postTransferWait = 200 * time.Millisecond // widened: the 2 ms production window is a race on a loaded host
	t.Cleanup(func() { postTransferWait = oldWait })
	for _, gap := range []time.Duration{0, 20 * time.Millisecond} {
		s := newFakeServer(t)
		c := connected(t, s, nil)
		s.setHook(func(ss *session, verb, arg string) (bool, bool) {
			if verb != "MLSD" {
				return false, true
			}
			ss.reply("150 opening")
			dc, err := ss.openData()
			if err != nil {
				return true, true
			}
			_, _ = io.WriteString(dc, "Type=file;Size=1;Modify=20200517103000; x.txt\r\n")
			_ = dc.Close()
			ss.reply("226 transfer complete") // an earlier transfer's reply taken for this one's ...
			time.Sleep(gap)
			ss.reply("451 the real verdict of THIS transfer")
			return true, true
		})
		_, err := c.ListDirectory(ctx5(t), "/")
		var te *textproto.Error
		require.True(t, errors.As(err, &te), "gap %v: the real, negative verdict is returned: %v", gap, err)
		assert.Equal(t, 451, te.Code)
		assert.False(t, c.IsConnected())
	}
}

func TestR3_K1i_PositiveReplyBehindTheFinalReply_DropsTheConnectionOnly(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLSD" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = io.WriteString(dc, "Type=file;Size=1;Modify=20200517103000; x.txt\r\n")
		_ = dc.Close()
		ss.reply("226 transfer complete")
		ss.reply("226 transfer complete, again")
		return true, true
	})
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err, "the listing itself was read to its end and confirmed")
	require.Len(t, got, 1)
	assert.False(t, c.IsConnected(), "but the channel is out of step: dropped")
	s.setHook(nil)
	_, err = c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	assert.Equal(t, 2, s.wfCtrl())
}

// A clean transfer is not disturbed by the post-transfer look (no false drop).
func TestR3_K1i_CleanTransfer_KeepsTheConnection(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	for i := 0; i < 5; i++ {
		_, err := c.ListDirectory(ctx5(t), "/")
		require.NoError(t, err)
	}
	rc, err := c.ReadFile(ctx5(t), "big.bin")
	require.NoError(t, err)
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Len(t, b, 100000)
	assert.Equal(t, 1, s.wfCtrl())
}

// K1.j / G11 (reviewer N14 adopted, inverted): a violation that already dropped the connection is retried on a fresh one.
func TestR3_K1j_LockStepViolation_IsRetriedOnAFreshConnection_G11(t *testing.T) {
	s := newFakeServer(t)
	sc, err := NewScanClient(cfgFor(s, pinned(t, s)), ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond}})
	require.NoError(t, err)
	require.NoError(t, sc.Connect(ctx5(t)))
	defer sc.Disconnect(ctx5(t))
	var mu sync.Mutex
	first := true
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "NOOP" {
			return false, true
		}
		mu.Lock()
		defer mu.Unlock()
		if first {
			first = false
			_, _ = io.WriteString(ss.conn, "200 ok\r\n226 stray\r\n")
			return true, true
		}
		return false, true
	})
	require.NoError(t, sc.TestConnection(ctx5(t)))
	got, err := sc.ListDirectory(ctx5(t), "/")
	require.NoError(t, err, "the violation is transient: the retry runs on a fresh connection")
	assert.NotEmpty(t, got)
	assert.Equal(t, 2, s.wfCtrl())
}

func TestR3_K1j_ProtoViolation_IsTransient_ButStaysAProtocolError(t *testing.T) {
	err := protoViolation("x %d", 1)
	assert.ErrorIs(t, err, ErrProtocol)
	assert.Equal(t, fabric.ClassTransient, fabric.Classify(err))
	lv := listViolation("y")
	assert.ErrorIs(t, lv, ErrProtocol)
	assert.ErrorIs(t, lv, ErrListingIncomplete)
	assert.Equal(t, fabric.ClassTransient, fabric.Classify(lv))
}

// The drain check meets a peer that closed the connection while idle: an I/O failure, then the next operation re-dials.
func TestR3_Drain_PeerClosedWhileIdle_IsATransientIOFailure(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.mu.Lock()
	for _, cc := range s.conns {
		_ = cc.Close()
	}
	s.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	_, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.Error(t, err)
	assert.Equal(t, fabric.ClassTransient, fabric.Classify(err), "%v", err)
	fi, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(10), fi.Size)
}

// The drain check must not undo an abort (it arms a read deadline): Disconnect during a stream still wins.
func TestR3_Drain_DoesNotUndoAnAbort(t *testing.T) {
	s := newFakeServer(t)
	rch, rel := releaser(t)
	c := connected(t, s, nil)
	s.setHook(slowHook(rch))
	rc, err := c.ReadFile(ctx5(t), "big.bin")
	require.NoError(t, err)
	_, err = io.ReadFull(rc, make([]byte, 1024))
	require.NoError(t, err)
	ddone := runAsync(func() { _ = c.Disconnect(ctx5(t)) })
	n, rerr := readFor(rc, time.Second)
	rel()
	_ = rc.Close()
	require.True(t, returnedWithin(ddone, 3*time.Second))
	require.Error(t, rerr)
	assert.Less(t, n, 16*1024)
}

var _ = client.Client(nil)

// F2e: after an early close the NOOP lock-step check wants a 200. A positive reply that is not a 200 (a late reply of the
// transfer) means the channel is out of step.
func TestR3_EarlyClose_NOOPAnsweredWithAnotherPositiveCode_DropsTheConnection(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		switch verb {
		case "RETR":
			if arg != "/data/big.bin" {
				return false, true
			}
			ss.reply("150 opening")
			dc, err := ss.openData()
			if err != nil {
				return true, true
			}
			_, _ = dc.Write(make([]byte, 2000))
			_ = dc.Close()
			ss.reply("226 transfer complete") // the early close is answered ...
			return true, true
		case "NOOP":
			ss.reply("226 a late reply of the transfer") // ... and the lock-step probe is answered by something else
			return true, true
		}
		return false, true
	})
	rc, err := c.ReadFile(ctx5(t), "big.bin")
	require.NoError(t, err)
	_, err = io.ReadFull(rc, make([]byte, 10))
	require.NoError(t, err)
	require.NoError(t, rc.Close(), "an early close is not an error")
	assert.False(t, c.IsConnected(), "226 is not the answer to NOOP: the channel is out of step and is dropped")
}

// F15 (second guard): Pin itself refuses a conflicting second name BEFORE it records anything.
type recordSpy struct {
	PinStore
	records int
}

func (r *recordSpy) Record(hp string, p CertPin) error { r.records++; return r.PinStore.Record(hp, p) }

func TestR3_Pin_ConflictingName_IsRefusedBeforeRecord(t *testing.T) {
	s := newFakeServer(t)
	s.cert = genCertNames(t, []string{"first.test"}, nil)
	inner := NewMemPinStore()
	spy := &recordSpy{PinStore: inner}
	_, err := Pin(ctx5(t), spy, "127.0.0.1", s.port(), Confirmation{Fingerprint: certFingerprint(t, s.cert)})
	require.NoError(t, err)
	s.mu.Lock()
	s.tcfg = nil
	s.cert = genCertNames(t, []string{"second.test"}, nil)
	s.mu.Unlock()
	_, err = Pin(ctx5(t), spy, "127.0.0.1", s.port(), Confirmation{Fingerprint: certFingerprint(t, s.cert)})
	require.ErrorIs(t, err, ErrPinNameConflict)
	assert.Equal(t, 1, spy.records, "the conflict is caught by Pin before the store is asked to record")
}

// K2i: a login that succeeds ends the back-off (another client's password step was ambiguous while this one was in flight).
func TestR3_K2_SuccessfulLogin_EndsTheBackoff(t *testing.T) {
	resetLoginBackoffs()
	s := newFakeServer(t)
	st := pinned(t, s)
	var mu sync.Mutex
	n := 0
	inUSER := make(chan struct{})
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "USER" {
			return false, true
		}
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if first { // client B: slow, it passed the back-off check long before client A fails
			close(inUSER)
			time.Sleep(500 * time.Millisecond)
		}
		return false, true
	})
	var bErr error
	bDone := runAsync(func() { bErr = NewFTPClient(cfgFor(s, st)).Connect(ctx5(t)) })
	<-inUSER
	s.dropNext("PASS", 1) // the next PASS to arrive is client A's: B is still asleep in USER
	require.Error(t, NewFTPClient(cfgFor(s, st)).Connect(ctx5(t)), "client A: an unanswered PASS")
	require.True(t, returnedWithin(bDone, 5*time.Second))
	require.NoError(t, bErr, "client B logged in: the credentials work")
	require.NoError(t, NewFTPClient(cfgFor(s, st)).Connect(ctx5(t)), "B's success ended the back-off that A's ambiguity started")
}
