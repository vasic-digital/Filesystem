package ftp

// Fix round 3 (WF24, constitution 11.4.276): class K2 - a SERVER-CONTROLLED TEXT must never decide a client-side class
// (G2), and an ambiguous password attempt must be remembered across clients (G3). The reviewer's scenarios N1 and N17
// are adopted here with the assertion inverted to the correct behaviour (each FAILS on the committed code 83c0ac1).

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
)

// G2 (reviewer N1 inverted): a USER-phase refusal, no password sent, never latches the pool root.
func TestR3_K2_UserPhaseRefusal_NeverLatchesThePoolRoot_G2(t *testing.T) {
	for _, v := range []struct {
		name, reply string
		want        fabric.ErrorClass
	}{
		{"530_capacity", "530 Sorry, the maximum number of clients (3) from your host are already connected.", fabric.ClassPermanent},
		{"530_access_denied_text", "530 Access denied: user is not allowed to log in", fabric.ClassPermanent},
		{"532_need_account", "532 Need account for login", fabric.ClassPermanent},
		{"332_need_account", "332 Need account for login", fabric.ClassPermanent},
		{"421_access_denied_text", "421 Access denied: too many connections from your IP, try again later", fabric.ClassTransient},
		{"CONTROL_421_plain", "421 Too many connections (5) from this IP", fabric.ClassTransient},
		{"550_login_incorrect_text", "550 login incorrect for this service", fabric.ClassPermanent},
	} {
		t.Run(v.name, func(t *testing.T) {
			s := newFakeServer(t)
			cfg := cfgFor(s, pinned(t, s))
			var mu sync.Mutex
			n := 0
			s.setHook(func(ss *session, verb, arg string) (bool, bool) {
				if verb != "USER" {
					return false, true
				}
				mu.Lock()
				n++
				first := n == 1
				mu.Unlock()
				if first {
					ss.reply("%s", v.reply)
					return true, false
				}
				return false, true
			})
			pool, err := NewWorkerPool(cfg, fabric.PoolOptions{MaxPerKey: 2}, ScanOptions{Retry: &fabric.RetryPolicy{MaxAttempts: 1}})
			require.NoError(t, err)
			defer pool.CloseAll()
			sc := &client.StorageConfig{ID: "root1", Protocol: "ftp"}
			_, err = pool.GetClientContext(ctx5(t), sc)
			require.Error(t, err)
			assert.Equal(t, v.want, fabric.Classify(err), "%v", err)
			assert.Zero(t, s.count("PASS"), "no password was sent")
			c2, err2 := pool.GetClientContext(ctx5(t), sc)
			require.NoError(t, err2, "the root is not latched: the second borrow dials again")
			_ = pool.ReturnClient(c2)
			assert.Equal(t, 2, s.count("USER"))
		})
	}
}

// Every connect phase, with the wording a real server might use ("Access denied", "not logged in", "login incorrect"):
// the class is the PHASE's class, never the text's (class K2.a-K2.f).
func TestR3_K2_ServerTextNeverDecidesTheClass_EveryPhase(t *testing.T) {
	const marker = "Access denied: you are not logged in, login incorrect, invalid credentials"
	type tc struct {
		name, verb string
		reply      string
		want       fabric.ErrorClass
		pass       int // PASS commands the server must have seen
	}
	cases := []tc{
		{"AUTH_5yz", "AUTH", "534 " + marker, fabric.ClassPermanent, 0},
		{"AUTH_550", "AUTH", "550 " + marker, fabric.ClassPermanent, 0},
		{"USER_4yz", "USER", "450 " + marker, fabric.ClassTransient, 0},
		{"USER_5yz", "USER", "501 " + marker, fabric.ClassPermanent, 0},
		{"USER_530", "USER", "530 " + marker, fabric.ClassPermanent, 0},
		{"FEAT_421", "FEAT", "421 " + marker, fabric.ClassTransient, 1},
		{"TYPE_4yz", "TYPE", "451 " + marker, fabric.ClassTransient, 1},
		{"TYPE_5yz", "TYPE", "504 " + marker, fabric.ClassPermanent, 1},
		{"OPTS_4yz", "OPTS", "451 " + marker, fabric.ClassTransient, 1},
		{"PBSZ_4yz", "PBSZ", "451 " + marker, fabric.ClassTransient, 1},
		{"PBSZ_5yz", "PBSZ", "503 " + marker, fabric.ClassPermanent, 1},
		{"PROT_4yz", "PROT", "451 " + marker, fabric.ClassTransient, 1},
		{"PROT_5yz", "PROT", "534 " + marker, fabric.ClassPermanent, 1},
		{"CWD_4yz", "CWD", "450 " + marker, fabric.ClassTransient, 1},
		{"CWD_553", "CWD", "553 " + marker, fabric.ClassPermanent, 1},
		{"PWD_5yz", "PWD", "553 " + marker, fabric.ClassPermanent, 1},
		{"PWD_4yz", "PWD", "450 " + marker, fabric.ClassTransient, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newFakeServer(t)
			cfg := cfgFor(s, pinned(t, s))
			s.setHook(func(ss *session, verb, arg string) (bool, bool) {
				if verb != c.verb {
					return false, true
				}
				ss.reply("%s", c.reply)
				return true, c.reply[:3] != "421"
			})
			err := NewFTPClient(cfg).Connect(ctx5(t))
			require.Error(t, err)
			assert.Equal(t, c.want, fabric.Classify(err), "the phase decides, not the server's words: %v", err)
			assert.NotEqual(t, fabric.ClassAuth, fabric.Classify(err))
			assert.Equal(t, c.pass, s.count("PASS"))
		})
	}
	t.Run("banner_421", func(t *testing.T) {
		port, _ := silentServer(t, func(c net.Conn) { _, _ = io.WriteString(c, "421 "+marker+"\r\n") })
		cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: TLSNone, TrustedLAN: true}
		err := NewFTPClient(cfg).Connect(ctx5(t))
		require.Error(t, err)
		assert.Equal(t, fabric.ClassTransient, fabric.Classify(err), "%v", err)
	})
	t.Run("banner_554", func(t *testing.T) {
		port, _ := silentServer(t, func(c net.Conn) { _, _ = io.WriteString(c, "554 "+marker+"\r\n") })
		cfg := &Config{Host: "127.0.0.1", Port: port, Username: "u", Password: "pw", TLSMode: TLSNone, TrustedLAN: true}
		err := NewFTPClient(cfg).Connect(ctx5(t))
		require.Error(t, err)
		assert.Equal(t, fabric.ClassPermanent, fabric.Classify(err), "%v", err)
	})
}

// The server text stays visible to a human (it is in the message), it just never sits in a leaf.
func TestR3_K2_ServerTextIsStillInTheMessage(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "USER" {
			ss.reply("530 Access denied: capacity text")
			return true, true
		}
		return false, true
	})
	err := NewFTPClient(cfg).Connect(ctx5(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Access denied: capacity text")
	assert.ErrorIs(t, err, errUserRefused)
}

// A definite credential verdict at PASS stays ClassAuth (the pool latch is the guard there) and starts no back-off.
func TestR3_K2_PassCredentialVerdict_StaysAuth_NoBackoff(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	cfg.Resolver = mapResolver{"ref": "WRONG"}
	err := NewFTPClient(cfg).Connect(ctx5(t))
	require.Error(t, err)
	assert.Equal(t, fabric.ClassAuth, fabric.Classify(err))
	cfg2 := cfgFor(s, pinned(t, s))
	require.NoError(t, NewFTPClient(cfg2).Connect(ctx5(t)), "no back-off after a definite verdict: the right password is sent at once")
}

func TestR3_K2_USER530_IsNotAuth_NoPasswordWasSent(t *testing.T) {
	s := newFakeServer(t)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "USER" {
			ss.reply("530 User not allowed to log in")
			return true, true
		}
		return false, true
	})
	err := NewFTPClient(cfgFor(s, pinned(t, s))).Connect(ctx5(t))
	require.Error(t, err)
	assert.Equal(t, fabric.ClassPermanent, fabric.Classify(err))
	assert.Zero(t, s.count("PASS"))
}

// ---- G3: the login back-off ----------------------------------------------------------------------------------------

// Reviewer N17 inverted: an unanswered PASS is sent ONCE, however many times the pool is asked.
func TestR3_K2_UnansweredPASS_IsSentOnce_AcrossPoolBorrows_G3(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	s.dropNext("PASS", 100)
	pool, err := NewWorkerPool(cfg, fabric.PoolOptions{MaxPerKey: 1}, ScanOptions{})
	require.NoError(t, err)
	defer pool.CloseAll()
	sc := &client.StorageConfig{ID: "root1", Protocol: "ftp"}
	var errs []error
	for i := 0; i < 4; i++ {
		_, err := pool.GetClientContext(ctx5(t), sc)
		errs = append(errs, err)
	}
	assert.Equal(t, 1, s.count("PASS"), "the password is re-sent once per borrow after an ambiguous attempt: lockout risk (D11 one layer up)")
	assert.Equal(t, 1, s.count("USER"), "the later borrows do not even dial")
	for _, e := range errs {
		require.Error(t, e)
		assert.Equal(t, fabric.ClassPermanent, fabric.Classify(e))
	}
	for _, e := range errs[1:] {
		assert.ErrorIs(t, e, ErrLoginBackoff)
	}
}

func TestR3_K2_Backoff_CoversEveryClient_AndIsLiftedByClear(t *testing.T) {
	resetLoginBackoffs()
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	s.dropNext("PASS", 1)
	c1 := NewFTPClient(cfg)
	require.Error(t, c1.Connect(ctx5(t)))
	assert.Equal(t, 1, s.count("PASS"))
	err := c1.Connect(ctx5(t)) // the same client calls Connect again
	require.ErrorIs(t, err, ErrLoginBackoff)
	err = NewFTPClient(cfgFor(s, cfg.PinStore)).Connect(ctx5(t)) // another client
	require.ErrorIs(t, err, ErrLoginBackoff)
	assert.NotContains(t, err.Error(), "pw")
	assert.Equal(t, 1, s.count("USER"), "no socket, no USER, no PASS")
	assert.Equal(t, 1, s.wfCtrl())
	ClearLoginBackoff("127.0.0.1", s.port(), "u")
	require.NoError(t, NewFTPClient(cfgFor(s, cfg.PinStore)).Connect(ctx5(t)), "lifted by the operator")
	assert.Equal(t, 2, s.count("PASS"))
}

func TestR3_K2_Backoff_ExpiresAfterItsTTL_AndCanBeDisabled(t *testing.T) {
	resetLoginBackoffs()
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	cfg.LoginBackoff = 300 * time.Millisecond
	s.dropNext("PASS", 1)
	require.Error(t, NewFTPClient(cfg).Connect(ctx5(t)))
	require.ErrorIs(t, NewFTPClient(cfg).Connect(ctx5(t)), ErrLoginBackoff)
	time.Sleep(400 * time.Millisecond)
	require.NoError(t, NewFTPClient(cfg).Connect(ctx5(t)), "the back-off is bounded: not forever")

	s2 := newFakeServer(t)
	cfg2 := cfgFor(s2, pinned(t, s2))
	cfg2.LoginBackoff = -1
	s2.dropNext("PASS", 1)
	require.Error(t, NewFTPClient(cfg2).Connect(ctx5(t)))
	require.NoError(t, NewFTPClient(cfg2).Connect(ctx5(t)), "a negative LoginBackoff disables it")
}

// K2.i: the context ends after the password was written.
func TestR3_K2_PASSInterruptedByTheDeadline_IsAmbiguous(t *testing.T) {
	resetLoginBackoffs()
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	rch, rel := releaser(t)
	s.setHook(mute(map[string]bool{"PASS": true}, rch))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := NewFTPClient(cfg).Connect(ctx)
	require.Error(t, err)
	assert.Equal(t, 1, s.count("PASS"))
	rel()
	s.setHook(nil)
	err = NewFTPClient(cfgFor(s, cfg.PinStore)).Connect(ctx5(t))
	require.ErrorIs(t, err, ErrLoginBackoff)
	assert.Equal(t, 1, s.count("PASS"))
}

// K2.h: a PASS reply that is no credential verdict.
func TestR3_K2_PASSRejectedWithANonCredentialCode_StartsTheBackoff(t *testing.T) {
	resetLoginBackoffs()
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "PASS" {
			ss.reply("503 Bad sequence of commands")
			return true, true
		}
		return false, true
	})
	err := NewFTPClient(cfg).Connect(ctx5(t))
	require.Error(t, err)
	assert.Equal(t, fabric.ClassPermanent, fabric.Classify(err))
	require.ErrorIs(t, NewFTPClient(cfgFor(s, cfg.PinStore)).Connect(ctx5(t)), ErrLoginBackoff)
	assert.Equal(t, 1, s.count("PASS"))
}

// The context ends BEFORE the password is written: nothing was sent, so no back-off.
func TestR3_K2_ContextEndedBeforePASS_NoBackoff(t *testing.T) {
	resetLoginBackoffs()
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	rch, rel := releaser(t)
	s.setHook(mute(map[string]bool{"USER": true}, rch))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	require.Error(t, NewFTPClient(cfg).Connect(ctx))
	rel()
	s.setHook(nil)
	assert.Zero(t, s.count("PASS"))
	require.NoError(t, NewFTPClient(cfgFor(s, cfg.PinStore)).Connect(ctx5(t)))
}

func TestR3_K2_BackoffRegistry_IsBounded(t *testing.T) {
	g := &loginGuard{until: map[string]time.Time{}, now: time.Now}
	for i := 0; i < maxLoginBackoffs+50; i++ {
		g.note(fmt.Sprintf("k%d", i), time.Minute)
	}
	assert.LessOrEqual(t, len(g.until), maxLoginBackoffs)
	g.note("", time.Minute)
	assert.Zero(t, g.remaining(""))
	g.note("x", -1)
	assert.Zero(t, g.remaining("x"))
}

// NM07: an empty resolved password never reaches the network.
func TestR3_NM07_EmptyResolvedPassword_IsRefusedBeforeAnyConnection(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	cfg.Resolver = mapResolver{"ref": ""}
	err := NewFTPClient(cfg).Connect(ctx5(t))
	require.ErrorIs(t, err, ErrCredentialUnavailable)
	assert.Zero(t, s.wfCtrl(), "no connection was opened")
	assert.Zero(t, s.count("PASS"))
}
