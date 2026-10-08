package ftp

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// The login back-off (WF24 G3). A password attempt whose outcome the client cannot read - the connection died before
// the reply, the reply is not a credential verdict, the context ended after the password was written - may have been
// counted by the server (or by an intrusion-prevention system in front of it). The classification of that failure is
// permanent, which stops fabric.Retrying, but a pool or a caller that connects again would send the password again,
// once per borrow. The back-off is the memory that closes this: a process-wide, TTL-bound record keyed by
// host:port and user name, consulted by connect() BEFORE any socket is opened, so no client of the process sends the
// password again until the back-off ends (or an operator calls ClearLoginBackoff). A definite credential verdict
// (530 and friends) does not start it: that is authentication, and the pool already latches the root.

// DefaultLoginBackoff is the back-off after an ambiguous password attempt (Config.LoginBackoff 0).
const DefaultLoginBackoff = 2 * time.Minute

// maxLoginBackoffs bounds the registry; expired entries are pruned first.
const maxLoginBackoffs = 1024

// ErrLoginBackoff is returned by Connect while the login to a host and user is suspended after an ambiguous password
// attempt. No socket was opened and no password was sent.
var ErrLoginBackoff = errors.New("ftp: logins are suspended after a password attempt whose outcome is unknown")

type loginGuard struct {
	mu    sync.Mutex
	until map[string]time.Time
	now   func() time.Time // replaceable in tests
}

var loginBackoffs = &loginGuard{until: map[string]time.Time{}, now: time.Now}

func loginKeyFor(host string, port int, user string) string {
	return HostPort(host, port) + "\x00" + strings.ToLower(user)
}

func (g *loginGuard) note(key string, d time.Duration) {
	if key == "" || d < 0 {
		return
	}
	if d == 0 {
		d = DefaultLoginBackoff
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if len(g.until) >= maxLoginBackoffs {
		for k, t := range g.until {
			if !t.After(now) {
				delete(g.until, k)
			}
		}
	}
	if len(g.until) >= maxLoginBackoffs { // still full of live entries: a bounded registry beats an unbounded one; the new key wins
		for k := range g.until {
			delete(g.until, k)
			break
		}
	}
	g.until[key] = now.Add(d)
}

// remaining is how long the login to key is still suspended (0: not suspended).
func (g *loginGuard) remaining(key string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	t, ok := g.until[key]
	if !ok {
		return 0
	}
	r := t.Sub(g.now())
	if r <= 0 {
		delete(g.until, key)
		return 0
	}
	return r
}

func (g *loginGuard) clear(key string) {
	g.mu.Lock()
	delete(g.until, key)
	g.mu.Unlock()
}

func noteAmbiguousLogin(key string, d time.Duration) { loginBackoffs.note(key, d) }

// ClearLoginBackoff lifts the login back-off of one host and user (the operator knows the password attempt did not
// count, or has waited out the server's lockout).
func ClearLoginBackoff(host string, port int, username string) {
	loginBackoffs.clear(loginKeyFor(host, port, username))
}

// loginBackoffError is what connect returns while a back-off runs.
func loginBackoffError(host string, port int, rem time.Duration) error {
	return fmt.Errorf("%w: %s for another %s (a retry would send the password again; ftp.ClearLoginBackoff lifts it)",
		ErrLoginBackoff, HostPort(host, port), rem.Round(time.Second))
}
