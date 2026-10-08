// Package sftp implements a READ-ORIENTED filesystem client for the SFTP protocol (SSH File Transfer).
//
// Properties (WP-12 PA-05, evidence under specs/001-full-project-audit-remediation/evidence/wp12/sftp/). Each one is
// pinned by a test that fails when the property is removed; the measured limits are listed in docs/testing/sftp-client.md.
//
//   - Read only by construction: every mutating method of client.Client returns ErrReadOnly and no write code
//     path to the server exists in this package.
//   - Host key verification by PIN per host (hostkey.go). A host without a pin, or whose key changed, is refused.
//     Trust on first use exists only as the explicit owner confirmation step Pin().
//   - Credentials come from a credential_ref resolved at connect time (credential.go). A key or a password (offered
//     as "password" and, for servers that only offer it, "keyboard-interactive"); the secret never appears in logs,
//     errors, GetConfig or String. Zeroing is best effort: a Go string cannot be wiped, see the guide.
//   - Pipelined reads: pkg/sftp issues a window of concurrent read requests per file (MaxConcurrentRequests); ReadFile
//     and ReadRange (bounded) both expose that path through WriteTo.
//   - ListDirectory returns the attributes the server sent with each entry. An absent or epoch modification time is
//     the zero time.Time. SFTP v3 cannot say "size unknown": an absent size reads as 0.
//   - Path confinement to Config.Root: lexical (".." is refused, no separator is rewritten) plus a server side RealPath
//     check against symlink escapes that FAILS CLOSED (a RealPath error other than "does not exist" refuses the call).
//     The check and the following open are two requests: a symlink swapped in between is a TOCTOU window this client
//     cannot close.
//   - Every call into pkg/sftp is bounded: a call whose context ends gets CancelGrace to finish on its own, then the
//     ssh connection is closed (which ends the call) and the call returns the context error. Because one client holds
//     one connection, that close also fails the other calls and streams that were using it; they see a lost connection
//     and (for the request/response calls) are re-dialled once, single-flight. An SSH keepalive closes a connection
//     whose peer stopped answering. Connect honours its context through the SSH handshake, the sftp subsystem start and
//     the root check.
//   - Every reply frame is parsed completely before pkg/sftp reads it (frame.go): a malformed reply ends the
//     connection and fails with ErrMalformedReply instead of panicking inside pkg/sftp (including its own worker
//     goroutines, which no recover() here could reach).
//   - Bounded retry with exponential backoff on TRANSIENT errors only (network timeouts, resets, a lost connection).
//     A server status reply (including SSH_FX_EOF to a stat or open) is a reply, not a lost connection. Authentication
//     failures, host key refusals, missing credentials, malformed replies, not found and permission denied are never
//     retried.
package sftp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	gosftp "github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"digital.vasic.filesystem/pkg/client"
)

// ErrReadOnly is returned by every mutating operation.
var ErrReadOnly = errors.New("sftp: client is read-only")

// ErrPathEscape is returned for a path that leaves the configured root.
var ErrPathEscape = errors.New("sftp: path escapes the configured root")

// ErrNotConnected is returned when an operation needs a connection that does not exist.
var ErrNotConnected = errors.New("sftp: not connected")

// AuthError reports that the server rejected the credentials. It is never retried.
type AuthError struct {
	User string
	Host string
	Err  error
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("sftp: authentication failed for user %q on %s: %v", e.User, e.Host, e.Err)
}
func (e *AuthError) Unwrap() error { return e.Err }

// serverStatus wraps an io.EOF that pkg/sftp produced from a STATUS reply (SSH_FX_EOF) of a request/response call.
// It hides io.EOF from errors.Is: a reply is not a transport failure and must not be retried or tear the connection down.
type serverStatus struct{ err error }

func (e *serverStatus) Error() string { return "sftp: server replied with status: " + e.err.Error() }

// Defaults.
const (
	DefaultPort                  = 22
	DefaultDialTimeout           = 30 * time.Second
	DefaultMaxRetries            = 3
	DefaultRetryBase             = 200 * time.Millisecond
	DefaultMaxConcurrentRequests = 64
	DefaultMaxPacket             = 32768
	DefaultKeepAliveInterval     = 30 * time.Second
	DefaultKeepAliveTimeout      = 15 * time.Second
	DefaultCancelGrace           = time.Second
	DefaultCloseTimeout          = 10 * time.Second
	DefaultMaxDirEntries         = 1_000_000
	maxRetryDelay                = 2 * time.Second
	maxReadWindow                = 4 << 20
)

// Config is the connection configuration. It contains NO secret: the secret is behind CredentialRef.
type Config struct {
	Host          string
	Port          int
	Username      string
	CredentialRef string
	// Root confines every path. Empty means "/". Paths are given to the client relative to it.
	Root string
	// Resolver resolves CredentialRef; nil means DefaultCredentialResolver.
	Resolver CredentialResolver
	// PinStore holds the host key pins. Required: without it every connection is refused.
	PinStore PinStore
	// DialTimeout bounds the TCP connect, the SSH handshake, the sftp subsystem start and the root check.
	DialTimeout time.Duration
	// MaxRetries is the number of retries after the first attempt; 0 selects DefaultMaxRetries, negative disables retry.
	MaxRetries int
	// RetryBase is the first backoff delay (doubled per retry, capped at 2s); 0 selects DefaultRetryBase.
	RetryBase time.Duration
	// MaxConcurrentRequests is the pipelining window per file; 0 selects DefaultMaxConcurrentRequests.
	MaxConcurrentRequests int
	// MaxPacket is the sftp packet size; 0 selects DefaultMaxPacket.
	MaxPacket int
	// SkipSymlinkCheck turns off the RealPath containment check (one extra round trip per open and listing).
	SkipSymlinkCheck bool
	// KeepAliveInterval is the period of the SSH keepalive request; 0 selects DefaultKeepAliveInterval, negative disables it.
	KeepAliveInterval time.Duration
	// KeepAliveTimeout is how long a keepalive may stay unanswered before the connection is closed; 0 selects
	// DefaultKeepAliveTimeout.
	KeepAliveTimeout time.Duration
	// CancelGrace is how long a call whose context ended may still finish on its own before the connection is closed to end
	// it; 0 selects DefaultCancelGrace, negative closes at once.
	CancelGrace time.Duration
	// CloseTimeout bounds closing a file (the CLOSE request) on a stalled server; 0 selects DefaultCloseTimeout.
	CloseTimeout time.Duration
	// MaxDirEntries bounds the entries one listing may deliver (concurrent listings on one client share the budget);
	// 0 selects DefaultMaxDirEntries, negative disables the limit. Exceeding it fails with ErrDirTooLarge.
	MaxDirEntries int
}

// PublicConfig is what GetConfig returns: the configuration without any secret or store handle.
type PublicConfig struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	CredentialRef string `json:"credential_ref"`
	Root          string `json:"root"`
	ReadOnly      bool   `json:"read_only"`
}

// conn is one ssh connection with its sftp session. It is created by dialConn, owned by Client.cur (or by a TestConnection
// probe) and closed exactly once.
type conn struct {
	ssh      *ssh.Client
	sftp     *gosftp.Client
	rootReal string
	done     chan struct{} // closed by close()
	dead     chan struct{} // closed when the ssh connection has ended, whoever ended it
	once     sync.Once
	probe    func() bool // tests: replaces the keepalive round trip of alive(); nil in production

	fmu   sync.Mutex
	fault error // first protocol fault (malformed reply, oversize listing); the connection is closed with it

	lmu        sync.Mutex
	lists      int // listings in flight
	seen       int // NAME entries received while listings were in flight
	maxEntries int // 0 = unlimited
}

func (cn *conn) isDead() bool {
	select {
	case <-cn.dead:
		return true
	default:
		return false
	}
}

// probeTimeout bounds alive() (a variable so that a test can shorten it).
var probeTimeout = 3 * time.Second

// alive reports whether the ssh connection still answers. It exists because pkg/sftp renders two different things as io.EOF: a
// STATUS reply SSH_FX_EOF (the connection is fine) and the write error of a channel that is already closed (the connection is
// gone). A keepalive round trip tells them apart: a dead transport fails it at once, a live server answers it.
func (cn *conn) alive() bool {
	if cn.probe != nil {
		return cn.probe()
	}
	if cn.isDead() {
		return false
	}
	res := make(chan error, 1)
	go func() { _, _, err := cn.ssh.SendRequest("keepalive@openssh.com", true, nil); res <- err }()
	t := time.NewTimer(probeTimeout)
	defer t.Stop()
	select {
	case err := <-res:
		return err == nil
	case <-t.C:
		return false
	case <-cn.dead:
		return false
	}
}

// close ends the connection. It must not be called from the goroutine that reads the sftp channel (pkg/sftp waits for it).
func (cn *conn) close() {
	cn.once.Do(func() {
		close(cn.done)
		_ = cn.ssh.Close() // first: it ends the reader goroutine pkg/sftp's Close waits for
		if cn.sftp != nil {
			_ = cn.sftp.Close()
		}
	})
}

// setFault records the first protocol fault and ends the connection without waiting for the reader (it may be the caller).
func (cn *conn) setFault(err error) {
	cn.fmu.Lock()
	if cn.fault == nil {
		cn.fault = err
	}
	cn.fmu.Unlock()
	_ = cn.ssh.Close()
}

func (cn *conn) faultErr() error {
	cn.fmu.Lock()
	defer cn.fmu.Unlock()
	return cn.fault
}

func (cn *conn) beginList() {
	cn.lmu.Lock()
	if cn.lists == 0 {
		cn.seen = 0
	}
	cn.lists++
	cn.lmu.Unlock()
}

func (cn *conn) endList() {
	cn.lmu.Lock()
	cn.lists--
	cn.lmu.Unlock()
}

// countNames is called by the frame reader for every NAME reply.
func (cn *conn) countNames(n int) error {
	cn.lmu.Lock()
	defer cn.lmu.Unlock()
	if cn.lists == 0 {
		return nil
	}
	cn.seen += n
	if cn.maxEntries > 0 && cn.seen > cn.maxEntries {
		return fmt.Errorf("%w: more than %d entries", ErrDirTooLarge, cn.maxEntries)
	}
	return nil
}

// protect runs fn and turns a panic of the calling goroutine into a protocol fault. The wire validator (frame.go) is the
// boundary that covers pkg/sftp's own goroutines; this is the second layer for everything else.
func protect(cn *conn, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			cn.setFault(fmt.Errorf("%w: internal failure while reading a reply: %v", ErrMalformedReply, r))
			err = cn.faultErr()
		}
	}()
	return fn()
}

// Client implements client.Client and client.SeekableClient for SFTP, read only.
type Client struct {
	cfg Config

	mu     sync.Mutex
	cur    *conn
	state  connState
	flight *dialFlight

	backoffHook func(time.Duration) // tests: observes every backoff delay before it is waited; nil in production
	listHook    func(*conn)         // tests: runs after a listing succeeded, before the connection is checked; nil in production
}

// dialFlight is the single in-flight implicit re-dial that concurrent callers wait for.
type dialFlight struct {
	done chan struct{}
	err  error
}

type connState int

const (
	stateNever connState = iota
	stateUp
	stateLost // the connection broke; a retry may re-dial
	stateDown // the caller disconnected; never re-dial implicitly
)

var (
	_ client.Client         = (*Client)(nil)
	_ client.SeekableClient = (*Client)(nil)
)

// NewSFTPClient creates an SFTP client. It does not connect.
func NewSFTPClient(cfg *Config) *Client {
	c := &Client{}
	if cfg != nil {
		c.cfg = *cfg
	}
	if c.cfg.Port == 0 {
		c.cfg.Port = DefaultPort
	}
	return c
}

func (c *Client) hostport() string { return HostPort(c.cfg.Host, c.cfg.Port) }

func (c *Client) retries() int {
	switch {
	case c.cfg.MaxRetries < 0:
		return 0
	case c.cfg.MaxRetries == 0:
		return DefaultMaxRetries
	}
	return c.cfg.MaxRetries
}

func (c *Client) retryBase() time.Duration {
	if c.cfg.RetryBase <= 0 {
		return DefaultRetryBase
	}
	return c.cfg.RetryBase
}

func (c *Client) cancelGrace() time.Duration {
	switch d := c.cfg.CancelGrace; {
	case d < 0:
		return 0
	case d == 0:
		return DefaultCancelGrace
	default:
		return d
	}
}

func (c *Client) closeTimeout() time.Duration {
	if c.cfg.CloseTimeout <= 0 {
		return DefaultCloseTimeout
	}
	return c.cfg.CloseTimeout
}

func (c *Client) maxDirEntries() int {
	switch n := c.cfg.MaxDirEntries; {
	case n < 0:
		return 0
	case n == 0:
		return DefaultMaxDirEntries
	default:
		return n
	}
}

// ---------------------------------------------------------------------------------------------------------
// connection

// kbdAnswer answers keyboard-interactive prompts with the password: only echo-off prompts, at most 3 rounds of at most 4
// questions. An echoed prompt (a user name, a one-time code) is refused rather than answered with the password.
func kbdAnswer(pw string) ssh.KeyboardInteractiveChallenge {
	rounds := 0
	return func(_, _ string, questions []string, echos []bool) ([]string, error) {
		if rounds++; rounds > 3 || len(questions) > 4 {
			return nil, errors.New("sftp: keyboard-interactive asks for more than a password")
		}
		answers := make([]string, len(questions))
		for i := range questions {
			if i < len(echos) && echos[i] {
				return nil, errors.New("sftp: keyboard-interactive asks for echoed input")
			}
			answers[i] = pw
		}
		return answers, nil
	}
}

func (c *Client) authMethods(ctx context.Context) ([]ssh.AuthMethod, error) {
	if strings.TrimSpace(c.cfg.CredentialRef) == "" {
		return nil, fmt.Errorf("%w: no credential_ref configured", ErrCredentialUnavailable)
	}
	res := c.cfg.Resolver
	if res == nil {
		res = DefaultCredentialResolver
	}
	cred, err := res.Resolve(ctx, c.cfg.CredentialRef)
	if err != nil {
		if errors.Is(err, ErrCredentialUnavailable) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %q: %v", ErrCredentialUnavailable, c.cfg.CredentialRef, err)
	}
	defer cred.wipe()
	if cred.Empty() {
		return nil, fmt.Errorf("%w: %q resolved to an empty credential", ErrCredentialUnavailable, c.cfg.CredentialRef)
	}
	var methods []ssh.AuthMethod
	if len(cred.PrivateKeyPEM) > 0 {
		var signer ssh.Signer
		var perr error
		if len(cred.Passphrase) > 0 {
			signer, perr = ssh.ParsePrivateKeyWithPassphrase(cred.PrivateKeyPEM, cred.Passphrase)
		} else {
			signer, perr = ssh.ParsePrivateKey(cred.PrivateKeyPEM)
		}
		if perr != nil {
			// Do not wrap perr: some parse errors quote key material fragments.
			return nil, fmt.Errorf("%w: %q: private key could not be parsed", ErrCredentialUnavailable, c.cfg.CredentialRef)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if cred.Password != "" {
		pw := cred.Password
		methods = append(methods, ssh.Password(pw), ssh.KeyboardInteractive(kbdAnswer(pw)))
	}
	return methods, nil
}

// openSFTP starts the sftp subsystem on sshc and puts the reply validator between the channel and pkg/sftp.
func (c *Client) openSFTP(sshc *ssh.Client, cn *conn) (*gosftp.Client, error) {
	s, err := sshc.NewSession()
	if err != nil {
		return nil, err
	}
	pw, err := s.StdinPipe()
	if err != nil {
		return nil, err
	}
	pr, err := s.StdoutPipe()
	if err != nil {
		return nil, err
	}
	perr, err := s.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := s.RequestSubsystem("sftp"); err != nil {
		return nil, err
	}
	go func() { _, _ = io.Copy(io.Discard, perr) }()
	opts := []gosftp.ClientOption{
		gosftp.MaxPacket(orInt(c.cfg.MaxPacket, DefaultMaxPacket)),
		gosftp.MaxConcurrentRequestsPerFile(orInt(c.cfg.MaxConcurrentRequests, DefaultMaxConcurrentRequests)),
		gosftp.UseConcurrentReads(true),
	}
	return gosftp.NewClientPipe(newFrameReader(pr, cn.countNames, cn.setFault), pw, opts...)
}

// dialConn establishes an ssh connection and its sftp session. It installs nothing: the caller decides who owns it.
// ctx and DialTimeout stay in force until the sftp session is up and the root has been resolved.
func (c *Client) dialConn(ctx context.Context) (*conn, error) {
	if c.cfg.PinStore == nil {
		return nil, ErrNoPinStore
	}
	if strings.TrimSpace(c.cfg.Host) == "" || strings.TrimSpace(c.cfg.Username) == "" {
		return nil, errors.New("sftp: host and username are required")
	}
	hp := c.hostport()
	pins, err := c.cfg.PinStore.Lookup(hp)
	if err != nil {
		return nil, err
	}
	auth, err := c.authMethods(ctx)
	if err != nil {
		return nil, err
	}
	timeout := c.cfg.DialTimeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	var refusal error
	scfg := &ssh.ClientConfig{
		User:            c.cfg.Username,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback(hp, pins, &refusal),
		Timeout:         timeout,
	}
	if algs := hostKeyAlgorithms(pins); len(algs) > 0 {
		scfg.HostKeyAlgorithms = algs
	}
	d := net.Dialer{Timeout: timeout}
	nc, err := d.DialContext(ctx, "tcp", hp)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("sftp: dial %s: %w", hp, err)
	}
	// Bound and make cancellable everything up to a usable sftp session: closing the TCP connection ends any blocked read.
	_ = nc.SetDeadline(time.Now().Add(timeout))
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	sconn, chans, reqs, err := ssh.NewClientConn(nc, hp, scfg)
	if err != nil {
		stop()
		_ = nc.Close()
		if refusal != nil {
			return nil, refusal
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if isAuthFailure(err) {
			return nil, &AuthError{User: c.cfg.Username, Host: hp, Err: err}
		}
		return nil, fmt.Errorf("sftp: ssh handshake with %s: %w", hp, err)
	}
	sshc := ssh.NewClient(sconn, chans, reqs)
	cn := &conn{ssh: sshc, done: make(chan struct{}), dead: make(chan struct{}), rootReal: "/", maxEntries: c.maxDirEntries()}
	go func() { _ = sshc.Wait(); close(cn.dead) }()
	fail := func(err error) (*conn, error) {
		stop()
		cn.close()
		if f := cn.faultErr(); f != nil {
			return nil, f
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	var sc *gosftp.Client
	if err := protect(cn, func() (e error) { sc, e = c.openSFTP(sshc, cn); return e }); err != nil {
		return fail(fmt.Errorf("sftp: open sftp subsystem on %s: %w", hp, err))
	}
	cn.sftp = sc
	if root := c.root(); !c.cfg.SkipSymlinkCheck && root != "/" {
		var rr string
		if err := protect(cn, func() (e error) { rr, e = sc.RealPath(root); return e }); err != nil {
			return fail(fmt.Errorf("sftp: root %q on %s: %w", root, hp, err))
		}
		cn.rootReal = rr
	}
	if !stop() {
		// cancellation fired during the setup: the connection is closed under us
		cn.close()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
	}
	_ = nc.SetDeadline(time.Time{})
	c.keepalive(cn)
	return cn, nil
}

// isAuthFailure recognises a rejected login in the error x/crypto/ssh returns (it has no typed error for it). Two shapes:
// the usual "unable to authenticate", and the one x/crypto produces when a server advertises keyboard-interactive but
// answers its start with a plain SSH_MSG_USERAUTH_FAILURE (51) instead of a prompt (OpenSSH without a PAM/BSD-auth device) -
// found against a real OpenSSH after a wrong password, where it surfaced as a protocol error instead of AuthError.
func isAuthFailure(err error) bool {
	m := err.Error()
	return strings.Contains(m, "unable to authenticate") || strings.Contains(m, "unexpected message type 51 (expected 60)")
}

func orInt(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

// keepalive closes cn when the peer stops answering SSH keepalive requests (a half-open TCP connection is otherwise only
// noticed after the kernel gives up). It ends with the connection.
func (c *Client) keepalive(cn *conn) {
	iv := c.cfg.KeepAliveInterval
	if iv < 0 {
		return
	}
	if iv == 0 {
		iv = DefaultKeepAliveInterval
	}
	to := c.cfg.KeepAliveTimeout
	if to <= 0 {
		to = DefaultKeepAliveTimeout
	}
	go func() {
		t := time.NewTicker(iv)
		defer t.Stop()
		for {
			select {
			case <-cn.done:
				return
			case <-t.C:
			}
			res := make(chan error, 1)
			go func() { _, _, err := cn.ssh.SendRequest("keepalive@openssh.com", true, nil); res <- err }()
			tm := time.NewTimer(to)
			select {
			case err := <-res:
				tm.Stop()
				if err != nil {
					c.drop(cn)
					return
				}
			case <-tm.C:
				c.drop(cn)
				return
			case <-cn.done:
				tm.Stop()
				return
			}
		}
	}()
}

// drop ends cn. If it is the client's current connection the client becomes "lost" (a later call may re-dial).
func (c *Client) drop(cn *conn) {
	c.mu.Lock()
	if c.cur == cn {
		c.cur = nil
		if c.state == stateUp {
			c.state = stateLost
		}
	}
	c.mu.Unlock()
	cn.close()
}

// Connect establishes the connection, retrying transient failures a bounded number of times.
func (c *Client) Connect(ctx context.Context) error {
	err := c.retry(ctx, func() error {
		cn, err := c.dialConn(ctx)
		if err != nil {
			return err
		}
		c.mu.Lock()
		old := c.cur
		c.cur, c.state = cn, stateUp
		c.mu.Unlock()
		if old != nil {
			old.close()
		}
		return nil
	})
	if err != nil {
		c.mu.Lock()
		if c.state == stateNever {
			c.state = stateDown
		}
		c.mu.Unlock()
	}
	return err
}

// Disconnect closes the connection. The client does not reconnect implicitly afterwards, not even a re-dial that was
// already in flight.
func (c *Client) Disconnect(_ context.Context) error {
	c.mu.Lock()
	cn := c.cur
	c.cur = nil
	c.state = stateDown
	c.mu.Unlock()
	if cn != nil {
		cn.close()
	}
	return nil
}

// IsConnected reports whether a connection is currently held.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == stateUp && c.cur != nil
}

// checkRoot is the TestConnection probe.
func (c *Client) checkRoot(sc *gosftp.Client, _ *conn) error {
	fi, err := sc.Stat(c.root())
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("sftp: root %q is not a directory", c.root())
	}
	return nil
}

// TestConnection verifies that the server is reachable, the host key is pinned, the credentials work and the root exists.
// A client the caller has connected (also one whose connection was lost) is tested on its own connection, which stays
// connected. A client that is not connected is tested on a connection of its own that is closed afterwards; the client's
// state is not changed.
func (c *Client) TestConnection(ctx context.Context) error {
	c.mu.Lock()
	st := c.state
	c.mu.Unlock()
	if st == stateUp || st == stateLost {
		return c.with(ctx, c.checkRoot)
	}
	var cn *conn
	if err := c.retry(ctx, func() (err error) { cn, err = c.dialConn(ctx); return err }); err != nil {
		return err
	}
	defer cn.close()
	return c.run(ctx, cn, func() error { return c.checkRoot(cn.sftp, cn) })
}

// ---------------------------------------------------------------------------------------------------------
// retry

// retry runs fn, retrying transient errors up to the configured bound with exponential backoff.
func (c *Client) retry(ctx context.Context, fn func() error) error {
	delay := c.retryBase()
	var err error
	for attempt := 0; ; attempt++ {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		err = fn()
		if err == nil || !IsTransient(err) || ctx.Err() != nil || attempt >= c.retries() {
			return err
		}
		if c.backoffHook != nil {
			c.backoffHook(delay)
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		if delay *= 2; delay > maxRetryDelay {
			delay = maxRetryDelay
		}
	}
}

// IsTransient classifies an error as worth retrying: network timeouts, resets, refused connections, a lost sftp
// connection, an unexpected EOF. Authentication failures, host key refusals, missing credentials, malformed replies, path
// refusals, not found, permission denied and context cancellation are NOT transient. Every connection loss is transient
// (isConnectionLoss implies IsTransient).
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	var (
		unk  *UnknownHostKeyError
		mis  *HostKeyMismatchError
		auth *AuthError
	)
	switch {
	case errors.As(err, &unk), errors.As(err, &mis), errors.As(err, &auth),
		errors.Is(err, ErrCredentialUnavailable), errors.Is(err, ErrNoPinStore), errors.Is(err, ErrReadOnly),
		errors.Is(err, ErrPathEscape), errors.Is(err, ErrNotConnected), errors.Is(err, ErrMalformedReply), errors.Is(err, ErrDirTooLarge),
		errors.Is(err, os.ErrNotExist), errors.Is(err, os.ErrPermission), errors.Is(err, os.ErrExist),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return false
	}
	if isConnectionLoss(err) {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNREFUSED)
}

// isConnectionLoss reports a failure of the transport underneath the sftp session. A server STATUS reply is not one: pkg/sftp
// maps SSH_FX_EOF to io.EOF, which is why io.EOF is not classified here by its value. (The loss of a live connection surfaces as
// ErrSSHFxConnectionLost / ErrSSHFxNoConnection, or - for the write error of an already closed channel - also as io.EOF; run and
// file tell that case from a reply by asking the connection, see conn.alive.)
func isConnectionLoss(err error) bool {
	if errors.Is(err, gosftp.ErrSSHFxConnectionLost) || errors.Is(err, gosftp.ErrSSHFxNoConnection) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// acquire returns the live connection. A lost connection is re-dialled by exactly one caller (single flight); the others
// wait for it. A client the caller disconnected, or that never connected, is not re-dialled.
func (c *Client) acquire(ctx context.Context) (*conn, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		switch c.state {
		case stateUp:
			cn := c.cur
			c.mu.Unlock()
			if cn == nil {
				return nil, ErrNotConnected
			}
			return cn, nil
		case stateLost:
			if f := c.flight; f != nil {
				c.mu.Unlock()
				select {
				case <-f.done:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				if f.err != nil && !isCtxErr(f.err) {
					return nil, f.err
				}
				continue
			}
			f := &dialFlight{done: make(chan struct{})}
			c.flight = f
			c.mu.Unlock()

			cn, err := c.dialConn(ctx)

			c.mu.Lock()
			c.flight = nil
			reuse := false
			switch {
			case err != nil:
			case c.state != stateLost:
				// the state changed while we dialled. The caller disconnected: the new connection must not come back (the next
				// turn of the loop answers ErrNotConnected). Or an explicit Connect installed one: the next turn uses that one.
				cn.close()
				cn, reuse = nil, true
			default:
				c.cur, c.state = cn, stateUp
			}
			c.mu.Unlock()
			f.err = err
			close(f.done)
			if reuse {
				continue
			}
			return cn, err
		default:
			c.mu.Unlock()
			return nil, ErrNotConnected
		}
	}
}

// guard bounds one blocking call into pkg/sftp by ctx: once ctx ends the call gets CancelGrace to finish by itself, then
// cn is closed, which makes the call return. The returned function must be called when the call has returned.
func (c *Client) guard(ctx context.Context, cn *conn) func() {
	var (
		mu       sync.Mutex
		tm       *time.Timer
		released bool
	)
	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if released {
			return
		}
		g := c.cancelGrace()
		if g == 0 {
			go c.drop(cn)
			return
		}
		tm = time.AfterFunc(g, func() { c.drop(cn) })
	})
	return func() {
		mu.Lock()
		released = true
		if tm != nil {
			tm.Stop()
		}
		mu.Unlock()
		stop()
	}
}

// run executes one blocking request/response call on cn under the cancellation guard and the panic boundary and
// classifies its error.
func (c *Client) run(ctx context.Context, cn *conn, fn func() error) error {
	rel := c.guard(ctx, cn)
	err := protect(cn, fn)
	rel()
	if err == nil {
		return nil
	}
	if f := cn.faultErr(); f != nil {
		c.drop(cn)
		return f
	}
	if cerr := ctx.Err(); cerr != nil && (isConnectionLoss(err) || isCtxErr(err)) {
		c.drop(cn)
		return cerr
	}
	if isConnectionLoss(err) {
		c.drop(cn)
		return err
	}
	if errors.Is(err, io.EOF) {
		// pkg/sftp renders a STATUS reply SSH_FX_EOF and the write error of a closed channel both as io.EOF
		if cn.alive() {
			return &serverStatus{err: err}
		}
		c.drop(cn)
		return fmt.Errorf("%w: %v", gosftp.ErrSSHFxConnectionLost, err)
	}
	return err
}

// with runs op against the live sftp client, re-dialling a lost connection (single flight) while the retry budget lasts.
func (c *Client) with(ctx context.Context, op func(*gosftp.Client, *conn) error) error {
	return c.retry(ctx, func() error {
		cn, err := c.acquire(ctx)
		if err != nil {
			return err
		}
		return c.run(ctx, cn, func() error { return op(cn.sftp, cn) })
	})
}

// ---------------------------------------------------------------------------------------------------------
// path confinement

// root is the configured confinement root as a clean POSIX path. Paths are opaque: nothing is rewritten, a backslash is an
// ordinary name byte on a POSIX server.
func (c *Client) root() string {
	r := strings.TrimSpace(c.cfg.Root)
	if r == "" {
		return "/"
	}
	return path.Clean(r)
}

// confine maps a caller path to (logical, remote). logical is the root-relative absolute form ("/a/b"),
// remote is the server path (root joined with logical). A path that climbs above the root with ".." is refused,
// not silently clamped.
func (c *Client) confine(p string) (logical, remote string, err error) {
	if strings.ContainsRune(p, 0) {
		return "", "", fmt.Errorf("%w: NUL byte in path", ErrPathEscape)
	}
	var segs []string
	for _, s := range strings.Split(p, "/") {
		switch s {
		case "", ".":
		case "..":
			if len(segs) == 0 {
				return "", "", fmt.Errorf("%w: %q", ErrPathEscape, p)
			}
			segs = segs[:len(segs)-1]
		default:
			segs = append(segs, s)
		}
	}
	logical = "/" + strings.Join(segs, "/")
	return logical, path.Join(c.root(), logical), nil
}

func within(root, p string) bool {
	if root == "/" {
		return true
	}
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}

// checkWithin verifies on the server that remote (after symlink resolution) is still inside the root. It fails CLOSED:
// only "does not exist" lets the operation continue (the operation itself then reports it); any other RealPath error, and
// an unknown resolved root, refuse the call.
func (c *Client) checkWithin(sc *gosftp.Client, cn *conn, remote string) error {
	if c.cfg.SkipSymlinkCheck {
		return nil
	}
	rootReal := cn.rootReal
	if rootReal == "" {
		return fmt.Errorf("%w: the resolved root is unknown", ErrPathEscape)
	}
	if rootReal == "/" {
		return nil
	}
	real, err := sc.RealPath(remote)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return fmt.Errorf("sftp: cannot verify that %q stays inside the root: %w", remote, err)
	}
	if !within(rootReal, real) {
		return fmt.Errorf("%w: %q resolves outside the root", ErrPathEscape, remote)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------
// reads

// ctxWriter makes io.Copy / WriteTo honour cancellation.
type ctxWriter struct {
	ctx context.Context
	w   io.Writer
}

func (cw ctxWriter) Write(p []byte) (int, error) {
	if err := cw.ctx.Err(); err != nil {
		return 0, err
	}
	return cw.w.Write(p)
}

// file wraps an open remote file. Every call into pkg/sftp runs under the cancellation guard and the panic boundary;
// WriteTo keeps the pipelined read path of pkg/sftp. A file whose context ends is closed (bounded by CloseTimeout).
type file struct {
	c    *Client
	cn   *conn
	ctx  context.Context
	f    *gosftp.File
	smu  sync.Mutex // guards stop: the AfterFunc below may run (and call Close) before newFile has stored it
	stop func() bool
	once sync.Once
}

func (c *Client) newFile(ctx context.Context, cn *conn, f *gosftp.File) *file {
	fl := &file{c: c, cn: cn, ctx: ctx, f: f}
	fl.smu.Lock()
	fl.stop = context.AfterFunc(ctx, func() { _ = fl.Close() })
	fl.smu.Unlock()
	return fl
}

// call runs one blocking call on the file.
func (fl *file) call(fn func() error) error {
	rel := fl.c.guard(fl.ctx, fl.cn)
	err := protect(fl.cn, fn)
	rel()
	if err == nil || err == io.EOF {
		return err
	}
	if f := fl.cn.faultErr(); f != nil {
		fl.c.drop(fl.cn)
		return f
	}
	if cerr := fl.ctx.Err(); cerr != nil {
		return cerr
	}
	if isConnectionLoss(err) {
		fl.c.drop(fl.cn)
	}
	return err
}

func (fl *file) Read(p []byte) (n int, err error) {
	if err := fl.ctx.Err(); err != nil {
		return 0, err
	}
	err = fl.call(func() (e error) { n, e = fl.f.Read(p); return e })
	if err == io.EOF && !fl.cn.alive() {
		// an EOF from a dead connection is a truncated file, not the end of it
		fl.c.drop(fl.cn)
		return n, fmt.Errorf("%w: %v", gosftp.ErrSSHFxConnectionLost, err)
	}
	return n, err
}

// WriteTo is the pipelined path: pkg/sftp keeps a window of concurrent read requests in flight.
func (fl *file) WriteTo(w io.Writer) (n int64, err error) {
	if err := fl.ctx.Err(); err != nil {
		return 0, err
	}
	err = fl.call(func() (e error) { n, e = fl.f.WriteTo(ctxWriter{ctx: fl.ctx, w: w}); return e })
	if (err == nil || err == io.EOF) && !fl.cn.alive() {
		// pkg/sftp maps a closed channel (io.EOF) to a clean end of file: a copy that ended on a dead connection is truncated
		fl.c.drop(fl.cn)
		return n, fmt.Errorf("%w: connection ended during the copy", gosftp.ErrSSHFxConnectionLost)
	}
	return n, err
}

func (fl *file) Seek(off int64, whence int) (pos int64, err error) {
	if err := fl.ctx.Err(); err != nil {
		return 0, err
	}
	err = fl.call(func() (e error) { pos, e = fl.f.Seek(off, whence); return e })
	return pos, err
}

// Close closes the remote file. On a stalled server the CLOSE request cannot hang the caller: after CloseTimeout the
// connection is closed.
func (fl *file) Close() error {
	var err error
	fl.once.Do(func() {
		fl.smu.Lock()
		stop := fl.stop
		fl.smu.Unlock()
		stop()
		t := time.AfterFunc(fl.c.closeTimeout(), func() { fl.c.drop(fl.cn) })
		err = protect(fl.cn, fl.f.Close)
		t.Stop()
		if errors.Is(err, os.ErrClosed) || errors.Is(err, gosftp.ErrSSHFxConnectionLost) || errors.Is(err, gosftp.ErrSSHFxNoConnection) {
			err = nil // the handle died with its connection
		}
	})
	return err
}

func (c *Client) open(ctx context.Context, p string) (*file, error) {
	_, remote, err := c.confine(p)
	if err != nil {
		return nil, err
	}
	var out *file
	err = c.with(ctx, func(sc *gosftp.Client, cn *conn) error {
		if err := c.checkWithin(sc, cn, remote); err != nil {
			return err
		}
		f, err := sc.Open(remote)
		if err != nil {
			return err
		}
		out = c.newFile(ctx, cn, f)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sftp: open %s: %w", p, err)
	}
	return out, nil
}

// ReadFile opens a file for sequential reading. io.Copy of the result uses the pipelined WriteTo path.
func (c *Client) ReadFile(ctx context.Context, p string) (io.ReadCloser, error) {
	f, err := c.open(ctx, p)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// OpenSeekable opens a file with random access (HTTP Range serving).
func (c *Client) OpenSeekable(ctx context.Context, p string) (client.ReadSeekCloser, error) {
	f, err := c.open(ctx, p)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// ranged is a bounded view of an open file. Its WriteTo reads in large windows, which pkg/sftp serves with its pipelined
// concurrent read path; io.Copy therefore uses it (the plain io.LimitReader would hide WriteTo).
type ranged struct {
	fl     *file
	remain int64
	window int
}

func (r *ranged) Read(p []byte) (int, error) {
	if r.remain <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remain {
		p = p[:r.remain]
	}
	n, err := r.fl.Read(p)
	r.remain -= int64(n)
	return n, err
}

func (r *ranged) WriteTo(w io.Writer) (int64, error) {
	size := int64(r.window)
	if size > r.remain {
		size = r.remain
	}
	if size <= 0 {
		return 0, nil
	}
	buf := make([]byte, size)
	var total int64
	for r.remain > 0 {
		b := buf
		if int64(len(b)) > r.remain {
			b = b[:r.remain]
		}
		n, err := r.fl.Read(b)
		if n > 0 {
			m, werr := w.Write(b[:n])
			total += int64(m)
			r.remain -= int64(n)
			if werr != nil {
				return total, werr
			}
			if m < n {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

func (r *ranged) Close() error { return r.fl.Close() }

// ReadRange returns length bytes starting at offset (length < 0 reads to the end).
func (c *Client) ReadRange(ctx context.Context, p string, offset, length int64) (io.ReadCloser, error) {
	if offset < 0 {
		return nil, fmt.Errorf("sftp: negative offset %d", offset)
	}
	f, err := c.open(ctx, p)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sftp: seek %s: %w", p, err)
	}
	if length < 0 {
		return f, nil
	}
	window := orInt(c.cfg.MaxPacket, DefaultMaxPacket) * orInt(c.cfg.MaxConcurrentRequests, DefaultMaxConcurrentRequests)
	if window > maxReadWindow {
		window = maxReadWindow
	}
	return &ranged{fl: f, remain: length, window: window}, nil
}

func toInfo(logical string, fi os.FileInfo) *client.FileInfo {
	mt := fi.ModTime()
	if mt.Unix() == 0 {
		// pkg/sftp reports Unix(0) when the server sent no mtime; that is "unknown", not 1970. (A real 1970-01-01T00:00:00Z
		// mtime is indistinguishable from it and reads as unknown too.)
		mt = time.Time{}
	}
	return &client.FileInfo{
		Name:    fi.Name(),
		Size:    fi.Size(),
		ModTime: mt,
		IsDir:   fi.IsDir(),
		Mode:    fi.Mode(),
		Path:    logical,
	}
}

// GetFileInfo returns the attributes of one path (symlinks followed).
func (c *Client) GetFileInfo(ctx context.Context, p string) (*client.FileInfo, error) {
	logical, remote, err := c.confine(p)
	if err != nil {
		return nil, err
	}
	var out *client.FileInfo
	err = c.with(ctx, func(sc *gosftp.Client, cn *conn) error {
		if err := c.checkWithin(sc, cn, remote); err != nil {
			return err
		}
		fi, err := sc.Stat(remote)
		if err != nil {
			return err
		}
		out = toInfo(logical, fi)
		if logical == "/" {
			out.Name = "/"
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sftp: stat %s: %w", p, err)
	}
	return out, nil
}

// FileExists reports whether a path exists. A missing path is (false, nil); any other error (including a path that
// escapes the root) is returned.
func (c *Client) FileExists(ctx context.Context, p string) (bool, error) {
	_, err := c.GetFileInfo(ctx, p)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// ListDirectory lists a directory with the attributes the server returned for each entry (no extra stat per
// entry). Symbolic links are reported as links (Mode has os.ModeSymlink) and are not followed. A listing that delivers
// more than Config.MaxDirEntries entries fails with ErrDirTooLarge.
func (c *Client) ListDirectory(ctx context.Context, p string) ([]*client.FileInfo, error) {
	logical, remote, err := c.confine(p)
	if err != nil {
		return nil, err
	}
	var out []*client.FileInfo
	err = c.with(ctx, func(sc *gosftp.Client, cn *conn) error {
		if err := c.checkWithin(sc, cn, remote); err != nil {
			return err
		}
		cn.beginList()
		defer cn.endList()
		entries, err := sc.ReadDirContext(ctx, remote)
		if err != nil {
			return err
		}
		if c.listHook != nil {
			c.listHook(cn)
		}
		if cn.isDead() {
			return fmt.Errorf("%w: connection ended during the listing", gosftp.ErrSSHFxConnectionLost) // pkg/sftp may have returned a partial list as success
		}
		out = make([]*client.FileInfo, 0, len(entries))
		for _, e := range entries {
			if e.Name() == "." || e.Name() == ".." {
				continue
			}
			out = append(out, toInfo(path.Join(logical, e.Name()), e))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sftp: list %s: %w", p, err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------------------
// mutations: impossible by construction

// WriteFile always returns ErrReadOnly.
func (c *Client) WriteFile(context.Context, string, io.Reader) error { return ErrReadOnly }

// DeleteFile always returns ErrReadOnly.
func (c *Client) DeleteFile(context.Context, string) error { return ErrReadOnly }

// CopyFile always returns ErrReadOnly.
func (c *Client) CopyFile(context.Context, string, string) error { return ErrReadOnly }

// CreateDirectory always returns ErrReadOnly.
func (c *Client) CreateDirectory(context.Context, string) error { return ErrReadOnly }

// DeleteDirectory always returns ErrReadOnly.
func (c *Client) DeleteDirectory(context.Context, string) error { return ErrReadOnly }

// ---------------------------------------------------------------------------------------------------------
// metadata

// GetProtocol returns "sftp".
func (c *Client) GetProtocol() string { return "sftp" }

// GetConfig returns the configuration without any secret.
func (c *Client) GetConfig() interface{} {
	return &PublicConfig{
		Host: c.cfg.Host, Port: c.cfg.Port, Username: c.cfg.Username,
		CredentialRef: c.cfg.CredentialRef, Root: c.root(), ReadOnly: true,
	}
}

// String never prints a secret.
func (c *Client) String() string {
	return fmt.Sprintf("sftp.Client{%s@%s root=%s ref=%s}", c.cfg.Username, c.hostport(), c.root(), c.cfg.CredentialRef)
}
