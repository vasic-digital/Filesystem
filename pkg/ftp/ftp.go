// Package ftp implements the filesystem client for the FTP protocol, with explicit FTPS (WP-12 PA-04).
//
// Properties (evidence under specs/001-full-project-audit-remediation/evidence/wp12/ftp/):
//
//   - Explicit FTPS by default: AUTH TLS, TLS 1.2 minimum, PBSZ 0 + PROT P (data channel protected), a TLS session
//     cache shared by the control and data connections (resumption). The server certificate must be PINNED per host
//     (tls.go); an unknown or changed certificate is refused BEFORE any credential is sent. InsecureSkipVerify is
//     never used.
//   - Clear-text FTP is refused unless the root sets trusted_lan=true (Config.TrustedLAN).
//   - Listings use MLSD and metadata uses MLST (RFC 3659). A modification time the server did not send is the zero
//     time.Time, never "now". A server without MLST is refused (ErrNoMLSD) unless Config.AllowDegradedList is set,
//     in which case LIST is used, Degraded() reports true and ModTime is the zero time. A listing line that cannot be
//     parsed fails the listing (ErrListingIncomplete); a partial listing is never returned as complete.
//   - "OPTS UTF8 ON" is sent after login whenever the server lists UTF8 in FEAT (every Synology host measured by the
//     WP-12 protocol survey does); without it these servers return 0x7f for every non-ASCII name. A server that
//     advertises UTF8 and refuses the command (pure-ftpd answers 504) still connects, but a listing that then
//     contains a name that is not valid UTF-8, or carries 0x7f, fails with ErrUTF8Refused instead of cataloguing a
//     garbled name.
//   - Every blocking operation is bounded: Config.DialTimeout bounds connect, greeting, TLS handshake and login
//     together; Config.IOTimeout bounds each control reply as a whole and every single read or write on data
//     connections; the ctx deadline
//     and ctx cancellation are honoured everywhere, including a blocked read; Disconnect aborts an open stream even
//     when no Read is in flight. A control reply is capped (Config.MaxReplyBytes) and so is a listing
//     (Config.MaxListEntries).
//   - The command/reply discipline is strict (proto.go): a reply that is not the expected one, a 421, or bytes nobody
//     asked for make the connection unusable and the next operation re-dials, so one stale reply can never be read as
//     the answer to a later command.
//   - One control connection is one session: every operation holds the session until it completes, and a read
//     stream holds it until it is closed, so the shared connection is never used by two commands at once. Parallel
//     scanning uses one client per worker (NewWorkerPool, built on fabric.Pool).
//   - Ranged reads use REST (ReadFileFrom, OpenSeekable). OpenSeekable reports a transfer the server aborted or cut
//     short as an error; it never returns a truncated file as complete.
//   - An authentication failure is classified as such (fabric.ErrAuth) and is never retried; a failure after the
//     password was sent is never retried either (a retry would send it again); other login-phase failures (TYPE, OPTS,
//     PBSZ, PROT) are configuration failures, never authentication failures.
//   - The password comes from a credential_ref (cred.go) and never appears in logs, errors, GetConfig or String, nor
//     through fmt of a Credential or of the scan factory.
//   - The scan path (NewScanClient, NewWorkerPool) is wrapped in decorators.ReadOnly: a catalog scan cannot modify
//     the server.
//
// Scope of path confinement: it is lexical and POSIX-only (separator "/"). A server that treats "\\" as a separator
// (a Windows FTP server) is not confined by it. A byte 0xFF in a path is sent doubled (Telnet IAC escaping,
// RFC 854/959).
package ftp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"digital.vasic.filesystem/pkg/client"
)

// TLS modes of Config.TLSMode.
const (
	TLSExplicit = "explicit" // AUTH TLS (the default)
	TLSNone     = "none"     // clear text; refused unless Config.TrustedLAN
)

// Defaults.
const (
	DefaultPort        = 21
	DefaultDialTimeout = 30 * time.Second
	DefaultIOTimeout   = 60 * time.Second
)

// Errors.
var (
	// ErrNotConnected is returned when an operation needs a connection that does not exist.
	ErrNotConnected = errors.New("ftp: not connected")
	// ErrPathEscape is returned for a path that leaves the configured root or carries control characters.
	ErrPathEscape = errors.New("ftp: path escapes the configured root or contains control characters")
	// ErrNoMLSD is returned when the server cannot provide RFC 3659 attributes and degraded listing is not allowed.
	ErrNoMLSD = errors.New("ftp: server offers no MLST/MLSD, so modification times would be unknown; set allow_degraded_list to list with LIST")
)

// Config contains FTP connection configuration. It contains no secret except the deprecated inline Password.
type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// Password is DEPRECATED: an inline secret, used only when CredentialRef is empty. Prefer CredentialRef.
	Password string `json:"-"`
	// CredentialRef names the secret; it is resolved at connect time by Resolver.
	CredentialRef string `json:"credential_ref"`
	Path          string `json:"path"`

	// Resolver resolves CredentialRef; nil means DefaultCredentialResolver.
	Resolver CredentialResolver `json:"-"`
	// TLSMode is TLSExplicit (default when empty) or TLSNone.
	TLSMode string `json:"tls_mode"`
	// TrustedLAN allows TLSNone. Without it clear-text FTP is refused.
	TrustedLAN bool `json:"trusted_lan"`
	// PinStore holds the certificate pins; required for TLSExplicit.
	PinStore PinStore `json:"-"`
	// AllowDegradedList permits LIST when the server has no MLST/MLSD (mtimes then unknown).
	AllowDegradedList bool `json:"allow_degraded_list"`
	// DialTimeout bounds, TOGETHER, the TCP connect, the greeting, AUTH TLS, the TLS handshake, the login and the
	// base-directory steps (one budget for the whole connect); 0 selects DefaultDialTimeout.
	DialTimeout time.Duration `json:"-"`
	// IOTimeout bounds each control reply as a whole (all its lines) and every single read or write on a data
	// connection: a server that stalls is detected after IOTimeout, whatever the command; 0 selects
	// DefaultIOTimeout. The ctx deadline applies too.
	IOTimeout time.Duration `json:"-"`
	// MaxReplyBytes bounds one control reply (all its lines); 0 selects DefaultMaxReplyBytes.
	MaxReplyBytes int `json:"-"`
	// MaxListEntries bounds the lines of one listing; 0 selects DefaultMaxListEntries.
	MaxListEntries int `json:"-"`
	// MaxListBytes bounds the bytes of one listing (all its lines); 0 selects DefaultMaxListBytes. The entry cap alone
	// would allow 1,048,576 lines of 16 KiB.
	MaxListBytes int `json:"-"`
	// LoginBackoff is how long logins to this host and user are suspended, for every client of the process, after a
	// password attempt whose outcome is unknown (see loginguard.go); 0 selects DefaultLoginBackoff, negative disables.
	LoginBackoff time.Duration `json:"-"`
	// OnWarning, when set, is called after a listing that skipped entries (a name with a line break, a name that cannot be
	// addressed): see ListingWarning. It is called on the goroutine of the listing; it must not call the client.
	OnWarning func(ListingWarning) `json:"-"`
	// DisableEPSV forces PASV (servers whose EPSV is broken).
	DisableEPSV bool `json:"disable_epsv"`
}

// PublicConfig is what GetConfig returns: the configuration without any secret or store handle.
type PublicConfig struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Username          string `json:"username"`
	CredentialRef     string `json:"credential_ref"`
	Path              string `json:"path"`
	TLSMode           string `json:"tls_mode"`
	TrustedLAN        bool   `json:"trusted_lan"`
	AllowDegradedList bool   `json:"allow_degraded_list"`
	DisableEPSV       bool   `json:"disable_epsv"`
}

type connState int

const (
	stateNever connState = iota
	stateUp
	stateLost // the connection broke; the next operation re-dials
	stateDown // the caller disconnected; never re-dial implicitly
)

// Client implements client.Client and client.SeekableClient for FTP/FTPS.
type Client struct {
	config *Config

	// sem is the session: held by every operation, and by a read stream until it is closed.
	sem chan struct{}

	mu            sync.Mutex // guards the fields below
	p             *proto
	state         connState
	root          string
	degraded      bool
	abort         func() // aborts the open stream, if any (Disconnect)
	closeWhenIdle bool   // a Disconnect timed out: whoever releases the session closes the connection
	gen           uint64 // bumped by every Disconnect: a connect that started before it must not publish its connection
	warnings      []ListingWarning
	skipped       int64
}

var (
	_ client.Client         = (*Client)(nil)
	_ client.SeekableClient = (*Client)(nil)
)

// NewFTPClient creates a new FTP client. It does not connect.
func NewFTPClient(config *Config) *Client {
	if config == nil {
		config = &Config{}
	}
	return &Client{config: config, sem: make(chan struct{}, 1)}
}

func (c *Client) port() int {
	if c.config.Port == 0 {
		return DefaultPort
	}
	return c.config.Port
}

func (c *Client) opts() protoOpts {
	o := protoOpts{dialTimeout: c.config.DialTimeout, ioTimeout: c.config.IOTimeout, maxReply: c.config.MaxReplyBytes, disableEPSV: c.config.DisableEPSV,
		loginBackoff: c.config.LoginBackoff}
	if o.dialTimeout <= 0 {
		o.dialTimeout = DefaultDialTimeout
	}
	if o.ioTimeout <= 0 {
		o.ioTimeout = DefaultIOTimeout
	}
	if o.maxReply <= 0 {
		o.maxReply = DefaultMaxReplyBytes
	}
	return o
}

func (c *Client) maxEntries() int {
	if c.config.MaxListEntries > 0 {
		return c.config.MaxListEntries
	}
	return DefaultMaxListEntries
}

func (c *Client) maxBytes() int {
	if c.config.MaxListBytes > 0 {
		return c.config.MaxListBytes
	}
	return DefaultMaxListBytes
}

// acquire takes the session or gives up when ctx is done.
func (c *Client) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release gives the session back. When a Disconnect timed out while the session was busy, the connection is closed
// here, by the holder that finally lets go, so a timed-out Disconnect never leaves the server's slot open.
func (c *Client) release() {
	c.mu.Lock()
	var stale *proto
	if c.closeWhenIdle && c.state == stateDown {
		stale, c.p, c.closeWhenIdle = c.p, nil, false
	}
	c.mu.Unlock()
	if stale != nil {
		stale.quit()
	}
	<-c.sem
}

// ---------------------------------------------------------------------------------------------------------
// connection

func (c *Client) password(ctx context.Context) (string, error) {
	if ref := strings.TrimSpace(c.config.CredentialRef); ref != "" {
		res := c.config.Resolver
		if res == nil {
			res = DefaultCredentialResolver
		}
		cred, err := res.Resolve(ctx, ref)
		if err != nil {
			if errors.Is(err, ErrCredentialUnavailable) {
				return "", err
			}
			return "", fmt.Errorf("%w: %q", ErrCredentialUnavailable, ref)
		}
		defer cred.wipe()
		if cred.Password == "" {
			return "", fmt.Errorf("%w: %q resolved to an empty password", ErrCredentialUnavailable, ref)
		}
		return cred.Password, nil
	}
	if c.config.Password != "" {
		return c.config.Password, nil
	}
	if u := strings.ToLower(c.config.Username); u == "anonymous" || u == "ftp" {
		return "anonymous@", nil
	}
	return "", fmt.Errorf("%w: no credential_ref configured", ErrCredentialUnavailable)
}

func isNetErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	for _, e := range []error{io.EOF, io.ErrUnexpectedEOF, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, syscall.ETIMEDOUT, syscall.ECONNREFUSED} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// connect dials, upgrades, logs in and verifies the base directory. The caller holds the session.
func (c *Client) connect(ctx context.Context) error {
	cfg := c.config
	if strings.TrimSpace(cfg.Host) == "" {
		return errors.New("ftp: no host configured")
	}
	mode := cfg.TLSMode
	if mode == "" {
		mode = TLSExplicit
	}
	switch mode {
	case TLSExplicit:
	case TLSNone:
		if !cfg.TrustedLAN {
			return ErrClearTextRefused
		}
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedTLSMode, mode)
	}
	key := loginKeyFor(cfg.Host, c.port(), cfg.Username)
	if rem := loginBackoffs.remaining(key); rem > 0 {
		// before the credential is even resolved and before any socket: no password can be sent again (WF24 G3)
		return loginBackoffError(cfg.Host, c.port(), rem)
	}
	pw, err := c.password(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	gen := c.gen
	c.mu.Unlock()

	var pins []CertPin
	var tlsCfg *tls.Config
	if mode == TLSExplicit {
		if cfg.PinStore == nil {
			return ErrNoPinStore
		}
		pins, err = cfg.PinStore.Lookup(HostPort(cfg.Host, c.port()))
		if err != nil {
			return err
		}
		tlsCfg = newTLSConfig(cfg.Host, pins)
	}

	p, err := dialProto(ctx, cfg.Host, c.port(), c.opts(), tlsCfg)
	if err != nil {
		m, _ := mapTLSError(err, cfg.Host, pins)
		return m
	}
	p.loginKey = key
	fail := func(err error) error {
		p.quit()
		return err
	}
	if err := p.banner(ctx); err != nil {
		return fail(err)
	}
	if tlsCfg != nil {
		if err := p.authTLS(ctx); err != nil {
			return fail(err)
		}
		if err := p.startTLS(ctx); err != nil {
			m, _ := mapTLSError(err, cfg.Host, pins)
			return fail(m)
		}
	}
	if err := p.login(ctx, cfg.Username, pw, false); err != nil {
		return fail(err)
	}
	loginBackoffs.clear(key) // a credential verdict was reached: any earlier doubt is over
	root := ""
	if cfg.Path != "" {
		if _, _, err := p.cmd(ctx, []int{250}, "CWD %s", cfg.Path); err != nil {
			bd := mapFTPError(err)
			if bd == err {
				bd = p.stepErr(ctx, "CWD", err)
			}
			return fail(fmt.Errorf("ftp: base directory %q: %w", cfg.Path, bd))
		}
		root, err = p.pwd(ctx)
		if err != nil {
			return fail(p.stepErr(ctx, "PWD", err))
		}
	}
	p.endPhase()
	c.mu.Lock()
	if c.gen != gen {
		// a Disconnect ran while this connection was being established (WF24 G6): it wins, the new connection is closed
		c.mu.Unlock()
		p.quit()
		return fmt.Errorf("%w: Disconnect was called while the connection was being established", ErrNotConnected)
	}
	old := c.p
	c.p, c.state, c.root = p, stateUp, strings.TrimSuffix(root, "/")
	c.degraded = !p.mlstOK()
	c.mu.Unlock()
	if old != nil {
		old.quit() // a connection left by a timed-out Disconnect must not leak
	}
	return nil
}

// Connect establishes the FTP connection. It is idempotent while the connection is up.
func (c *Client) Connect(ctx context.Context) error {
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()
	c.mu.Lock()
	up := c.state == stateUp && c.p != nil && !c.p.isBroken()
	c.mu.Unlock()
	if up {
		return nil
	}
	return c.connect(ctx)
}

// Disconnect closes the FTP connection. An open stream is aborted, also when no Read is in flight. It never
// re-dials afterwards. When ctx ends before the session is free, the connection is closed by whoever releases the
// session next, so the server's slot is not kept.
func (c *Client) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	c.state = stateDown
	c.gen++
	abort := c.abort
	c.mu.Unlock()
	if abort != nil {
		abort()
	}
	if err := c.acquire(ctx); err != nil {
		c.mu.Lock()
		c.closeWhenIdle = true
		c.mu.Unlock()
		// the holder may have released between the failed acquire and the flag: take the session if it is free now
		select {
		case c.sem <- struct{}{}:
			c.release()
		default:
		}
		return err
	}
	defer c.release()
	c.mu.Lock()
	p := c.p
	c.p = nil
	c.state = stateDown
	c.mu.Unlock()
	if p != nil {
		p.quit() // a connection that is already gone cannot say goodbye: that is not a failure of Disconnect
	}
	return nil
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == stateUp && c.p != nil && !c.p.isBroken()
}

// Degraded reports whether the server lacks MLSD/MLST, so that listings come from LIST (names, sizes and types
// only; modification times unknown). It is meaningful once connected.
func (c *Client) Degraded() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.degraded
}

// ensure returns the live connection, re-dialling after a lost connection. The caller holds the session.
func (c *Client) ensure(ctx context.Context) (*proto, error) {
	c.mu.Lock()
	state, p := c.state, c.p
	c.mu.Unlock()
	if state == stateUp && p != nil && p.isBroken() {
		c.lost(p)
		state = stateLost
	}
	switch state {
	case stateUp:
		if p != nil {
			return p, nil
		}
	case stateLost:
		if err := c.connect(ctx); err != nil {
			return nil, err
		}
		c.mu.Lock()
		p = c.p
		c.mu.Unlock()
		return p, nil
	}
	return nil, ErrNotConnected
}

// lost marks the connection broken and closes it (a connection nobody can use must not occupy a server slot).
func (c *Client) lost(p *proto) {
	if p == nil {
		return
	}
	c.mu.Lock()
	if c.p == p && c.state == stateUp {
		c.state = stateLost
		c.p = nil
	}
	c.mu.Unlock()
	go p.quit()
}

// afterErr drops the connection when the protocol layer doubts it (any I/O failure, an unexpected reply, 421, an
// abort); an ordinary negative reply (4yz/5yz other than 421) leaves it alone.
func (c *Client) afterErr(p *proto, err error) error {
	if p != nil && p.isBroken() {
		c.lost(p)
	}
	return err
}

// run executes fn with the session held.
func (c *Client) run(ctx context.Context, fn func(p *proto) error) error {
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()
	p, err := c.ensure(ctx)
	if err != nil {
		return err
	}
	return c.afterErr(p, fn(p))
}

// TestConnection tests the FTP connection.
func (c *Client) TestConnection(ctx context.Context) error {
	return c.run(ctx, func(p *proto) error {
		_, _, err := p.cmd(ctx, []int{200}, "NOOP")
		return err
	})
}

// ---------------------------------------------------------------------------------------------------------
// paths

// confine maps a client path to (logical, remote). Logical is absolute below the root ("/a/b"), remote is the path
// sent to the server. A path that leaves the root, or contains CR, LF or NUL, is refused.
func (c *Client) confine(p string) (logical, remote string, err error) {
	if strings.ContainsAny(p, "\r\n\x00") {
		return "", "", fmt.Errorf("%w: %q", ErrPathEscape, p)
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
	c.mu.Lock()
	root := c.root
	c.mu.Unlock()
	if root == "" {
		root = strings.TrimSuffix(c.config.Path, "/")
	}
	if logical == "/" {
		if root == "" {
			return "/", "/", nil
		}
		return "/", root, nil
	}
	return logical, root + logical, nil
}

// resolvePath resolves a relative path within the FTP base directory (no escape check; see confine).
func (c *Client) resolvePath(p string) string {
	_, remote, err := c.confine(p)
	if err != nil {
		return ""
	}
	return remote
}

// mapFTPError turns a 550 reply into what it says: absent (os.ErrNotExist), denied (os.ErrPermission), or - when the
// text does not tell - the reply itself. RFC 959 uses 550 for both "not found" and "no access", so an unreadable
// 550 is never reported as "does not exist".
func mapFTPError(err error) error {
	var te *textproto.Error
	if !errors.As(err, &te) || te.Code != 550 {
		return err
	}
	switch classify550(te.Msg) {
	case k550Absent:
		return fmt.Errorf("%w: %v", os.ErrNotExist, err)
	case k550Denied:
		return fmt.Errorf("%w: %v", os.ErrPermission, err)
	}
	return err
}

// ---------------------------------------------------------------------------------------------------------
// streams

// stream is a read of a data connection. It holds the session until closed.
type stream struct {
	c    *Client
	p    *proto
	dc   *dconn
	ctx  context.Context
	stop func() bool
	once sync.Once
	eof  bool
	rerr error
}

func (c *Client) newStream(ctx context.Context, p *proto, dc *dconn) *stream {
	s := &stream{c: c, p: p, dc: dc, ctx: ctx}
	s.stop = context.AfterFunc(ctx, dc.abortNow)
	c.mu.Lock()
	c.abort = p.interrupt
	down := c.state == stateDown
	c.mu.Unlock()
	if down { // Disconnect ran before the abort hook existed
		p.interrupt()
	}
	return s
}

func (s *stream) Read(b []byte) (int, error) {
	n, err := s.dc.Read(b)
	switch {
	case err == nil:
	case errors.Is(err, io.EOF):
		s.eof = true
	default:
		s.rerr = err
	}
	return n, err
}

// Close ends the transfer, reads the final reply and releases the session. After a complete read (EOF) a negative
// final reply (426, 451, ...) is returned: the file may be incomplete. An early close (the caller stopped reading) is
// not an error, whatever the server answers; the control channel is then proven to be in step, or dropped. A stream
// that failed or was aborted is not waited for: its connection is dropped.
func (s *stream) Close() error {
	var err error
	s.once.Do(func() {
		s.stop()
		s.c.mu.Lock()
		s.c.abort = nil
		s.c.mu.Unlock()
		if s.rerr != nil || s.dc.aborted.Load() || s.ctx.Err() != nil {
			s.p.markBroken()
			_ = s.dc.Close()
		} else if ferr := s.p.finishTransfer(s.ctx, s.dc, s.eof); ferr != nil {
			err = fmt.Errorf("ftp: transfer did not complete: %w", mapFTPError(ferr))
		}
		_ = s.c.afterErr(s.p, nil)
		s.c.release()
	})
	return err
}

// openStream starts RETR at offset and returns the stream (session held until it is closed).
func (c *Client) openStream(ctx context.Context, remote string, offset uint64) (*stream, error) {
	if err := c.acquire(ctx); err != nil {
		return nil, err
	}
	p, err := c.ensure(ctx)
	if err != nil {
		c.release()
		return nil, err
	}
	dc, err := p.beginTransfer(ctx, offset, "RETR %s", remote)
	if err != nil {
		err = c.afterErr(p, mapFTPError(err))
		c.release()
		return nil, fmt.Errorf("ftp: retrieve %s: %w", remote, err)
	}
	return c.newStream(ctx, p, dc), nil
}

// ReadFile reads a file from the FTP server. The session is held until the returned reader is closed.
func (c *Client) ReadFile(ctx context.Context, p string) (io.ReadCloser, error) {
	_, remote, err := c.confine(p)
	if err != nil {
		return nil, err
	}
	return c.openStream(ctx, remote, 0)
}

// ReadFileFrom reads a file starting at offset (REST). The session is held until the reader is closed.
func (c *Client) ReadFileFrom(ctx context.Context, p string, offset int64) (io.ReadCloser, error) {
	if offset < 0 {
		return nil, fmt.Errorf("ftp: negative offset %d", offset)
	}
	_, remote, err := c.confine(p)
	if err != nil {
		return nil, err
	}
	return c.openStream(ctx, remote, uint64(offset))
}

// seeker is a ReadSeekCloser: every Seek ends the transfer and the next Read resumes with REST.
type seeker struct {
	c      *Client
	ctx    context.Context
	remote string
	size   int64
	off    int64
	st     *stream
}

// OpenSeekable opens a file for reading with seek support (REST-based resume).
func (c *Client) OpenSeekable(ctx context.Context, p string) (client.ReadSeekCloser, error) {
	_, remote, err := c.confine(p)
	if err != nil {
		return nil, err
	}
	var size int64
	if err := c.run(ctx, func(pr *proto) error {
		_, lines, e := pr.cmd(ctx, []int{213}, "SIZE %s", remote)
		if e != nil {
			return mapFTPError(e)
		}
		n, perr := strconv.ParseInt(strings.TrimSpace(strings.Join(lines, " ")), 10, 64)
		if perr != nil || n < 0 {
			// a 213 whose text is not a size is not the answer to our SIZE: the lock-step is in doubt (WF24 K1.e)
			pr.markBroken()
			return protoViolation("unreadable SIZE reply %q", flat(strings.Join(lines, " ")))
		}
		size = n
		return nil
	}); err != nil {
		return nil, fmt.Errorf("ftp: open %s: %w", remote, err)
	}
	return &seeker{c: c, ctx: ctx, remote: remote, size: size}, nil
}

func (s *seeker) Read(p []byte) (int, error) {
	if s.off >= s.size {
		return 0, io.EOF
	}
	if s.st == nil {
		st, err := s.c.openStream(s.ctx, s.remote, uint64(s.off))
		if err != nil {
			return 0, err
		}
		s.st = st
	}
	n, err := s.st.Read(p)
	s.off += int64(n)
	switch {
	case errors.Is(err, io.EOF):
		// the data ended: the final reply says whether the server finished or gave up
		cerr := s.dropStream()
		switch {
		case cerr != nil:
			return n, cerr
		case s.off < s.size:
			return n, fmt.Errorf("ftp: %s ended at byte %d of %d: %w", s.remote, s.off, s.size, io.ErrUnexpectedEOF)
		case n > 0:
			return n, nil
		}
		return 0, io.EOF
	case err != nil:
		_ = s.dropStream()
		return n, err
	case s.off >= s.size:
		// everything announced was received: the transfer is finished AS COMPLETE (its final reply is read and a
		// negative one is returned), not dropped through the early-close path that accepts any reply (WF24 G4)
		if cerr := s.finishAtEnd(); cerr != nil {
			return n, cerr
		}
	}
	return n, nil
}

// finishAtEnd closes the stream after SIZE bytes were read: the end of the data (EOF) is awaited for at most
// earlyCloseWait and the transfer is closed as complete, so a final 4yz/5yz reply is an error. A server that sends more
// than SIZE announced, or does not close the data connection, gets the early-close path (any reply accepted).
func (s *seeker) finishAtEnd() error {
	st := s.st
	s.st = nil
	if st == nil {
		return nil
	}
	if !st.eof && st.rerr == nil {
		st.dc.maxWait.Store(int64(earlyCloseWait))
		var one [1]byte
		n, err := st.dc.Read(one[:])
		var ne net.Error
		switch {
		case n > 0:
		case errors.Is(err, io.EOF):
			st.eof = true
		case err != nil && errors.As(err, &ne) && ne.Timeout() && st.ctx.Err() == nil && !st.dc.aborted.Load():
		case err != nil:
			st.rerr = err
		}
	}
	return st.Close()
}

func (s *seeker) dropStream() error {
	st := s.st
	s.st = nil
	if st == nil {
		return nil
	}
	return st.Close()
}

func (s *seeker) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = s.off
	case io.SeekEnd:
		base = s.size
	default:
		return 0, fmt.Errorf("ftp: invalid whence %d", whence)
	}
	n := base + offset
	if n < 0 {
		return 0, fmt.Errorf("ftp: negative seek position %d", n)
	}
	if n != s.off && s.st != nil {
		_ = s.dropStream()
	}
	s.off = n
	return n, nil
}

func (s *seeker) Close() error { return s.dropStream() }

// ---------------------------------------------------------------------------------------------------------
// metadata

func clampSize(u uint64) int64 {
	if u > uint64(1<<63-1) {
		return 1<<63 - 1
	}
	return int64(u)
}

func toInfo(logicalDir string, e *entry, degraded bool) *client.FileInfo {
	fi := &client.FileInfo{
		Name:  e.name,
		Size:  e.size,
		IsDir: e.kind == kindDir || e.kind == kindSelf || e.kind == kindParent,
		Path:  strings.TrimSuffix(logicalDir, "/") + "/" + e.name,
		Mode:  e.mode(),
	}
	if !degraded {
		fi.ModTime = e.mtime // zero when the server sent no "modify" fact: never fabricated
	}
	return fi
}

// listEntries lists the directory remote (always with an explicit argument: an argument-less LIST lists the login
// directory, which is not the directory that was asked for). logical is the directory as the client names it (warnings).
func (c *Client) listEntries(ctx context.Context, p *proto, logical, remote string, degraded bool) ([]*entry, error) {
	acc := &listAcc{}
	var err error
	if degraded {
		err = p.list(ctx, c.maxEntries(), c.maxBytes(), func(line string) error { return acc.add(line, true) }, "LIST %s", remote)
	} else {
		err = p.list(ctx, c.maxEntries(), c.maxBytes(), func(line string) error { return acc.add(line, false) }, "MLSD %s", remote)
	}
	if err != nil {
		return nil, mapFTPError(err)
	}
	if err := acc.verdict(); err != nil {
		return nil, err
	}
	if !p.utf8On {
		// the session is not known to be UTF-8 (UTF8 not offered, or OPTS UTF8 ON refused): a name that is not valid
		// UTF-8 or carries the 0x7f replacement cannot be represented (WF24 G9: checked whatever the reason)
		for _, e := range acc.entries {
			if !utf8.ValidString(e.name) || strings.ContainsRune(e.name, 0x7f) {
				return nil, fmt.Errorf("%w: %q", ErrUTF8Refused, e.name)
			}
		}
	}
	if w := acc.warning(logical); w != nil {
		c.noteWarning(*w)
	}
	return acc.entries, nil
}

// listAcc collects the lines of one listing. A line without fact structure that cannot be parsed AFTER at least one entry
// was understood is a FRAGMENT: the rest of a name that contains a line break (the NAS leg of WP-12: one such name made the whole directory
// fail and lost 189 other entries). Fragments are skipped and counted, and the entry in front of one is dropped too (its
// name is a truncated one). A listing whose FIRST line cannot be parsed, or in which fragments are more than a tenth of
// the lines, is not a listing with an odd name but a desynchronised channel: it fails closed (ErrListingIncomplete).
type listAcc struct {
	entries       []*entry
	lines         int
	sawEntry      bool
	lastAppended  bool
	fragments     int
	truncated     int
	unaddressable int
}

func (a *listAcc) add(line string, degraded bool) error {
	var (
		e    *entry
		skip bool
		perr error
	)
	if degraded {
		e, skip, perr = parseListLine(line)
	} else {
		e, perr = parseMLEntry(line)
	}
	if perr == nil && skip {
		return nil // a "total N" line
	}
	a.lines++
	if perr != nil {
		// A fragment is a line without structure that follows an understood entry. An MLSD line that HAS the fact
		// structure (a ";") but is invalid (Size=zz) is a damaged entry, not a piece of a name: the listing fails as
		// before. A LIST line has no marker that tells a name fragment from garbage, so any unparseable one qualifies.
		if !a.sawEntry || (!degraded && strings.Contains(line, ";")) {
			return perr
		}
		a.fragments++
		if a.lastAppended {
			a.entries = a.entries[:len(a.entries)-1]
			a.truncated++
			a.lastAppended = false
		}
		return nil
	}
	a.sawEntry = true
	if strings.ContainsAny(e.name, "\r\n\x00") {
		a.unaddressable++ // confine refuses such a path: listing it would only produce an entry nobody can open
		a.lastAppended = false
		return nil
	}
	a.entries = append(a.entries, e)
	a.lastAppended = true
	return nil
}

// verdict fails a listing that looks desynchronised rather than odd.
func (a *listAcc) verdict() error {
	if a.fragments > 8 && a.fragments*10 > a.lines {
		return fmt.Errorf("%w: %d of %d lines could not be parsed", ErrListingIncomplete, a.fragments, a.lines)
	}
	return nil
}

func (a *listAcc) warning(dir string) *ListingWarning {
	if a.fragments+a.truncated+a.unaddressable == 0 {
		return nil
	}
	listed := 0
	for _, e := range a.entries {
		if e.kind != kindSelf && e.kind != kindParent && visibleName(e.name) {
			listed++
		}
	}
	return &ListingWarning{Dir: dir, Fragments: a.fragments, Truncated: a.truncated, Unaddressable: a.unaddressable, Listed: listed}
}

// ErrEntriesSkipped is what a ListingWarning unwraps to.
var ErrEntriesSkipped = errors.New("ftp: directory entries were skipped")

// ListingWarning reports a listing that succeeded but skipped entries: names that contain a line break (their MLSD line
// is split in two) or CR, LF or NUL (they cannot be addressed by any later command). It is delivered to
// Config.OnWarning and kept in Client.Warnings; Client.SkippedEntries counts them. It carries counts and the
// directory, never a name.
type ListingWarning struct {
	Dir           string // the directory as the client names it
	Fragments     int    // unparseable lines swallowed as the rest of a name that contains a line break
	Truncated     int    // entries dropped because a fragment followed them (their names were cut)
	Unaddressable int    // entries whose name contains CR, LF or NUL
	Listed        int    // entries returned
}

// Skipped is the number of entries that are missing from the listing (a name with a line break counts once as its
// truncated head, which is dropped, and once per fragment line; Fragments + Truncated + Unaddressable lines in all).
func (w ListingWarning) Skipped() int { return w.Fragments + w.Truncated + w.Unaddressable }

func (w ListingWarning) Error() string {
	return fmt.Sprintf("ftp: listing of %s skipped entries: %d fragment line(s), %d truncated entr(y/ies), %d unaddressable name(s); %d listed",
		w.Dir, w.Fragments, w.Truncated, w.Unaddressable, w.Listed)
}

func (w ListingWarning) Unwrap() error { return ErrEntriesSkipped }

const maxKeptWarnings = 16

func (c *Client) noteWarning(w ListingWarning) {
	c.mu.Lock()
	c.skipped += int64(w.Skipped())
	if len(c.warnings) >= maxKeptWarnings {
		c.warnings = c.warnings[1:]
	}
	c.warnings = append(c.warnings, w)
	cb := c.config.OnWarning
	c.mu.Unlock()
	if cb != nil {
		cb(w)
	}
}

// Warnings returns the most recent listing warnings (at most 16).
func (c *Client) Warnings() []ListingWarning {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ListingWarning(nil), c.warnings...)
}

// SkippedEntries is the number of listing lines/entries skipped over the life of this client (see ListingWarning).
func (c *Client) SkippedEntries() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.skipped
}

func visibleName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\x00")
}

// ListDirectory lists files in a directory (MLSD; see Degraded for the LIST fallback).
func (c *Client) ListDirectory(ctx context.Context, p string) ([]*client.FileInfo, error) {
	logical, remote, err := c.confine(p)
	if err != nil {
		return nil, err
	}
	var out []*client.FileInfo
	err = c.run(ctx, func(pr *proto) error {
		degraded := !pr.mlstOK()
		if degraded && !c.config.AllowDegradedList {
			return ErrNoMLSD
		}
		c.mu.Lock()
		c.degraded = degraded
		c.mu.Unlock()
		entries, e := c.listEntries(ctx, pr, logical, remote, degraded)
		if e != nil {
			return e
		}
		for _, en := range entries {
			if !visibleName(en.name) || en.kind == kindSelf || en.kind == kindParent {
				continue
			}
			out = append(out, toInfo(logical, en, degraded))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ftp: list %s: %w", remote, err)
	}
	return out, nil
}

// statViaParent finds name in the listing of its parent. It settles an ambiguous 550 (RFC 959 uses it for "absent"
// and for "no access"): present means the file exists, absent in a readable parent means it does not.
func (c *Client) statViaParent(ctx context.Context, p *proto, logical, remote string, degraded bool) (*client.FileInfo, bool, error) {
	entries, err := c.listEntries(ctx, p, path.Dir(logical), path.Dir(remote), degraded)
	if err != nil {
		return nil, false, err
	}
	name := path.Base(remote)
	for _, en := range entries {
		if en.name == name && en.kind != kindSelf && en.kind != kindParent {
			return toInfo(path.Dir(logical), en, degraded), true, nil
		}
	}
	return nil, false, nil
}

// GetFileInfo gets information about a file with MLST. The modification time is the server's, never "now".
func (c *Client) GetFileInfo(ctx context.Context, p string) (*client.FileInfo, error) {
	logical, remote, err := c.confine(p)
	if err != nil {
		return nil, err
	}
	var fi *client.FileInfo
	err = c.run(ctx, func(pr *proto) error {
		if pr.mlstOK() {
			_, lines, e := pr.cmd(ctx, []int{250}, "MLST %s", remote)
			if e != nil {
				var te *textproto.Error
				if errors.As(e, &te) && te.Code == 550 && logical != "/" && classify550(te.Msg) == k550Unknown {
					// ambiguous: settle it through the parent listing; if that cannot be read either the 550 stays as it is
					if f2, found, lerr := c.statViaParent(ctx, pr, logical, remote, false); lerr == nil {
						if found {
							fi = f2
							return nil
						}
						return fmt.Errorf("%w: %s", os.ErrNotExist, remote)
					}
				}
				return mapFTPError(e)
			}
			ents, perr := mlstEntries(lines)
			if perr != nil {
				// a reply of the right code but the wrong shape: it may be somebody else's answer, so every later
				// reply could be one behind - the connection is dropped (WF24 G1(b))
				pr.markBroken()
				return perr
			}
			if len(ents) != 1 {
				pr.markBroken()
				return listViolation("MLST returned %d entries for one path", len(ents))
			}
			e0 := ents[0]
			if logical != "/" && !mlstNameMatches(e0.name, remote) {
				pr.markBroken()
				return protoViolation("the MLST reply describes another file than the one asked for")
			}
			e0.name = path.Base(logical)
			fi = toInfo(path.Dir(logical), e0, false)
			fi.Path = logical
			return nil
		}
		if !c.config.AllowDegradedList {
			return ErrNoMLSD
		}
		if logical == "/" { // the root itself: there is no parent to list
			if _, _, e := pr.cmd(ctx, []int{250}, "CWD %s", remote); e != nil {
				return mapFTPError(e)
			}
			fi = &client.FileInfo{Name: "/", IsDir: true, Path: "/", Mode: os.ModeDir}
			return nil
		}
		f2, found, lerr := c.statViaParent(ctx, pr, logical, remote, true)
		if lerr != nil {
			return lerr
		}
		if !found {
			return fmt.Errorf("%w: %s", os.ErrNotExist, remote)
		}
		fi = f2
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ftp: stat %s: %w", remote, err)
	}
	return fi, nil
}

// FileExists checks if a file or directory exists. An ambiguous or permission failure is an error, never "false".
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

// ---------------------------------------------------------------------------------------------------------
// mutations (the scan path wraps them in decorators.ReadOnly)

// WriteFile writes a file to the FTP server.
func (c *Client) WriteFile(ctx context.Context, p string, data io.Reader) error {
	_, remote, err := c.confine(p)
	if err != nil {
		return err
	}
	return c.run(ctx, func(pr *proto) error {
		if data == nil {
			return errors.New("ftp: store: nil reader")
		}
		if dir := path.Dir(remote); dir != "." && dir != "/" {
			_, _, _ = pr.cmd(ctx, []int{257}, "MKD %s", dir) // best effort: the directory may exist
		}
		dc, e := pr.beginTransfer(ctx, 0, "STOR %s", remote)
		if e != nil {
			return fmt.Errorf("ftp: store %s: %w", remote, e)
		}
		n, cerr := io.Copy(dc, data)
		if cerr == nil && n == 0 {
			if th, ok := dc.Conn.(*tls.Conn); ok { // a zero-byte upload still needs the handshake (ProFTPd)
				cerr = th.HandshakeContext(ctx)
			}
		}
		if cerr != nil {
			pr.markBroken()
			_ = dc.Close()
			return fmt.Errorf("ftp: store %s: %w", remote, cerr)
		}
		if e := pr.finishTransfer(ctx, dc, true); e != nil {
			return fmt.Errorf("ftp: store %s: %w", remote, e)
		}
		return nil
	})
}

func (c *Client) simple(ctx context.Context, p string, expect int, verb string) error {
	_, remote, err := c.confine(p)
	if err != nil {
		return err
	}
	return c.run(ctx, func(pr *proto) error {
		_, _, e := pr.cmd(ctx, []int{expect}, "%s %s", verb, remote)
		return e
	})
}

// CreateDirectory creates a directory.
func (c *Client) CreateDirectory(ctx context.Context, p string) error {
	return c.simple(ctx, p, 257, "MKD")
}

// DeleteDirectory deletes a directory.
func (c *Client) DeleteDirectory(ctx context.Context, p string) error {
	return c.simple(ctx, p, 250, "RMD")
}

// DeleteFile deletes a file.
func (c *Client) DeleteFile(ctx context.Context, p string) error {
	return c.simple(ctx, p, 250, "DELE")
}

// CopyFile copies a file on the FTP server through a temporary local file (one data connection at a time).
func (c *Client) CopyFile(ctx context.Context, srcPath, dstPath string) error {
	rc, err := c.ReadFile(ctx, srcPath)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "ftpcopy-*")
	if err != nil {
		_ = rc.Close()
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	_, cerr := io.Copy(tmp, rc)
	if e := rc.Close(); cerr == nil {
		cerr = e
	}
	if cerr != nil {
		return cerr
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return c.WriteFile(ctx, dstPath, tmp)
}

// GetProtocol returns the protocol name.
func (c *Client) GetProtocol() string { return "ftp" }

// GetConfig returns the configuration without any secret.
func (c *Client) GetConfig() interface{} {
	mode := c.config.TLSMode
	if mode == "" {
		mode = TLSExplicit
	}
	return &PublicConfig{
		Host: c.config.Host, Port: c.port(), Username: c.config.Username, CredentialRef: c.config.CredentialRef,
		Path: c.config.Path, TLSMode: mode, TrustedLAN: c.config.TrustedLAN, AllowDegradedList: c.config.AllowDegradedList, DisableEPSV: c.config.DisableEPSV,
	}
}

// String never includes the password.
func (c *Client) String() string {
	return fmt.Sprintf("ftp.Client(%s@%s)", c.config.Username, net.JoinHostPort(c.config.Host, fmt.Sprintf("%d", c.port())))
}

// String redacts the secrets of a Config (inline password, resolver contents) for %v and %s.
func (c Config) String() string {
	return fmt.Sprintf("ftp.Config(%s@%s tls_mode=%s credential_ref=%q)", c.Username, net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port)), c.TLSMode, c.CredentialRef)
}

// GoString redacts the secrets of a Config for %#v.
func (c Config) GoString() string { return c.String() }
