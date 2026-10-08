package ftp

// The FTP control/data protocol layer of this package (WP-12 PA-04, fix-r2).
//
// Why this package speaks the protocol itself instead of wrapping github.com/jlaffaye/ftp (v0.2.4, read for the
// WF21 review): the library (1) bounds nothing except the TCP connect (banner, TLS handshake, every reply and
// every MLSD/LIST data read can block forever), (2) hides the final reply of a transfer from the caller, so an
// unexpected extra reply desynchronises the control channel for good, (3) drops listing lines it cannot parse
// without any signal, (4) folds every login-phase failure into one error and (5) offers no hook to bound reply
// sizes. All five were measured as defects (WF21 D1-D7, D11, D12, D16, D17). The layer below is small, owns the
// net.Conn of both channels, and is the only code that touches the wire.
//
// Rules this file enforces:
//   - Every blocking I/O is armed with a deadline = min(ctx deadline, now + IOTimeout, the connect-phase deadline),
//     and ctx cancellation or Disconnect interrupts a blocked read or write at once (interrupt / dconn.abortNow).
//   - A connection that saw ANY doubt (I/O failure, a reply that is not the one expected, bytes nobody asked for,
//     421, an oversized reply, a cancelled command) is marked broken and is never used again.
//   - Replies are matched to commands by exact code; an unexpected positive reply is a protocol violation.
//   - A reply or listing larger than the configured bound is an error, never an allocation.

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"digital.vasic.filesystem/pkg/fabric"
)

// Limits (Config.MaxReplyBytes, Config.MaxListEntries override them).
const (
	DefaultMaxReplyBytes  = 1 << 20   // one control reply, all its lines
	DefaultMaxListEntries = 1 << 20   // lines of one MLSD/LIST listing
	DefaultMaxListBytes   = 256 << 20 // bytes of one MLSD/LIST listing (all its lines)
	maxLineBytes          = 16 << 10  // one listing line
	// controlLineBytes is the longest control-channel LINE: it must hold every line the listing can return (an MLST reply
	// repeats such a line), otherwise an entry that was listed could not be stat'ed (WF24 G8).
	controlLineBytes = 2 * maxLineBytes
	quitTimeout      = 2 * time.Second
	// drainWait is the zero-wait socket check before a command: data that is already in the kernel buffer is seen at once,
	// the wait only covers a reply that is a few hundred microseconds behind. postTransferWait is the same check after the
	// final reply of a complete transfer (a second reply there is the masked-451 case of WF24 K1.i).
	drainWait = 250 * time.Microsecond
)

// postTransferWait: see drainWait. A variable only so that a test can widen the window (a loaded host makes a 2 ms window
// a race).
var postTransferWait = 2 * time.Millisecond

// earlyCloseWait bounds the wait for the server's reply to a download the CALLER stopped reading (a Seek, an early
// Close): measured against pure-ftpd, a download closed after a few bytes is sometimes never answered (30 s until the
// IOTimeout, WF24 G5, trace in the round-3 evidence); the connection is then dropped and the next operation re-dials.
// It also bounds the wait for the end of the data after the seeker read the announced SIZE. A variable only so that
// tests can shorten it.
var earlyCloseWait = 3 * time.Second

// Errors of the protocol layer.
var (
	// ErrReplyTooLarge is returned when one control reply exceeds Config.MaxReplyBytes.
	ErrReplyTooLarge = errors.New("ftp: server reply exceeds the size limit")
	// ErrListingTooLarge is returned when one listing exceeds Config.MaxListEntries lines.
	ErrListingTooLarge = errors.New("ftp: directory listing exceeds the entry limit")
	// ErrListingIncomplete is returned when a listing line could not be understood: a partial listing is never returned as complete.
	ErrListingIncomplete = errors.New("ftp: directory listing has lines that could not be parsed")
	// ErrAborted is returned by a transfer that was aborted by Disconnect.
	ErrAborted = errors.New("ftp: transfer aborted")
	// ErrUTF8Refused is returned by a listing when the server refused OPTS UTF8 ON (it lists UTF8 in FEAT, pure-ftpd
	// answers 504) AND sent a name that is not valid UTF-8 or carries the 0x7f replacement some servers (Synology)
	// send for non-ASCII names: that name cannot be represented, and listing it as if it were right would catalogue
	// a garbled name. Names the server sent as valid UTF-8 are listed normally.
	ErrUTF8Refused = errors.New("ftp: the server refused OPTS UTF8 ON and sent a name that is not valid UTF-8, so non-ASCII names would be garbled")
	// ErrProtocol marks a violation of the command/reply discipline; the connection is dropped.
	ErrProtocol = errors.New("ftp: protocol violation")
	// ErrTLSNotOffered is the leaf of an AUTH TLS refusal: clear text is never used as a fallback.
	ErrTLSNotOffered = errors.New("ftp: the server does not offer explicit TLS; clear text is never used as a fallback")
)

// Leaf sentinels of the connect phases. fabric.Classify scans the text of every LEAF error for credential-failure
// markers BEFORE it honours the phase class, so a server's wording ("Access denied: too many connections") must never
// sit in a leaf: the server text is carried by a wrapper message, the leaf is one of these marker-free sentinels
// (WF24 G2, class K2).
var (
	errPhaseTransient = errors.New("ftp: the server answered a connect-phase command with a temporary refusal")
	errPhaseRefused   = errors.New("ftp: the server refused a connect-phase command")
	errUserRefused    = errors.New("ftp: the server refused the user name before any password was sent")
	errPassRejected   = errors.New("ftp: the server rejected the password step with a reply that is not a credential verdict")
	errPassUnknown    = errors.New("ftp: the outcome of the password step is unknown")
)

// listViolation is protoViolation for a reply whose SHAPE is wrong (an MLST with no entry or several); it also is an
// ErrListingIncomplete, which is how callers and tests recognise an unusable listing reply.
func listViolation(format string, a ...any) error {
	return fabric.MarkTransient(fmt.Errorf("%w: %w: "+format, append([]any{ErrProtocol, ErrListingIncomplete}, a...)...))
}

// protoViolation builds a lock-step violation: ErrProtocol, transient. The connection is already dropped when this is
// returned, so a retry (Retrying on the scan path) runs on a fresh connection that is in step again (WF24 G11).
func protoViolation(format string, a ...any) error {
	return fabric.MarkTransient(fmt.Errorf("%w: "+format, append([]any{ErrProtocol}, a...)...))
}

type protoOpts struct {
	dialTimeout  time.Duration
	ioTimeout    time.Duration
	maxReply     int
	disableEPSV  bool
	loginBackoff time.Duration // 0 selects DefaultLoginBackoff, negative disables the back-off
}

// proto is one FTP control connection plus at most one data connection.
type proto struct {
	o        protoOpts
	raw      net.Conn // the TCP connection
	ctl      net.Conn // raw, or the TLS connection over raw
	br       *bufio.Reader
	tlsCfg   *tls.Config
	protP    bool // data connections are TLS
	remoteIP string
	feats    map[string]string
	skipEPSV bool
	// utf8On: OPTS UTF8 ON was accepted, so names are UTF-8 by agreement. When it is false (the server did not list UTF8,
	// or refused the switch - pure-ftpd answers 504) connect still succeeds, and listings check the names they return
	// (WF24 G9: not only after a refusal).
	utf8On bool
	// passWritten: the PASS command has been written on this connection (the password may have been seen and counted).
	passWritten bool
	// loginKey identifies host:port + user for the login back-off (set by connect).
	loginKey string

	aborted atomic.Bool

	mu       sync.Mutex
	broken   bool
	closed   bool
	phaseEnd time.Time // connect-phase deadline; zero once connected
	data     *dconn
}

// dialTCP opens the control connection; a variable only so that a test can make the dial slow.
var dialTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
	return d.DialContext(ctx, "tcp", addr)
}

func dialProto(ctx context.Context, host string, port int, o protoOpts, tlsCfg *tls.Config) (*proto, error) {
	// ONE budget for the whole connect: it starts BEFORE the TCP dial, so the dial and the phases after it share
	// DialTimeout (WF24 G12: it used to start after the dial, so the worst case was twice DialTimeout).
	var phaseEnd time.Time
	if o.dialTimeout > 0 {
		phaseEnd = time.Now().Add(o.dialTimeout)
	}
	d := net.Dialer{Timeout: o.dialTimeout}
	raw, err := dialTCP(ctx, &d, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	p := &proto{o: o, raw: raw, ctl: raw, br: bufio.NewReaderSize(raw, controlLineBytes), tlsCfg: tlsCfg, feats: map[string]string{}, remoteIP: host}
	if ta, ok := raw.RemoteAddr().(*net.TCPAddr); ok {
		p.remoteIP = ta.IP.String()
	}
	p.phaseEnd = phaseEnd
	return p, nil
}

func (p *proto) isBroken() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.broken
}

func (p *proto) markBroken() {
	p.mu.Lock()
	p.broken = true
	p.mu.Unlock()
}

func (p *proto) endPhase() {
	p.mu.Lock()
	p.phaseEnd = time.Time{}
	p.mu.Unlock()
}

// deadline is the deadline of the next blocking I/O for ctx.
func (p *proto) deadline(ctx context.Context) time.Time { return p.deadlineFrom(ctx, time.Now()) }

// deadlineFrom is the deadline of an I/O whose IOTimeout budget started at start (a whole control reply shares one budget).
func (p *proto) deadlineFrom(ctx context.Context, start time.Time) time.Time {
	return p.deadlineFor(ctx, start, p.o.ioTimeout)
}

// deadlineFor is deadlineFrom with an explicit budget (an early-closed download waits less than a full IOTimeout).
func (p *proto) deadlineFor(ctx context.Context, start time.Time, budget time.Duration) time.Time {
	d := start.Add(budget)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		d = cd
	}
	p.mu.Lock()
	pe := p.phaseEnd
	p.mu.Unlock()
	if !pe.IsZero() && pe.Before(d) {
		d = pe
	}
	return d
}

// interrupt aborts everything that is blocked on this connection and poisons it (Disconnect, a cancelled command).
func (p *proto) interrupt() {
	p.aborted.Store(true)
	p.mu.Lock()
	p.broken = true
	ctl, d := p.ctl, p.data
	p.mu.Unlock()
	if ctl != nil {
		_ = ctl.SetDeadline(time.Now())
	}
	if d != nil {
		d.abortNow()
	}
}

// quit says goodbye (best effort, bounded) and closes both connections. It is idempotent.
func (p *proto) quit() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	ctl, d := p.ctl, p.data
	p.mu.Unlock()
	if d != nil {
		_ = d.Close()
	}
	if ctl != nil {
		_ = ctl.SetWriteDeadline(time.Now().Add(quitTimeout))
		_, _ = ctl.Write([]byte("QUIT\r\n"))
		_ = ctl.Close()
	}
	if p.raw != nil {
		_ = p.raw.Close()
	}
}

// hardClose closes without saying goodbye (a connection nobody can talk to).
func (p *proto) hardClose() {
	p.mu.Lock()
	p.closed = true
	ctl, d := p.ctl, p.data
	p.mu.Unlock()
	if d != nil {
		_ = d.Close()
	}
	if ctl != nil {
		_ = ctl.Close()
	}
	if p.raw != nil {
		_ = p.raw.Close()
	}
}

// ---------------------------------------------------------------------------------------------------------
// control channel

func escapeIAC(s string) string { return strings.ReplaceAll(s, "\xff", "\xff\xff") } // RFC 854: a data byte 0xFF is doubled

func verbOf(line string) string {
	v, _, _ := strings.Cut(line, " ")
	return v
}

func flat(s string) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " | ")), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func (p *proto) readLine() (string, error) {
	b, err := p.br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", fmt.Errorf("%w: control line longer than %d bytes", ErrReplyTooLarge, p.br.Size())
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", io.ErrUnexpectedEOF
		}
		return "", err
	}
	s := string(b)
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return s, nil
}

// readReply reads one complete reply (RFC 959 multi-line included) with its size bound. It does not judge the code.
func (p *proto) readReply(ctx context.Context) (int, []string, error) {
	return p.readReplyBudget(ctx, p.o.ioTimeout)
}

// readReplyBudget is readReply with an explicit time budget for the whole reply.
func (p *proto) readReplyBudget(ctx context.Context, budget time.Duration) (int, []string, error) {
	var (
		lines []string
		total int
		code  string
		multi bool
	)
	start := time.Now() // the whole reply, all its lines, gets ONE IOTimeout budget (a server dripping one byte a minute is not "alive")
	for first := true; ; first = false {
		_ = p.ctl.SetReadDeadline(p.deadlineFor(ctx, start, budget))
		if p.aborted.Load() {
			return 0, nil, ErrAborted
		}
		line, err := p.readLine()
		if err != nil {
			return 0, nil, err
		}
		total += len(line) + 2
		if total > p.o.maxReply {
			return 0, nil, ErrReplyTooLarge
		}
		if first {
			if len(line) < 3 || !isDigits(line[:3]) || (len(line) > 3 && line[3] != ' ' && line[3] != '-') {
				return 0, nil, fmt.Errorf("%w: not a reply line: %q", ErrProtocol, flat(line))
			}
			code = line[:3]
			multi = len(line) > 3 && line[3] == '-'
			text := ""
			if len(line) > 4 {
				text = line[4:]
			}
			lines = append(lines, text)
			if !multi {
				break
			}
			continue
		}
		if len(line) >= 3 && line[:3] == code && (len(line) == 3 || line[3] == ' ') {
			text := ""
			if len(line) > 4 {
				text = line[4:]
			}
			lines = append(lines, text)
			break
		}
		lines = append(lines, line)
	}
	n, _ := strconv.Atoi(code)
	return n, lines, nil
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func contains(codes []int, c int) bool {
	for _, x := range codes {
		if x == c {
			return true
		}
	}
	return false
}

// judge applies the command/reply discipline to a read reply.
func (p *proto) judge(ctx context.Context, verb string, code int, lines []string, expect []int) (int, []string, error) {
	switch {
	case code >= 400:
		if code == 421 {
			p.markBroken() // the server is closing the control connection
		}
		return code, lines, &textproto.Error{Code: code, Msg: strings.Join(lines, "\n")}
	case expect == nil || contains(expect, code):
		return code, lines, nil
	default:
		p.markBroken()
		return code, lines, protoViolation("reply %d to %s", code, verb)
	}
}

// fail records an I/O failure of the control channel and maps a context end to the context's error.
func (p *proto) fail(ctx context.Context, err error) error {
	p.markBroken()
	if ce := ctx.Err(); ce != nil {
		return fmt.Errorf("ftp: %w (%v)", ce, err)
	}
	if cd, ok := ctx.Deadline(); ok && !time.Now().Before(cd.Add(-5*time.Millisecond)) {
		// the I/O deadline IS the ctx deadline, so the I/O timeout can fire a hair before ctx.Err() flips
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("ftp: %w (%v)", context.DeadlineExceeded, err)
		}
	}
	if errors.Is(err, ErrAborted) {
		return err
	}
	if p.aborted.Load() {
		return ErrAborted
	}
	return err
}

// reply reads and judges the next reply without sending anything.
func (p *proto) reply(ctx context.Context, verb string, expect []int) (int, []string, error) {
	return p.replyBudget(ctx, verb, expect, p.o.ioTimeout)
}

// replyBudget is reply with an explicit time budget for the whole reply.
func (p *proto) replyBudget(ctx context.Context, verb string, expect []int, budget time.Duration) (int, []string, error) {
	stop := context.AfterFunc(ctx, p.interrupt)
	defer stop()
	if p.isBroken() {
		return 0, nil, p.fail(ctx, io.ErrClosedPipe)
	}
	code, lines, err := p.readReplyBudget(ctx, budget)
	if err != nil {
		return 0, nil, p.fail(ctx, err)
	}
	return p.judge(ctx, verb, code, lines, expect)
}

// drain proves that nothing is waiting on the control channel: no byte in the read buffer and none arriving within
// wait. Anything there is a reply nobody asked for (the connection is dropped, ErrProtocol, transient); a peer that
// closed the connection while idle is reported as the I/O failure it is. The check arms a short read deadline, so an
// abort (interrupt) that happens meanwhile is re-checked and never undone.
func (p *proto) drain(ctx context.Context, what string, wait time.Duration) error {
	if p.br.Buffered() > 0 {
		p.markBroken()
		return protoViolation("unsolicited data %s", what)
	}
	_ = p.ctl.SetReadDeadline(time.Now().Add(wait))
	if p.aborted.Load() {
		return p.fail(ctx, ErrAborted)
	}
	_, err := p.br.Peek(1)
	if p.aborted.Load() {
		return p.fail(ctx, ErrAborted)
	}
	if err == nil {
		p.markBroken()
		return protoViolation("unsolicited data %s", what)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil // nothing waiting: in step
	}
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return p.fail(ctx, err)
}

// cmd sends one command and reads its reply. expect lists the accepted positive codes (nil accepts any 1yz-3yz).
// A 4yz/5yz reply is returned as *textproto.Error and leaves the connection usable, except 421.
func (p *proto) cmd(ctx context.Context, expect []int, format string, a ...any) (int, []string, error) {
	stop := context.AfterFunc(ctx, p.interrupt)
	defer stop()
	line := fmt.Sprintf(format, a...)
	verb := verbOf(line)
	if strings.ContainsAny(line, "\r\n\x00") {
		return 0, nil, fmt.Errorf("%w: control characters in a %s command", ErrPathEscape, verb)
	}
	if p.isBroken() {
		return 0, nil, p.fail(ctx, io.ErrClosedPipe)
	}
	// bytes nobody asked for (an extra reply of an earlier command) in the buffer OR still in the kernel socket buffer:
	// everything after them is out of step (WF24 G1(a): the bufio check alone cannot see a reply that is still in flight)
	if err := p.drain(ctx, "before "+verb, drainWait); err != nil {
		return 0, nil, err
	}
	_ = p.ctl.SetWriteDeadline(p.deadline(ctx))
	if p.aborted.Load() {
		return 0, nil, p.fail(ctx, ErrAborted)
	}
	if _, err := p.ctl.Write([]byte(escapeIAC(line) + "\r\n")); err != nil {
		return 0, nil, p.fail(ctx, err)
	}
	if verb == "PASS" {
		p.mu.Lock()
		p.passWritten = true
		p.mu.Unlock()
	}
	code, lines, err := p.readReply(ctx)
	if err != nil {
		return 0, nil, p.fail(ctx, err)
	}
	return p.judge(ctx, verb, code, lines, expect)
}

// stepErr classifies a failure of a connect phase (before PASS): a network failure or a 4yz reply is transient, a
// 5yz reply is a permanent configuration failure, never an authentication failure.
func (p *proto) stepErr(ctx context.Context, phase string, err error) error {
	if err == nil {
		return nil
	}
	if ce := ctx.Err(); ce != nil {
		return fmt.Errorf("ftp: %s: %w", phase, ce)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("ftp: %s: %w", phase, err)
	}
	var te *textproto.Error
	if errors.As(err, &te) {
		if te.Code/100 == 4 {
			return fabric.MarkTransient(fmt.Errorf("ftp: %s: %d %s: %w", phase, te.Code, flat(te.Msg), errPhaseTransient))
		}
		return fmt.Errorf("ftp: %s refused by the server: %d %s: %w", phase, te.Code, flat(te.Msg), errPhaseRefused)
	}
	if errors.Is(err, ErrProtocol) || errors.Is(err, ErrReplyTooLarge) || errors.Is(err, ErrAborted) {
		return fmt.Errorf("ftp: %s: %w", phase, err)
	}
	if isNetErr(err) {
		return fabric.MarkTransient(fmt.Errorf("ftp: %s: %w", phase, err))
	}
	return fmt.Errorf("ftp: %s: %w", phase, err)
}

// banner reads the 220 greeting.
func (p *proto) banner(ctx context.Context) error {
	_, _, err := p.reply(ctx, "banner", []int{220})
	return p.stepErr(ctx, "greeting", err)
}

// authTLS asks for the explicit TLS upgrade. A refusal is final: there is no clear-text fallback.
func (p *proto) authTLS(ctx context.Context) error {
	_, _, err := p.cmd(ctx, []int{234}, "AUTH TLS")
	if err != nil {
		var te *textproto.Error
		if errors.As(err, &te) && te.Code/100 == 5 {
			return fmt.Errorf("ftp: AUTH TLS refused: %d %s: %w", te.Code, flat(te.Msg), ErrTLSNotOffered)
		}
		return p.stepErr(ctx, "AUTH TLS", err)
	}
	return nil
}

// startTLS runs the TLS handshake over the control connection. The caller maps the error (pin errors).
func (p *proto) startTLS(ctx context.Context) error {
	if p.br.Buffered() > 0 {
		p.markBroken()
		return fmt.Errorf("%w: data received before the TLS handshake", ErrProtocol)
	}
	stop := context.AfterFunc(ctx, p.interrupt)
	defer stop()
	tc := tls.Client(p.raw, p.tlsCfg)
	p.mu.Lock()
	p.ctl = tc
	p.mu.Unlock()
	p.br = bufio.NewReaderSize(tc, controlLineBytes)
	_ = tc.SetDeadline(p.deadline(ctx))
	if err := tc.HandshakeContext(ctx); err != nil {
		p.markBroken()
		return err
	}
	return nil
}

// login authenticates and prepares the session. Classification by phase:
//
//	USER      421 and other 4yz transient; 530/332/532 and other 5yz permanent - NEVER authentication: no password was sent,
//	          so a USER-phase refusal ("too many connections", "user not allowed") cannot be a lockout and must not latch the
//	          pool (WF24 G2); the server's text is carried by a wrapper, never by the leaf Classify scans
//	PASS      530/430/534/535/332/532 authentication; ANYTHING else, including a connection lost before the reply, is
//	          permanent, is never retried, and starts the login back-off (a retry would send the password again: lockout
//	          risk; the back-off covers every client of the process, WF24 G3)
//	FEAT      a refusal means "no features"; I/O failures are transient
//	TYPE, OPTS UTF8, PBSZ, PROT   a refusal is a permanent configuration failure, never an authentication failure
func (p *proto) login(ctx context.Context, user, pass string, disableMLSD bool) error {
	code, _, err := p.cmd(ctx, []int{230, 331}, "USER %s", user)
	if err != nil {
		return p.userErr(ctx, code, err)
	}
	if code == 331 {
		code, _, err = p.cmd(ctx, []int{230, 202}, "PASS %s", pass)
		if err != nil {
			return p.passErr(ctx, user, code, err)
		}
	}
	// FEAT is advisory: its refusal is not an error
	fcode, lines, err := p.cmd(ctx, nil, "FEAT")
	if err != nil {
		var te *textproto.Error
		if !errors.As(err, &te) || te.Code == 421 {
			return p.stepErr(ctx, "FEAT", err)
		}
		lines = nil
	} else if fcode != 211 {
		lines = nil
	}
	for _, l := range lines {
		if strings.HasPrefix(l, " ") {
			k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
			p.feats[strings.ToUpper(k)] = v
		}
	}
	if disableMLSD {
		delete(p.feats, "MLST")
	}
	if _, _, err = p.cmd(ctx, []int{200}, "TYPE I"); err != nil {
		return p.stepErr(ctx, "TYPE I", err)
	}
	if _, ok := p.feats["UTF8"]; ok {
		if _, _, err = p.cmd(ctx, []int{200, 202}, "OPTS UTF8 ON"); err != nil {
			var te *textproto.Error
			if !errors.As(err, &te) || te.Code/100 == 4 {
				return p.stepErr(ctx, "OPTS UTF8 ON", err)
			}
			// 5yz: the server will not switch (pure-ftpd answers 504); names stay checked, see utf8On
		} else {
			p.utf8On = true
		}
	}
	if p.tlsCfg != nil {
		if _, _, err = p.cmd(ctx, []int{200}, "PBSZ 0"); err != nil {
			return p.stepErr(ctx, "PBSZ", err)
		}
		if _, _, err = p.cmd(ctx, []int{200}, "PROT P"); err != nil {
			return p.stepErr(ctx, "PROT P", err)
		}
		p.protP = true
	}
	return nil
}

func (p *proto) userErr(ctx context.Context, code int, err error) error {
	if code == 332 && errors.Is(err, ErrProtocol) {
		// "need account" is a 3yz reply the lock-step does not expect at USER (it also dropped the connection): the
		// account step (ACCT) is not supported, which is a configuration refusal, not a transient fault
		return fmt.Errorf("ftp: login refused at USER (no password was sent): 332 the server wants an account (ACCT is not supported): %w", errUserRefused)
	}
	var te *textproto.Error
	if errors.As(err, &te) && (te.Code == 530 || te.Code == 532 || te.Code == 332) {
		// no password was sent: this cannot be a lockout and must not latch the pool root (WF24 G2). The server's text
		// is in the wrapper, the leaf is marker-free, so fabric.Classify cannot read it as a credential failure.
		return fmt.Errorf("ftp: login refused at USER (no password was sent): %d %s: %w", te.Code, flat(te.Msg), errUserRefused)
	}
	return p.stepErr(ctx, "USER", err)
}

// passErr classifies a failure of the PASS step. A definite credential verdict (530, 430, 534, 535, 332, 532) is
// authentication (never retried; the pool latches the root). Everything else - no reply, a reply that is not a
// credential verdict, the context ending after the password was written - is AMBIGUOUS: the server may have counted
// an attempt, so the failure is permanent AND the login back-off is started, which refuses the next login of this
// host and user from ANY client of the process before a password is sent again (WF24 G3).
func (p *proto) passErr(ctx context.Context, user string, code int, err error) error {
	p.mu.Lock()
	written := p.passWritten
	p.mu.Unlock()
	if ce := ctx.Err(); ce != nil {
		if written {
			noteAmbiguousLogin(p.loginKey, p.o.loginBackoff)
		}
		return fmt.Errorf("ftp: login: %w", ce)
	}
	if code == 332 && errors.Is(err, ErrProtocol) {
		// "need account" at PASS: the credentials are not enough (a verdict about the credentials, not an unknown outcome)
		return fabric.MarkAuth(fmt.Errorf("ftp: login as %q failed: 332 the server wants an account (ACCT is not supported)", user))
	}
	var te *textproto.Error
	if errors.As(err, &te) {
		switch te.Code {
		case 530, 430, 534, 535, 332, 532:
			return fabric.MarkAuth(fmt.Errorf("ftp: login as %q failed: %d %s", user, te.Code, flat(te.Msg)))
		}
		noteAmbiguousLogin(p.loginKey, p.o.loginBackoff)
		return fmt.Errorf("ftp: PASS rejected: %d %s (not retried: a retry would send the password again): %w", te.Code, flat(te.Msg), errPassRejected)
	}
	// no reply to PASS (or an unexpected one): not retryable, and deliberately not wrapped (a wrapped network error is
	// classified transient by fabric.Classify)
	if written {
		noteAmbiguousLogin(p.loginKey, p.o.loginBackoff)
	}
	return fmt.Errorf("ftp: connection failed after the password was sent (%v); not retried, a retry would send it again: %w", err, errPassUnknown)
}

// ---------------------------------------------------------------------------------------------------------
// data channel

// dconn is a data connection: deadlines are re-armed per I/O, and an abort cannot be overwritten.
type dconn struct {
	net.Conn
	p       *proto
	ctx     context.Context
	tls     bool
	aborted atomic.Bool
	once    sync.Once
	// maxWait, when > 0, caps the wait of every read (nanoseconds): the seeker reads the end of a transfer with it, so a
	// server that does not close the data connection after the announced SIZE does not cost a whole IOTimeout.
	maxWait atomic.Int64
}

func (d *dconn) abortNow() {
	d.aborted.Store(true)
	_ = d.Conn.SetDeadline(time.Now())
}

func (d *dconn) abortErr() error {
	if e := d.ctx.Err(); e != nil {
		return e
	}
	return ErrAborted
}

func (d *dconn) Read(b []byte) (int, error) {
	if d.aborted.Load() {
		return 0, d.abortErr()
	}
	dl := d.p.deadline(d.ctx)
	if w := d.maxWait.Load(); w > 0 {
		if e := time.Now().Add(time.Duration(w)); e.Before(dl) {
			dl = e
		}
	}
	_ = d.Conn.SetReadDeadline(dl)
	if d.aborted.Load() { // abort between the first check and arming: arming must not undo it
		return 0, d.abortErr()
	}
	n, err := d.Conn.Read(b)
	if err != nil && !errors.Is(err, io.EOF) {
		if d.aborted.Load() {
			return n, d.abortErr()
		}
		if d.tls && errors.Is(err, io.ErrUnexpectedEOF) {
			// many servers close the data channel without close_notify; the verdict is the (TLS protected) final
			// reply on the control channel, which a transfer must still produce
			return n, io.EOF
		}
	}
	return n, err
}

func (d *dconn) Write(b []byte) (int, error) {
	if d.aborted.Load() {
		return 0, d.abortErr()
	}
	_ = d.Conn.SetWriteDeadline(d.p.deadline(d.ctx))
	if d.aborted.Load() {
		return 0, d.abortErr()
	}
	n, err := d.Conn.Write(b)
	if err != nil && d.aborted.Load() {
		err = d.abortErr()
	}
	return n, err
}

func (d *dconn) Close() error {
	var err error
	d.once.Do(func() {
		if !d.aborted.Load() {
			_ = d.Conn.SetWriteDeadline(time.Now().Add(quitTimeout)) // bounds the TLS close_notify
		}
		err = d.Conn.Close()
		d.p.mu.Lock()
		if d.p.data == d {
			d.p.data = nil
		}
		d.p.mu.Unlock()
	})
	return err
}

// parseEPSV reads the port of a 229 reply. RFC 2428: "(<d><d><d><port><d>)" where <d> is ANY printable delimiter
// character (33..126), usually "|"; a reply without parentheses is read the lenient way (the first "|||").
func parseEPSV(line string) (int, bool) {
	if i, j := strings.Index(line, "("), strings.LastIndex(line, ")"); i >= 0 && j > i+4 {
		in := line[i+1 : j]
		d := in[0]
		if d >= 33 && d <= 126 && d != '(' && d != ')' && len(in) >= 5 && in[1] == d && in[2] == d && in[len(in)-1] == d {
			n, err := strconv.Atoi(in[3 : len(in)-1])
			if err == nil && n > 0 && n < 65536 {
				return n, true
			}
			return 0, false
		}
	}
	start := strings.Index(line, "|||")
	end := strings.LastIndex(line, "|")
	if start < 0 || start+3 >= end {
		return 0, false
	}
	n, err := strconv.Atoi(line[start+3 : end])
	return n, err == nil && n > 0 && n < 65536
}

func parsePASV(line string) (int, bool) {
	start, end := strings.Index(line, "("), strings.LastIndex(line, ")")
	if start < 0 || end < start {
		return 0, false
	}
	f := strings.Split(line[start+1:end], ",")
	if len(f) != 6 {
		return 0, false
	}
	p1, e1 := strconv.Atoi(strings.TrimSpace(f[4]))
	p2, e2 := strconv.Atoi(strings.TrimSpace(f[5]))
	n := p1*256 + p2
	return n, e1 == nil && e2 == nil && n > 0 && n < 65536
}

// passivePort asks for a passive port. The host is always the control connection's peer: the address in a PASV
// reply is never trusted (SSRF).
func (p *proto) passivePort(ctx context.Context) (int, error) {
	if !p.o.disableEPSV && !p.skipEPSV {
		_, lines, err := p.cmd(ctx, []int{229}, "EPSV")
		if err == nil {
			if port, ok := parseEPSV(strings.Join(lines, " ")); ok {
				return port, nil
			}
		}
		if err == nil {
			// a 229 whose text holds no port is a reply we cannot read: the lock-step is in doubt (WF24 K1.g)
			p.markBroken()
			return 0, protoViolation("unusable EPSV reply")
		}
		if p.isBroken() {
			return 0, err
		}
		p.skipEPSV = true
	}
	_, lines, err := p.cmd(ctx, []int{227}, "PASV")
	if err != nil {
		return 0, err
	}
	port, ok := parsePASV(strings.Join(lines, " "))
	if !ok {
		p.markBroken()
		return 0, protoViolation("unusable PASV reply")
	}
	return port, nil
}

func (p *proto) openData(ctx context.Context) (*dconn, error) {
	port, err := p.passivePort(ctx)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: p.o.dialTimeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.remoteIP, strconv.Itoa(port)))
	if err != nil {
		return nil, p.fail(ctx, err)
	}
	var nc net.Conn = c
	if p.protP {
		nc = tls.Client(c, p.tlsCfg) // the handshake runs on the first Read/Write, i.e. after the transfer command
	}
	dc := &dconn{Conn: nc, p: p, ctx: ctx, tls: p.protP}
	p.mu.Lock()
	p.data = dc
	ab := p.aborted.Load()
	p.mu.Unlock()
	if ab {
		dc.abortNow()
	}
	return dc, nil
}

// beginTransfer opens the data connection, optionally positions with REST, and starts the transfer command.
func (p *proto) beginTransfer(ctx context.Context, offset uint64, format string, a ...any) (*dconn, error) {
	dc, err := p.openData(ctx)
	if err != nil {
		return nil, err
	}
	if offset != 0 {
		if _, _, err = p.cmd(ctx, []int{350}, "REST %d", offset); err != nil {
			_ = dc.Close()
			return nil, err
		}
	}
	if _, _, err = p.cmd(ctx, []int{125, 150}, format, a...); err != nil {
		_ = dc.Close()
		return nil, err
	}
	return dc, nil
}

// finishTransfer closes the data connection and consumes the transfer's final reply. complete says the data ended
// cleanly (EOF for a download, everything written for an upload): then the reply must be 226/250 and a negative
// reply is returned. An early close (the caller stopped reading) accepts whatever the server says, then proves the
// control channel is still in step with a NOOP: a server that answers an early close with TWO replies fails the
// NOOP and the connection is dropped instead of silently answering the next command with a stale reply.
// (Measured: pure-ftpd answers an early-closed download with ONE reply, "150 <statistics>" over TLS, 226 in clear
// text.)
func (p *proto) finishTransfer(ctx context.Context, dc *dconn, complete bool) error {
	_ = dc.Close()
	if p.isBroken() {
		if complete {
			return errors.New("ftp: the connection was lost before the transfer's final reply, so the transfer cannot be confirmed")
		}
		return nil
	}
	if complete {
		if _, _, err := p.reply(ctx, "transfer", []int{226, 250}); err != nil {
			return err
		}
		return p.trailing(ctx)
	}
	// Early close: the first reply may be 226/250 (the transfer had finished), 426/451/450 (aborted) or, measured
	// against pure-ftpd over TLS, "150 <statistics>"; the lock-step check below is what proves nothing else follows.
	// The wait is bounded by earlyCloseWait: pure-ftpd sometimes never answers a download closed after a few bytes
	// (WF24 G5: 30 s until the IOTimeout, measured in the round-3 trace); the connection is then dropped, not waited for.
	wait := p.o.ioTimeout
	if wait > earlyCloseWait {
		wait = earlyCloseWait
	}
	_, _, err := p.replyBudget(ctx, "transfer", nil, wait)
	var te *textproto.Error
	if err != nil && !errors.As(err, &te) {
		return nil // broken is recorded; the caller already stopped reading
	}
	if _, _, err = p.cmd(ctx, []int{200}, "NOOP"); err != nil {
		p.markBroken()
	}
	return nil
}

// trailing looks for a second reply right behind the final reply of a COMPLETE transfer (an extra 226 of an earlier
// transfer that was taken for this one's final reply would mask the real, possibly negative, one). A second reply drops
// the connection; when it is itself negative it is the transfer's real verdict and is returned. Best effort: a reply
// more than postTransferWait behind is caught by the drain check of the next command.
func (p *proto) trailing(ctx context.Context) error {
	if p.isBroken() {
		return nil
	}
	if p.br.Buffered() == 0 {
		_ = p.ctl.SetReadDeadline(time.Now().Add(postTransferWait))
		if p.aborted.Load() {
			return nil
		}
		if _, err := p.br.Peek(1); err != nil {
			return nil // nothing there (timeout), or the peer closed: the next command finds out
		}
	}
	p.markBroken()
	tctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	code, lines, err := p.readReplyBudget(tctx, time.Second)
	if err == nil && code >= 400 {
		return &textproto.Error{Code: code, Msg: strings.Join(lines, "\n")}
	}
	return nil
}

// list runs a listing command (MLSD or LIST) and feeds every line to onLine. A line onLine rejects does not stop the
// transfer (it is read to its end so that the connection stays in step); the first such error is returned at the end.
func (p *proto) list(ctx context.Context, maxEntries, maxBytes int, onLine func(string) error, format string, a ...any) error {
	dc, err := p.beginTransfer(ctx, 0, format, a...)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(dc, maxLineBytes)
	var first error
	n, total := 0, 0
	for {
		b, rerr := br.ReadSlice('\n')
		if errors.Is(rerr, bufio.ErrBufferFull) {
			p.markBroken()
			_ = dc.Close()
			return fmt.Errorf("%w: listing line longer than %d bytes", ErrListingIncomplete, br.Size())
		}
		if len(b) > 0 {
			line := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
			n++
			total += len(b)
			if n > maxEntries || total > maxBytes {
				p.markBroken()
				_ = dc.Close()
				return ErrListingTooLarge
			}
			if line != "" {
				if lerr := onLine(line); lerr != nil && first == nil {
					first = lerr
				}
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			p.markBroken()
			_ = dc.Close()
			return p.fail(ctx, rerr)
		}
	}
	if err := p.finishTransfer(ctx, dc, true); err != nil {
		return err
	}
	return first
}

// pwd returns the current directory.
func (p *proto) pwd(ctx context.Context) (string, error) {
	_, lines, err := p.cmd(ctx, []int{257}, "PWD")
	if err != nil {
		return "", err
	}
	s := strings.Join(lines, "\n")
	i := strings.IndexByte(s, '"')
	if i < 0 {
		p.markBroken()
		return "", protoViolation("unsupported PWD reply %q", flat(s))
	}
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		if s[j] == '"' {
			if j+1 < len(s) && s[j+1] == '"' { // "" is a quote inside the name (RFC 959)
				b.WriteByte('"')
				j++
				continue
			}
			return b.String(), nil
		}
		b.WriteByte(s[j])
	}
	p.markBroken()
	return "", protoViolation("unsupported PWD reply %q", flat(s))
}

func (p *proto) mlstOK() bool { _, ok := p.feats["MLST"]; return ok }
