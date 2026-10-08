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
	DefaultMaxReplyBytes  = 1 << 20 // one control reply, all its lines
	DefaultMaxListEntries = 1 << 20 // lines of one MLSD/LIST listing
	maxLineBytes          = 16 << 10
	quitTimeout           = 2 * time.Second
)

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
)

type protoOpts struct {
	dialTimeout time.Duration
	ioTimeout   time.Duration
	maxReply    int
	disableEPSV bool
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
	// utf8Refused: FEAT listed UTF8 but the server answered OPTS UTF8 ON with a refusal. Connect still succeeds (a
	// server that is always UTF-8 says no to a switch it does not need); listings check the names they return.
	utf8Refused bool

	aborted atomic.Bool

	mu       sync.Mutex
	broken   bool
	closed   bool
	phaseEnd time.Time // connect-phase deadline; zero once connected
	data     *dconn
}

func dialProto(ctx context.Context, host string, port int, o protoOpts, tlsCfg *tls.Config) (*proto, error) {
	d := net.Dialer{Timeout: o.dialTimeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	p := &proto{o: o, raw: raw, ctl: raw, br: bufio.NewReaderSize(raw, 4096), tlsCfg: tlsCfg, feats: map[string]string{}, remoteIP: host}
	if ta, ok := raw.RemoteAddr().(*net.TCPAddr); ok {
		p.remoteIP = ta.IP.String()
	}
	if o.dialTimeout > 0 {
		p.phaseEnd = time.Now().Add(o.dialTimeout)
	}
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
	d := start.Add(p.o.ioTimeout)
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
	var (
		lines []string
		total int
		code  string
		multi bool
	)
	start := time.Now() // the whole reply, all its lines, gets ONE IOTimeout budget (a server dripping one byte a minute is not "alive")
	for first := true; ; first = false {
		_ = p.ctl.SetReadDeadline(p.deadlineFrom(ctx, start))
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
		return code, lines, fmt.Errorf("%w: reply %d to %s", ErrProtocol, code, verb)
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
	stop := context.AfterFunc(ctx, p.interrupt)
	defer stop()
	if p.isBroken() {
		return 0, nil, p.fail(ctx, io.ErrClosedPipe)
	}
	code, lines, err := p.readReply(ctx)
	if err != nil {
		return 0, nil, p.fail(ctx, err)
	}
	return p.judge(ctx, verb, code, lines, expect)
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
	if p.br.Buffered() > 0 {
		// bytes nobody asked for (an extra reply of an earlier command): everything after them is out of step
		p.markBroken()
		return 0, nil, fmt.Errorf("%w: unsolicited data before %s", ErrProtocol, verb)
	}
	_ = p.ctl.SetWriteDeadline(p.deadline(ctx))
	if p.aborted.Load() {
		return 0, nil, p.fail(ctx, ErrAborted)
	}
	if _, err := p.ctl.Write([]byte(escapeIAC(line) + "\r\n")); err != nil {
		return 0, nil, p.fail(ctx, err)
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
			return fabric.MarkTransient(fmt.Errorf("ftp: %s: %d %s", phase, te.Code, flat(te.Msg)))
		}
		return fmt.Errorf("ftp: %s refused by the server: %d %s", phase, te.Code, flat(te.Msg))
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
			return fmt.Errorf("ftp: server does not offer explicit TLS (AUTH TLS: %d %s); clear text is never used as a fallback", te.Code, flat(te.Msg))
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
	p.br = bufio.NewReaderSize(tc, 4096)
	_ = tc.SetDeadline(p.deadline(ctx))
	if err := tc.HandshakeContext(ctx); err != nil {
		p.markBroken()
		return err
	}
	return nil
}

// login authenticates and prepares the session. Classification by phase:
//
//	USER      421 and other 4yz transient; 530 (and 332/532) authentication; other 5yz permanent
//	PASS      530/430/534/535/332/532 authentication; ANYTHING else, including a connection lost before the reply, is
//	          permanent and is never retried (a retry would send the password again: lockout risk)
//	FEAT      a refusal means "no features"; I/O failures are transient
//	TYPE, OPTS UTF8, PBSZ, PROT   a refusal is a permanent configuration failure, never an authentication failure
func (p *proto) login(ctx context.Context, user, pass string, disableMLSD bool) error {
	code, _, err := p.cmd(ctx, []int{230, 331}, "USER %s", user)
	if err != nil {
		return p.userErr(ctx, err)
	}
	if code == 331 {
		_, _, err = p.cmd(ctx, []int{230, 202}, "PASS %s", pass)
		if err != nil {
			return p.passErr(ctx, user, err)
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
			p.utf8Refused = true // 5yz: the server will not switch; see utf8Refused
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

func (p *proto) userErr(ctx context.Context, err error) error {
	var te *textproto.Error
	if errors.As(err, &te) && (te.Code == 530 || te.Code == 532 || te.Code == 332) {
		return fabric.MarkAuth(fmt.Errorf("ftp: login refused at USER: %d %s", te.Code, flat(te.Msg)))
	}
	return p.stepErr(ctx, "USER", err)
}

func (p *proto) passErr(ctx context.Context, user string, err error) error {
	if ce := ctx.Err(); ce != nil {
		return fmt.Errorf("ftp: login: %w", ce)
	}
	var te *textproto.Error
	if errors.As(err, &te) {
		switch te.Code {
		case 530, 430, 534, 535, 332, 532:
			return fabric.MarkAuth(fmt.Errorf("ftp: login as %q failed: %d %s", user, te.Code, flat(te.Msg)))
		}
		return fmt.Errorf("ftp: PASS rejected: %d %s (not retried: a retry would send the password again)", te.Code, flat(te.Msg))
	}
	// no reply to PASS (or an unexpected one): not retryable, and deliberately not wrapped (a wrapped network error is
	// classified transient by fabric.Classify)
	return fmt.Errorf("ftp: connection failed after the password was sent (%v); not retried, a retry would send it again", err)
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
	_ = d.Conn.SetReadDeadline(d.p.deadline(d.ctx))
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

func parseEPSV(line string) (int, bool) {
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
		if p.isBroken() {
			if err == nil {
				err = fmt.Errorf("%w: unusable EPSV reply", ErrProtocol)
			}
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
		return 0, fmt.Errorf("%w: unusable PASV reply", ErrProtocol)
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
		_, _, err := p.reply(ctx, "transfer", []int{226, 250})
		return err
	}
	// Early close: the first reply may be 226/250 (the transfer had finished), 426/451/450 (aborted) or, measured
	// against pure-ftpd over TLS, "150 <statistics>"; the lock-step check below is what proves nothing else follows.
	_, _, err := p.reply(ctx, "transfer", nil)
	var te *textproto.Error
	if err != nil && !errors.As(err, &te) {
		return nil // broken is recorded; the caller already stopped reading
	}
	if _, _, err = p.cmd(ctx, []int{200}, "NOOP"); err != nil {
		p.markBroken()
	}
	return nil
}

// list runs a listing command (MLSD or LIST) and feeds every line to onLine. A line onLine rejects does not stop the
// transfer (it is read to its end so that the connection stays in step); the first such error is returned at the end.
func (p *proto) list(ctx context.Context, maxEntries int, onLine func(string) error, format string, a ...any) error {
	dc, err := p.beginTransfer(ctx, 0, format, a...)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(dc, maxLineBytes)
	var first error
	n := 0
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
			if n > maxEntries {
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
		return "", fmt.Errorf("ftp: unsupported PWD reply %q", flat(s))
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
	return "", fmt.Errorf("ftp: unsupported PWD reply %q", flat(s))
}

func (p *proto) mlstOK() bool { _, ok := p.feats["MLST"]; return ok }
