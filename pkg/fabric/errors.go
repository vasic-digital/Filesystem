package fabric

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"strings"
	"syscall"
)

// Sentinel errors of the fabric.
var (
	// ErrAuth marks an authentication/authorisation failure. It is never
	// retried: repeating a failed login can lock the account out.
	ErrAuth = errors.New("fabric: authentication failure")
	// ErrTransient marks a failure that is safe to retry.
	ErrTransient = errors.New("fabric: transient failure")
	// ErrRetriesExhausted wraps the last error after the attempt budget is spent.
	ErrRetriesExhausted = errors.New("fabric: retries exhausted")
	// ErrOutsideRoot is returned by Confined for a path that escapes its root.
	ErrOutsideRoot = errors.New("fabric: path outside the confinement root")
	// ErrNilStream is returned by a fabric layer when the inner client returned
	// a nil stream together with a nil error: handing a wrapper around nil to
	// the caller would panic on Close and leak whatever the layer holds.
	ErrNilStream = errors.New("fabric: inner client returned a nil stream without an error")
	// ErrProbeSkipped is returned by Limited.TestConnection when the host
	// budget had no free slot right now, so the probe was NOT run. It says
	// nothing about the health of the connection: Pool treats it as "no
	// evidence of a fault" and keeps the connection; a caller that needs a real
	// probe retries later. See Limited.
	ErrProbeSkipped = errors.New("fabric: connection probe skipped, the host budget is busy")
)

// MarkAuth wraps err so that Classify reports ClassAuth. Protocol glue that
// knows its own login-failure error type uses it. nil stays nil.
func MarkAuth(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrAuth, err)
}

// MarkTransient wraps err so that Classify reports ClassTransient, with two
// precedences that cannot be overridden by the mark: an error that carries a
// credential failure (MarkAuth, an auth marker in a leaf, an SMB logon status)
// stays ClassAuth - a lockout must never be retried - and a structured FTP
// reply (*textproto.Error) is decided by its reply code, so a marked 5yz reply
// stays permanent. nil stays nil.
func MarkTransient(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrTransient, err)
}

// ErrorClass is the retry class of a failure.
type ErrorClass int

const (
	// ClassPermanent is the zero value on purpose: an error nobody positively
	// identified as transient is never retried.
	ClassPermanent ErrorClass = iota
	// ClassTransient failures are retried (network drop, timeout, reset).
	ClassTransient
	// ClassAuth failures are never retried.
	ClassAuth
)

func (c ErrorClass) String() string {
	switch c {
	case ClassTransient:
		return "transient"
	case ClassAuth:
		return "auth"
	default:
		return "permanent"
	}
}

// credentialMarkers are lower-case fragments of a message that are specific to
// a refused login. They are matched against LEAF errors only (see leafErrors)
// and, for an FTP reply, only on a 4yz reply and only when no path precedes
// them (see credentialInReply): a 5yz reply other than the credential codes is
// a file-level answer ("550 Access denied" for one file is not bad
// credentials). The two "server returned status" entries are the text of
// pkg/webdav, which returns no typed error for a refused login.
var credentialMarkers = []string{
	"status_logon_failure", "logon failure", "authentication failed", "login incorrect",
	"unable to authenticate", "permission denied (publickey", "invalid credentials",
	"invalid username or password", "incorrect password", "bad password", "wrong password",
	"server returned status 401", "server returned status 407",
}

// genericAuthMarkers read as "bad credentials" in a leaf error but are also
// ordinary words of a file-level refusal or of a file NAME, so they are never
// applied to a structured FTP reply.
var genericAuthMarkers = []string{"access denied", "not logged in", "status_access_denied"}

// authMarkers is every marker applied to the text of a leaf error.
var authMarkers = append(append([]string(nil), credentialMarkers...), genericAuthMarkers...)

// ftpAuthCodes are the FTP reply codes that mean "credentials or account
// missing/wrong" (RFC 959): 530 not logged in, 332 need account for login,
// 532 need account for storing files. They are never retried. 534 and 535
// (RFC 2228 policy / failed security check) and 430 (not an RFC reply) are
// deliberately not here: see Classify.
var ftpAuthCodes = map[int]bool{530: true, 332: true, 532: true}

// leafErrors returns the root causes of err: the errors reached by following
// Unwrap (single and multi) until an error has none. Wrappers such as
// fmt.Errorf("stat %s: %w", path, ...) and *fs.PathError carry file names and
// server text in their own message; only the leaf is the error a protocol
// actually produced.
func leafErrors(err error) []error {
	var out []error
	var walk func(e error, depth int)
	walk = func(e error, depth int) {
		if e == nil || depth > 32 {
			return
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, c := range u.Unwrap() {
				walk(c, depth+1)
			}
		case interface{ Unwrap() error }:
			if c := u.Unwrap(); c != nil {
				walk(c, depth+1)
				return
			}
			out = append(out, e)
		default:
			out = append(out, e)
		}
	}
	walk(err, 0)
	return out
}

func hasAuthMarker(s string) bool {
	low := strings.ToLower(s)
	for _, m := range authMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// credentialInReply reports whether the text of a structured FTP reply says the
// login was refused: a credential-specific marker (never a generic word such as
// "access denied") with no path in front of it. Servers echo the path of the
// failing file in 4yz replies ("450 /Movies/Access Denied (2019).mkv: ..."), and
// a file name must never read as bad credentials. The stronger rule - decide by
// the command the reply answers (USER, PASS, ACCT) - needs the protocol glue,
// which marks those replies with MarkAuth (pkg/ftp does).
func credentialInReply(msg string) bool {
	low := strings.ToLower(msg)
	for _, m := range credentialMarkers {
		if i := strings.Index(low, m); i >= 0 && !strings.ContainsAny(low[:i], "/\\") {
			return true
		}
	}
	return false
}

func hasCredentialMarker(s string) bool {
	low := strings.ToLower(s)
	for _, m := range credentialMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// isCredentialFailure is the strict half of ClassAuth: the error says the
// ACCOUNT's credentials were refused (MarkAuth, an AuthFailure() seam, a logon
// NTSTATUS, an FTP credential reply, a credential-specific text marker). A
// generic marker such as "access denied" is ClassAuth too - it is never
// retried - but it can just as well be a refused share or file ("failed to
// mount SMB share: {Access Denied}"), so it does NOT prove that the account is
// bad. Pool uses the difference: only a credential failure is remembered for
// every root of the account; a generic one is remembered for its own root.
func isCredentialFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrAuth) || isSMBCredentialFailure(err) {
		return true
	}
	var af authFailer
	if errors.As(err, &af) && af.AuthFailure() {
		return true
	}
	var te *textproto.Error
	if errors.As(err, &te) {
		return ftpAuthCodes[te.Code] || (te.Code >= 400 && te.Code < 500 && credentialInReply(te.Msg))
	}
	for _, leaf := range leafErrors(err) {
		if hasCredentialMarker(leaf.Error()) {
			return true
		}
	}
	return false
}

// authFailer is the structural seam for protocol glue: an error that can say
// by itself that it is a credential failure does not depend on English text.
type authFailer interface{ AuthFailure() bool }

// Classify is the default error classifier. Order: (1) an error marked with
// MarkAuth, one that reports AuthFailure() == true, or an SMB refusal whose
// NTSTATUS is a logon/account status (a *smb2.ResponseError, see
// isSMBCredentialFailure) is auth; (2) a structured FTP reply
// (textproto.Error) is decided by its code - 530/332/532 auth, 4yz transient
// (RFC 959: "the action may be requested again") unless the reply text, with no
// path in front of it, names a refused login (credentialInReply), in which
// case auth wins so that a lockout reply is never retried, every other 5yz
// permanent; (3) otherwise an auth marker in a LEAF error's text - never in a
// wrapper that embeds a file name - is auth; (4) ErrTransient marks transient;
// (5) caller-side cancellation and not-found style errors are permanent;
// (6) only positively identified network-level failures are transient;
// everything else is permanent.
//
// Limit: a leaf error whose own message embeds a file name and was built with
// fmt.Errorf without %w is indistinguishable from a server message; protocol
// glue that knows its login-failure type should use MarkAuth.
func Classify(err error) ErrorClass {
	if err == nil {
		return ClassPermanent
	}
	if errors.Is(err, ErrAuth) || isSMBCredentialFailure(err) {
		return ClassAuth
	}
	var af authFailer
	if errors.As(err, &af) && af.AuthFailure() {
		return ClassAuth
	}
	var te *textproto.Error
	if errors.As(err, &te) {
		switch {
		case ftpAuthCodes[te.Code]:
			return ClassAuth
		case te.Code >= 400 && te.Code < 500:
			if credentialInReply(te.Msg) {
				return ClassAuth
			}
			return ClassTransient
		default:
			return ClassPermanent
		}
	}
	for _, leaf := range leafErrors(err) {
		if hasAuthMarker(leaf.Error()) {
			return ClassAuth
		}
	}
	if errors.Is(err, ErrTransient) {
		return ClassTransient
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) ||
		errors.Is(err, os.ErrExist) || errors.Is(err, ErrOutsideRoot) {
		return ClassPermanent
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return ClassTransient
	}
	for _, e := range []error{syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, syscall.ETIMEDOUT,
		syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ENETDOWN} {
		if errors.Is(err, e) {
			return ClassTransient
		}
	}
	// A DNS timeout is covered by the net.Error branch below (DNSError.Timeout
	// reports IsTimeout); only the "temporary" flag needs its own test.
	var dns *net.DNSError
	if errors.As(err, &dns) && dns.IsTemporary {
		return ClassTransient
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ClassTransient
	}
	return ClassPermanent
}

// ClassifyLogin classifies the error of a LOGIN attempt (a client's Connect). It
// is Classify plus the one signal that is only a credential failure at login:
// an HTTP 403 from the server a client just tried to connect to (pkg/webdav:
// "WebDAV server returned status 403"). The same 403 for a single file is a
// permission answer about that file, so Classify itself does not read it as
// bad credentials. Pool uses it to decide whether to remember a rejected login.
func ClassifyLogin(err error) ErrorClass {
	if c := Classify(err); c != ClassPermanent {
		return c
	}
	for _, leaf := range leafErrors(err) {
		low := strings.ToLower(leaf.Error())
		if strings.Contains(low, "server returned status 403") && !strings.Contains(low, " for file ") {
			return ClassAuth
		}
	}
	return ClassPermanent
}
