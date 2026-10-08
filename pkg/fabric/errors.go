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
)

// MarkAuth wraps err so that Classify reports ClassAuth. Protocol glue that
// knows its own login-failure error type uses it. nil stays nil.
func MarkAuth(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrAuth, err)
}

// MarkTransient wraps err so that Classify reports ClassTransient. nil stays nil.
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

// authMarkers are lower-case fragments of a credential-failure message. They
// are matched against LEAF errors only (see leafErrors) and, for an FTP reply,
// only on a 4yz reply: a 5yz reply other than the credential codes is a
// file-level answer ("550 Access denied" for one file is not bad credentials).
var authMarkers = []string{
	"status_logon_failure", "logon failure", "authentication failed", "login incorrect",
	"unable to authenticate", "permission denied (publickey", "invalid credentials",
	"invalid username or password", "incorrect password",
	"access denied", "bad password", "wrong password", "not logged in", "status_access_denied",
}

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

// Classify is the default error classifier. Order: (1) an error marked with
// MarkAuth is auth; (2) a structured FTP reply (textproto.Error) is decided by
// its code - 530/332/532 auth, 4yz transient (RFC 959: "the action may be
// requested again") unless the reply text says the login failed, in which case
// auth wins so that a lockout reply is never retried, every other 5yz
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
	if errors.Is(err, ErrAuth) {
		return ClassAuth
	}
	var te *textproto.Error
	if errors.As(err, &te) {
		switch {
		case ftpAuthCodes[te.Code]:
			return ClassAuth
		case te.Code >= 400 && te.Code < 500:
			if hasAuthMarker(te.Msg) {
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
