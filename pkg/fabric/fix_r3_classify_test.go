package fabric_test

// Round-3 (WF24 re-review) regression tests for N1 (login failures of the real
// protocol clients), N7 (4yz path echo), D1 (MarkTransient precedence).
//
// Ground truth (11.4.276(B)): every error here is built from the protocol
// library's own exported type (go-smb2 *ResponseError, wrapped exactly as
// pkg/smb wraps it) or produced by the real pkg/webdav client against a
// loopback httptest server. No MarkAuth fake stands in for a real failure.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"sync/atomic"
	"testing"

	smb2 "github.com/hirochachacha/go-smb2"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
)

// smbStatuses are the NTSTATUS values of MS-ERREF 2.3.1 that a server answers a
// SESSION SETUP with when the credentials or the account are refused. Stated
// here independently of the implementation's table.
var smbCredentialStatuses = []struct {
	name string
	code uint32
}{
	{"STATUS_WRONG_PASSWORD", 0xC000006A},
	{"STATUS_NO_SUCH_USER", 0xC0000064},
	{"STATUS_LOGON_FAILURE", 0xC000006D},
	{"STATUS_ACCOUNT_RESTRICTION", 0xC000006E},
	{"STATUS_INVALID_LOGON_HOURS", 0xC000006F},
	{"STATUS_INVALID_WORKSTATION", 0xC0000070},
	{"STATUS_PASSWORD_EXPIRED", 0xC0000071},
	{"STATUS_ACCOUNT_DISABLED", 0xC0000072},
	{"STATUS_LOGON_TYPE_NOT_GRANTED", 0xC000015B},
	{"STATUS_ACCOUNT_EXPIRED", 0xC0000193},
	{"STATUS_PASSWORD_MUST_CHANGE", 0xC0000224},
	{"STATUS_ACCOUNT_LOCKED_OUT", 0xC0000234},
}

// file-level statuses: they answer about ONE file, never about the credentials.
var smbFileStatuses = []struct {
	name string
	code uint32
}{
	{"STATUS_ACCESS_DENIED", 0xC0000022},
	{"STATUS_OBJECT_NAME_NOT_FOUND", 0xC0000034},
	{"STATUS_OBJECT_PATH_NOT_FOUND", 0xC000003A},
	{"STATUS_SHARING_VIOLATION", 0xC0000043},
	{"STATUS_BAD_NETWORK_NAME", 0xC00000CC},
	{"STATUS_FILE_IS_A_DIRECTORY", 0xC00000BA},
}

func TestR3_ClassifyEverySMBCredentialStatusThroughTheRealType(t *testing.T) {
	t.Parallel()
	// control needles: the instrument sees MarkAuth and does not see a plain error
	if fabric.Classify(fabric.MarkAuth(errors.New("x"))) != fabric.ClassAuth || fabric.Classify(errors.New("x")) == fabric.ClassAuth {
		t.Fatal("CONTROL FAILED")
	}
	for _, s := range smbCredentialStatuses {
		raw := &smb2.ResponseError{Code: s.code}
		wrapped := fmt.Errorf("fabric: connect nas: %w", fmt.Errorf("failed to create SMB session: %w", raw)) // pkg/smb + Pool wrapping
		for name, e := range map[string]error{"raw": raw, "wrapped": wrapped, "joined": errors.Join(errors.New("close: ok"), wrapped)} {
			if got := fabric.Classify(e); got != fabric.ClassAuth {
				t.Errorf("%s (%s): %v -> %v, want auth", s.name, name, e, got)
			}
			if got := fabric.ClassifyLogin(e); got != fabric.ClassAuth {
				t.Errorf("%s (%s): ClassifyLogin = %v, want auth", s.name, name, got)
			}
		}
	}
}

// A refusal of the SHARE (tree connect) or of a file is not proof that the
// account is bad: the real go-smb2 text of STATUS_ACCESS_DENIED hits the generic
// "access denied" marker (ClassAuth, never retried), but the Pool must remember
// it for that root only, so the account's other roots are still tried.
func TestR3_ShareDenialIsRememberedPerRootNotPerAccount(t *testing.T) {
	t.Parallel()
	for _, s := range smbFileStatuses {
		denied := fmt.Errorf("failed to mount SMB share: %w", &smb2.ResponseError{Code: s.code})
		f := &r3Factory{errFor: func(n int64) error {
			if n == 1 {
				return denied
			}
			return nil
		}}
		p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
		_, err := p.GetClient(cfgRoot("private", "private"))
		if err == nil {
			t.Fatalf("%s: the first login should have failed", s.name)
		}
		c, err := p.GetClient(cfgRoot("movies", "movies"))
		if err != nil {
			t.Errorf("%s on one share blocked another share of the same account: %v", s.name, err)
			continue
		}
		_ = p.ReturnClient(c)
		if fabric.ClassifyLogin(denied) == fabric.ClassAuth { // and the denied root itself is not retried
			before := f.conn.Load()
			_, _ = p.GetClient(cfgRoot("private", "private"))
			if f.conn.Load() != before {
				t.Errorf("%s: the denied root was tried again", s.name)
			}
		}
	}
}

type authSeamErr struct{ auth bool }

func (e authSeamErr) Error() string     { return "opaque protocol failure" }
func (e authSeamErr) AuthFailure() bool { return e.auth }

func TestR3_ClassifyStructuralAuthFailureSeam(t *testing.T) {
	t.Parallel()
	if got := fabric.Classify(fmt.Errorf("connect: %w", authSeamErr{auth: true})); got != fabric.ClassAuth {
		t.Errorf("AuthFailure()==true -> %v, want auth", got)
	}
	if got := fabric.Classify(fmt.Errorf("connect: %w", authSeamErr{auth: false})); got != fabric.ClassPermanent {
		t.Errorf("AuthFailure()==false -> %v, want permanent (the seam must not turn everything into auth)", got)
	}
}

func TestR3_ClassifyWebDAVStatusText(t *testing.T) {
	t.Parallel()
	cases := []struct {
		text         string
		classify     fabric.ErrorClass
		classifyLogn fabric.ErrorClass
	}{
		{"WebDAV server returned status 401", fabric.ClassAuth, fabric.ClassAuth},
		{"WebDAV server returned status 407", fabric.ClassAuth, fabric.ClassAuth},
		{"WebDAV server returned status 401 for file http://nas/x/a.mkv", fabric.ClassAuth, fabric.ClassAuth},
		{"WebDAV server returned status 403", fabric.ClassPermanent, fabric.ClassAuth}, // forbidden for these credentials AT LOGIN
		{"WebDAV server returned status 403 for file http://nas/x/a.mkv", fabric.ClassPermanent, fabric.ClassPermanent},
		{"WebDAV server returned status 404 for file http://nas/x/a.mkv", fabric.ClassPermanent, fabric.ClassPermanent},
		{"WebDAV server returned status 500", fabric.ClassPermanent, fabric.ClassPermanent},
	}
	for _, c := range cases {
		e := fmt.Errorf("fabric: connect dav: %w", errors.New(c.text))
		if got := fabric.Classify(e); got != c.classify {
			t.Errorf("Classify(%q) = %v, want %v", c.text, got, c.classify)
		}
		if got := fabric.ClassifyLogin(e); got != c.classifyLogn {
			t.Errorf("ClassifyLogin(%q) = %v, want %v", c.text, got, c.classifyLogn)
		}
	}
}

// ClassifyLogin never lowers what Classify decided, and agrees on everything
// that is not the login-only 403.
func TestR3_ClassifyLoginAgreesWithClassifyEverywhereElse(t *testing.T) {
	t.Parallel()
	for _, e := range []error{
		nil, errors.New("x"), errReset, fabric.MarkAuth(errors.New("y")), fabric.MarkTransient(errors.New("z")),
		&textproto.Error{Code: 530, Msg: "nope"}, &textproto.Error{Code: 421, Msg: "closing"}, &textproto.Error{Code: 550, Msg: "no"},
		context.Canceled, context.DeadlineExceeded,
	} {
		if a, b := fabric.Classify(e), fabric.ClassifyLogin(e); a != b {
			t.Errorf("%v: Classify=%v ClassifyLogin=%v", e, a, b)
		}
	}
}

// webdavServer answers every request with status and counts them.
func webdavServer(t *testing.T, status int, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="nas"`)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The REAL pkg/webdav client against a refusing server, through the Pool: one
// login for 20 borrows, whatever refusal the server uses at login.
func TestR3_PoolRealWebDAVRefusalsAreRememberedOnce(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusUnauthorized, http.StatusProxyAuthRequired, http.StatusForbidden} {
		var hits atomic.Int64
		srv := webdavServer(t, status, &hits)
		p := newPool(t, webdavFactory{srv.URL}, fabric.PoolOptions{MaxPerKey: 4})
		var last error
		for i := 0; i < 20; i++ {
			_, last = p.GetClient(cfgFor("dav"))
		}
		if hits.Load() != 1 {
			t.Errorf("status %d: %d authenticated requests for 20 borrows, want 1 (last: %v)", status, hits.Load(), last)
		}
		if fabric.ClassifyLogin(last) != fabric.ClassAuth {
			t.Errorf("status %d: last error is not an auth failure: %v", status, last)
		}
	}
	// control: a server error (not credentials) is NOT remembered, every borrow tries again
	var hits atomic.Int64
	srv := webdavServer(t, http.StatusServiceUnavailable, &hits)
	p := newPool(t, webdavFactory{srv.URL}, fabric.PoolOptions{MaxPerKey: 4})
	for i := 0; i < 5; i++ {
		_, _ = p.GetClient(cfgFor("dav"))
	}
	if hits.Load() != 5 {
		t.Errorf("a 503 must not be remembered as bad credentials: %d requests for 5 borrows, want 5", hits.Load())
	}
}

// Every protocol the factory supports: the shape its Connect returns for a
// refused login, classified. nfs3 and local have no credentials (AUTH_SYS / the
// host account) and so no row.
func TestR3_LoginFailureShapesOfEveryCredentialedProtocol(t *testing.T) {
	t.Parallel()
	rows := []struct {
		protocol string
		err      error
	}{
		{"smb", fmt.Errorf("failed to create SMB session: %w", &smb2.ResponseError{Code: 0xC000006D})},
		{"ftp/ftps 530 at PASS (glue marks it)", fabric.MarkAuth(fmt.Errorf("ftp: login as %q failed: 530 Login incorrect", "u"))},
		{"ftp/ftps raw 530", fmt.Errorf("ftp: %w", &textproto.Error{Code: 530, Msg: "Not logged in"})},
		{"sftp (x/crypto/ssh text)", fmt.Errorf("sftp: dial: %w", errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain"))},
		{"webdav 401", errors.New("WebDAV server returned status 401")},
	}
	for _, r := range rows {
		if got := fabric.ClassifyLogin(fmt.Errorf("fabric: connect root: %w", r.err)); got != fabric.ClassAuth {
			t.Errorf("%s: %v -> %v, want auth", r.protocol, r.err, got)
		}
	}
}

// ---- D1: MarkTransient's precedence is part of its documented contract ----

func TestR3_MarkTransientPrecedence(t *testing.T) {
	t.Parallel()
	if g := fabric.Classify(fabric.MarkTransient(&textproto.Error{Code: 550, Msg: "x"})); g != fabric.ClassPermanent {
		t.Errorf("marked structured 5yz: %v, want permanent", g)
	}
	if g := fabric.Classify(fabric.MarkTransient(&smb2.ResponseError{Code: 0xC0000234})); g != fabric.ClassAuth {
		t.Errorf("marked SMB lockout: %v, want auth", g)
	}
	if g := fabric.Classify(fabric.MarkTransient(errors.New("reset"))); g != fabric.ClassTransient {
		t.Errorf("marked plain error: %v, want transient", g)
	}
	if fabric.MarkTransient(nil) != nil {
		t.Error("MarkTransient(nil) must stay nil")
	}
}

// ---- N7 (the 4yz path echo), the externally visible half; the per-marker
// enumeration lives in markers_internal_test.go ----

func TestR3_FTP4yzPathEchoIsTransientAndCredentialTextIsAuth(t *testing.T) {
	t.Parallel()
	transient := []*textproto.Error{
		{Code: 450, Msg: "/Movies/Access Denied (2019).mkv: Resource temporarily unavailable"},
		{Code: 451, Msg: "/home/m/not logged in.txt: Requested action aborted"},
		{Code: 450, Msg: `\\nas\share\Login incorrect.txt: busy`},
		{Code: 450, Msg: "/dir/Wrong Password Recovery.pdf: busy"},
		{Code: 450, Msg: "Access denied"}, // a generic phrase alone, 4yz: still the RFC 959 class
	}
	for _, e := range transient {
		if got := fabric.Classify(fmt.Errorf("ftp: retrieve /x: %w", e)); got != fabric.ClassTransient {
			t.Errorf("%d %q -> %v, want transient", e.Code, e.Msg, got)
		}
	}
	auth := []*textproto.Error{
		{Code: 430, Msg: "Invalid username or password"},
		{Code: 421, Msg: "Login authentication failed, too many attempts"},
		{Code: 450, Msg: "Login incorrect"},
	}
	for _, e := range auth {
		if got := fabric.Classify(e); got != fabric.ClassAuth {
			t.Errorf("%d %q -> %v, want auth", e.Code, e.Msg, got)
		}
	}
}

// a cfg for a real WebDAV client; the factory is the W03 one (webdavFactory).
var _ client.Factory = webdavFactory{}
