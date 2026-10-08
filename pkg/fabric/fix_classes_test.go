package fabric_test

// Round-2 review (WF19) regression tests, class by class (11.4.276(C)): every
// member of a defect class named by the review has its own assertion here, and
// every survivor of the reviewer's mutation set (T1: R01..R20) is killed by at
// least one test in this file, pool_fix_test.go or budget_fix_test.go.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/decorators/guard"
	"digital.vasic.filesystem/pkg/fabric"
	"digital.vasic.filesystem/pkg/local"
	"digital.vasic.filesystem/pkg/smb"
	"digital.vasic.filesystem/pkg/webdav"
)

// allLayers builds every fabric decorator over inner (the budget is generous).
func allLayers(t testing.TB, inner client.Client) map[string]client.Client {
	t.Helper()
	b := mustBudget(t, 8, 1e9, nil)
	r, err := fabric.Retrying(inner, fabric.RetryPolicy{MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]client.Client{
		"Limited":  fabric.Limited(inner, b),
		"Retrying": r,
		"Confined": confined(t, inner, "/"),
		"Metered":  fabric.Metered(inner, &fabric.CounterSink{}, nil),
	}
}

// ---------------------------------------------------------------- S9: classifier

func TestClassify_FTPCodeTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code int
		msg  string
		want fabric.ErrorClass
	}{
		{530, "Not logged in", fabric.ClassAuth},
		{332, "Need account for login", fabric.ClassAuth},
		{532, "Need account for storing files", fabric.ClassAuth},
		{534, "Request denied for policy reasons", fabric.ClassPermanent},
		{535, "Failed security check", fabric.ClassPermanent},
		{533, "Command protection level denied for policy reasons", fabric.ClassPermanent},
		{536, "Requested PROT level not supported by mechanism", fabric.ClassPermanent},
		{550, "Access denied", fabric.ClassPermanent},
		{550, "Not logged in.txt: no such file", fabric.ClassPermanent},
		{553, "File name not allowed", fabric.ClassPermanent},
		{421, "Service not available", fabric.ClassTransient},
		{425, "Can't open data connection", fabric.ClassTransient},
		{426, "Connection closed; transfer aborted", fabric.ClassTransient},
		{430, "Please wait", fabric.ClassTransient},
		{430, "Invalid username or password", fabric.ClassAuth},
		{431, "Need some unavailable resource to process security", fabric.ClassTransient},
		{450, "Requested file action not taken", fabric.ClassTransient},
		{451, "Requested action aborted: local error", fabric.ClassTransient},
		{452, "Insufficient storage space", fabric.ClassTransient},
		{421, "Login authentication failed, too many attempts", fabric.ClassAuth},
		{450, "Login incorrect", fabric.ClassAuth},
	}
	for _, c := range cases {
		e := &textproto.Error{Code: c.code, Msg: c.msg}
		if got := fabric.Classify(e); got != c.want {
			t.Errorf("%d %q: %v, want %v", c.code, c.msg, got, c.want)
		}
		// the same through wrappers (the glue wraps with context)
		if got := fabric.Classify(fmt.Errorf("ftp list /x: %w", e)); got != c.want {
			t.Errorf("wrapped %d %q: %v, want %v", c.code, c.msg, got, c.want)
		}
	}
}

// S9 member 1: markers are matched on the LEAF cause, never on a wrapper that
// embeds a file name.
func TestClassify_PathTextIsNeverAuthEvidence(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Access Denied (2019).mkv", "not logged in.txt", "Logon Failure.avi", "wrong password.txt", "invalid credentials", "status_logon_failure"} {
		pe := &os.PathError{Op: "open", Path: "/media/" + name, Err: syscall.ECONNRESET}
		if got := fabric.Classify(pe); got != fabric.ClassTransient {
			t.Errorf("reset on %q: %v, want transient", name, got)
		}
		nf := fmt.Errorf("stat /m/%s: %w", name, os.ErrNotExist)
		if got := fabric.Classify(nf); got != fabric.ClassPermanent {
			t.Errorf("not-found on %q: %v, want permanent", name, got)
		}
		perm := &os.PathError{Op: "open", Path: "/m/" + name, Err: os.ErrPermission}
		if got := fabric.Classify(perm); got != fabric.ClassPermanent {
			t.Errorf("EACCES on %q: %v, want permanent", name, got)
		}
	}
}

// T1 R15: EVERY auth marker is recognised in a leaf cause (and the table is
// closed: a near-miss is not auth).
func TestClassify_EveryAuthMarkerInALeaf(t *testing.T) {
	t.Parallel()
	markers := []string{"STATUS_LOGON_FAILURE", "logon failure", "authentication failed", "Login incorrect",
		"unable to authenticate", "permission denied (publickey,password)", "invalid credentials",
		"Invalid username or password", "incorrect password", "Access Denied", "bad password", "wrong password",
		"not logged in", "STATUS_ACCESS_DENIED"}
	for _, m := range markers {
		leaf := errors.New("proto: " + m)
		if got := fabric.Classify(fmt.Errorf("dial: %w", leaf)); got != fabric.ClassAuth {
			t.Errorf("%q: %v, want auth", m, got)
		}
		if got := fabric.Classify(errors.Join(errors.New("other"), leaf)); got != fabric.ClassAuth {
			t.Errorf("joined %q: %v, want auth", m, got)
		}
	}
	if got := fabric.Classify(errors.New("login ok but slow")); got != fabric.ClassPermanent {
		t.Errorf("near-miss: %v", got)
	}
}

// S9 member 2 / RV16: auth beats transient for every source, as documented.
func TestClassify_AuthBeatsTransientForEverySource(t *testing.T) {
	t.Parallel()
	to := &net.OpError{Op: "read", Err: timeoutErr{}}
	for name, err := range map[string]error{
		"textproto 4yz":                &textproto.Error{Code: 421, Msg: "Login authentication failed"},
		"marked + reset":               fmt.Errorf("%w: %w", fabric.ErrAuth, syscall.ECONNRESET),
		"leaf text + timeout":          fmt.Errorf("%w; %w", errors.New("unable to authenticate"), to),
		"marked transient + auth text": fabric.MarkTransient(errors.New("Login incorrect")),
	} {
		if got := fabric.Classify(err); got != fabric.ClassAuth {
			t.Errorf("%s: %v, want auth", name, got)
		}
	}
}

// T1 R12/R16/R17: every network-level signal is transient.
func TestClassify_EveryTransientSignal(t *testing.T) {
	t.Parallel()
	for _, e := range []error{syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, syscall.ETIMEDOUT,
		syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ENETDOWN,
		io.EOF, io.ErrUnexpectedEOF, &net.DNSError{IsTimeout: true}, &net.DNSError{IsTemporary: true},
		fmt.Errorf("wrapped: %w", syscall.ENETUNREACH)} {
		if got := fabric.Classify(e); got != fabric.ClassTransient {
			t.Errorf("%v: %v, want transient", e, got)
		}
	}
	for _, e := range []error{syscall.ENOENT, syscall.EACCES, &net.DNSError{IsNotFound: true}} {
		if got := fabric.Classify(e); got != fabric.ClassPermanent {
			t.Errorf("%v: %v, want permanent", e, got)
		}
	}
}

// ---------------------------------------------------------------- S10: HostKey

func TestHostKey_RejectsNonHostsAndCanonicalisesIPs(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"smb://nas-a.example", "http://x/dav", "nas/share", "user@nas", "nas?x", "nas#f", "na s", "na\ns", "\\\\nas\\share", "nas\x00"} {
		if k, err := fabric.HostKey(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, k)
		}
	}
	same := [][]string{
		{"::1", "0:0:0:0:0:0:0:1", "[::1]:22", "[0::1]:445"},
		{"192.168.1.5", "::ffff:192.168.1.5", "192.168.1.5:445", "[::ffff:192.168.1.5]:22"},
		{"NAS.Local", "nas.local.", "nas.local:445"},
		{"2001:DB8::1", "2001:db8:0:0:0:0:0:1"},
	}
	for _, g := range same {
		first, err := fabric.HostKey(g[0])
		if err != nil {
			t.Fatalf("%q: %v", g[0], err)
		}
		for _, h := range g[1:] {
			k, err := fabric.HostKey(h)
			if err != nil || k != first {
				t.Errorf("HostKey(%q)=%q,%v want %q (same as %q)", h, k, err, first, g[0])
			}
		}
	}
	a, _ := fabric.HostKey("nas-a.example")
	b, _ := fabric.HostKey("nas-b.example")
	if a == b {
		t.Fatal("different hosts share a key")
	}
	if k, _ := fabric.HostKey("192.168.1.5"); k == "nas.local" {
		t.Fatal("names are not resolved")
	}
}

// ---------------------------------------------------------------- S11: Confined control characters

func TestConfined_EveryControlCharacterIsRefusedInPathsAndRoot(t *testing.T) {
	t.Parallel()
	for r := rune(0); r < 0x20; r++ {
		for _, p := range []string{"/data/a" + string(r) + "b", "a" + string(r), string(r)} {
			f := newFk("p")
			c := confined(t, f, "/data")
			if _, err := c.GetFileInfo(context.Background(), p); !errors.Is(err, fabric.ErrOutsideRoot) || f.total() != 0 {
				t.Errorf("%U in %q reached the inner client: err=%v calls=%d", r, p, err, f.total())
			}
		}
		if _, err := fabric.Confined(newFk("p"), "/da"+string(r)+"ta"); err == nil {
			t.Errorf("%U accepted in the root", r)
		}
	}
	f := newFk("p")
	c := confined(t, f, "/data")
	if _, err := c.GetFileInfo(context.Background(), "/data/a\x7fb"); !errors.Is(err, fabric.ErrOutsideRoot) {
		t.Errorf("DEL accepted: %v", err)
	}
	// CopyFile: either path
	if err := c.CopyFile(context.Background(), "/data/ok", "/data/x\ny"); !errors.Is(err, fabric.ErrOutsideRoot) || f.total() != 0 {
		t.Errorf("CopyFile with a control character in dst: %v calls=%d", err, f.total())
	}
	// legitimate unicode and spaces are untouched
	if _, err := c.GetFileInfo(context.Background(), "/data/Film (2019) é中.mkv"); err != nil {
		t.Errorf("legitimate name refused: %v", err)
	}
}

// ---------------------------------------------------------------- S13: typed nil

func TestTypedNilInnerPanicsAtConstructionEverywhere(t *testing.T) {
	t.Parallel()
	var lc *local.Client
	var sc *smb.Client
	b := mustBudget(t, 1, 1, nil)
	cases := map[string]func(){
		"Limited":       func() { fabric.Limited(lc, b) },
		"Metered":       func() { fabric.Metered(lc, &fabric.CounterSink{}, nil) },
		"Retrying":      func() { _, _ = fabric.Retrying(lc, fabric.RetryPolicy{MaxAttempts: 1}) },
		"Confined":      func() { _, _ = fabric.Confined(lc, "/") },
		"ReadOnly":      func() { decorators.ReadOnly(lc) },
		"ReadOnly(smb)": func() { decorators.ReadOnly(sc) },
	}
	for n, fn := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: a typed-nil inner was accepted", n)
				}
			}()
			fn()
		}()
	}
	// a real client is accepted
	fabric.Limited(local.NewLocalClient(&local.Config{BasePath: t.TempDir()}), b)
	for _, v := range []interface{}{nil, lc, (*int)(nil), map[string]int(nil), []int(nil), (func())(nil), (chan int)(nil)} {
		if !guard.IsNil(v) {
			t.Errorf("IsNil(%T %v) = false", v, v)
		}
	}
	x := 1
	for _, v := range []interface{}{&x, map[string]int{}, []int{}, 0, "", struct{}{}} {
		if guard.IsNil(v) {
			t.Errorf("IsNil(%T) = true", v)
		}
	}
}

// ---------------------------------------------------------------- S14: retry policy

func TestRetryPolicy_BoundedAndNeverBackToBack(t *testing.T) {
	t.Parallel()
	bad := []fabric.RetryPolicy{
		{MaxAttempts: 2}, {MaxAttempts: 1000}, {MaxAttempts: fabric.MaxRetryAttempts + 1, BaseDelay: time.Millisecond},
		{MaxAttempts: 3, BaseDelay: 0, MaxDelay: time.Second},
	}
	for _, p := range bad {
		if _, err := fabric.Retrying(newFk("p"), p); !errors.Is(err, fabric.ErrRetryPolicy) {
			t.Errorf("%+v accepted (err=%v)", p, err)
		}
	}
	for _, p := range []fabric.RetryPolicy{{MaxAttempts: 1}, {MaxAttempts: fabric.MaxRetryAttempts, BaseDelay: time.Nanosecond}} {
		if _, err := fabric.Retrying(newFk("p"), p); err != nil {
			t.Errorf("%+v rejected: %v", p, err)
		}
	}
}

// The delay is BaseDelay*2^(n-1), capped, in closed form: compare with the
// definition for every attempt number and several bases (incl. the overflow zone).
func TestRetryPolicy_DelayClosedFormMatchesDefinition(t *testing.T) {
	t.Parallel()
	for _, base := range []time.Duration{1, 3, time.Millisecond, 7 * time.Second, time.Hour} {
		for _, capd := range []time.Duration{0, time.Second, 90 * time.Minute} {
			f := newFk("p")
			for i := 0; i < fabric.MaxRetryAttempts; i++ {
				f.queue("TestConnection", errReset)
			}
			clk := newFakeClock()
			c := retrying(t, f, fabric.RetryPolicy{MaxAttempts: fabric.MaxRetryAttempts, BaseDelay: base, MaxDelay: capd, Clock: clk})
			_ = c.TestConnection(context.Background())
			got := clk.slept()
			if len(got) != fabric.MaxRetryAttempts-1 {
				t.Fatalf("%d sleeps", len(got))
			}
			for i, d := range got {
				want := naiveDelay(base, capd, i+1)
				if d != want {
					t.Fatalf("base=%v cap=%v attempt %d: delay %v, want %v", base, capd, i+1, d, want)
				}
			}
		}
	}
}

// naiveDelay is the specification: double, saturate at MaxInt64, cap, then raise to MinRetryDelay.
func naiveDelay(base, capd time.Duration, attempt int) time.Duration {
	d := base
	for i := 1; i < attempt; i++ {
		if d > (1<<63-1)/2 {
			d = 1<<63 - 1
			break
		}
		d *= 2
	}
	if capd > 0 && d > capd {
		d = capd
	}
	if d < fabric.MinRetryDelay { // round 3 (N5): the effective delay is never below the floor
		d = fabric.MinRetryDelay
	}
	return d
}

// T1 R19: a cancelled caller context stops the loop BEFORE it sleeps: one
// inner call, and the error is the plain failure, not an "interrupted retry".
func TestRetrying_CancelledContextReturnsTheFailureWithoutBackoff(t *testing.T) {
	t.Parallel()
	f := newFk("p").queue("ListDirectory", errReset, errReset)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	clk := newFakeClock()
	c := retrying(t, f, fabric.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond, Clock: clk})
	_, err := c.ListDirectory(ctx, "/a")
	if err == nil || strings.Contains(err.Error(), "interrupted") || len(clk.slept()) != 0 || f.count("ListDirectory") != 1 {
		t.Fatalf("err=%v sleeps=%v calls=%d", err, clk.slept(), f.count("ListDirectory"))
	}
}

// ---------------------------------------------------------------- layers: T1 R03/R04/R05/R18, S5

// R03: every layer forwards BOTH CopyFile paths in order.
func TestLayers_CopyFileForwardsSourceAndDestination(t *testing.T) {
	t.Parallel()
	f := newFk("p")
	for name, c := range allLayers(t, f) {
		if err := c.CopyFile(context.Background(), "/s1", "/d2"); err != nil {
			t.Fatal(err)
		}
		if got := f.paths("CopyFile"); len(got) != 2 || got[0] != "/s1" || got[1] != "/d2" {
			t.Errorf("%s forwarded %v, want [/s1 /d2]", name, got)
		}
	}
}

// R04: OpenSeekable closes a stream returned together with an error.
type leakySeek struct {
	*fk
	closed *int
}

func (l leakySeek) OpenSeekable(context.Context, string) (client.ReadSeekCloser, error) {
	return seekCloseCounter{l.closed}, errors.New("open failed")
}

type seekCloseCounter struct{ n *int }

func (c seekCloseCounter) Read([]byte) (int, error)       { return 0, io.EOF }
func (c seekCloseCounter) Seek(int64, int) (int64, error) { return 0, nil }
func (c seekCloseCounter) Close() error                   { *c.n++; return nil }

func TestLayer_OpenSeekableClosesStreamReturnedAlongsideAnError(t *testing.T) {
	t.Parallel()
	n := 0
	c := fabric.Limited(leakySeek{newFk("p"), &n}, mustBudget(t, 1, 1e6, nil)).(client.SeekableClient)
	if rc, err := c.OpenSeekable(context.Background(), "/a"); err == nil || rc != nil {
		t.Fatalf("rc=%v err=%v", rc, err)
	}
	if n != 1 {
		t.Fatalf("stream closed %d times, want 1", n)
	}
}

// R05: IsConnected / GetProtocol are forwarded by every layer, both ways.
func TestLayers_IsConnectedAndProtocolAreTheInnersAnswer(t *testing.T) {
	t.Parallel()
	for _, connected := range []bool{true, false} {
		f := newFk("proto-x")
		f.connected = connected
		for name, c := range allLayers(t, f) {
			if c.IsConnected() != connected {
				t.Errorf("%s: IsConnected=%v with inner %v", name, c.IsConnected(), connected)
			}
			if c.GetProtocol() != "proto-x" {
				t.Errorf("%s: GetProtocol=%q", name, c.GetProtocol())
			}
		}
	}
}

// R18: the Sample carries the protocol of the inner client.
type sinkRec struct {
	mu sync.Mutex
	s  []fabric.Sample
}

func (r *sinkRec) Observe(x fabric.Sample) { r.mu.Lock(); r.s = append(r.s, x); r.mu.Unlock() }

func TestMetered_SampleCarriesProtocolOpAndError(t *testing.T) {
	t.Parallel()
	r := &sinkRec{}
	f := newFk("smb").queue("FileExists", errors.New("boom"))
	c := fabric.Metered(f, r, nil)
	_, _ = c.FileExists(context.Background(), "/a")
	if len(r.s) != 1 || r.s[0].Protocol != "smb" || r.s[0].Op != fabric.OpFileExists || r.s[0].Err == nil {
		t.Fatalf("samples %+v", r.s)
	}
}

// S5 (RV07 + members): the capabilities of the inner stream survive EVERY layer
// and the metering sees every byte however it is read.
func TestLayers_PreserveStreamCapabilitiesAndMeterEveryReadPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	lc := local.NewLocalClient(&local.Config{BasePath: dir})
	if err := lc.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, _ := lc.OpenSeekable(context.Background(), "a")
	_, rawRA := raw.(io.ReaderAt)
	_, rawWT := raw.(io.WriterTo)
	_ = raw.Close()
	if !rawRA || !rawWT {
		t.Fatalf("setup: the local stream must offer ReaderAt and WriterTo (RA=%v WT=%v)", rawRA, rawWT)
	}
	for name, c := range allLayers(t, lc) {
		sc := c.(client.SeekableClient)
		s, err := sc.OpenSeekable(context.Background(), "a")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ra, ok := s.(io.ReaderAt)
		if !ok {
			t.Errorf("%s: OpenSeekable dropped io.ReaderAt", name)
		} else {
			buf := make([]byte, 4)
			if n, err := ra.ReadAt(buf, 3); n != 4 || err != nil || string(buf) != "3456" {
				t.Errorf("%s: ReadAt %d %v %q", name, n, err, buf)
			}
		}
		if _, ok := s.(io.WriterTo); !ok {
			t.Errorf("%s: OpenSeekable dropped io.WriterTo", name)
		}
		_ = s.Close()
		rf, err := c.ReadFile(context.Background(), "a")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := rf.(io.ReadSeeker); !ok {
			t.Errorf("%s: ReadFile dropped io.Seeker", name)
		}
		_ = rf.Close()
	}
	// metering: ReadAt and WriteTo bytes are counted (Read alone was counted before)
	sink := &fabric.CounterSink{}
	m := fabric.Metered(lc, sink, nil).(client.SeekableClient)
	s, _ := m.OpenSeekable(context.Background(), "a")
	buf := make([]byte, 4)
	_, _ = s.(io.ReaderAt).ReadAt(buf, 0)
	n, _ := s.(io.WriterTo).WriteTo(io.Discard)
	_ = s.Close()
	if got := sink.Snapshot(fabric.OpOpenSeekable).Bytes; got != 4+n || n == 0 {
		t.Fatalf("metered %d bytes, want ReadAt 4 + WriteTo %d", got, n)
	}
	// a stream that is NOT seekable stays not seekable through ReadFile
	nf := fabric.Limited(newFk("p"), mustBudget(t, 1, 1e6, nil))
	rc, _ := nf.ReadFile(context.Background(), "/x")
	if _, ok := rc.(io.Seeker); ok {
		t.Error("a layer invented io.Seeker")
	}
	if _, ok := rc.(io.ReaderAt); ok {
		t.Error("a layer invented io.ReaderAt")
	}
	_ = rc.Close()
}

// Limited keeps the slot of a stream opened through ReadAt-capable wrappers until Close.
func TestLimited_ReadAtStreamHoldsSlotUntilClose(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a"), []byte("0123456789"), 0o600)
	lc := local.NewLocalClient(&local.Config{BasePath: dir})
	_ = lc.Connect(context.Background())
	b := mustBudget(t, 1, 1e6, nil)
	s, err := fabric.Limited(lc, b).(client.SeekableClient).OpenSeekable(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if b.Stats().InFlight != 1 {
		t.Fatal("slot not held")
	}
	_ = s.Close()
	_ = s.Close()
	if b.Stats().InFlight != 0 {
		t.Fatal("slot not released")
	}
}

// ---------------------------------------------------------------- S6: GetConfig of every layer

func TestLayers_GetConfigIsRedactedAndDetached(t *testing.T) {
	t.Parallel()
	sc := &smb.Config{Host: "nas.invalid", Share: "media", Username: "u", Password: "DUMMY-NOT-A-SECRET"}
	wc := &webdav.Config{URL: "http://nas.invalid/dav", Username: "u", Password: "DUMMY-NOT-A-SECRET"}
	for name, c := range allLayers(t, smb.NewSMBClient(sc)) {
		got, ok := c.GetConfig().(*smb.Config)
		if !ok {
			t.Fatalf("%s: GetConfig is %T", name, c.GetConfig())
		}
		if got.Password != "" || got.Host != "nas.invalid" || got.Username != "u" {
			t.Errorf("%s: password present or public fields lost (password length %d)", name, len(got.Password))
		}
		got.Share = "admin$"
		if sc.Share != "media" {
			t.Fatalf("%s: GetConfig returned the live config", name)
		}
	}
	for name, c := range allLayers(t, webdav.NewWebDAVClient(wc)) {
		if got, ok := c.GetConfig().(*webdav.Config); !ok || got.Password != "" {
			t.Errorf("%s: webdav password exposed", name)
		}
	}
	if wc.Password == "" || sc.Password == "" {
		t.Fatal("redaction blanked the INNER config")
	}
}
