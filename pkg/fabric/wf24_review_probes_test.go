// ADOPTED VERBATIM (constitution 11.4.276(D)) from the independent re-review WF24 (zz_wf24_test.go); strengthenings, if any, are marked ADOPTED AS ASSERTION / ADAPTED.
package fabric_test

// WF24 independent re-review probes (reviewer-authored, scratch copy only, never in the repo).
// Each probe asserts the CORRECT behaviour; a FAIL is the captured evidence of a defect.
// "OBSERVATION" probes only log.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode"

	smb2 "github.com/hirochachacha/go-smb2"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators/guard"
	"digital.vasic.filesystem/pkg/fabric"
	"digital.vasic.filesystem/pkg/webdav"
)

// smbLogonErr is the exact value pkg/smb Connect returns when go-smb2's session setup is refused:
// go-smb2 conn.go accept() -> acceptError() -> &ResponseError{Code: status}; pkg/smb wraps it with
// fmt.Errorf("failed to create SMB session: %w", err) (smb.go:66).
func smbLogonErr(code uint32) error {
	return fmt.Errorf("failed to create SMB session: %w", &smb2.ResponseError{Code: code})
}

// W01: the classifier must recognise the REAL SMB credential-failure errors (MS-ERREF NTSTATUS).
func TestW01_ClassifyRealSMBLogonFailure(t *testing.T) {
	// control needles: the instrument (Classify through a wrapper) can see auth at all
	if fabric.Classify(fmt.Errorf("x: %w", fabric.MarkAuth(errors.New("y")))) != fabric.ClassAuth {
		t.Fatal("CONTROL FAILED: MarkAuth not seen")
	}
	if fabric.Classify(fmt.Errorf("ssh: handshake failed: %w", errors.New("ssh: unable to authenticate, attempted methods [none password], no supported methods remain"))) != fabric.ClassAuth {
		t.Fatal("CONTROL FAILED: SSH text marker not seen")
	}
	codes := []struct {
		name string
		code uint32
	}{
		{"STATUS_LOGON_FAILURE", 0xC000006D},
		{"STATUS_ACCOUNT_LOCKED_OUT", 0xC0000234},
		{"STATUS_ACCOUNT_DISABLED", 0xC0000072},
		{"STATUS_PASSWORD_EXPIRED", 0xC0000071},
		{"STATUS_NO_SUCH_USER", 0xC0000064},
		{"STATUS_ACCOUNT_RESTRICTION", 0xC000006E},
		{"STATUS_INVALID_LOGON_HOURS", 0xC000006F},
		{"STATUS_PASSWORD_MUST_CHANGE", 0xC0000224},
	}
	bad := 0
	for _, c := range codes {
		err := smbLogonErr(c.code)
		got := fabric.Classify(err)
		t.Logf("%s (0x%08X): %q -> %v", c.name, c.code, err.Error(), got)
		if got != fabric.ClassAuth {
			bad++
		}
	}
	if bad > 0 {
		t.Errorf("DEFECT: %d of %d real SMB credential/account failures are NOT ClassAuth", bad, len(codes))
	}
}

// W02: the Pool's rejected-login memory (S3 fix) must engage for the real SMB logon failure.
func TestW02_PoolRepeatsLoginsAfterRealSMBRejection(t *testing.T) {
	f := &slowFactory{connectErr: smbLogonErr(0xC000006D)}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 4})
	for i := 0; i < 20; i++ {
		_, _ = p.GetClient(cfgFor("nas-video"))
	}
	t.Logf("20 borrows after a real SMB STATUS_LOGON_FAILURE produced %d login attempts", f.conn.Load())
	if f.conn.Load() != 1 {
		t.Errorf("DEFECT: %d SMB logins for 20 borrows after a rejected password (want 1): NAS auto-block risk", f.conn.Load())
	}
}

// W03: the same over the REAL pkg/webdav client against a server that answers 401 (loopback httptest, not the NAS).
type webdavFactory struct{ url string }

func (w webdavFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	return webdav.NewWebDAVClient(&webdav.Config{URL: w.url, Username: "u", Password: "dummy-wrong"}), nil
}
func (webdavFactory) SupportedProtocols() []string { return nil }

func TestW03_PoolRepeatsLoginsAfterRealWebDAV401(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("WWW-Authenticate", `Basic realm="nas"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	p := newPool(t, webdavFactory{srv.URL}, fabric.PoolOptions{MaxPerKey: 4})
	var last error
	for i := 0; i < 20; i++ {
		_, last = p.GetClient(cfgFor("dav"))
	}
	t.Logf("20 borrows against a 401 server: %d authenticated requests; last err=%v class=%v", hits.Load(), last, fabric.Classify(last))
	if hits.Load() != 1 {
		t.Errorf("DEFECT: %d WebDAV logins (401) for 20 borrows, want 1", hits.Load())
	}
}

// W04: concurrent borrowers after a rejected login: a single login attempt should be made (single-flight).
type slowAuthFail struct {
	*fk
	n *atomic.Int64
}

func (c *slowAuthFail) Connect(ctx context.Context) error {
	c.n.Add(1)
	select {
	case <-time.After(30 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	return fabric.MarkAuth(errors.New("530 Login incorrect"))
}
func (c *slowAuthFail) IsConnected() bool { return false }

type slowAuthFactory struct{ n atomic.Int64 }

func (f *slowAuthFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	return &slowAuthFail{fk: newFk("p"), n: &f.n}, nil
}
func (*slowAuthFactory) SupportedProtocols() []string { return nil }

func TestW04_ConcurrentBorrowsEachLogInAfterRejection(t *testing.T) {
	f := &slowAuthFactory{}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 4})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.GetClientContext(context.Background(), cfgFor("a")) }()
	}
	wg.Wait()
	conc := f.n.Load()
	g := &slowAuthFactory{}
	q := newPool(t, g, fabric.PoolOptions{MaxPerKey: 4})
	for _, root := range []string{"movies", "music", "photos"} { // three roots, same NAS account
		_, _ = q.GetClient(cfgFor(root))
	}
	t.Logf("4 concurrent borrows of one root: %d logins; 3 roots on one account: %d logins", conc, g.n.Load())
	if conc != 1 {
		t.Errorf("DEFECT (residual of S3): %d concurrent login attempts with the same rejected credentials (no single-flight)", conc)
	}
}

// W05: an inner client returning (nil, nil) from ReadFile: a layer must not hand out a stream that panics, nor leak the slot.
type nilStream struct{ *fk }

func (n nilStream) ReadFile(context.Context, string) (io.ReadCloser, error) { return nil, nil }

func TestW05_LayerNilStreamNilError(t *testing.T) {
	b := mustBudget(t, 1, 1e6, nil)
	c := fabric.Limited(nilStream{newFk("p")}, b)
	rc, err := c.ReadFile(context.Background(), "/x")
	t.Logf("Limited.ReadFile over (nil,nil): rc=%T(nil=%v) err=%v", rc, rc == nil, err)
	var pv any
	if rc != nil {
		pv = func() (v any) { defer func() { v = recover() }(); _ = rc.Close(); return nil }()
	}
	st := b.Stats()
	t.Logf("Close panic=%v; budget after Close: %+v", pv, st)
	if pv != nil || st.InFlight != 0 {
		t.Errorf("DEFECT: a (nil,nil) stream became a non-nil wrapper that panics on Close (%v) and leaks the host slot (InFlight=%d)", pv, st.InFlight)
	}
}

// W06: a 1 ns BaseDelay/MaxDelay passes validation and retries back to back (same class as RV12/S14).
func TestW06_RetryNanosecondDelayIsAStorm(t *testing.T) {
	f := newFk("p")
	for i := 0; i < 100; i++ {
		f.queue("ListDirectory", fmt.Errorf("dial: %w", syscall.ECONNREFUSED))
	}
	c, err := fabric.Retrying(f, fabric.RetryPolicy{MaxAttempts: 100, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond})
	if err != nil {
		t.Logf("policy rejected: %v", err)
		return
	}
	t0 := time.Now()
	_, _ = c.ListDirectory(context.Background(), "/")
	d := time.Since(t0)
	t.Logf("MaxAttempts=100 BaseDelay=MaxDelay=1ns accepted: %d attempts in %v against a refusing host", f.count("ListDirectory"), d)
	if d < 50*time.Millisecond {
		t.Errorf("DEFECT: %d attempts in %v - a back-to-back retry storm passes validation with a 1ns delay", f.count("ListDirectory"), d)
	}
}

// W07: "any control character" in Confined: C1 controls (Unicode Cc U+0080..U+009F) and raw C1 bytes.
func TestW07_ConfinedC1Controls(t *testing.T) {
	cases := []string{"/data/a\u0085b", "/data/a\u009b2J", "/data/a\x9b2J", "/data/a\x85b"}
	for _, p := range cases {
		f := newFk("p")
		c := confined(t, f, "/data")
		_, err := c.GetFileInfo(context.Background(), p)
		cc := false
		for _, r := range p {
			if unicode.IsControl(r) {
				cc = true
			}
		}
		t.Logf("%q (contains Unicode Cc rune: %v): err=%v inner saw %q", p, cc, err, f.paths("GetFileInfo"))
		if !errors.Is(err, fabric.ErrOutsideRoot) {
			t.Errorf("DEFECT (claim 'any control character'): %q reached the inner client", p)
		}
	}
}

// W08: a 4yz FTP reply whose text echoes a file name holding an auth marker is read as bad credentials.
func TestW08_ClassifyFTP4yzWithPathText(t *testing.T) {
	cases := []*textproto.Error{
		{Code: 450, Msg: "/Movies/Access Denied (2019).mkv: Resource temporarily unavailable"},
		{Code: 451, Msg: "/home/m/not logged in.txt: Requested action aborted: local error in processing"},
	}
	for _, e := range cases {
		wrapped := fmt.Errorf("ftp: retrieve %s: %w", "/x", e)
		got := fabric.Classify(wrapped)
		t.Logf("%d %q -> %v", e.Code, e.Msg, got)
		if got != fabric.ClassTransient {
			t.Errorf("DEFECT: transient file-level reply %d classified %v (path text read as credentials)", e.Code, got)
		}
	}
}

// ---- HostBudget ----

// W09: a REUSED slot that ends up as the schedule tail is not wound back when given back: the next caller waits
// for a slot nobody used (member of the S1 class "cancelled tail then idle time is not lost").
func TestW09_BudgetReusedTailNotWoundBack(t *testing.T) {
	clk := newParkClock()
	b := mustBudget(t, 8, 10, clk)           // 100 ms spacing
	r1, _ := b.Acquire(context.Background()) // T+0 (starts now)
	defer r1()
	ctxB, cancelB := context.WithCancel(context.Background())
	cB := acquireAsync(b, ctxB) // T+100
	clk.waitParked(t, 1)
	ctxC, cancelC := context.WithCancel(context.Background())
	cC := acquireAsync(b, ctxC) // T+200 (tail)
	clk.waitParked(t, 2)
	cancelB()
	<-cB // T+100 freed (middle)
	clk.waitParked(t, 1)
	ctxD, cancelD := context.WithCancel(context.Background())
	cD := acquireAsync(b, ctxD) // reuses T+100
	clk.waitParked(t, 2)
	cancelC()
	<-cC // tail cancelled: front wound back to T+200
	clk.waitParked(t, 1)
	cancelD()
	<-cD // the reused T+100 is now the last reservation; given back with reused=true
	clk.waitParked(t, 0)
	clk.advance(150 * time.Millisecond) // T+150: one interval and a half after the only real start
	cE := acquireAsync(b, context.Background())
	var waited bool
	select {
	case r := <-cE:
		if r.err != nil {
			t.Fatal(r.err)
		}
		r.rel()
	case <-time.After(300 * time.Millisecond):
		waited = true
		clk.advance(time.Second)
		if r := <-cE; r.err == nil {
			r.rel()
		}
	}
	t.Logf("sleeps %v (B, C, D, E...) waited=%v", clk.sleeps(), waited)
	if waited {
		t.Errorf("DEFECT: the 5th caller waits for slot T+200 although the last real start was T+0 and it arrives at T+150 (sleeps %v)", clk.sleeps())
	}
}

// W10: property test of the spacing invariant: no two granted start slots closer than one interval, under
// random arrivals, cancellations and time advances (deterministic seeds, parkClock).
type idKey struct{}

type recClock struct {
	*parkClock
	mu sync.Mutex
	d  map[int]time.Duration
}

func (r *recClock) Sleep(ctx context.Context, d time.Duration) error {
	if id, ok := ctx.Value(idKey{}).(int); ok {
		r.mu.Lock()
		r.d[id] = d
		r.mu.Unlock()
	}
	return r.parkClock.Sleep(ctx, d)
}

func TestW10_BudgetSpacingInvariantRandomised(t *testing.T) {
	const interval = 100 * time.Millisecond
	violations, granted, cancelled := 0, 0, 0
	type waiter struct {
		id     int
		arrive time.Time
		cancel context.CancelFunc
		ch     chan acqResult
		res    *acqResult
	}
	poll := func(w *waiter) bool {
		if w.res != nil {
			return true
		}
		select {
		case r := <-w.ch:
			w.res = &r
			return true
		default:
			return false
		}
	}
	for seed := int64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		pc := newParkClock()
		rc := &recClock{parkClock: pc, d: map[int]time.Duration{}}
		b := mustBudget(t, 4, 10, rc)
		var live []*waiter
		var slots []time.Time
		id := 0
		collect := func() {
			keep := live[:0]
			for _, w := range live {
				if poll(w) {
					if w.res.err == nil {
						rc.mu.Lock()
						d := rc.d[w.id]
						rc.mu.Unlock()
						slots = append(slots, w.arrive.Add(d))
						w.res.rel()
					} else {
						cancelled++
					}
					continue
				}
				keep = append(keep, w)
			}
			live = keep
		}
		for step := 0; step < 200; step++ {
			op := rng.Intn(10)
			switch {
			case op < 4 && len(live) < 3:
				id++
				ctx, cancel := context.WithCancel(context.WithValue(context.Background(), idKey{}, id))
				w := &waiter{id: id, arrive: pc.Now(), cancel: cancel, ch: acquireAsync(b, ctx)}
				live = append(live, w)
				for i := 0; i < 20000; i++ {
					if poll(w) {
						break
					}
					rc.mu.Lock()
					_, slept := rc.d[w.id]
					rc.mu.Unlock()
					if slept {
						break
					}
					time.Sleep(100 * time.Microsecond)
				}
			case op < 7 && len(live) > 0:
				w := live[rng.Intn(len(live))]
				w.cancel()
				for i := 0; i < 20000 && !poll(w); i++ {
					time.Sleep(100 * time.Microsecond)
				}
			default:
				pc.advance(time.Duration(rng.Intn(250)) * time.Millisecond)
				time.Sleep(500 * time.Microsecond)
			}
			collect()
		}
		for _, w := range live {
			w.cancel()
			for i := 0; i < 20000 && !poll(w); i++ {
				time.Sleep(100 * time.Microsecond)
			}
		}
		collect()
		sort.Slice(slots, func(i, j int) bool { return slots[i].Before(slots[j]) })
		for i := 1; i < len(slots); i++ {
			if gap := slots[i].Sub(slots[i-1]); gap < interval {
				violations++
				t.Logf("seed %d: granted slots %v apart (< %v)", seed, gap, interval)
			}
		}
		granted += len(slots)
		if st := b.Stats(); st.InFlight != 0 || len(live) != 0 {
			t.Errorf("seed %d: InFlight=%d live=%d after every holder released and every waiter cancelled", seed, st.InFlight, len(live))
		}
	}
	t.Logf("granted starts across 40 seeds: %d, cancelled waiters: %d, spacing violations: %d", granted, cancelled, violations)
	if granted < 40 || cancelled < 40 {
		t.Fatalf("CONTROL: the driver exercised too little (granted %d, cancelled %d)", granted, cancelled)
	}
	if violations > 0 {
		t.Errorf("DEFECT: %d granted start slots closer than one interval", violations)
	}
}

// W11: Limited no longer bounds TestConnection: with MaxConcurrent=1 held by a stream, N probes run concurrently.
func TestW11_ProbesBypassTheConcurrencyCap(t *testing.T) {
	b := mustBudget(t, 1, 10, nil)
	g := &gauge{}
	inner := newFk("smb")
	inner.g = g
	inner.work = 20 * time.Millisecond
	c := fabric.Limited(inner, b)
	hold := fabric.Limited(newFk("sftp"), b)
	rc, err := hold.ReadFile(context.Background(), "/movie.mkv")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = c.TestConnection(context.Background()) }()
	}
	wg.Wait()
	t.Logf("MaxConcurrent=1 (held by an open stream), MaxReqPerSec=10: 8 TestConnection calls ran, peak concurrency %d, total %d", g.max.Load(), inner.count("TestConnection"))
	if g.max.Load() > int64(b.Config().MaxConcurrent) {
		t.Errorf("CLAIM vs REALITY: BudgetConfig.MaxConcurrent is documented as 'the maximum number of operations in flight at once'; probes ran %d at once with the cap held", g.max.Load())
	}
}

// W12: RedactConfig shapes outside the flat struct: nested struct, exported pointer field, slice of maps.
type wfInnerCreds struct{ Password string }
type wfTLS struct{ InsecureSkipVerify bool }
type wfCfg struct {
	Host    string
	Login   wfInnerCreds
	TLS     *wfTLS
	Extra   map[string]interface{}
	Pass    string
	PrivKey []byte
}

func TestW12_RedactConfigNestedShapes(t *testing.T) {
	live := &wfCfg{Host: "nas", Login: wfInnerCreds{Password: "dummy-pw-1"}, TLS: &wfTLS{},
		Extra: map[string]interface{}{"servers": []interface{}{map[string]interface{}{"password": "dummy-pw-2"}}},
		Pass:  "dummy-pw-3", PrivKey: []byte("dummy-key")}
	got := guard.RedactConfig(live).(*wfCfg)
	if got.Host != "nas" {
		t.Fatal("CONTROL: redaction lost a plain field")
	}
	problems := []string{}
	if got.Login.Password != "" {
		problems = append(problems, fmt.Sprintf("nested struct secret kept (len %d)", len(got.Login.Password)))
	}
	got.TLS.InsecureSkipVerify = true
	if live.TLS.InsecureSkipVerify {
		problems = append(problems, "exported pointer field shared: mutation reached the live config (TLS.InsecureSkipVerify)")
	}
	if m, ok := got.Extra["servers"].([]interface{})[0].(map[string]interface{}); ok {
		if _, has := m["password"]; has {
			problems = append(problems, "secret inside a slice of maps kept")
		}
	}
	if got.Pass != "" {
		problems = append(problems, "field 'Pass' not treated as a secret")
	}
	if len(got.PrivKey) != 0 {
		problems = append(problems, "field 'PrivKey' not treated as a secret")
	}
	t.Logf("problems: %v", problems)
	if len(problems) > 0 {
		t.Errorf("DEFECT (latent, claim 'no secret field, no pointer to the live config'): %d shape gaps: %v", len(problems), problems)
	}
}

// W13: a factory that hands out the SAME client twice (memoising) collides in the inUse map: a token leaks.
type memoFactory struct {
	mu sync.Mutex
	c  *poolClient
}

func (m *memoFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.c == nil {
		k := newFk("p")
		k.connected = false
		m.c = &poolClient{k}
	}
	return m.c, nil
}
func (*memoFactory) SupportedProtocols() []string { return nil }

func TestW13_DuplicateClientFromFactoryLeaksAToken(t *testing.T) {
	p := newPool(t, &memoFactory{}, fabric.PoolOptions{MaxPerKey: 2})
	c1, e1 := p.GetClient(cfgFor("a"))
	c2, e2 := p.GetClient(cfgFor("a"))
	t.Logf("two borrows: e1=%v e2=%v same=%v stats=%+v", e1, e2, c1 == c2, p.Stats())
	if e2 != nil {
		return // duplicate detected: correct
	}
	r1, r2 := p.ReturnClient(c1), p.ReturnClient(c2)
	t.Logf("returns: %v / %v stats=%+v", r1, r2, p.Stats())
	// capacity check: MaxPerKey=2 concurrent borrows must be possible again
	var got []client.Client
	var err error
	for i := 0; i < 2; i++ {
		var c client.Client
		c, err = p.GetClient(cfgFor("a"))
		if err != nil {
			break
		}
		got = append(got, c)
	}
	if err != nil {
		t.Errorf("DEFECT: after two borrows of one (duplicate) client the pool lost a slot permanently: %v", err)
	}
}

// W14: HostKey accepts malformed inputs (unterminated bracket, two colons without brackets) as keys.
func TestW14_HostKeyMalformed(t *testing.T) {
	for _, in := range []string{"[::1", "nas:445:1", "[nas]x:22"} {
		k, err := fabric.HostKey(in)
		t.Logf("HostKey(%q) = %q, %v", in, k, err)
		if err == nil {
			t.Errorf("DEFECT (LOW): malformed host %q accepted as key %q", in, k)
		}
	}
}
