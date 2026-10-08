package fabric_test

// Round-3 (WF24 re-review) regression tests: N4 (nil streams through every
// layer), N5 (retry delay floor), N6 (path guard characters), N11 (HostKey).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"
	"unicode"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/fabric"
)

// ---- N4 ----

type nilReadClient struct{ *fk }

func (nilReadClient) ReadFile(context.Context, string) (io.ReadCloser, error) { return nil, nil }

type nilSeekClient struct{ nilReadClient }

func (nilSeekClient) OpenSeekable(context.Context, string) (client.ReadSeekCloser, error) {
	return nil, nil
}

type typedNilReadClient struct{ *fk }

type tnRC struct{}

func (*tnRC) Read([]byte) (int, error) { return 0, io.EOF }
func (*tnRC) Close() error             { return nil }

func (typedNilReadClient) ReadFile(context.Context, string) (io.ReadCloser, error) {
	var p *tnRC
	return p, nil
}

type nopSink struct{}

func (nopSink) Observe(fabric.Sample) {}

func TestR3_EveryLayerRefusesANilStreamAndLeaksNothing(t *testing.T) {
	t.Parallel()
	for name, mk := range map[string]func(client.Client, *fabric.HostBudget) client.Client{
		"Limited":  func(c client.Client, b *fabric.HostBudget) client.Client { return fabric.Limited(c, b) },
		"Confined": func(c client.Client, b *fabric.HostBudget) client.Client { x, _ := fabric.Confined(c, "/"); return x },
		"Retrying": func(c client.Client, b *fabric.HostBudget) client.Client {
			x, _ := fabric.Retrying(c, fabric.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond})
			return x
		},
		"Metered": func(c client.Client, b *fabric.HostBudget) client.Client { return fabric.Metered(c, nopSink{}, nil) },
		"chain": func(c client.Client, b *fabric.HostBudget) client.Client {
			x, _ := fabric.Confined(c, "/")
			return fabric.Metered(fabric.Limited(x, b), nopSink{}, nil)
		},
	} {
		for _, inner := range []struct {
			label string
			c     client.Client
		}{
			{"(nil,nil)", nilReadClient{newFk("p")}},
			{"typed nil", typedNilReadClient{newFk("p")}},
			{"seekable (nil,nil)", nilSeekClient{nilReadClient{newFk("p")}}},
		} {
			b := mustBudget(t, 1, 1e6, nil)
			c := mk(inner.c, b)
			rc, err := c.ReadFile(context.Background(), "/x")
			if !errors.Is(err, fabric.ErrNilStream) || rc != nil {
				t.Errorf("%s/%s ReadFile: rc=%v err=%v, want (nil, ErrNilStream)", name, inner.label, rc, err)
			}
			if sc, ok := c.(client.SeekableClient); ok {
				rs, err := sc.OpenSeekable(context.Background(), "/x")
				if !errors.Is(err, fabric.ErrNilStream) || rs != nil {
					t.Errorf("%s/%s OpenSeekable: rs=%v err=%v", name, inner.label, rs, err)
				}
			}
			if st := b.Stats(); st.InFlight != 0 || st.Held != 0 {
				t.Errorf("%s/%s leaked a host slot: %+v", name, inner.label, st)
			}
		}
	}
	// control: a real stream still works through the same layers
	b := mustBudget(t, 1, 1e6, nil)
	c := fabric.Limited(newFk("p"), b)
	rc, err := c.ReadFile(context.Background(), "/x")
	if err != nil || rc == nil {
		t.Fatalf("control: %v", err)
	}
	_ = rc.Close()
	if b.Stats().InFlight != 0 {
		t.Fatal("control: slot not released")
	}
}

// A nil or typed-nil stream from the inner client comes out of ReadOnly as a
// plain nil interface (the caller's `rc == nil` works), never as a wrapper that
// panics on Close.
func TestR3_ReadOnlyKeepsNilStreamsNil(t *testing.T) {
	t.Parallel()
	rc, err := decorators.ReadOnly(typedNilReadClient{newFk("p")}).ReadFile(context.Background(), "/x")
	if err != nil || rc != nil {
		t.Errorf("typed-nil stream became (%T, %v)", rc, err)
	}
	rs, err := decorators.ReadOnly(nilSeekClient{nilReadClient{newFk("p")}}).(client.SeekableClient).OpenSeekable(context.Background(), "/x")
	if rs != nil || err != nil {
		t.Errorf("(nil,nil) seekable became (%T,%v)", rs, err)
	}
}

// ---- N5: the effective delay is never below MinRetryDelay ----

func TestR3_RetryDelayFloorAppliesToBaseMaxAndJitter(t *testing.T) {
	t.Parallel()
	policies := map[string]fabric.RetryPolicy{
		"1ns base":            {MaxAttempts: 6, BaseDelay: time.Nanosecond},
		"1ns base and cap":    {MaxAttempts: 6, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond},
		"tiny cap":            {MaxAttempts: 6, BaseDelay: time.Second, MaxDelay: time.Microsecond},
		"jitter returns zero": {MaxAttempts: 6, BaseDelay: time.Second, Jitter: func(time.Duration) time.Duration { return 0 }},
		"jitter negative":     {MaxAttempts: 6, BaseDelay: time.Second, Jitter: func(time.Duration) time.Duration { return -time.Second }},
	}
	for name, pol := range policies {
		f := newFk("p")
		for i := 0; i < 6; i++ {
			f.queue("TestConnection", errReset)
		}
		clk := newFakeClock()
		pol.Clock = clk
		c := retrying(t, f, pol)
		_ = c.TestConnection(context.Background())
		sl := clk.slept()
		if len(sl) != 5 {
			t.Fatalf("%s: %d sleeps", name, len(sl))
		}
		for i, d := range sl {
			if d < fabric.MinRetryDelay {
				t.Errorf("%s: sleep %d = %v, below the floor %v", name, i, d, fabric.MinRetryDelay)
			}
		}
	}
	if fabric.MinRetryDelay < 5*time.Millisecond || fabric.MinRetryDelay > 100*time.Millisecond {
		t.Errorf("MinRetryDelay %v is not a sane floor", fabric.MinRetryDelay)
	}
}

// the floor must not RAISE a legitimate larger delay
func TestR3_RetryDelayAboveTheFloorIsUntouched(t *testing.T) {
	t.Parallel()
	f := newFk("p")
	for i := 0; i < 3; i++ {
		f.queue("TestConnection", errReset)
	}
	clk := newFakeClock()
	c := retrying(t, f, fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: 200 * time.Millisecond, Clock: clk})
	_ = c.TestConnection(context.Background())
	if s := clk.slept(); len(s) != 2 || s[0] != 200*time.Millisecond || s[1] != 400*time.Millisecond {
		t.Fatalf("sleeps %v", s)
	}
}

// ---- N6: every control character and every invalid byte is refused ----

func TestR3_ConfinedRefusesEveryControlRuneAndInvalidByte(t *testing.T) {
	t.Parallel()
	check := func(label, p string, wantRefused bool) {
		f := newFk("p")
		c := confined(t, f, "/data")
		_, err := c.GetFileInfo(context.Background(), p)
		refused := errors.Is(err, fabric.ErrOutsideRoot)
		if refused != wantRefused {
			t.Errorf("%s %q: refused=%v err=%v inner=%q", label, p, refused, err, f.paths("GetFileInfo"))
		}
		if refused && f.total() != 0 {
			t.Errorf("%s %q: refused but the inner client was called", label, p)
		}
	}
	for r := rune(0); r <= 0xFF; r++ {
		p := "/data/a" + string(r) + "b"
		check(fmt.Sprintf("rune U+%04X", r), p, unicode.IsControl(r))
	}
	for b := 0x80; b <= 0xFF; b++ { // a lone byte >= 0x80 is never valid UTF-8
		check(fmt.Sprintf("raw byte %#x", b), "/data/a"+string([]byte{byte(b)})+"b", true)
	}
	check("overlong sequence", "/data/a\xc0\xafb", true)
	check("truncated multibyte", "/data/a\xe6\x97", true)
	for _, ok := range []string{"/data/日本語.mkv", "/data/café", "/data/a b", "/data/emoji \U0001F3AC", "/data/�.txt"} {
		check("valid UTF-8", ok, false)
	}
	// every path argument and the root
	f := newFk("p")
	c := confined(t, f, "/data")
	if err := c.CopyFile(context.Background(), "/data/a", "/data/b\u0085"); !errors.Is(err, fabric.ErrOutsideRoot) || f.total() != 0 {
		t.Errorf("CopyFile with a C1 control in the destination: %v (inner calls %d)", err, f.total())
	}
	if _, err := fabric.Confined(newFk("p"), "/da\u009bta"); err == nil {
		t.Error("a root with a C1 control was accepted")
	}
	if _, err := fabric.Confined(newFk("p"), "/da\xffta"); err == nil {
		t.Error("a root with invalid UTF-8 was accepted")
	}
}

// ---- N11: HostKey ----

func TestR3_HostKeyGrid(t *testing.T) {
	t.Parallel()
	good := map[string]string{
		"nas": "nas", "NAS.Local.": "nas.local", " nas ": "nas", "nas:445": "nas", "192.168.1.5": "192.168.1.5", "192.168.1.5:22": "192.168.1.5",
		"::1": "::1", "0:0:0:0:0:0:0:1": "::1", "[::1]": "::1", "[::1]:445": "::1", "[0:0:0:0:0:0:0:1]:22": "::1",
		"::ffff:192.168.1.5": "192.168.1.5", "[::ffff:192.168.1.5]:445": "192.168.1.5", "[fe80::1%eth0]:22": "fe80::1%eth0", "nas:65535": "nas", "nas:1": "nas",
	}
	for in, want := range good {
		got, err := fabric.HostKey(in)
		if err != nil || got != want {
			t.Errorf("HostKey(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "   ", "[::1", "[::1]x", "[::1]x:22", "[::1]:", "[::1]:0", "[::1]:65536", "[::1]:abc", "[::1]:22:1", "[nas]:22", "[nas]x:22", "[]", "[]:22",
		"nas:", "nas:abc", "nas:0", "nas:65536", "nas:99999", "nas:-1", "nas:+22", ":445", "nas:445:1", "1:2:3", "a:b:c", "nas::445",
		"http://nas", "nas/share", `nas\share`, "user@nas", "nas?x", "nas#x", "na s", "nas\x00",
	}
	for _, in := range bad {
		if k, err := fabric.HostKey(in); err == nil {
			t.Errorf("HostKey(%q) accepted as %q", in, k)
		}
	}
	// the three reviewer inputs, by name
	for _, in := range []string{"[::1", "nas:445:1", "[nas]x:22"} {
		if _, err := fabric.HostKey(in); err == nil {
			t.Errorf("reviewer input %q accepted", in)
		}
	}
}
