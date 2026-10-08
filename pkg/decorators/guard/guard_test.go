package guard_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators/guard"
)

// ---- streams: every capability subset

type baseRC struct{ r *strings.Reader }

func (b baseRC) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b baseRC) Close() error               { return nil }

type withRA struct{ baseRC }

func (w withRA) ReadAt(p []byte, off int64) (int, error) { return w.r.ReadAt(p, off) }

type withSK struct{ baseRC }

func (w withSK) Seek(o int64, wh int) (int64, error) { return w.r.Seek(o, wh) }

type withWT struct{ baseRC }

func (w withWT) WriteTo(dst io.Writer) (int64, error) { return w.r.WriteTo(dst) }

type withAll struct{ baseRC }

func (w withAll) ReadAt(p []byte, off int64) (int, error) { return w.r.ReadAt(p, off) }
func (w withAll) Seek(o int64, wh int) (int64, error)     { return w.r.Seek(o, wh) }
func (w withAll) WriteTo(dst io.Writer) (int64, error)    { return w.r.WriteTo(dst) }

type raSK struct{ baseRC }

func (w raSK) ReadAt(p []byte, off int64) (int, error) { return w.r.ReadAt(p, off) }
func (w raSK) Seek(o int64, wh int) (int64, error)     { return w.r.Seek(o, wh) }

type raWT struct{ baseRC }

func (w raWT) ReadAt(p []byte, off int64) (int, error) { return w.r.ReadAt(p, off) }
func (w raWT) WriteTo(dst io.Writer) (int64, error)    { return w.r.WriteTo(dst) }

type skWT struct{ baseRC }

func (w skWT) Seek(o int64, wh int) (int64, error)  { return w.r.Seek(o, wh) }
func (w skWT) WriteTo(dst io.Writer) (int64, error) { return w.r.WriteTo(dst) }

func TestWrap_ExposesExactlyTheInnerCapabilitiesAndMetersAllReadPaths(t *testing.T) {
	t.Parallel()
	mk := func(f func(baseRC) io.ReadCloser) func() io.ReadCloser {
		return func() io.ReadCloser { return f(baseRC{strings.NewReader("0123456789")}) }
	}
	cases := []struct {
		name       string
		rc         func() io.ReadCloser
		ra, sk, wt bool
	}{
		{"none", mk(func(b baseRC) io.ReadCloser { return b }), false, false, false},
		{"ReaderAt", mk(func(b baseRC) io.ReadCloser { return withRA{b} }), true, false, false},
		{"Seeker", mk(func(b baseRC) io.ReadCloser { return withSK{b} }), false, true, false},
		{"WriterTo", mk(func(b baseRC) io.ReadCloser { return withWT{b} }), false, false, true},
		{"RA+SK", mk(func(b baseRC) io.ReadCloser { return raSK{b} }), true, true, false},
		{"RA+WT", mk(func(b baseRC) io.ReadCloser { return raWT{b} }), true, false, true},
		{"SK+WT", mk(func(b baseRC) io.ReadCloser { return skWT{b} }), false, true, true},
		{"all", mk(func(b baseRC) io.ReadCloser { return withAll{b} }), true, true, true},
	}
	for _, c := range cases {
		var read, closed atomic.Int64
		w := guard.Wrap(c.rc(), guard.Hooks{OnRead: func(n int) { read.Add(int64(n)) }, OnClose: func() { closed.Add(1) }})
		_, ra := w.(io.ReaderAt)
		_, sk := w.(io.Seeker)
		_, wt := w.(io.WriterTo)
		if ra != c.ra || sk != c.sk || wt != c.wt {
			t.Errorf("%s: capabilities RA=%v SK=%v WT=%v, want %v %v %v", c.name, ra, sk, wt, c.ra, c.sk, c.wt)
		}
		buf := make([]byte, 3)
		n, _ := w.Read(buf)
		want := int64(n)
		if ra {
			m, _ := w.(io.ReaderAt).ReadAt(buf, 5)
			want += int64(m)
		}
		if wt {
			m, _ := w.(io.WriterTo).WriteTo(io.Discard)
			want += m
		}
		if read.Load() != want || want == 0 {
			t.Errorf("%s: metered %d, want %d", c.name, read.Load(), want)
		}
		_ = w.Close()
		if closed.Load() != 1 {
			t.Errorf("%s: OnClose ran %d times", c.name, closed.Load())
		}
		// nothing else leaks through: the only methods are the declared ones
		for i := 0; i < reflect.TypeOf(w).NumMethod(); i++ {
			switch reflect.TypeOf(w).Method(i).Name {
			case "Read", "Close", "ReadAt", "Seek", "WriteTo":
			default:
				t.Errorf("%s: unexpected method %s", c.name, reflect.TypeOf(w).Method(i).Name)
			}
		}
	}
	// nil hooks are fine
	w := guard.Wrap(baseRC{strings.NewReader("x")}, guard.Hooks{})
	_, _ = w.Read(make([]byte, 1))
	_ = w.Close()
}

type rsc struct{ *bytes.Reader }

func (rsc) Close() error { return nil }

func TestWrapSeekable_StaysSeekable(t *testing.T) {
	t.Parallel()
	var rs client.ReadSeekCloser = rsc{bytes.NewReader([]byte("abcdef"))}
	w := guard.WrapSeekable(rs, guard.Hooks{})
	if _, err := w.Seek(2, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(w)
	if string(b) != "cdef" {
		t.Fatalf("%q", b)
	}
	if _, ok := w.(io.ReaderAt); !ok {
		t.Fatal("bytes.Reader's ReadAt was dropped")
	}
}

// the inner stream's own mutators are unreachable: an *os.File behind Wrap
// cannot be asserted to anything with Chmod / Fd / Stat / Truncate.
func TestWrap_HidesMetadataMutatorsOfTheConcreteHandle(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	w := guard.Wrap(f, guard.Hooks{})
	defer w.Close()
	if _, ok := w.(interface{ Chmod(os.FileMode) error }); ok {
		t.Fatal("Chmod reachable")
	}
	if _, ok := w.(interface{ Fd() uintptr }); ok {
		t.Fatal("Fd reachable")
	}
	if _, ok := w.(interface{ Truncate(int64) error }); ok {
		t.Fatal("Truncate reachable")
	}
	if _, ok := w.(*os.File); ok {
		t.Fatal("the raw *os.File is returned")
	}
}

// ---- config redaction

type cfgT struct {
	Host       string
	Password   string
	Passphrase string
	APIKey     string
	Token      string
	PrivateKey []byte
	Tags       []string
	Extra      map[string]interface{}
	hidden     string
}

func TestRedactConfig_StructPointerMapAndDetached(t *testing.T) {
	t.Parallel()
	orig := &cfgT{Host: "h", Password: "p", Passphrase: "pp", APIKey: "k", Token: "t", PrivateKey: []byte("pk"),
		Tags: []string{"a"}, Extra: map[string]interface{}{"user": "u", "secret": "s", "client_secret": "cs", "nested": map[string]interface{}{"password": "x", "ok": "y"}}, hidden: "h"}
	got := guard.RedactConfig(orig).(*cfgT)
	if got == orig {
		t.Fatal("same pointer")
	}
	if got.Host != "h" || got.Password != "" || got.Passphrase != "" || got.APIKey != "" || got.Token != "" || got.PrivateKey != nil || got.hidden != "h" {
		t.Fatalf("redaction wrong: %+v", got)
	}
	if _, ok := got.Extra["secret"]; ok {
		t.Fatal("secret map key kept")
	}
	if _, ok := got.Extra["client_secret"]; ok {
		t.Fatal("client_secret map key kept")
	}
	nested := got.Extra["nested"].(map[string]interface{})
	if _, ok := nested["password"]; ok || nested["ok"] != "y" || got.Extra["user"] != "u" {
		t.Fatalf("nested map: %v", got.Extra)
	}
	// detached: mutating the copy cannot reach the original
	got.Host = "evil"
	got.Tags[0] = "evil"
	got.Extra["user"] = "evil"
	nested["ok"] = "evil"
	if orig.Host != "h" || orig.Tags[0] != "a" || orig.Extra["user"] != "u" || orig.Extra["nested"].(map[string]interface{})["ok"] != "y" || orig.Password != "p" {
		t.Fatalf("the original changed: %+v", orig)
	}
	// struct value
	v := guard.RedactConfig(*orig).(cfgT)
	if v.Password != "" || v.Host != "h" {
		t.Fatalf("value form: %+v", v)
	}
	// map
	m := guard.RedactConfig(map[string]string{"user": "u", "Password": "p", "api_key": "k"}).(map[string]string)
	if len(m) != 1 || m["user"] != "u" {
		t.Fatalf("map: %v", m)
	}
}

func TestRedactConfig_PassThroughShapes(t *testing.T) {
	t.Parallel()
	if guard.RedactConfig(nil) != nil {
		t.Fatal("nil")
	}
	if guard.RedactConfig("cfg") != "cfg" || guard.RedactConfig(7) != 7 {
		t.Fatal("scalars must pass through")
	}
	var np *cfgT
	if got := guard.RedactConfig(np); got.(*cfgT) != nil {
		t.Fatal("typed nil pointer")
	}
	var nm map[string]string
	if got := guard.RedactConfig(nm); got.(map[string]string) != nil {
		t.Fatal("nil map")
	}
	for _, n := range []string{"Password", "password", "DB_PASSWD", "SecretKey", "AccessToken", "private_key", "PrivateKey", "ApiKey", "api_key", "Credentials", "Passphrase"} {
		if !guard.IsSensitiveName(n) {
			t.Errorf("%q not sensitive", n)
		}
	}
	for _, n := range []string{"Host", "Username", "Share", "Port", "Domain", "BasePath", "ReadOnly", "KnownHostsFile"} {
		if guard.IsSensitiveName(n) {
			t.Errorf("%q wrongly sensitive", n)
		}
	}
}
