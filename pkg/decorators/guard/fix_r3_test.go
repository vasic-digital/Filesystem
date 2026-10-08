package guard_test

// Round-3 (WF24 re-review) tests: N9 (RedactConfig shapes and names), N4
// (nil streams), D2 (WriteTo reports while it copies).

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/decorators/guard"
)

func TestR3_IsSensitiveNameWordsAndSubstrings(t *testing.T) {
	t.Parallel()
	secret := []string{"Password", "PassWord", "passwd", "Pass", "pass", "PW", "pwd", "Pwd", "PrivKey", "priv_key", "PrivateKey", "private_key",
		"SSHKey", "ssh_key", "APIKey", "api_key", "ApiKey", "SecretKey", "AccessKey", "SigningKey", "AuthKey", "SessionKey",
		"Token", "refresh_token", "Cookie", "Cookies", "Authorization", "Bearer", "ClientSecret", "Passphrase", "CredentialRef", "db_password_2"}
	for _, n := range secret {
		if !guard.IsSensitiveName(n) {
			t.Errorf("%q is not treated as a secret", n)
		}
	}
	plain := []string{"Host", "Port", "Username", "Bypass", "Compass", "Passive", "PassiveMode", "Passenger", "HostKey", "PublicKey", "KeyFile",
		"Keyboard", "Monkey", "Share", "Path", "TLSMode", "Domain", "Root", "Timeout", "Display"}
	for _, n := range plain {
		if guard.IsSensitiveName(n) {
			t.Errorf("%q is treated as a secret", n)
		}
	}
}

type r3Creds struct {
	User     string
	Password string
}
type r3TLS struct{ InsecureSkipVerify bool }
type r3Node struct {
	Name string
	Next *r3Node
}
type r3Cfg struct {
	Host    string
	Login   r3Creds
	TLS     *r3TLS
	Servers []r3Creds
	ByName  map[string]r3Creds
	Extra   map[string]interface{}
	Arr     [2]r3Creds
	Any     interface{}
	Pass    string
	PrivKey []byte
	HostKey string
	Ch      chan int
	Fn      func() string
	Chain   *r3Node
}

func TestR3_RedactConfigNestedShapesAreDeepCopiedAndBlanked(t *testing.T) {
	t.Parallel()
	live := &r3Cfg{
		Host: "nas", Login: r3Creds{"u", "dummy-1"}, TLS: &r3TLS{},
		Servers: []r3Creds{{"a", "dummy-2"}},
		ByName:  map[string]r3Creds{"x": {"b", "dummy-3"}},
		Extra:   map[string]interface{}{"servers": []interface{}{map[string]interface{}{"password": "dummy-4", "host": "h"}}, "opts": map[string]interface{}{"token": "dummy-5", "n": 1}},
		Arr:     [2]r3Creds{{"c", "dummy-6"}, {"d", "dummy-7"}},
		Any:     &r3Creds{"e", "dummy-8"},
		Pass:    "dummy-9", PrivKey: []byte("dummy-10"), HostKey: "ssh-ed25519 AAAA", Ch: make(chan int), Fn: func() string { return "dummy-11" },
	}
	got := guard.RedactConfig(live).(*r3Cfg)
	if got.Host != "nas" || got.HostKey != "ssh-ed25519 AAAA" || got.Login.User != "u" || got.Servers[0].User != "a" || got.Any.(*r3Creds).User != "e" {
		t.Fatalf("CONTROL: redaction lost plain data: %+v", got)
	}
	if got.Login.Password != "" || got.Servers[0].Password != "" || got.ByName["x"].Password != "" || got.Arr[0].Password != "" || got.Arr[1].Password != "" ||
		got.Any.(*r3Creds).Password != "" || got.Pass != "" || len(got.PrivKey) != 0 {
		t.Errorf("a secret survived: %+v", got)
	}
	srv := got.Extra["servers"].([]interface{})[0].(map[string]interface{})
	if _, has := srv["password"]; has || srv["host"] != "h" {
		t.Errorf("slice of maps inside a map: %v", srv)
	}
	if opts := got.Extra["opts"].(map[string]interface{}); opts["token"] != nil || opts["n"] != 1 {
		t.Errorf("nested map: %v", opts)
	}
	if got.Ch != nil || got.Fn != nil {
		t.Error("live handles (chan, func) must be blanked")
	}
	// no pointer into the live config: mutate EVERYTHING reachable from the copy, compare with a pristine twin
	got.TLS.InsecureSkipVerify = true
	got.Servers[0].User = "mut"
	got.Extra["servers"].([]interface{})[0].(map[string]interface{})["host"] = "mut"
	got.Any.(*r3Creds).User = "mut"
	got.ByName["y"] = r3Creds{}
	if live.TLS.InsecureSkipVerify || live.Servers[0].User != "a" || live.Extra["servers"].([]interface{})[0].(map[string]interface{})["host"] != "h" ||
		live.Any.(*r3Creds).User != "e" || len(live.ByName) != 1 {
		t.Errorf("the copy shares memory with the live config: %+v", live)
	}
	if live.Login.Password != "dummy-1" || live.Pass != "dummy-9" || live.Fn == nil {
		t.Error("the live config was modified by RedactConfig")
	}
}

// a pointer cycle and a very deep chain neither hang nor panic; the part beyond
// the depth bound is blanked (fail closed).
func TestR3_RedactConfigDepthBoundAndCycle(t *testing.T) {
	t.Parallel()
	a := &r3Node{Name: "a"}
	a.Next = a
	type holder struct{ Chain *r3Node }
	done := make(chan interface{}, 1)
	go func() { done <- guard.RedactConfig(&holder{Chain: a}) }()
	select {
	case v := <-done:
		n := v.(*holder).Chain
		depth := 0
		for n != nil && depth < 100 {
			n = n.Next
			depth++
		}
		if depth > 8 || depth < 3 {
			t.Errorf("chain depth after redaction = %d, want bounded (<= 8, half the depth limit) and >= 3", depth)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RedactConfig hung on a pointer cycle")
	}
}

func TestR3_RedactConfigKeepsTopLevelContract(t *testing.T) {
	t.Parallel()
	if guard.RedactConfig(nil) != nil || guard.RedactConfig("s") != "s" || guard.RedactConfig(3) != 3 {
		t.Error("pass-through shapes changed")
	}
	var np *r3Cfg
	if got := guard.RedactConfig(np); got.(*r3Cfg) != nil {
		t.Error("nil pointer must stay nil")
	}
	m := guard.RedactConfig(map[string]interface{}{"user": "u", "Pass": "p", "cookie": "c", "n": 1}).(map[string]interface{})
	if len(m) != 2 || m["user"] != "u" || m["n"] != 1 {
		t.Errorf("map: %v", m)
	}
	if !reflect.DeepEqual(guard.RedactConfig(r3Creds{"u", "p"}), r3Creds{"u", ""}) {
		t.Error("struct value")
	}
}

// ---- N4: nil streams ----

type typedNilRC struct{}

func (*typedNilRC) Read([]byte) (int, error) { return 0, io.EOF }
func (*typedNilRC) Close() error             { return nil }

func TestR3_WrapOfANilStreamIsNil(t *testing.T) {
	t.Parallel()
	if guard.Wrap(nil, guard.Hooks{}) != nil {
		t.Error("Wrap(nil) != nil")
	}
	var tn *typedNilRC
	if w := guard.Wrap(tn, guard.Hooks{OnClose: func() { t.Error("hook ran") }}); w != nil {
		t.Errorf("Wrap(typed nil) = %T, want nil", w)
	}
	if guard.WrapSeekable(nil, guard.Hooks{}) != nil {
		t.Error("WrapSeekable(nil) != nil")
	}
	if w := guard.Wrap(io.NopCloser(strings.NewReader("x")), guard.Hooks{}); w == nil {
		t.Error("control: a real stream must be wrapped")
	}
}

// ---- D2: WriteTo is reported as it copies ----

type chunkWT struct{ chunks int }

func (c chunkWT) Read([]byte) (int, error) { return 0, io.EOF }
func (c chunkWT) Close() error             { return nil }
func (c chunkWT) WriteTo(w io.Writer) (int64, error) {
	var n int64
	for i := 0; i < c.chunks; i++ {
		k, err := w.Write([]byte("abcd"))
		n += int64(k)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func TestR3_WriteToReportsEveryWriteAndTheTotalOnce(t *testing.T) {
	t.Parallel()
	var calls []int
	w := guard.Wrap(chunkWT{chunks: 5}, guard.Hooks{OnRead: func(n int) { calls = append(calls, n) }})
	var sink bytes.Buffer
	n, err := w.(io.WriterTo).WriteTo(&sink)
	if err != nil || n != 20 || sink.String() != strings.Repeat("abcd", 5) {
		t.Fatalf("n=%d err=%v out=%q", n, err, sink.String())
	}
	if len(calls) != 5 {
		t.Fatalf("OnRead calls %v, want one per write", calls)
	}
	sum := 0
	for _, c := range calls {
		sum += c
	}
	if sum != 20 {
		t.Fatalf("bytes reported %d, want 20 (no double count)", sum)
	}
	// without an OnRead hook the destination is passed through untouched
	var seen io.Writer
	w2 := guard.Wrap(wtProbe{&seen}, guard.Hooks{})
	var dst bytes.Buffer
	_, _ = w2.(io.WriterTo).WriteTo(&dst)
	if seen != io.Writer(&dst) {
		t.Errorf("destination was wrapped although nobody observes reads: %T", seen)
	}
}

type wtProbe struct{ seen *io.Writer }

func (wtProbe) Read([]byte) (int, error) { return 0, io.EOF }
func (wtProbe) Close() error             { return nil }
func (p wtProbe) WriteTo(w io.Writer) (int64, error) {
	*p.seen = w
	return 0, nil
}
