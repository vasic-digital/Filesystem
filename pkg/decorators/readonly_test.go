package decorators_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/local"
)

// rec is a recording stand-in for a protocol client (unit tests only).
type rec struct {
	mu    sync.Mutex
	calls map[string]int
}

func newRec() *rec { return &rec{calls: map[string]int{}} }

func (r *rec) hit(n string) {
	r.mu.Lock()
	r.calls[n]++
	r.mu.Unlock()
}
func (r *rec) count(n string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[n]
}
func (r *rec) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := 0
	for _, v := range r.calls {
		t += v
	}
	return t
}

var errInner = errors.New("inner sentinel")

func (r *rec) Connect(context.Context) error        { r.hit("Connect"); return errInner }
func (r *rec) Disconnect(context.Context) error     { r.hit("Disconnect"); return errInner }
func (r *rec) IsConnected() bool                    { r.hit("IsConnected"); return true }
func (r *rec) TestConnection(context.Context) error { r.hit("TestConnection"); return errInner }
func (r *rec) ReadFile(context.Context, string) (io.ReadCloser, error) {
	r.hit("ReadFile")
	return io.NopCloser(strings.NewReader("x")), errInner
}
func (r *rec) WriteFile(context.Context, string, io.Reader) error { r.hit("WriteFile"); return nil }
func (r *rec) GetFileInfo(context.Context, string) (*client.FileInfo, error) {
	r.hit("GetFileInfo")
	return &client.FileInfo{Name: "n"}, errInner
}
func (r *rec) FileExists(context.Context, string) (bool, error) {
	r.hit("FileExists")
	return true, errInner
}
func (r *rec) DeleteFile(context.Context, string) error       { r.hit("DeleteFile"); return nil }
func (r *rec) CopyFile(context.Context, string, string) error { r.hit("CopyFile"); return nil }
func (r *rec) ListDirectory(context.Context, string) ([]*client.FileInfo, error) {
	r.hit("ListDirectory")
	return []*client.FileInfo{{Name: "a"}}, errInner
}
func (r *rec) CreateDirectory(context.Context, string) error { r.hit("CreateDirectory"); return nil }
func (r *rec) DeleteDirectory(context.Context, string) error { r.hit("DeleteDirectory"); return nil }
func (r *rec) GetProtocol() string                           { r.hit("GetProtocol"); return "rec" }
func (r *rec) GetConfig() interface{}                        { r.hit("GetConfig"); return "cfg" }

type recSeek struct{ *rec }

func (r recSeek) OpenSeekable(context.Context, string) (client.ReadSeekCloser, error) {
	r.hit("OpenSeekable")
	return nil, errInner
}

type kind int

const (
	kindRead kind = iota
	kindMutator
	kindLifecycle
)

// classification is the reviewed decision for every method of client.Client.
// A new interface method that is not listed here fails
// TestReadOnly_ClassifiesEveryInterfaceMethod: decide mutator or not, add it.
var classification = map[string]kind{
	"Connect": kindLifecycle, "Disconnect": kindLifecycle, "IsConnected": kindLifecycle,
	"TestConnection": kindLifecycle, "GetProtocol": kindRead, "GetConfig": kindRead,
	"ReadFile": kindRead, "GetFileInfo": kindRead, "FileExists": kindRead, "ListDirectory": kindRead,
	"WriteFile": kindMutator, "DeleteFile": kindMutator, "CopyFile": kindMutator,
	"CreateDirectory": kindMutator, "DeleteDirectory": kindMutator,
}

var mutatingPrefixes = []string{"Write", "Delete", "Create", "Copy", "Move", "Rename", "Remove", "Mkdir",
	"Chmod", "Chown", "Truncate", "Symlink", "Link", "Put", "Append", "Upload", "Set", "Touch", "Save", "Update", "Mv", "Rm"}

// problems returns one message per method of iface that is unclassified or
// whose name looks like a mutator but is not classified as one.
func problems(iface reflect.Type, cls map[string]kind) []string {
	var out []string
	for i := 0; i < iface.NumMethod(); i++ {
		n := iface.Method(i).Name
		k, ok := cls[n]
		if !ok {
			out = append(out, "unclassified method "+n)
			continue
		}
		for _, p := range mutatingPrefixes {
			if strings.HasPrefix(n, p) && k != kindMutator {
				out = append(out, "mutator-named method "+n+" is not classified as mutator")
			}
		}
	}
	return out
}

func clientType() reflect.Type { return reflect.TypeOf((*client.Client)(nil)).Elem() }

func TestReadOnly_ClassifiesEveryInterfaceMethod(t *testing.T) {
	t.Parallel()
	typ := clientType()
	// control needle: the instrument must see the whole interface, incl. known names.
	if typ.NumMethod() != len(classification) {
		t.Fatalf("interface has %d methods, classification has %d: %v", typ.NumMethod(), len(classification), problems(typ, classification))
	}
	if _, ok := typ.MethodByName("WriteFile"); !ok {
		t.Fatal("needle WriteFile not visible to reflection")
	}
	if p := problems(typ, classification); len(p) != 0 {
		t.Fatalf("classification drift: %v", p)
	}
}

// negative control: a synthetic interface with a new mutator must be reported.
func TestReadOnly_ClassifierSeesAnInjectedMutator(t *testing.T) {
	t.Parallel()
	type withMove interface {
		client.Client
		MoveFile(ctx context.Context, a, b string) error
	}
	p := problems(reflect.TypeOf((*withMove)(nil)).Elem(), classification)
	if len(p) != 1 || !strings.Contains(p[0], "MoveFile") {
		t.Fatalf("classifier missed the injected mutator MoveFile: %v", p)
	}
	// and a mutator-named method wrongly classified as read is flagged
	bad := map[string]kind{}
	for k, v := range classification {
		bad[k] = v
	}
	bad["WriteFile"] = kindRead
	if p := problems(clientType(), bad); len(p) != 1 {
		t.Fatalf("misclassified WriteFile not flagged: %v", p)
	}
}

type countingReader struct{ n int }

func (c *countingReader) Read([]byte) (int, error) { c.n++; return 0, io.EOF }

// argsFor builds call arguments from the method signature (ctx, strings, a reader).
func argsFor(m reflect.Method, path string, rd io.Reader) []reflect.Value {
	var args []reflect.Value
	for i := 1; i < m.Type.NumIn(); i++ { // 0 is the receiver
		switch m.Type.In(i) {
		case reflect.TypeOf((*context.Context)(nil)).Elem():
			args = append(args, reflect.ValueOf(context.Background()))
		case reflect.TypeOf(""):
			args = append(args, reflect.ValueOf(path))
		case reflect.TypeOf((*io.Reader)(nil)).Elem():
			args = append(args, reflect.ValueOf(&rd).Elem())
		default:
			panic("argsFor: unsupported parameter type " + m.Type.In(i).String() + " of " + m.Name)
		}
	}
	return args
}

// invoke calls method name on ro with generated arguments.
func invoke(ro client.Client, name, path string, rd io.Reader) []reflect.Value {
	v := reflect.ValueOf(ro)
	m, ok := v.Type().MethodByName(name)
	if !ok {
		panic("method not found " + name)
	}
	return v.MethodByName(name).Call(argsFor(m, path, rd)[0:])
}

// mutatorNames lists the mutators from the interface by classification.
func mutatorNames() []string {
	var out []string
	typ := clientType()
	for i := 0; i < typ.NumMethod(); i++ {
		if classification[typ.Method(i).Name] == kindMutator {
			out = append(out, typ.Method(i).Name)
		}
	}
	return out
}

func TestReadOnly_EveryMutatorRefusesAndNeverCallsInner(t *testing.T) {
	t.Parallel()
	names := mutatorNames()
	if len(names) != 5 {
		t.Fatalf("expected 5 mutators in the interface, found %d: %v", len(names), names)
	}
	for _, seekable := range []bool{false, true} {
		r := newRec()
		var in client.Client = r
		if seekable {
			in = recSeek{r}
		}
		ro := decorators.ReadOnly(in)
		for _, n := range names {
			cr := &countingReader{}
			res := invoke(ro, n, "/some/path", cr)
			errV := res[len(res)-1]
			err, _ := errV.Interface().(error)
			if !errors.Is(err, decorators.ErrReadOnly) {
				t.Errorf("seekable=%v %s: err=%v, want ErrReadOnly", seekable, n, err)
			}
			if cr.n != 0 {
				t.Errorf("%s consumed the data reader", n)
			}
		}
		if r.total() != 0 {
			t.Errorf("seekable=%v inner was called: %v", seekable, r.calls)
		}
	}
}

func TestReadOnly_ReadsAndLifecycleAreForwarded(t *testing.T) {
	t.Parallel()
	r := newRec()
	ro := decorators.ReadOnly(r)
	ctx := context.Background()
	if err := ro.Connect(ctx); !errors.Is(err, errInner) {
		t.Errorf("Connect: %v", err)
	}
	if err := ro.Disconnect(ctx); !errors.Is(err, errInner) {
		t.Errorf("Disconnect: %v", err)
	}
	if err := ro.TestConnection(ctx); !errors.Is(err, errInner) {
		t.Errorf("TestConnection: %v", err)
	}
	if !ro.IsConnected() {
		t.Error("IsConnected not forwarded")
	}
	if rc, err := ro.ReadFile(ctx, "/a"); !errors.Is(err, errInner) || rc == nil {
		t.Errorf("ReadFile: %v %v", rc, err)
	}
	if fi, err := ro.GetFileInfo(ctx, "/a"); !errors.Is(err, errInner) || fi == nil || fi.Name != "n" {
		t.Errorf("GetFileInfo: %v %v", fi, err)
	}
	if ok, err := ro.FileExists(ctx, "/a"); !errors.Is(err, errInner) || !ok {
		t.Errorf("FileExists: %v %v", ok, err)
	}
	if l, err := ro.ListDirectory(ctx, "/a"); !errors.Is(err, errInner) || len(l) != 1 {
		t.Errorf("ListDirectory: %v %v", l, err)
	}
	if ro.GetProtocol() != "rec" || ro.GetConfig() != "cfg" {
		t.Error("metadata not forwarded")
	}
	for _, n := range []string{"Connect", "Disconnect", "TestConnection", "IsConnected", "ReadFile", "GetFileInfo", "FileExists", "ListDirectory", "GetProtocol", "GetConfig"} {
		if r.count(n) != 1 {
			t.Errorf("%s forwarded %d times, want 1", n, r.count(n))
		}
	}
}

func TestReadOnly_SeekablePassthroughOnlyWhenInnerHasIt(t *testing.T) {
	t.Parallel()
	if _, ok := decorators.ReadOnly(newRec()).(client.SeekableClient); ok {
		t.Error("non-seekable inner must not yield a SeekableClient")
	}
	r := newRec()
	ro := decorators.ReadOnly(recSeek{r})
	sc, ok := ro.(client.SeekableClient)
	if !ok {
		t.Fatal("seekable inner lost OpenSeekable")
	}
	if _, err := sc.OpenSeekable(context.Background(), "/a"); !errors.Is(err, errInner) || r.count("OpenSeekable") != 1 {
		t.Errorf("OpenSeekable not forwarded: %v %d", err, r.count("OpenSeekable"))
	}
}

func TestReadOnly_NilInnerPanicsAtConstruction(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil inner")
		}
	}()
	decorators.ReadOnly(nil)
}

// Real filesystem (no fake): the decorated local client cannot change the disk.
func TestReadOnly_RealLocalFilesystemUntouched(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	lc := local.NewLocalClient(&local.Config{BasePath: dir})
	ro := decorators.ReadOnly(lc)
	ctx := context.Background()
	if err := ro.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ro.WriteFile(ctx, "new.txt", strings.NewReader("x")); !errors.Is(err, decorators.ErrReadOnly) {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ro.DeleteFile(ctx, "keep.txt"); !errors.Is(err, decorators.ErrReadOnly) {
		t.Fatalf("DeleteFile: %v", err)
	}
	if err := ro.CreateDirectory(ctx, "d"); !errors.Is(err, decorators.ErrReadOnly) {
		t.Fatalf("CreateDirectory: %v", err)
	}
	if err := ro.CopyFile(ctx, "keep.txt", "copy.txt"); !errors.Is(err, decorators.ErrReadOnly) {
		t.Fatalf("CopyFile: %v", err)
	}
	if err := ro.DeleteDirectory(ctx, "d"); !errors.Is(err, decorators.ErrReadOnly) {
		t.Fatalf("DeleteDirectory: %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 1 || ents[0].Name() != "keep.txt" {
		t.Fatalf("disk changed: %v %v", ents, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "keep.txt"))
	if string(b) != "original" {
		t.Fatalf("content changed: %q", b)
	}
	// reads still work through the decorator
	list, err := ro.ListDirectory(ctx, "/")
	if err != nil || len(list) != 1 {
		t.Fatalf("read through decorator failed: %v %v", list, err)
	}
	rc, err := ro.ReadFile(ctx, "keep.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(got) != "original" {
		t.Fatalf("read back %q", got)
	}
}

// FuzzReadOnly_Mutators: for any path text every mutator refuses and the
// inner client is never reached.
func FuzzReadOnly_Mutators(f *testing.F) {
	for _, s := range []string{"", "/", "a", "../../etc/passwd", "a\x00b", "\\\\host\\share", "é/日本", strings.Repeat("x", 4096)} {
		f.Add(s)
	}
	names := mutatorNames()
	f.Fuzz(func(t *testing.T, path string) {
		r := newRec()
		ro := decorators.ReadOnly(recSeek{r})
		for _, n := range names {
			cr := &countingReader{}
			res := invoke(ro, n, path, cr)
			err, _ := res[len(res)-1].Interface().(error)
			if !errors.Is(err, decorators.ErrReadOnly) || cr.n != 0 {
				t.Fatalf("%s(%q): err=%v consumed=%d", n, path, err, cr.n)
			}
		}
		if r.total() != 0 {
			t.Fatalf("inner reached: %v", r.calls)
		}
	})
}
