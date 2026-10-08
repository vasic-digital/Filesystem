package fabric_test

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
)

// passthrough methods are local (no I/O, no error): no Op exists for them.
var passthrough = map[string]bool{"IsConnected": true, "GetProtocol": true, "GetConfig": true}

// uncovered lists the methods of the given interfaces that are neither an Op
// nor a declared passthrough method.
func uncovered(ifaces ...reflect.Type) []string {
	var out []string
	for _, it := range ifaces {
		for i := 0; i < it.NumMethod(); i++ {
			n := it.Method(i).Name
			if passthrough[n] {
				continue
			}
			found := false
			for _, op := range fabric.AllOps() {
				if op.String() == n {
					found = true
				}
			}
			if !found {
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestOpTable_CoversEveryClientMethod(t *testing.T) {
	cl := reflect.TypeOf((*client.Client)(nil)).Elem()
	sk := reflect.TypeOf((*client.SeekableClient)(nil)).Elem()
	// control needle: the instrument sees the interfaces and a known method.
	if cl.NumMethod() != 15 || sk.NumMethod() != 1 {
		t.Fatalf("instrument sees %d+%d methods, want 15+1", cl.NumMethod(), sk.NumMethod())
	}
	if _, ok := cl.MethodByName("ListDirectory"); !ok {
		t.Fatal("needle ListDirectory not visible")
	}
	if u := uncovered(cl, sk); len(u) != 0 {
		t.Fatalf("methods without an Op (classify them in opTable): %v", u)
	}
	// every Op names a real method
	names := map[string]bool{}
	for _, it := range []reflect.Type{cl, sk} {
		for i := 0; i < it.NumMethod(); i++ {
			names[it.Method(i).Name] = true
		}
	}
	for _, op := range fabric.AllOps() {
		if !names[op.String()] {
			t.Errorf("Op %v is not a method of client.Client/SeekableClient", op)
		}
	}
	if len(fabric.AllOps())+len(passthrough) != cl.NumMethod()+sk.NumMethod() {
		t.Errorf("op count %d + passthrough %d != methods %d", len(fabric.AllOps()), len(passthrough), cl.NumMethod()+sk.NumMethod())
	}
}

// negative control: an interface with a new method is reported.
func TestOpTable_InstrumentDetectsInjectedMethod(t *testing.T) {
	type extended interface {
		client.Client
		MoveFile(ctx context.Context, a, b string) error
	}
	u := uncovered(reflect.TypeOf((*extended)(nil)).Elem())
	if len(u) != 1 || u[0] != "MoveFile" {
		t.Fatalf("injected MoveFile not detected: %v", u)
	}
}

func TestOpTable_Classification(t *testing.T) {
	mut := []string{}
	for _, op := range fabric.AllOps() {
		if op.Mutating() {
			mut = append(mut, op.String())
		}
		if op.Mutating() && op.Retryable() {
			t.Errorf("%v is both mutating and retryable", op)
		}
	}
	sort.Strings(mut)
	want := "CopyFile,CreateDirectory,DeleteDirectory,DeleteFile,WriteFile"
	if strings.Join(mut, ",") != want {
		t.Errorf("mutating ops = %v, want %s", mut, want)
	}
	if fabric.OpDisconnect.Retryable() {
		t.Error("Disconnect must not be retryable")
	}
	if fabric.OpCopyFile.Paths() != 2 || fabric.OpConnect.Paths() != 0 {
		t.Error("path arity wrong")
	}
	if fabric.Op(99).String() != "Op(99)" || fabric.Op(99).Mutating() || fabric.Op(99).Retryable() || fabric.Op(99).Paths() != 0 {
		t.Error("invalid Op must be inert")
	}
}

func TestHostKey(t *testing.T) {
	cases := map[string]string{
		"NAS.local": "nas.local", "nas.local:445": "nas.local", "Nas.Local.": "nas.local",
		"[fe80::1]:22": "fe80::1", "[::1]": "::1", "192.168.1.5:21": "192.168.1.5", " host ": "host",
		"fe80::1": "fe80::1",
	}
	for in, want := range cases {
		got, err := fabric.HostKey(in)
		if err != nil || got != want {
			t.Errorf("HostKey(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "  ", ":445", "[]"} {
		if _, err := fabric.HostKey(bad); err == nil {
			t.Errorf("HostKey(%q) must fail", bad)
		}
	}
}
