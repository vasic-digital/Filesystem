package decorators_test

// The independent reviewer's probes (WF19, Opus xhigh), adopted VERBATIM as
// permanent regression tests (11.4.276(D)); against the pre-fix code each of
// them FAILED (evidence/wp12/fabric/fix-r2-red.txt).

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/local"
	"digital.vasic.filesystem/pkg/smb"
	"digital.vasic.filesystem/pkg/webdav"
)

// RV20: doc "A nil inner panics at construction, not on first use" - a typed nil is accepted.
func TestRV20_ReadOnlyTypedNilAccepted(t *testing.T) {
	var lc *local.Client
	pv := func() (v any) {
		defer func() { v = recover() }()
		decorators.ReadOnly(lc)
		return nil
	}()
	if pv == nil {
		t.Errorf("DEFECT (claim): typed-nil inner accepted at construction")
	}
}

// RV21: the read-only handle hands out the live, mutable inner config with the plaintext
// password: enough to build a read-WRITE client for the same share.
func TestRV21_ReadOnlyGetConfigLeaksCredentials(t *testing.T) {
	sc := &smb.Config{Host: "nas.invalid", Share: "media", Username: "u", Password: "REVIEW-DUMMY-NOT-A-SECRET"}
	ro := decorators.ReadOnly(smb.NewSMBClient(sc))
	if got, ok := ro.GetConfig().(*smb.Config); ok {
		if got.Password != "" {
			t.Errorf("DEFECT: ReadOnly(smb).GetConfig() exposes the password (len %d) - smb.NewSMBClient(got) is a read-write client", len(got.Password))
		}
		got.Share = "admin$"
		if sc.Share == "admin$" {
			t.Errorf("DEFECT: ReadOnly(smb).GetConfig() returns the live inner config pointer: the holder of the read-only handle re-targeted the inner client's share")
		}
	}
	wc := &webdav.Config{URL: "http://nas.invalid/dav", Username: "u", Password: "REVIEW-DUMMY-NOT-A-SECRET"}
	row := decorators.ReadOnly(webdav.NewWebDAVClient(wc))
	if got, ok := row.GetConfig().(*webdav.Config); ok && got.Password != "" {
		t.Errorf("DEFECT: ReadOnly(webdav).GetConfig() exposes the password (len %d)", len(got.Password))
	}
}

// RV22: the stream ReadOnly forwards is the inner client's raw handle; for the local client it is an
// *os.File, whose metadata mutators work on a read-only descriptor.
func TestRV22_ReadOnlyStreamHandleCanChmod(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	ro := decorators.ReadOnly(local.NewLocalClient(&local.Config{BasePath: dir}))
	ctx := context.Background()
	_ = ro.Connect(ctx)
	rc, err := ro.ReadFile(ctx, "keep.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	f, ok := rc.(*os.File)
	if !ok {
		// ADOPTED AS ASSERTION (was t.Skipf): the fixed behaviour is exactly that the
		// stream is NOT the raw handle, so there is nothing to Chmod. A skip here
		// would report a pass without testing anything, so it returns explicitly.
		t.Logf("stream is %T, not the inner *os.File: the metadata mutators are unreachable", rc)
		return
	}
	cerr := f.Chmod(0o600)
	st, _ := os.Stat(p)
	t.Logf("Chmod via the read-only handle: err=%v mode now %v", cerr, st.Mode().Perm())
	if cerr == nil && st.Mode().Perm() == 0o600 {
		t.Errorf("DEFECT (read-only claim): a ReadOnly client's ReadFile result changed the file mode on disk (%T exposes Chmod)", rc)
	}
}
