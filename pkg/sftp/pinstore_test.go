package sftp

// SFTP-17: the pin file is a trust anchor; these tests pin the properties of FilePinStore that protect it.

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pinFixture(t *testing.T) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	return dir, filepath.Join(dir, "pins.json")
}

func TestFilePinStore_RefusesAFileOthersCanWrite(t *testing.T) {
	_, p := pinFixture(t)
	s := NewFilePinStore(p)
	require.NoError(t, s.Record("h:22", HostKeyPin{Fingerprint: "SHA256:a"}))
	for _, mode := range []os.FileMode{0o660, 0o666, 0o620, 0o602} {
		require.NoError(t, os.Chmod(p, mode))
		_, err := s.Lookup("h:22")
		assert.ErrorIs(t, err, ErrPinStoreInsecure, "mode %v: Lookup", mode)
		assert.ErrorIs(t, s.Record("h:22", HostKeyPin{Fingerprint: "SHA256:b"}), ErrPinStoreInsecure, "mode %v: Record", mode)
		assert.ErrorIs(t, s.Remove("h:22", "SHA256:a"), ErrPinStoreInsecure, "mode %v: Remove", mode)
	}
	require.NoError(t, os.Chmod(p, 0o600))
	pins, err := s.Lookup("h:22")
	require.NoError(t, err)
	assert.Len(t, pins, 1, "nothing was written while the file was insecure")
	require.NoError(t, os.Chmod(p, 0o644)) // group/world READABLE is fine: only writability is the risk
	_, err = s.Lookup("h:22")
	assert.NoError(t, err)
}

func TestFilePinStore_RefusesADirectoryOthersCanWriteUnlessSticky(t *testing.T) {
	d, p := pinFixture(t)
	s := NewFilePinStore(p)
	require.NoError(t, s.Record("h:22", HostKeyPin{Fingerprint: "SHA256:a"}))
	require.NoError(t, os.Chmod(d, 0o777))
	_, err := s.Lookup("h:22")
	assert.ErrorIs(t, err, ErrPinStoreInsecure)
	assert.ErrorIs(t, s.Record("h:22", HostKeyPin{Fingerprint: "SHA256:b"}), ErrPinStoreInsecure)
	require.NoError(t, os.Chmod(d, 0o777|os.ModeSticky)) // like /tmp: others cannot replace our entry
	_, err = s.Lookup("h:22")
	assert.NoError(t, err)
	require.NoError(t, os.Chmod(d, 0o755))
	_, err = s.Lookup("h:22")
	assert.NoError(t, err)
}

// a pin "file" that is a directory (benign mode and owner) is refused as insecure, not reported as a read error
func TestFilePinStore_RefusesANonRegularPinFile(t *testing.T) {
	d, p := pinFixture(t)
	require.NoError(t, os.Mkdir(p, 0o700))
	_, err := NewFilePinStore(p).Lookup("h:22")
	assert.ErrorIs(t, err, ErrPinStoreInsecure)
	assert.ErrorIs(t, NewFilePinStore(p).Record("h:22", HostKeyPin{Fingerprint: "SHA256:a"}), ErrPinStoreInsecure)
	_ = d
}

func TestFilePinStore_RefusesASymlinkAsPinFile(t *testing.T) {
	d, p := pinFixture(t)
	target := filepath.Join(d, "real.json")
	require.NoError(t, os.WriteFile(target, []byte(`{}`), 0o600))
	require.NoError(t, os.Symlink(target, p))
	_, err := NewFilePinStore(p).Lookup("h:22")
	assert.ErrorIs(t, err, ErrPinStoreInsecure)
}

// Two store objects over one file (two processes would behave the same: the lock is an flock on a lock file) must not lose updates.
func TestFilePinStore_ConcurrentWritersLoseNothing(t *testing.T) {
	_, p := pinFixture(t)
	const per = 40
	var wg sync.WaitGroup
	for w := 0; w < 3; w++ {
		s := NewFilePinStore(p) // separate in-process mutexes
		wg.Add(1)
		go func(w int, s *FilePinStore) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				assert.NoError(t, s.Record(fmt.Sprintf("host%d:22", w), HostKeyPin{Fingerprint: fmt.Sprintf("SHA256:%d-%d", w, i)}))
			}
		}(w, s)
	}
	wg.Wait()
	s := NewFilePinStore(p)
	for w := 0; w < 3; w++ {
		pins, err := s.Lookup(fmt.Sprintf("host%d:22", w))
		require.NoError(t, err)
		assert.Len(t, pins, per, "writer %d lost updates", w)
	}
	fi, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}
