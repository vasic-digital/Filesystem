package sftp

// White-box half of the pin store tests (trustedOwner exists only after the fix).

import (
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustedOwner(t *testing.T) {
	_, p := pinFixture(t)
	require.NoError(t, os.WriteFile(p, nil, 0o600))
	fi, err := os.Stat(p)
	require.NoError(t, err)
	me := uint32(os.Getuid())
	assert.True(t, trustedOwner(fakeOwner{fi, me}), "own file")
	assert.True(t, trustedOwner(fakeOwner{fi, 0}), "root-owned")
	assert.False(t, trustedOwner(fakeOwner{fi, me + 7}), "somebody else's")
	assert.True(t, trustedOwner(fi), "real stat of own file")
}

type fakeOwner struct {
	os.FileInfo
	uid uint32
}

func (f fakeOwner) Sys() any { return &syscall.Stat_t{Uid: f.uid} }
