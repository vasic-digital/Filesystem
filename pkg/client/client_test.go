package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFileInfo_Fields(t *testing.T) {
	fi := &FileInfo{
		Name:    "test.txt",
		Size:    1024,
		ModTime: time.Now(),
		IsDir:   false,
		Mode:    0644,
		Path:    "/path/to/test.txt",
	}
	assert.Equal(t, "test.txt", fi.Name)
	assert.Equal(t, int64(1024), fi.Size)
	assert.False(t, fi.IsDir)
}

func TestStorageConfig_Fields(t *testing.T) {
	cfg := &StorageConfig{
		ID:       "test-1",
		Name:     "Test Storage",
		Protocol: "local",
		Enabled:  true,
		MaxDepth: 10,
		Settings: map[string]interface{}{"base_path": "/tmp"},
	}
	assert.Equal(t, "local", cfg.Protocol)
	assert.True(t, cfg.Enabled)
}

func TestCopyOperation_Fields(t *testing.T) {
	op := &CopyOperation{
		SourcePath:        "/src/file.txt",
		DestinationPath:   "/dst/file.txt",
		OverwriteExisting: true,
	}
	assert.Equal(t, "/src/file.txt", op.SourcePath)
	assert.True(t, op.OverwriteExisting)
}
