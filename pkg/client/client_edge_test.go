package client_test

import (
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
	"github.com/stretchr/testify/assert"
)

// --- FileInfo Edge Cases ---

func TestFileInfo_ZeroValues(t *testing.T) {
	t.Parallel()
	fi := client.FileInfo{}
	assert.Empty(t, fi.Name)
	assert.Equal(t, int64(0), fi.Size)
	assert.True(t, fi.ModTime.IsZero())
	assert.False(t, fi.IsDir)
	assert.Empty(t, fi.Path)
}

func TestFileInfo_NegativeSize(t *testing.T) {
	t.Parallel()
	fi := client.FileInfo{
		Name: "test.txt",
		Size: -1,
	}
	assert.Equal(t, int64(-1), fi.Size)
}

func TestFileInfo_UnicodeFilename(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		filename string
	}{
		{"chinese", "\u4e2d\u6587\u6587\u4ef6.txt"},
		{"arabic", "\u0645\u0644\u0641.txt"},
		{"emoji", "\U0001f4c4 document.txt"},
		{"japanese", "\u30c6\u30b9\u30c8.txt"},
		{"korean", "\ud14c\uc2a4\ud2b8.txt"},
		{"cyrillic", "\u0444\u0430\u0439\u043b.txt"},
		{"accented", "r\u00e9sum\u00e9.pdf"},
		{"mixed", "file_\u6d4b\u8bd5_test.dat"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi := client.FileInfo{Name: tt.filename}
			assert.Equal(t, tt.filename, fi.Name)
		})
	}
}

func TestFileInfo_PathTraversalStrings(t *testing.T) {
	t.Parallel()
	// These are stored as metadata - not executed - but verify they don't crash
	traversalPaths := []string{
		"../../etc/passwd",
		"../../../etc/shadow",
		"..\\..\\windows\\system32\\config\\sam",
		"....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"/dev/null",
		"NUL",
		"CON",
		"PRN",
	}

	for _, path := range traversalPaths {
		fi := client.FileInfo{
			Name: "file.txt",
			Path: path,
		}
		assert.Equal(t, path, fi.Path)
	}
}

func TestFileInfo_EmptyPath(t *testing.T) {
	t.Parallel()
	fi := client.FileInfo{
		Name: "file.txt",
		Path: "",
	}
	assert.Empty(t, fi.Path)
}

func TestFileInfo_PathWithSpacesAndSpecialChars(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
	}{
		{"spaces", "/path/to/my folder/file name.txt"},
		{"hash", "/path/to/dir#1/file#2.txt"},
		{"parentheses", "/path/to/dir (copy)/file (1).txt"},
		{"ampersand", "/path/Tom & Jerry/movie.mkv"},
		{"single_quotes", "/path/'quoted'/file.txt"},
		{"double_quotes", "/path/\"quoted\"/file.txt"},
		{"null_byte", "/path/file\x00name.txt"},
		{"newline", "/path/file\nname.txt"},
		{"tab", "/path/file\tname.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi := client.FileInfo{Path: tt.path}
			assert.Equal(t, tt.path, fi.Path)
		})
	}
}

func TestFileInfo_FutureModTime(t *testing.T) {
	t.Parallel()
	future := time.Now().Add(365 * 24 * time.Hour)
	fi := client.FileInfo{
		Name:    "future.txt",
		ModTime: future,
	}
	assert.True(t, fi.ModTime.After(time.Now()))
}

func TestFileInfo_VeryOldModTime(t *testing.T) {
	t.Parallel()
	old := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	fi := client.FileInfo{
		Name:    "old.txt",
		ModTime: old,
	}
	assert.Equal(t, 1970, fi.ModTime.Year())
}

// --- StorageConfig Edge Cases ---

func TestStorageConfig_EmptyFields(t *testing.T) {
	t.Parallel()
	cfg := client.StorageConfig{}
	assert.Empty(t, cfg.ID)
	assert.Empty(t, cfg.Name)
	assert.Empty(t, cfg.Protocol)
	assert.False(t, cfg.Enabled)
	assert.Equal(t, 0, cfg.MaxDepth)
	assert.Nil(t, cfg.Settings)
}

func TestStorageConfig_NilSettings(t *testing.T) {
	t.Parallel()
	cfg := client.StorageConfig{
		ID:       "test-id",
		Protocol: "local",
		Settings: nil,
	}
	assert.Nil(t, cfg.Settings)
}

func TestStorageConfig_UnsupportedProtocol(t *testing.T) {
	t.Parallel()
	cfg := client.StorageConfig{
		Protocol: "nonexistent_protocol",
	}
	assert.Equal(t, "nonexistent_protocol", cfg.Protocol)
}

func TestStorageConfig_NegativeMaxDepth(t *testing.T) {
	t.Parallel()
	cfg := client.StorageConfig{
		MaxDepth: -1,
	}
	assert.Equal(t, -1, cfg.MaxDepth)
}

// --- CopyOperation Edge Cases ---

func TestCopyOperation_EmptyPaths(t *testing.T) {
	t.Parallel()
	op := client.CopyOperation{
		SourcePath:      "",
		DestinationPath: "",
	}
	assert.Empty(t, op.SourcePath)
	assert.Empty(t, op.DestinationPath)
}

func TestCopyOperation_SameSourceAndDest(t *testing.T) {
	t.Parallel()
	op := client.CopyOperation{
		SourcePath:      "/same/path/file.txt",
		DestinationPath: "/same/path/file.txt",
	}
	assert.Equal(t, op.SourcePath, op.DestinationPath)
}

// --- CopyResult Edge Cases ---

func TestCopyResult_FailedCopy(t *testing.T) {
	t.Parallel()
	result := client.CopyResult{
		Success:     false,
		BytesCopied: 0,
		Error:       assert.AnError,
	}
	assert.False(t, result.Success)
	assert.Error(t, result.Error)
}

func TestCopyResult_ZeroBytesSuccess(t *testing.T) {
	t.Parallel()
	result := client.CopyResult{
		Success:     true,
		BytesCopied: 0,
	}
	assert.True(t, result.Success)
	assert.Equal(t, int64(0), result.BytesCopied)
}

// --- ObjectRef (ensure types can hold edge-case values) ---

func TestObjectRef_LongPath(t *testing.T) {
	t.Parallel()
	longName := ""
	for i := 0; i < 1000; i++ {
		longName += "a"
	}
	fi := client.FileInfo{
		Name: longName,
		Path: "/" + longName,
	}
	assert.Len(t, fi.Name, 1000)
}
