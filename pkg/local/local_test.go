package local

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"digital.vasic.filesystem/pkg/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalClient_Connect(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)

	err := c.Connect(context.Background())
	require.NoError(t, err)
	assert.True(t, c.IsConnected())

	err = c.Disconnect(context.Background())
	require.NoError(t, err)
	assert.False(t, c.IsConnected())
}

func TestLocalClient_Connect_InvalidPath(t *testing.T) {
	config := &Config{BasePath: "/nonexistent/path/that/does/not/exist"}
	c := NewLocalClient(config)

	err := c.Connect(context.Background())
	assert.Error(t, err)
	assert.False(t, c.IsConnected())
}

func TestLocalClient_Connect_NotADirectory(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "file.txt")
	err := os.WriteFile(filePath, []byte("test"), 0644)
	require.NoError(t, err)

	config := &Config{BasePath: filePath}
	c := NewLocalClient(config)

	err = c.Connect(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

func TestLocalClient_TestConnection(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	err = c.TestConnection(context.Background())
	assert.NoError(t, err)
}

func TestLocalClient_TestConnection_NotConnected(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	err := c.TestConnection(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestLocalClient_WriteFile(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	testContent := "Hello, World!"
	testPath := "test.txt"

	err = c.WriteFile(context.Background(), testPath, bytes.NewReader([]byte(testContent)))
	require.NoError(t, err)

	fullPath := filepath.Join(tempDir, testPath)
	content, err := os.ReadFile(fullPath)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(content))
}

func TestLocalClient_WriteFile_NestedDirectory(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	testContent := "nested content"
	testPath := "sub/dir/test.txt"

	err = c.WriteFile(context.Background(), testPath, bytes.NewReader([]byte(testContent)))
	require.NoError(t, err)

	fullPath := filepath.Join(tempDir, testPath)
	content, err := os.ReadFile(fullPath)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(content))
}

func TestLocalClient_WriteFile_NotConnected(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	err := c.WriteFile(context.Background(), "test.txt", bytes.NewReader([]byte("data")))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestLocalClient_ReadFile(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	testContent := "Hello, World!"
	testPath := "test.txt"
	fullPath := filepath.Join(tempDir, testPath)

	err = os.WriteFile(fullPath, []byte(testContent), 0644)
	require.NoError(t, err)

	reader, err := c.ReadFile(context.Background(), testPath)
	require.NoError(t, err)
	defer reader.Close()

	content, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(content))
}

func TestLocalClient_ReadFile_NotConnected(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	_, err := c.ReadFile(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestLocalClient_GetFileInfo(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	testContent := "Hello, World!"
	testPath := "test.txt"
	fullPath := filepath.Join(tempDir, testPath)

	err = os.WriteFile(fullPath, []byte(testContent), 0644)
	require.NoError(t, err)

	info, err := c.GetFileInfo(context.Background(), testPath)
	require.NoError(t, err)

	assert.Equal(t, "test.txt", info.Name)
	assert.Equal(t, int64(len(testContent)), info.Size)
	assert.False(t, info.IsDir)
	assert.Equal(t, testPath, info.Path)
}

func TestLocalClient_GetFileInfo_Directory(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	subDir := "subdir"
	err = os.Mkdir(filepath.Join(tempDir, subDir), 0755)
	require.NoError(t, err)

	info, err := c.GetFileInfo(context.Background(), subDir)
	require.NoError(t, err)

	assert.Equal(t, "subdir", info.Name)
	assert.True(t, info.IsDir)
}

func TestLocalClient_GetFileInfo_NotConnected(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	_, err := c.GetFileInfo(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestLocalClient_ListDirectory(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	testFile := filepath.Join(tempDir, "test.txt")
	testDir := filepath.Join(tempDir, "testdir")

	err = os.WriteFile(testFile, []byte("test"), 0644)
	require.NoError(t, err)

	err = os.Mkdir(testDir, 0755)
	require.NoError(t, err)

	files, err := c.ListDirectory(context.Background(), "")
	require.NoError(t, err)

	assert.Len(t, files, 2)

	foundFile := false
	foundDir := false
	for _, file := range files {
		if file.Name == "test.txt" && !file.IsDir {
			foundFile = true
		}
		if file.Name == "testdir" && file.IsDir {
			foundDir = true
		}
	}

	assert.True(t, foundFile, "Test file not found in directory listing")
	assert.True(t, foundDir, "Test directory not found in directory listing")
}

func TestLocalClient_ListDirectory_NotConnected(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	_, err := c.ListDirectory(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestLocalClient_FileExists(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	testPath := "test.txt"
	fullPath := filepath.Join(tempDir, testPath)

	err = os.WriteFile(fullPath, []byte("test"), 0644)
	require.NoError(t, err)

	exists, err := c.FileExists(context.Background(), testPath)
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = c.FileExists(context.Background(), "nonexistent.txt")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestLocalClient_FileExists_NotConnected(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	_, err := c.FileExists(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestLocalClient_CreateDirectory(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	err = c.CreateDirectory(context.Background(), "newdir/sub")
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(tempDir, "newdir", "sub"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestLocalClient_CreateDirectory_NotConnected(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	err := c.CreateDirectory(context.Background(), "newdir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestLocalClient_DeleteDirectory(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	dirPath := filepath.Join(tempDir, "deldir")
	err = os.Mkdir(dirPath, 0755)
	require.NoError(t, err)

	err = c.DeleteDirectory(context.Background(), "deldir")
	require.NoError(t, err)

	_, err = os.Stat(dirPath)
	assert.True(t, os.IsNotExist(err))
}

func TestLocalClient_DeleteDirectory_NotConnected(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	err := c.DeleteDirectory(context.Background(), "dir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestLocalClient_DeleteFile(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	filePath := filepath.Join(tempDir, "todelete.txt")
	err = os.WriteFile(filePath, []byte("delete me"), 0644)
	require.NoError(t, err)

	err = c.DeleteFile(context.Background(), "todelete.txt")
	require.NoError(t, err)

	_, err = os.Stat(filePath)
	assert.True(t, os.IsNotExist(err))
}

func TestLocalClient_DeleteFile_NotConnected(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	err := c.DeleteFile(context.Background(), "file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestLocalClient_CopyFile(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{BasePath: tempDir}
	c := NewLocalClient(config)
	defer c.Disconnect(context.Background())

	err := c.Connect(context.Background())
	require.NoError(t, err)

	srcContent := "copy me"
	srcPath := filepath.Join(tempDir, "source.txt")
	err = os.WriteFile(srcPath, []byte(srcContent), 0644)
	require.NoError(t, err)

	err = c.CopyFile(context.Background(), "source.txt", "dest.txt")
	require.NoError(t, err)

	dstPath := filepath.Join(tempDir, "dest.txt")
	content, err := os.ReadFile(dstPath)
	require.NoError(t, err)
	assert.Equal(t, srcContent, string(content))
}

func TestLocalClient_CopyFile_NotConnected(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	err := c.CopyFile(context.Background(), "src.txt", "dst.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestLocalClient_GetProtocol(t *testing.T) {
	config := &Config{BasePath: "/tmp"}
	c := NewLocalClient(config)

	assert.Equal(t, "local", c.GetProtocol())
}

func TestLocalClient_GetConfig(t *testing.T) {
	config := &Config{BasePath: "/tmp/test"}
	c := NewLocalClient(config)

	retrievedConfig := c.GetConfig().(*Config)
	assert.Equal(t, "/tmp/test", retrievedConfig.BasePath)
}

// Verify the Client type implements client.Client interface.
var _ client.Client = (*Client)(nil)
