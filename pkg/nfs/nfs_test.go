//go:build linux
// +build linux

package nfs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
)

// Verify NFS Client implements client.Client interface.
var _ client.Client = (*Client)(nil)

func TestNewNFSClient(t *testing.T) {
	config := Config{
		Host:       "nas.local",
		Path:       "/export/media",
		MountPoint: "/tmp/catalog-test-mount/nfs",
		Options:    "vers=3",
	}
	c, err := NewNFSClient(config)
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, config, c.config)
	assert.False(t, c.mounted)
	assert.False(t, c.connected)
	assert.Equal(t, "/tmp/catalog-test-mount/nfs", c.mountPoint)
}

func TestNewNFSClient_EmptyMountPoint(t *testing.T) {
	config := Config{
		Host:       "nas.local",
		Path:       "/export",
		MountPoint: "",
	}
	c, err := NewNFSClient(config)
	assert.Error(t, err)
	assert.Nil(t, c)
	assert.Contains(t, err.Error(), "mount point is required")
}

func TestNFSClient_GetProtocol(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/test"})
	assert.Equal(t, "nfs", c.GetProtocol())
}

func TestNFSClient_GetConfig(t *testing.T) {
	config := Config{
		Host:       "nfs.example.com",
		Path:       "/exports/data",
		MountPoint: "/mnt/nfs",
		Options:    "vers=4",
	}
	c, _ := NewNFSClient(config)
	cfg := c.GetConfig()
	assert.NotNil(t, cfg)
}

func TestNFSClient_ResolvePath_Simple(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	assert.Equal(t, "/mnt/nfs/subdir/file.txt", c.resolvePath("subdir/file.txt"))
}

func TestNFSClient_ResolvePath_PathTraversal(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	resolved := c.resolvePath("../../../etc/passwd")
	assert.NotContains(t, resolved, "..")
}

func TestNFSClient_ResolvePath_DotDot(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	resolved := c.resolvePath("subdir/../test.txt")
	// filepath.Clean resolves this, then we strip any remaining ..
	assert.NotContains(t, resolved, "..")
}

func TestNFSClient_ResolvePath_CurrentDir(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	resolved := c.resolvePath(".")
	assert.Equal(t, "/mnt/nfs", resolved)
}

func TestNFSClient_IsConnected_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	assert.False(t, c.IsConnected())
}

func TestNFSClient_TestConnection_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	err := c.TestConnection(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNFSClient_ReadFile_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	reader, err := c.ReadFile(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNFSClient_WriteFile_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	err := c.WriteFile(context.Background(), "test.txt", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNFSClient_GetFileInfo_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	info, err := c.GetFileInfo(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNFSClient_ListDirectory_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	files, err := c.ListDirectory(context.Background(), "/")
	assert.Error(t, err)
	assert.Nil(t, files)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNFSClient_FileExists_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	exists, err := c.FileExists(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNFSClient_CreateDirectory_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	err := c.CreateDirectory(context.Background(), "newdir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNFSClient_DeleteDirectory_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	err := c.DeleteDirectory(context.Background(), "olddir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNFSClient_DeleteFile_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	err := c.DeleteFile(context.Background(), "file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNFSClient_CopyFile_NotConnected(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	err := c.CopyFile(context.Background(), "src.txt", "dst.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNFSClient_Disconnect_NotMounted(t *testing.T) {
	c, _ := NewNFSClient(Config{MountPoint: "/mnt/nfs"})
	err := c.Disconnect(context.Background())
	assert.NoError(t, err)
	assert.False(t, c.connected)
}

func TestNFSConfig_Fields(t *testing.T) {
	config := Config{
		Host:       "nfs.example.com",
		Path:       "/exports/media",
		MountPoint: "/mnt/media",
		Options:    "vers=4,rsize=8192",
	}
	assert.Equal(t, "nfs.example.com", config.Host)
	assert.Equal(t, "/exports/media", config.Path)
	assert.Equal(t, "/mnt/media", config.MountPoint)
	assert.Equal(t, "vers=4,rsize=8192", config.Options)
}
