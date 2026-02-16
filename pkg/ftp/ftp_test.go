package ftp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
)

// Verify FTP Client implements client.Client interface.
var _ client.Client = (*Client)(nil)

func TestNewFTPClient(t *testing.T) {
	config := &Config{
		Host:     "localhost",
		Port:     21,
		Username: "user",
		Password: "pass",
		Path:     "/data",
	}
	c := NewFTPClient(config)
	require.NotNil(t, c)
	assert.Equal(t, config, c.config)
	assert.False(t, c.connected)
	assert.Nil(t, c.client)
}

func TestFTPClient_GetProtocol(t *testing.T) {
	c := NewFTPClient(&Config{})
	assert.Equal(t, "ftp", c.GetProtocol())
}

func TestFTPClient_GetConfig(t *testing.T) {
	config := &Config{
		Host:     "ftp.example.com",
		Port:     2121,
		Username: "admin",
		Password: "secret",
		Path:     "/files",
	}
	c := NewFTPClient(config)
	assert.Equal(t, config, c.GetConfig())
}

func TestFTPClient_IsConnected_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	assert.False(t, c.IsConnected())
}

func TestFTPClient_IsConnected_FlagTrueButNilClient(t *testing.T) {
	c := NewFTPClient(&Config{})
	c.connected = true
	assert.False(t, c.IsConnected())
}

func TestFTPClient_ResolvePath_WithBasePath(t *testing.T) {
	c := NewFTPClient(&Config{Path: "/data"})
	assert.Equal(t, "/data/subdir/file.txt", c.resolvePath("subdir/file.txt"))
}

func TestFTPClient_ResolvePath_WithoutBasePath(t *testing.T) {
	c := NewFTPClient(&Config{Path: ""})
	assert.Equal(t, "subdir/file.txt", c.resolvePath("subdir/file.txt"))
}

func TestFTPClient_ResolvePath_RootPath(t *testing.T) {
	c := NewFTPClient(&Config{Path: "/uploads"})
	assert.Equal(t, "/uploads/test.txt", c.resolvePath("test.txt"))
}

func TestFTPClient_TestConnection_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	err := c.TestConnection(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestFTPClient_ReadFile_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	reader, err := c.ReadFile(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "not connected")
}

func TestFTPClient_WriteFile_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	err := c.WriteFile(context.Background(), "test.txt", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestFTPClient_GetFileInfo_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	info, err := c.GetFileInfo(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "not connected")
}

func TestFTPClient_ListDirectory_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	files, err := c.ListDirectory(context.Background(), "/")
	assert.Error(t, err)
	assert.Nil(t, files)
	assert.Contains(t, err.Error(), "not connected")
}

func TestFTPClient_FileExists_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	exists, err := c.FileExists(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "not connected")
}

func TestFTPClient_CreateDirectory_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	err := c.CreateDirectory(context.Background(), "newdir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestFTPClient_DeleteDirectory_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	err := c.DeleteDirectory(context.Background(), "olddir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestFTPClient_DeleteFile_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	err := c.DeleteFile(context.Background(), "file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestFTPClient_CopyFile_NotConnected(t *testing.T) {
	c := NewFTPClient(&Config{})
	err := c.CopyFile(context.Background(), "src.txt", "dst.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestFTPClient_Disconnect_NilClient(t *testing.T) {
	c := NewFTPClient(&Config{})
	err := c.Disconnect(context.Background())
	assert.NoError(t, err)
	assert.False(t, c.connected)
}

func TestFTPClient_Disconnect_SetsState(t *testing.T) {
	c := NewFTPClient(&Config{})
	c.connected = true
	// client is nil, so Quit() won't be called
	err := c.Disconnect(context.Background())
	assert.NoError(t, err)
	assert.False(t, c.connected)
}

func TestFTPClient_Connect_InvalidServer(t *testing.T) {
	c := NewFTPClient(&Config{
		Host:     "127.0.0.1",
		Port:     1, // port 1 is unlikely to have an FTP server
		Username: "user",
		Password: "pass",
	})
	err := c.Connect(context.Background())
	assert.Error(t, err)
	assert.False(t, c.IsConnected())
}

func TestFTPConfig_Fields(t *testing.T) {
	config := Config{
		Host:     "ftp.example.com",
		Port:     2121,
		Username: "admin",
		Password: "s3cret",
		Path:     "/uploads",
	}
	assert.Equal(t, "ftp.example.com", config.Host)
	assert.Equal(t, 2121, config.Port)
	assert.Equal(t, "admin", config.Username)
	assert.Equal(t, "s3cret", config.Password)
	assert.Equal(t, "/uploads", config.Path)
}
