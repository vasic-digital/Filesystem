package smb

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
)

// Verify SMB Client implements client.Client interface.
var _ client.Client = (*Client)(nil)

func TestNewSMBClient(t *testing.T) {
	config := &Config{
		Host:     "localhost",
		Port:     445,
		Share:    "share",
		Username: "user",
		Password: "pass",
		Domain:   "WORKGROUP",
	}
	c := NewSMBClient(config)
	require.NotNil(t, c)
	assert.Equal(t, config, c.config)
	assert.Nil(t, c.conn)
	assert.Nil(t, c.session)
	assert.Nil(t, c.share)
}

func TestSMBClient_GetProtocol(t *testing.T) {
	c := NewSMBClient(&Config{})
	assert.Equal(t, "smb", c.GetProtocol())
}

func TestSMBClient_GetConfig(t *testing.T) {
	config := &Config{
		Host:     "nas.local",
		Port:     445,
		Share:    "media",
		Username: "admin",
		Password: "secret",
		Domain:   "EXAMPLE",
	}
	c := NewSMBClient(config)
	assert.Equal(t, config, c.GetConfig())
}

func TestSMBClient_IsConnected_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	assert.False(t, c.IsConnected())
}

func TestSMBClient_IsConnected_AllNil(t *testing.T) {
	c := &Client{}
	assert.False(t, c.IsConnected())
}

func TestSMBClient_TestConnection_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	err := c.TestConnection(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSMBClient_ReadFile_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	reader, err := c.ReadFile(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSMBClient_WriteFile_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	err := c.WriteFile(context.Background(), "test.txt", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSMBClient_GetFileInfo_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	info, err := c.GetFileInfo(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSMBClient_ListDirectory_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	files, err := c.ListDirectory(context.Background(), ".")
	assert.Error(t, err)
	assert.Nil(t, files)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSMBClient_FileExists_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	exists, err := c.FileExists(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSMBClient_CreateDirectory_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	err := c.CreateDirectory(context.Background(), "newdir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSMBClient_DeleteDirectory_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	err := c.DeleteDirectory(context.Background(), "olddir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSMBClient_DeleteFile_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	err := c.DeleteFile(context.Background(), "file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSMBClient_CopyFile_NotConnected(t *testing.T) {
	c := NewSMBClient(&Config{})
	err := c.CopyFile(context.Background(), "src.txt", "dst.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSMBClient_Disconnect_AllNil(t *testing.T) {
	c := NewSMBClient(&Config{})
	err := c.Disconnect(context.Background())
	assert.NoError(t, err)
}

func TestSMBClient_Connect_InvalidServer(t *testing.T) {
	c := NewSMBClient(&Config{
		Host:     "192.0.2.1", // RFC 5737 test address
		Port:     445,
		Share:    "share",
		Username: "user",
		Password: "pass",
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	err := c.Connect(ctx)
	assert.Error(t, err)
	assert.False(t, c.IsConnected())
}

func TestIsNotExistError_FileDoesNotExist(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "file does not exist",
			err:      fmt.Errorf("file does not exist"),
			expected: true,
		},
		{
			name:     "no such file or directory",
			err:      fmt.Errorf("no such file or directory"),
			expected: true,
		},
		{
			name:     "other error",
			err:      fmt.Errorf("permission denied"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isNotExistError(tt.err))
		})
	}
}

func TestSMBConfig_Fields(t *testing.T) {
	config := Config{
		Host:     "nas.example.com",
		Port:     445,
		Share:    "media",
		Username: "admin",
		Password: "s3cret",
		Domain:   "CORP",
	}
	assert.Equal(t, "nas.example.com", config.Host)
	assert.Equal(t, 445, config.Port)
	assert.Equal(t, "media", config.Share)
	assert.Equal(t, "admin", config.Username)
	assert.Equal(t, "s3cret", config.Password)
	assert.Equal(t, "CORP", config.Domain)
}
