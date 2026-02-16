package factory

import (
	"testing"

	"digital.vasic.filesystem/pkg/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultFactory_SupportedProtocols(t *testing.T) {
	f := NewDefaultFactory()

	protocols := f.SupportedProtocols()

	expected := []string{"smb", "ftp", "nfs", "webdav", "local"}
	assert.Equal(t, len(expected), len(protocols))

	for i, protocol := range expected {
		assert.Equal(t, protocol, protocols[i])
	}
}

func TestDefaultFactory_CreateClient_SMB(t *testing.T) {
	f := NewDefaultFactory()

	config := &client.StorageConfig{
		Protocol: "smb",
		Settings: map[string]interface{}{
			"host":     "localhost",
			"port":     445,
			"share":    "test",
			"username": "user",
			"password": "pass",
			"domain":   "WORKGROUP",
		},
	}

	c, err := f.CreateClient(config)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, "smb", c.GetProtocol())
}

func TestDefaultFactory_CreateClient_FTP(t *testing.T) {
	f := NewDefaultFactory()

	config := &client.StorageConfig{
		Protocol: "ftp",
		Settings: map[string]interface{}{
			"host":     "localhost",
			"port":     21,
			"username": "user",
			"password": "pass",
			"path":     "/",
		},
	}

	c, err := f.CreateClient(config)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, "ftp", c.GetProtocol())
}

func TestDefaultFactory_CreateClient_NFS(t *testing.T) {
	f := NewDefaultFactory()

	config := &client.StorageConfig{
		Protocol: "nfs",
		Settings: map[string]interface{}{
			"host":        "localhost",
			"path":        "/export",
			"mount_point": "/tmp/catalog-test-mount/nfs",
			"options":     "vers=3",
		},
	}

	c, err := f.CreateClient(config)
	// On Linux this succeeds, on other platforms it returns an error
	if err == nil {
		assert.NotNil(t, c)
		assert.Equal(t, "nfs", c.GetProtocol())
	}
}

func TestDefaultFactory_CreateClient_WebDAV(t *testing.T) {
	f := NewDefaultFactory()

	config := &client.StorageConfig{
		Protocol: "webdav",
		Settings: map[string]interface{}{
			"url":      "http://localhost/webdav",
			"username": "user",
			"password": "pass",
			"path":     "/",
		},
	}

	c, err := f.CreateClient(config)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, "webdav", c.GetProtocol())
}

func TestDefaultFactory_CreateClient_Local(t *testing.T) {
	f := NewDefaultFactory()

	config := &client.StorageConfig{
		Protocol: "local",
		Settings: map[string]interface{}{
			"base_path": "/tmp",
		},
	}

	c, err := f.CreateClient(config)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, "local", c.GetProtocol())
}

func TestDefaultFactory_CreateClient_Unsupported(t *testing.T) {
	f := NewDefaultFactory()

	config := &client.StorageConfig{
		Protocol: "unsupported",
		Settings: map[string]interface{}{},
	}

	c, err := f.CreateClient(config)
	assert.Error(t, err)
	assert.Nil(t, c)
	assert.Contains(t, err.Error(), "unsupported protocol")
}

func TestGetStringSetting(t *testing.T) {
	settings := map[string]interface{}{
		"host":   "example.com",
		"number": 42,
	}

	assert.Equal(t, "example.com", GetStringSetting(settings, "host", ""))
	assert.Equal(t, "default", GetStringSetting(settings, "missing", "default"))
	assert.Equal(t, "", GetStringSetting(settings, "number", ""))
}

func TestGetIntSetting(t *testing.T) {
	settings := map[string]interface{}{
		"port":       445,
		"float_port": float64(8080),
		"text":       "not a number",
	}

	assert.Equal(t, 445, GetIntSetting(settings, "port", 0))
	assert.Equal(t, 8080, GetIntSetting(settings, "float_port", 0))
	assert.Equal(t, 99, GetIntSetting(settings, "missing", 99))
	assert.Equal(t, 0, GetIntSetting(settings, "text", 0))
}

// Verify DefaultFactory implements client.Factory interface.
var _ client.Factory = (*DefaultFactory)(nil)
