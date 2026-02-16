//go:build linux
// +build linux

package factory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
)

func TestDefaultFactory_CreateNFSClient_Linux(t *testing.T) {
	f := NewDefaultFactory()
	config := &client.StorageConfig{
		Protocol: "nfs",
		Settings: map[string]interface{}{
			"host":        "nas.local",
			"path":        "/export/media",
			"mount_point": "/tmp/catalog-test-nfs",
			"options":     "vers=3",
		},
	}
	c, err := f.CreateClient(config)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, "nfs", c.GetProtocol())
}

func TestDefaultFactory_CreateNFSClient_DefaultOptions(t *testing.T) {
	f := NewDefaultFactory()
	config := &client.StorageConfig{
		Protocol: "nfs",
		Settings: map[string]interface{}{
			"host":        "nas.local",
			"path":        "/export",
			"mount_point": "/tmp/catalog-test-nfs2",
		},
	}
	c, err := f.CreateClient(config)
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestDefaultFactory_CreateNFSClient_EmptyMountPoint(t *testing.T) {
	f := NewDefaultFactory()
	config := &client.StorageConfig{
		Protocol: "nfs",
		Settings: map[string]interface{}{
			"host":        "nas.local",
			"path":        "/export",
			"mount_point": "",
		},
	}
	c, err := f.CreateClient(config)
	assert.Error(t, err)
	assert.Nil(t, c)
}
