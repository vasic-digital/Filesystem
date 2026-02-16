//go:build !linux
// +build !linux

package factory

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"digital.vasic.filesystem/pkg/client"
)

func TestDefaultFactory_CreateNFSClient_NonLinux(t *testing.T) {
	f := NewDefaultFactory()
	config := &client.StorageConfig{
		Protocol: "nfs",
		Settings: map[string]interface{}{
			"host":        "nas.local",
			"path":        "/export",
			"mount_point": "/tmp/nfs",
		},
	}
	c, err := f.CreateClient(config)
	assert.Error(t, err)
	assert.Nil(t, c)
	assert.Contains(t, err.Error(), "only supported on Linux")
}

func TestDefaultFactory_CreateNFSClient_NonLinux_StillInSupportedProtocols(t *testing.T) {
	f := NewDefaultFactory()
	protocols := f.SupportedProtocols()
	assert.Contains(t, protocols, "nfs")
}
