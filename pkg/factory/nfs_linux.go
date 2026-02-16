//go:build linux
// +build linux

package factory

import (
	"fmt"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/nfs"
)

// createNFSClient creates an NFS client (Linux implementation).
func (f *DefaultFactory) createNFSClient(config *client.StorageConfig) (client.Client, error) {
	nfsConfig := nfs.Config{
		Host:       GetStringSetting(config.Settings, "host", ""),
		Path:       GetStringSetting(config.Settings, "path", ""),
		MountPoint: GetStringSetting(config.Settings, "mount_point", ""),
		Options:    GetStringSetting(config.Settings, "options", "vers=3"),
	}
	c, err := nfs.NewNFSClient(nfsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create NFS client: %w", err)
	}
	return c, nil
}
