//go:build !linux
// +build !linux

package factory

import (
	"fmt"

	"digital.vasic.filesystem/pkg/client"
)

// createNFSClient returns an error on non-Linux platforms.
func (f *DefaultFactory) createNFSClient(config *client.StorageConfig) (client.Client, error) {
	return nil, fmt.Errorf("NFS protocol is only supported on Linux")
}
