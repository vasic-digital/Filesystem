// Package factory provides a default implementation of the client.Factory interface,
// creating filesystem clients based on protocol configuration.
package factory

import (
	"fmt"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/ftp"
	"digital.vasic.filesystem/pkg/local"
	"digital.vasic.filesystem/pkg/smb"
	"digital.vasic.filesystem/pkg/webdav"
)

// DefaultFactory implements client.Factory for all supported protocols.
type DefaultFactory struct{}

// NewDefaultFactory creates a new default client factory.
func NewDefaultFactory() *DefaultFactory {
	return &DefaultFactory{}
}

// CreateClient creates a filesystem client based on the storage configuration.
func (f *DefaultFactory) CreateClient(config *client.StorageConfig) (client.Client, error) {
	switch config.Protocol {
	case "smb":
		smbConfig := &smb.Config{
			Host:     GetStringSetting(config.Settings, "host", ""),
			Port:     GetIntSetting(config.Settings, "port", 445),
			Share:    GetStringSetting(config.Settings, "share", ""),
			Username: GetStringSetting(config.Settings, "username", ""),
			Password: GetStringSetting(config.Settings, "password", ""),
			Domain:   GetStringSetting(config.Settings, "domain", "WORKGROUP"),
		}
		return NewSMBClient(smbConfig), nil

	case "ftp":
		ftpConfig := &ftp.Config{
			Host:     GetStringSetting(config.Settings, "host", ""),
			Port:     GetIntSetting(config.Settings, "port", 21),
			Username: GetStringSetting(config.Settings, "username", ""),
			Password: GetStringSetting(config.Settings, "password", ""),
			Path:     GetStringSetting(config.Settings, "path", ""),
		}
		return ftp.NewFTPClient(ftpConfig), nil

	case "nfs":
		return f.createNFSClient(config)

	case "webdav":
		webdavConfig := &webdav.Config{
			URL:      GetStringSetting(config.Settings, "url", ""),
			Username: GetStringSetting(config.Settings, "username", ""),
			Password: GetStringSetting(config.Settings, "password", ""),
			Path:     GetStringSetting(config.Settings, "path", ""),
		}
		return webdav.NewWebDAVClient(webdavConfig), nil

	case "local":
		localConfig := &local.Config{
			BasePath: GetStringSetting(config.Settings, "base_path", ""),
		}
		return local.NewLocalClient(localConfig), nil

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}
}

// SupportedProtocols returns the list of supported protocols.
func (f *DefaultFactory) SupportedProtocols() []string {
	return []string{"smb", "ftp", "nfs", "webdav", "local"}
}

// NewSMBClient is a convenience wrapper for creating SMB clients directly.
func NewSMBClient(config *smb.Config) client.Client {
	return smb.NewSMBClient(config)
}

// GetStringSetting extracts a string setting from a settings map.
func GetStringSetting(settings map[string]interface{}, key, defaultValue string) string {
	if val, ok := settings[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

// GetIntSetting extracts an int setting from a settings map.
func GetIntSetting(settings map[string]interface{}, key string, defaultValue int) int {
	if val, ok := settings[key]; ok {
		if num, ok := val.(int); ok {
			return num
		}
		if floatNum, ok := val.(float64); ok {
			return int(floatNum)
		}
	}
	return defaultValue
}
