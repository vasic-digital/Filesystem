// Package factory provides a default implementation of the client.Factory interface,
// creating filesystem clients based on protocol configuration.
package factory

import (
	"fmt"
	"strings"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/local"
	sftppkg "digital.vasic.filesystem/pkg/sftp"
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
		return f.createFTPClient(config)

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

	case "sftp":
		return f.createSFTPClient(config)

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
	return []string{"smb", "ftp", "nfs", "webdav", "local", "sftp"}
}

// createSFTPClient builds the read-only SFTP client. It accepts NO inline password: the secret is behind
// "credential_ref" (resolved by sftp.DefaultCredentialResolver at connect time). The host key pins come from the
// package-level sftp.DefaultPinStore, which the application must set before it connects.
func (f *DefaultFactory) createSFTPClient(config *client.StorageConfig) (client.Client, error) {
	// No secret is accepted inline, under any of its usual names: it would sit in the stored settings and be ignored.
	for _, k := range []string{"password", "passphrase", "private_key", "privatekey", "key", "secret", "token"} {
		if _, ok := config.Settings[k]; ok {
			return nil, fmt.Errorf("sftp: inline %q is not accepted, use credential_ref", k)
		}
	}
	port := 22
	if v, ok := config.Settings["port"]; ok {
		n, isNum := 0, false
		switch p := v.(type) {
		case int:
			n, isNum = p, true
		case float64:
			n, isNum = int(p), p == float64(int(p))
		}
		if !isNum || n < 1 || n > 65535 {
			return nil, fmt.Errorf("sftp: port must be a number between 1 and 65535")
		}
		port = n
	}
	// "path" wins over "root" only when it is non-empty: an empty path must not silently widen the root to "/".
	root := GetStringSetting(config.Settings, "path", "")
	if strings.TrimSpace(root) == "" {
		root = GetStringSetting(config.Settings, "root", "")
	}
	c := &sftppkg.Config{
		Host:          GetStringSetting(config.Settings, "host", ""),
		Port:          port,
		Username:      GetStringSetting(config.Settings, "username", ""),
		CredentialRef: GetStringSetting(config.Settings, "credential_ref", ""),
		Root:          root,
		PinStore:      sftppkg.DefaultPinStore,
	}
	return sftppkg.NewSFTPClient(c), nil
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
