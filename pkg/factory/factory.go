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

// sftpSettingKeys are the only settings the sftp protocol reads. Every other key is refused: a setting the factory does not read would
// sit in the stored configuration and be silently ignored (for a secret-like name, with a secret in it).
var sftpSettingKeys = map[string]bool{"host": true, "port": true, "username": true, "credential_ref": true, "path": true, "root": true}

// secretLike reports whether a settings key looks like it carries a secret: lower-cased with "-", "_", "." and spaces removed, it
// contains one of the usual fragments ("Password", "PASSWD", "pwd", "private-key", "ssh_key", "credentials", "api_token" ...).
func secretLike(k string) bool {
	n := strings.ToLower(k)
	for _, r := range []string{"-", "_", ".", " "} {
		n = strings.ReplaceAll(n, r, "")
	}
	for _, frag := range []string{"pass", "pwd", "secret", "token", "key", "cred", "auth"} {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}

// createSFTPClient builds the read-only SFTP client. It accepts NO inline password: the secret is behind
// "credential_ref" (resolved by sftp.DefaultCredentialResolver at connect time). The host key pins come from the
// package-level sftp.DefaultPinStore, which the application must set before the client CONNECTS (it is followed at connect
// time, not captured when the client is created).
func (f *DefaultFactory) createSFTPClient(config *client.StorageConfig) (client.Client, error) {
	// Only the settings the client reads are accepted. A secret under any spelling is refused with its own message.
	for k := range config.Settings {
		if sftpSettingKeys[k] {
			continue
		}
		if secretLike(k) {
			return nil, fmt.Errorf("sftp: inline %q is not accepted, use credential_ref", k)
		}
		return nil, fmt.Errorf("sftp: unknown setting %q (accepted: host, port, username, credential_ref, path, root)", k)
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
		PinStore:      sftppkg.DefaultPinStoreRef(),
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
