package factory

import (
	"fmt"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/ftp"
)

// createFTPClient builds the read-only FTP/FTPS scan client (ftp.NewScanClient: every mutation refused, transient
// read failures retried). Like SFTP it accepts NO inline secret: the password is behind "credential_ref", resolved
// by ftp.DefaultCredentialResolver at connect time, and the certificate pins come from the package-level
// ftp.DefaultPinStore, which the application must set before it connects (without it every explicit-TLS root is
// refused, fail closed).
//
// Settings: host, port (default 21), username, credential_ref, path, tls_mode ("explicit" by default, or "none"),
// trusted_lan (bool; required for tls_mode "none"), allow_degraded_list (bool), disable_epsv (bool).
func (f *DefaultFactory) createFTPClient(config *client.StorageConfig) (client.Client, error) {
	for _, k := range []string{"password", "passphrase", "private_key", "privatekey", "key", "secret", "token"} {
		if _, ok := config.Settings[k]; ok {
			return nil, fmt.Errorf("ftp: inline %q is not accepted, use credential_ref", k)
		}
	}
	port := ftp.DefaultPort
	if v, ok := config.Settings["port"]; ok {
		n, isNum := 0, false
		switch p := v.(type) {
		case int:
			n, isNum = p, true
		case float64:
			n, isNum = int(p), p == float64(int(p))
		}
		if !isNum || n < 1 || n > 65535 {
			return nil, fmt.Errorf("ftp: port must be a number between 1 and 65535")
		}
		port = n
	}
	trusted, err := boolSetting(config.Settings, "trusted_lan")
	if err != nil {
		return nil, err
	}
	degraded, err := boolSetting(config.Settings, "allow_degraded_list")
	if err != nil {
		return nil, err
	}
	noEPSV, err := boolSetting(config.Settings, "disable_epsv")
	if err != nil {
		return nil, err
	}
	if v, ok := config.Settings["tls_mode"]; ok {
		if _, isStr := v.(string); !isStr {
			return nil, fmt.Errorf("ftp: setting %q must be a string", "tls_mode")
		}
	}
	return ftp.NewScanClient(&ftp.Config{
		Host:              GetStringSetting(config.Settings, "host", ""),
		Port:              port,
		Username:          GetStringSetting(config.Settings, "username", ""),
		CredentialRef:     GetStringSetting(config.Settings, "credential_ref", ""),
		Path:              GetStringSetting(config.Settings, "path", ""),
		TLSMode:           GetStringSetting(config.Settings, "tls_mode", ""),
		TrustedLAN:        trusted,
		AllowDegradedList: degraded,
		DisableEPSV:       noEPSV,
		PinStore:          ftp.DefaultPinStore,
	}, ftp.ScanOptions{})
}

// boolSetting reads a boolean setting; absent is false, any other type is an error (a quoted "false" must not read as true).
func boolSetting(settings map[string]interface{}, key string) (bool, error) {
	v, ok := settings[key]
	if !ok {
		return false, nil
	}
	b, isBool := v.(bool)
	if !isBool {
		return false, fmt.Errorf("ftp: setting %q must be a boolean", key)
	}
	return b, nil
}
