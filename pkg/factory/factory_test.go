package factory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gosftp "github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultFactory_SupportedProtocols(t *testing.T) {
	f := NewDefaultFactory()

	protocols := f.SupportedProtocols()

	expected := []string{"smb", "ftp", "nfs", "webdav", "local", "sftp"}
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
			"host":           "localhost",
			"port":           21,
			"username":       "user",
			"credential_ref": "nas",
			"path":           "/",
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

func TestDefaultFactory_CreateClient_SFTP(t *testing.T) {
	f := NewDefaultFactory()
	c, err := f.CreateClient(&client.StorageConfig{
		Protocol: "sftp",
		Settings: map[string]interface{}{
			"host":           "nas.example",
			"port":           float64(2222), // JSON numbers arrive as float64
			"username":       "svc",
			"credential_ref": "nas-1",
			"path":           "/volume1/media",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "sftp", c.GetProtocol())
	assert.False(t, c.IsConnected())

	b, err := json.Marshal(c.GetConfig())
	require.NoError(t, err)
	assert.Contains(t, string(b), `"host":"nas.example"`)
	assert.Contains(t, string(b), `"port":2222`)
	assert.Contains(t, string(b), `"credential_ref":"nas-1"`)
	assert.Contains(t, string(b), `"root":"/volume1/media"`)
	assert.Contains(t, string(b), `"read_only":true`)

	// read only by construction, reached through the factory too
	assert.ErrorIs(t, c.DeleteFile(context.Background(), "/x"), sftp.ErrReadOnly)
}

func TestDefaultFactory_CreateClient_SFTP_RejectsInlinePassword(t *testing.T) {
	f := NewDefaultFactory()
	_, err := f.CreateClient(&client.StorageConfig{
		Protocol: "sftp",
		Settings: map[string]interface{}{"host": "h", "username": "u", "password": "INLINE-SECRET-123"},
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "INLINE-SECRET-123")
}

// NOTE (review SFTP-10): this passes whether or not the factory wires sftp.DefaultPinStore (it is nil here anyway); the positive path is
// TestDefaultFactory_SFTP_UsesTheInstalledPinStoreEndToEnd.
func TestDefaultFactory_SFTP_RefusesToConnectWithoutPinStore(t *testing.T) {
	f := NewDefaultFactory()
	c, err := f.CreateClient(&client.StorageConfig{
		Protocol: "sftp",
		Settings: map[string]interface{}{"host": "127.0.0.1", "port": 9, "username": "u", "credential_ref": "r"},
	})
	require.NoError(t, err)
	assert.ErrorIs(t, c.Connect(context.Background()), sftp.ErrNoPinStore, "no pin store installed: every host is refused")
}

// ---- fix-r2 (SFTP-13, R09) ---------------------------------------------------------------------------------------

func sftpRoot(t *testing.T, settings map[string]interface{}) string {
	t.Helper()
	c, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp", Settings: settings})
	require.NoError(t, err)
	b, err := json.Marshal(c.GetConfig())
	require.NoError(t, err)
	var pc struct {
		Root string `json:"root"`
		Port int    `json:"port"`
	}
	require.NoError(t, json.Unmarshal(b, &pc))
	return pc.Root
}

// Every spelling of an inline secret is refused, not silently ignored and stored.
func TestDefaultFactory_SFTP_RejectsEverySecretLikeSetting(t *testing.T) {
	for _, k := range []string{"password", "passphrase", "private_key", "privatekey", "key", "secret", "token"} {
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp",
			Settings: map[string]interface{}{"host": "h", "username": "u", "credential_ref": "r", k: "INLINE-SECRET-XYZ"}})
		require.Error(t, err, k)
		assert.NotContains(t, err.Error(), "INLINE-SECRET-XYZ", k)
	}
}

// An empty "path" must not win over "root" and widen the confinement to "/".
func TestDefaultFactory_SFTP_EmptyPathDoesNotWidenTheRoot(t *testing.T) {
	assert.Equal(t, "/volume1/x", sftpRoot(t, map[string]interface{}{"host": "h", "path": "", "root": "/volume1/x"}))
	assert.Equal(t, "/volume1/x", sftpRoot(t, map[string]interface{}{"host": "h", "path": "   ", "root": "/volume1/x"}))
	assert.Equal(t, "/volume1/p", sftpRoot(t, map[string]interface{}{"host": "h", "path": "/volume1/p", "root": "/volume1/x"}), "a non-empty path still wins")
	assert.Equal(t, "/volume1/x", sftpRoot(t, map[string]interface{}{"host": "h", "root": "/volume1/x"}))
	assert.Equal(t, "/", sftpRoot(t, map[string]interface{}{"host": "h"}))
}

// A port that is not a usable number is an error, not a silent fall back to 22.
func TestDefaultFactory_SFTP_PortIsValidated(t *testing.T) {
	for _, bad := range []interface{}{"2222", 0, -1, 65536, 70000, float64(22.5), true, nil} {
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp", Settings: map[string]interface{}{"host": "h", "port": bad}})
		assert.Error(t, err, "port %#v", bad)
	}
	for _, good := range []interface{}{1, 22, 2222, 65535, float64(2222)} {
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp", Settings: map[string]interface{}{"host": "h", "port": good}})
		assert.NoError(t, err, "port %#v", good)
	}
	b, _ := json.Marshal(func() interface{} {
		c, _ := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp", Settings: map[string]interface{}{"host": "h"}})
		return c.GetConfig()
	}())
	assert.Contains(t, string(b), `"port":22`)
}

// startSFTPPeer is a real ssh server with the real pkg/sftp server behind the "sftp" subsystem (password alice/pw-fx).
func startSFTPPeer(t *testing.T) (host string, port int, hostKey ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "alice" && string(pw) == "pw-fx" {
			return nil, nil
		}
		return nil, os.ErrPermission
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer nc.Close()
				sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "no")
						continue
					}
					ch, creqs, err := newCh.Accept()
					if err != nil {
						return
					}
					go func() {
						for r := range creqs {
							ok := r.Type == "subsystem" && strings.HasSuffix(string(r.Payload), "sftp")
							_ = r.Reply(ok, nil)
							if ok {
								if srv, err := gosftp.NewServer(ch); err == nil {
									_ = srv.Serve()
								}
								return
							}
						}
					}()
				}
			}()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, signer.PublicKey()
}

// R09: a factory-built client really uses sftp.DefaultPinStore: with a pinned key installed it connects and lists; the
// refusal test above covers the other direction.
func TestDefaultFactory_SFTP_UsesTheInstalledPinStoreEndToEnd(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644))
	host, port, hk := startSFTPPeer(t)
	store := sftp.NewMemPinStore()
	require.NoError(t, store.Record(sftp.HostPort(host, port), sftp.HostKeyPin{KeyType: hk.Type(), Fingerprint: sftp.Fingerprint(hk), ConfirmedBy: "test"}))
	old := sftp.DefaultPinStore
	sftp.DefaultPinStore = store
	t.Cleanup(func() { sftp.DefaultPinStore = old })
	t.Setenv("SFTP_CRED_fxref_PASSWORD", "pw-fx")

	c, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp", Settings: map[string]interface{}{
		"host": host, "port": port, "username": "alice", "credential_ref": "fxref", "path": dir}})
	require.NoError(t, err)
	require.NoError(t, c.Connect(context.Background()))
	defer c.Disconnect(context.Background()) //nolint:errcheck
	ents, err := c.ListDirectory(context.Background(), "/")
	require.NoError(t, err)
	require.Len(t, ents, 1)
	assert.Equal(t, "hello.txt", ents[0].Name)
}
