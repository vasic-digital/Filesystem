package factory

// fix-r3 (review WF24 S11, S14): the settings the sftp protocol accepts, and the pin store being followed at connect time.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/sftp"
)

// S11: the refusal of an inline secret is not spelling-exact. Every spelling below was accepted silently before (stored in the
// settings and ignored); each is refused now, with the value never in the message.
func TestDefaultFactory_SFTP_RefusesEverySecretSpelling(t *testing.T) {
	spellings := []string{"password", "Password", "PASSWORD", "passwd", "pwd", "pass", "privateKey", "private-key", "ssh_key", "credentials",
		"passphrase", "private_key", "privatekey", "key", "secret", "token", "api-token", "Secret_Key", "pass word", "auth", "authorization"}
	for _, k := range spellings {
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp",
			Settings: map[string]interface{}{"host": "h", "username": "u", "credential_ref": "r", k: "INLINE-SECRET-XYZ"}})
		require.Error(t, err, "%q must be refused", k)
		assert.NotContains(t, err.Error(), "INLINE-SECRET-XYZ", k)
		assert.Contains(t, err.Error(), "is not accepted, use credential_ref", "%q: refused AS A SECRET (not merely as an unknown key), with the way to give a secret", k)
		assert.NotContains(t, err.Error(), "unknown setting", k)
	}
}

// Any key the factory does not read is refused, secret-like or not (it would sit in the stored settings and be ignored); the keys it
// reads are accepted (control: the refusal is not a blanket one).
func TestDefaultFactory_SFTP_RefusesUnknownKeysAndAcceptsTheReadOnes(t *testing.T) {
	for _, k := range []string{"hostname", "Host", "user", "timeout", "known_hosts", "name"} {
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp",
			Settings: map[string]interface{}{"host": "h", "username": "u", "credential_ref": "r", k: "x"}})
		require.Error(t, err, "%q is not read by the factory", k)
		assert.Contains(t, err.Error(), "unknown setting", k)
		assert.Contains(t, err.Error(), k)
	}
	for _, k := range []string{"host", "port", "username", "credential_ref", "path", "root"} {
		v := interface{}("x")
		if k == "port" {
			v = 22
		}
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp", Settings: map[string]interface{}{k: v}})
		assert.NoError(t, err, "%q is read by the factory", k)
	}
}

// S14: the pin store is followed at CONNECT time. A client created before the application installed its store used to be captured
// with a nil store and refuse every host for good, against the factory's own comment.
func TestDefaultFactory_SFTP_FollowsAPinStoreInstalledAfterTheClientWasCreated(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644))
	host, port, hk := startSFTPPeer(t)
	old := sftp.DefaultPinStore
	sftp.DefaultPinStore = nil
	t.Cleanup(func() { sftp.DefaultPinStore = old })
	t.Setenv("SFTP_CRED_lateref_PASSWORD", "pw-fx")

	c, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp", Settings: map[string]interface{}{
		"host": host, "port": port, "username": "alice", "credential_ref": "lateref", "path": dir}})
	require.NoError(t, err)
	assert.ErrorIs(t, c.Connect(context.Background()), sftp.ErrNoPinStore, "no store yet: refused")

	store := sftp.NewMemPinStore()
	require.NoError(t, store.Record(sftp.HostPort(host, port), sftp.HostKeyPin{KeyType: hk.Type(), Fingerprint: sftp.Fingerprint(hk), ConfirmedBy: "test"}))
	sftp.DefaultPinStore = store // installed AFTER the client was created
	require.NoError(t, c.Connect(context.Background()))
	defer c.Disconnect(context.Background()) //nolint:errcheck
	ents, err := c.ListDirectory(context.Background(), "/")
	require.NoError(t, err)
	require.Len(t, ents, 1)
}
