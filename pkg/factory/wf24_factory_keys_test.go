package factory

import (
	"testing"

	"digital.vasic.filesystem/pkg/client"
)

// WF24 probe N10: the factory refuses inline secrets under 7 exact lower-case names; other spellings are accepted silently.
func TestWF24_N10_InlineSecretSpellingsAccepted(t *testing.T) {
	var accepted []string
	for _, k := range []string{"password", "Password", "PASSWORD", "passwd", "pwd", "pass", "privateKey", "private-key", "ssh_key", "credentials"} {
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "sftp",
			Settings: map[string]interface{}{"host": "h", "username": "u", "credential_ref": "r", k: "INLINE-SECRET-XYZ"}})
		if err == nil {
			accepted = append(accepted, k)
		}
	}
	t.Logf("WF24-PROBE N10 accepted_inline_secret_keys=%v (control: \"password\" must be refused)", accepted)
	for _, k := range accepted {
		if k == "password" {
			t.Fatalf("control failed: the exact key 'password' was accepted")
		}
	}
	if len(accepted) > 0 {
		t.Logf("OBSERVATION N10: %d secret-like spellings are accepted and stored silently", len(accepted))
	}
}
