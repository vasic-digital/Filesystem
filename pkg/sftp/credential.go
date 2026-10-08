package sftp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Credential is the secret material of one credential_ref. It never appears in logs, errors, GetConfig or String.
type Credential struct {
	Password      string
	PrivateKeyPEM []byte
	Passphrase    []byte
}

// String redacts the secret.
func (c *Credential) String() string {
	if c == nil {
		return "Credential(nil)"
	}
	return "Credential(redacted)"
}

// GoString redacts the secret for %#v.
func (c *Credential) GoString() string { return c.String() }

// Empty reports whether the credential carries no usable secret.
func (c *Credential) Empty() bool {
	return c == nil || (c.Password == "" && len(c.PrivateKeyPEM) == 0)
}

func (c *Credential) wipe() {
	if c == nil {
		return
	}
	for i := range c.PrivateKeyPEM {
		c.PrivateKeyPEM[i] = 0
	}
	for i := range c.Passphrase {
		c.Passphrase[i] = 0
	}
	c.Password = ""
}

// CredentialResolver turns a credential_ref (an opaque name, never a secret) into its secret. The resolver MUST
// return a fresh Credential (fresh byte slices) on every call: the client overwrites the key and passphrase bytes it
// receives after use. The Password is a Go string: it can only be dropped, not overwritten, and the ssh library keeps a
// copy for as long as the connection attempt needs it, so zeroing is best effort and not a guarantee.
type CredentialResolver interface {
	Resolve(ctx context.Context, ref string) (*Credential, error)
}

// ErrCredentialUnavailable is returned when a reference cannot be resolved. It never contains the secret.
var ErrCredentialUnavailable = errors.New("sftp: credential_ref could not be resolved")

// EnvCredentialResolver resolves a ref from the process environment. For ref "NAS1" and prefix "SFTP_CRED"
// it reads SFTP_CRED_NAS1_PASSWORD, SFTP_CRED_NAS1_PRIVATE_KEY (PEM) and SFTP_CRED_NAS1_PASSPHRASE.
// The ref is used EXACTLY as written (case included) and may contain only letters, digits and "_": the mapping from ref
// to variable names is injective, so a secret set for one ref can never be read through another ref. Any other
// character is refused (ErrCredentialUnavailable) instead of being folded onto "_".
type EnvCredentialResolver struct {
	Prefix string
	// Getenv replaces os.Getenv (tests).
	Getenv func(string) string
}

// DefaultCredentialResolver is the resolver the factory uses.
var DefaultCredentialResolver CredentialResolver = EnvCredentialResolver{Prefix: "SFTP_CRED"}

func envName(prefix, ref, field string) string { return prefix + "_" + ref + "_" + field }

// validRef reports whether ref is made of letters, digits and underscore only (the injective subset).
func validRef(ref string) bool {
	if ref == "" {
		return false
	}
	for _, r := range ref {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// Resolve implements CredentialResolver.
func (r EnvCredentialResolver) Resolve(_ context.Context, ref string) (*Credential, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, fmt.Errorf("%w: empty credential_ref", ErrCredentialUnavailable)
	}
	if !validRef(ref) {
		return nil, fmt.Errorf("%w: %q: a credential_ref for the environment resolver may contain only letters, digits and '_'", ErrCredentialUnavailable, ref)
	}
	get := r.Getenv
	if get == nil {
		get = os.Getenv
	}
	prefix := r.Prefix
	if prefix == "" {
		prefix = "SFTP_CRED"
	}
	c := &Credential{
		Password:      get(envName(prefix, ref, "PASSWORD")),
		PrivateKeyPEM: []byte(get(envName(prefix, ref, "PRIVATE_KEY"))),
		Passphrase:    []byte(get(envName(prefix, ref, "PASSPHRASE"))),
	}
	if c.Empty() {
		// The message names the variables, never a value.
		return nil, fmt.Errorf("%w: %q (set %s or %s)", ErrCredentialUnavailable, ref,
			envName(prefix, ref, "PASSWORD"), envName(prefix, ref, "PRIVATE_KEY"))
	}
	return c, nil
}
