package ftp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Credential is the secret of one credential_ref. It never appears in logs, errors, GetConfig or String.
type Credential struct {
	Password string
}

// String redacts the secret. It has a VALUE receiver on purpose: with a pointer receiver fmt of a Credential value
// (not a pointer) prints the password.
func (c Credential) String() string { return "Credential(redacted)" }

// GoString redacts the secret for %#v.
func (c Credential) GoString() string { return c.String() }

func (c *Credential) wipe() {
	if c != nil {
		c.Password = ""
	}
}

// CredentialResolver turns a credential_ref (an opaque name, never a secret) into its secret.
type CredentialResolver interface {
	Resolve(ctx context.Context, ref string) (*Credential, error)
}

// ErrCredentialUnavailable is returned when no password can be obtained. It never contains the secret.
var ErrCredentialUnavailable = errors.New("ftp: credential could not be resolved")

// EnvCredentialResolver resolves a ref from the process environment: for ref "nas1" and prefix "FTP_CRED" it
// reads FTP_CRED_NAS1_PASSWORD. The ref is upper-cased and every character outside [A-Z0-9] becomes "_".
type EnvCredentialResolver struct {
	Prefix string
	// Getenv replaces os.Getenv (tests).
	Getenv func(string) string
}

// DefaultCredentialResolver is the resolver used when Config.Resolver is nil.
var DefaultCredentialResolver CredentialResolver = EnvCredentialResolver{Prefix: "FTP_CRED"}

func envName(prefix, ref string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(ref) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return prefix + "_" + b.String() + "_PASSWORD"
}

// Resolve implements CredentialResolver.
func (r EnvCredentialResolver) Resolve(_ context.Context, ref string) (*Credential, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, fmt.Errorf("%w: empty credential_ref", ErrCredentialUnavailable)
	}
	get := r.Getenv
	if get == nil {
		get = os.Getenv
	}
	prefix := r.Prefix
	if prefix == "" {
		prefix = "FTP_CRED"
	}
	name := envName(prefix, ref)
	pw := get(name)
	if pw == "" {
		// The message names the variable, never a value.
		return nil, fmt.Errorf("%w: %q (set %s)", ErrCredentialUnavailable, ref, name)
	}
	return &Credential{Password: pw}, nil
}
