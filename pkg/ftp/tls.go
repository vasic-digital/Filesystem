package ftp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Certificate policy: pin per host, no trust on first use without an explicit owner confirmation.
//
//   - A host with no pin is REFUSED before any credential is sent (UnknownCertError). The error carries the
//     SHA-256 fingerprint the server presented so that the owner can compare it out of band and then call Pin.
//   - A host whose presented certificate matches none of its pins is REFUSED (CertMismatchError), again before
//     any credential is sent.
//   - Pin re-reads the certificate from the server and records it only when the owner's confirmation carries
//     the same fingerprint, so the pin is exactly what the owner saw.
//   - The pinned certificate is the ONLY trust anchor of the connection (tls.Config.RootCAs), the TLS minimum is
//     1.2, and tls.Config.InsecureSkipVerify is never set anywhere in this package.

// Sentinel errors.
var (
	ErrNoPinStore         = errors.New("ftp: no certificate pin store configured")
	ErrPinNotConfirmed    = errors.New("ftp: the certificate presented by the server is not the one the owner confirmed")
	ErrClearTextRefused   = errors.New("ftp: clear-text FTP is refused (set trusted_lan=true on the root to allow it on a trusted LAN)")
	ErrUnsupportedTLSMode = errors.New("ftp: unsupported tls_mode (use \"explicit\" or \"none\")")
	// ErrPinNameConflict is returned by Pin when the host already has a pin for a certificate valid for ANOTHER name:
	// one TLS server name is verified per host, so a second name would fail verification at connect time. Remove the
	// old pin first (certificate rotation to a new name is a deliberate owner action).
	ErrPinNameConflict = errors.New("ftp: the host already has a pin for a certificate with a different server name; remove that pin first")
)

// CertPin is one pinned server certificate of one host.
type CertPin struct {
	Fingerprint string    `json:"fingerprint"` // "SHA256:AA:BB:..." (as printed by openssl x509 -fingerprint -sha256)
	ServerName  string    `json:"server_name"` // the name the certificate is valid for; used for SNI and verification
	CertDER     []byte    `json:"cert_der"`
	ConfirmedBy string    `json:"confirmed_by"`
	PinnedAt    time.Time `json:"pinned_at"`
}

// UnknownCertError reports a host that has no pin. The connection was refused and no credential was sent.
type UnknownCertError struct {
	Host        string
	Fingerprint string
}

func (e *UnknownCertError) Error() string {
	return fmt.Sprintf("ftp: host %s has no pinned certificate (server presented %s); the owner must confirm and pin it first", e.Host, e.Fingerprint)
}

// CertMismatchError reports a host whose presented certificate is not one of its pins. The connection was
// refused and no credential was sent.
type CertMismatchError struct {
	Host      string
	Presented string
	Pinned    []string
}

func (e *CertMismatchError) Error() string {
	return fmt.Sprintf("ftp: certificate for %s CHANGED: server presented %s, pinned %s", e.Host, e.Presented, strings.Join(e.Pinned, ","))
}

// DefaultPinStore is the store the factory hands to the clients it creates (pkg/factory). The application sets it
// once at start, before any client connects; nil means "no store": every explicit-TLS root is then refused with
// ErrNoPinStore (fail closed).
var DefaultPinStore PinStore

// PinStore persists certificate pins. Implementations must be safe for concurrent use.
type PinStore interface {
	Lookup(hostport string) ([]CertPin, error)
	Record(hostport string, pin CertPin) error
	Remove(hostport, fingerprint string) error
}

// Fingerprint returns the "SHA256:AA:BB:.." fingerprint of a certificate.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return "SHA256:" + strings.Join(parts, ":")
}

// NormalizeFingerprint makes two spellings of one fingerprint comparable (case, colons, optional prefix).
func NormalizeFingerprint(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "SHA256:"), "sha256:")
	s = strings.ReplaceAll(s, ":", "")
	return strings.ToLower(s)
}

// HostPort normalises the address used as the pin key.
func HostPort(host string, port int) string {
	if port == 0 {
		port = 21
	}
	return net.JoinHostPort(strings.ToLower(host), fmt.Sprintf("%d", port))
}

// MemPinStore is an in-memory PinStore (tests, short lived tools).
type MemPinStore struct {
	mu   sync.Mutex
	pins map[string][]CertPin
}

// NewMemPinStore creates an empty in-memory store.
func NewMemPinStore() *MemPinStore { return &MemPinStore{pins: map[string][]CertPin{}} }

// Lookup returns a copy of the pins of hostport.
func (s *MemPinStore) Lookup(hostport string) ([]CertPin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]CertPin(nil), s.pins[hostport]...), nil
}

// Record adds a pin (idempotent for an identical fingerprint).
func (s *MemPinStore) Record(hostport string, pin CertPin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.pins[hostport] {
		if NormalizeFingerprint(p.Fingerprint) == NormalizeFingerprint(pin.Fingerprint) {
			return nil
		}
	}
	s.pins[hostport] = append(s.pins[hostport], pin)
	return nil
}

// Remove deletes one pin.
func (s *MemPinStore) Remove(hostport, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keep []CertPin
	for _, p := range s.pins[hostport] {
		if NormalizeFingerprint(p.Fingerprint) != NormalizeFingerprint(fingerprint) {
			keep = append(keep, p)
		}
	}
	if len(keep) == 0 {
		delete(s.pins, hostport)
	} else {
		s.pins[hostport] = keep
	}
	return nil
}

// FilePinStore keeps the pins in one JSON file (mode 0600), rewritten atomically on every change.
type FilePinStore struct {
	path string
	mu   sync.Mutex
}

// NewFilePinStore returns a store backed by path. The file is created on the first Record.
func NewFilePinStore(path string) *FilePinStore { return &FilePinStore{path: path} }

func (s *FilePinStore) load() (map[string][]CertPin, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]CertPin{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ftp: read pin store: %w", err)
	}
	m := map[string][]CertPin{}
	if len(strings.TrimSpace(string(data))) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(data, &m); err != nil {
		// A corrupt pin file must never read as "no pins" and then be overwritten: that would drop real pins.
		return nil, fmt.Errorf("ftp: pin store %s is corrupt: %w", s.path, err)
	}
	return m, nil
}

func (s *FilePinStore) save(m map[string][]CertPin) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".ftppins-*")
	if err != nil {
		return fmt.Errorf("ftp: write pin store: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

// Lookup returns the pins of hostport.
func (s *FilePinStore) Lookup(hostport string) ([]CertPin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return nil, err
	}
	return m[hostport], nil
}

// Record adds a pin (idempotent for an identical fingerprint).
func (s *FilePinStore) Record(hostport string, pin CertPin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	for _, p := range m[hostport] {
		if NormalizeFingerprint(p.Fingerprint) == NormalizeFingerprint(pin.Fingerprint) {
			return nil
		}
	}
	m[hostport] = append(m[hostport], pin)
	return s.save(m)
}

// Remove deletes one pin.
func (s *FilePinStore) Remove(hostport, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	var keep []CertPin
	for _, p := range m[hostport] {
		if NormalizeFingerprint(p.Fingerprint) != NormalizeFingerprint(fingerprint) {
			keep = append(keep, p)
		}
	}
	if len(keep) == 0 {
		delete(m, hostport)
	} else {
		m[hostport] = keep
	}
	return s.save(m)
}

// newTLSConfig builds the client TLS configuration for host from its pins. Without pins the trust pool is empty,
// so the handshake fails and the presented certificate is reported as UnknownCertError.
func newTLSConfig(host string, pins []CertPin) *tls.Config {
	pool := x509.NewCertPool()
	var fps []string
	serverName := host
	for _, p := range pins {
		if cert, err := x509.ParseCertificate(p.CertDER); err == nil {
			pool.AddCert(cert)
			fps = append(fps, NormalizeFingerprint(Fingerprint(cert)))
		}
		// One server name is verified per host (Pin refuses a second, different name); the first pin's name wins.
		if serverName == host && p.ServerName != "" {
			serverName = p.ServerName
		}
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            pool,
		ServerName:         serverName,
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
		// Defence in depth: whatever the chain verification decided, the leaf must be one of the pins.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("ftp: server presented no certificate")
			}
			got := Fingerprint(cs.PeerCertificates[0])
			for _, f := range fps {
				if f == NormalizeFingerprint(got) {
					return nil
				}
			}
			return &CertMismatchError{Host: host, Presented: got, Pinned: pinFingerprints(pins)}
		},
	}
}

func pinFingerprints(pins []CertPin) []string {
	out := make([]string, 0, len(pins))
	for _, p := range pins {
		out = append(out, p.Fingerprint)
	}
	return out
}

// mapTLSError turns a failed certificate verification into the typed refusal (ok=true). Other errors pass through.
func mapTLSError(err error, host string, pins []CertPin) (error, bool) {
	var mm *CertMismatchError
	if errors.As(err, &mm) || errors.As(err, new(*UnknownCertError)) {
		return err, true
	}
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) && len(cve.UnverifiedCertificates) > 0 {
		fp := Fingerprint(cve.UnverifiedCertificates[0])
		if len(pins) == 0 {
			return &UnknownCertError{Host: host, Fingerprint: fp}, true
		}
		for _, p := range pins {
			if NormalizeFingerprint(p.Fingerprint) == NormalizeFingerprint(fp) {
				return err, true // pinned certificate, but expired / wrong name / ...: a real verification failure
			}
		}
		return &CertMismatchError{Host: host, Presented: fp, Pinned: pinFingerprints(pins)}, true
	}
	return err, false
}

// Discovered is what DiscoverCert read from a server.
type Discovered struct {
	Fingerprint string
	Leaf        *x509.Certificate
}

// DiscoverCert connects to host:port, upgrades with AUTH TLS and returns the presented leaf certificate. It sends
// no credential. The certificate is NOT trusted by this call: it is information for the owner to confirm. timeout
// bounds the whole discovery (connect, greeting, AUTH TLS, handshake); ctx cancellation interrupts it at once.
// Port 0 means the FTP default port (as everywhere else in this package).
func DiscoverCert(ctx context.Context, host string, port int, timeout time.Duration) (*Discovered, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if port == 0 {
		port = DefaultPort
	}
	// An empty trust pool: the handshake is expected to fail verification, and the failure carries the
	// presented chain. No InsecureSkipVerify is needed for that.
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool(), ServerName: host}
	p, err := dialProto(ctx, host, port, protoOpts{dialTimeout: timeout, ioTimeout: timeout, maxReply: DefaultMaxReplyBytes}, cfg)
	if err != nil {
		return nil, err
	}
	defer p.hardClose()
	if err := p.banner(ctx); err != nil {
		return nil, fmt.Errorf("ftp: discover: banner: %w", err)
	}
	if err := p.authTLS(ctx); err != nil {
		return nil, fmt.Errorf("ftp: discover: %w", err)
	}
	herr := p.startTLS(ctx)
	var leaf *x509.Certificate
	var cve *tls.CertificateVerificationError
	switch {
	case herr == nil:
		if tc, ok := p.ctl.(*tls.Conn); ok {
			if pc := tc.ConnectionState().PeerCertificates; len(pc) > 0 {
				leaf = pc[0]
			}
		}
	case errors.As(herr, &cve) && len(cve.UnverifiedCertificates) > 0:
		leaf = cve.UnverifiedCertificates[0]
	default:
		return nil, fmt.Errorf("ftp: discover: TLS handshake: %w", herr)
	}
	if leaf == nil {
		return nil, errors.New("ftp: discover: server presented no certificate")
	}
	return &Discovered{Fingerprint: Fingerprint(leaf), Leaf: leaf}, nil
}

// Confirmation is what the owner states after comparing the fingerprint out of band.
type Confirmation struct {
	Fingerprint string
	ConfirmedBy string
}

// serverNameFor picks the name the pinned certificate is valid for.
func serverNameFor(leaf *x509.Certificate, host string) (string, error) {
	if leaf.VerifyHostname(host) == nil {
		return host, nil
	}
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0], nil
	}
	return "", fmt.Errorf("ftp: certificate has no name that matches %q and no DNS name; it cannot be verified", host)
}

// Pin re-reads the certificate from the server and records it only when it has the fingerprint the owner
// confirmed. A mismatch records nothing.
func Pin(ctx context.Context, store PinStore, host string, port int, conf Confirmation) (*CertPin, error) {
	if store == nil {
		return nil, ErrNoPinStore
	}
	if NormalizeFingerprint(conf.Fingerprint) == "" {
		return nil, fmt.Errorf("%w: empty confirmation", ErrPinNotConfirmed)
	}
	d, err := DiscoverCert(ctx, host, port, 0)
	if err != nil {
		return nil, err
	}
	if NormalizeFingerprint(d.Fingerprint) != NormalizeFingerprint(conf.Fingerprint) {
		return nil, fmt.Errorf("%w: server presented %s, owner confirmed %s", ErrPinNotConfirmed, d.Fingerprint, conf.Fingerprint)
	}
	name, err := serverNameFor(d.Leaf, host)
	if err != nil {
		return nil, err
	}
	existing, err := store.Lookup(HostPort(host, port))
	if err != nil {
		return nil, err
	}
	for _, e := range existing {
		if e.ServerName != "" && e.ServerName != name && NormalizeFingerprint(e.Fingerprint) != NormalizeFingerprint(d.Fingerprint) {
			return nil, fmt.Errorf("%w (pinned %q, new certificate %q)", ErrPinNameConflict, e.ServerName, name)
		}
	}
	pin := CertPin{Fingerprint: d.Fingerprint, ServerName: name, CertDER: d.Leaf.Raw, ConfirmedBy: conf.ConfirmedBy, PinnedAt: time.Now().UTC()}
	if err := store.Record(HostPort(host, port), pin); err != nil {
		return nil, err
	}
	return &pin, nil
}
