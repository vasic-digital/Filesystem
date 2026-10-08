package sftp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// Host key policy: pin per host, no trust-on-first-use without an explicit owner confirmation.
//
//   - A host with no pin is REFUSED (UnknownHostKeyError). The error carries the fingerprint the server
//     presented so that the owner can compare it out of band and then call Pin.
//   - A host whose presented key matches none of its pins is REFUSED (HostKeyMismatchError).
//   - Pin re-reads the key from the server and only records it when the owner's confirmation carries the
//     same fingerprint, so the pin is exactly what the owner saw.
//   - InsecureIgnoreHostKey is never used anywhere in this package.

// ErrNoPinStore is returned when a client is configured without a pin store.
var ErrNoPinStore = errors.New("sftp: no host key pin store configured")

// HostKeyPin is one pinned server key of one host.
type HostKeyPin struct {
	KeyType     string    `json:"key_type"`    // ssh key algorithm name, e.g. ssh-ed25519
	Fingerprint string    `json:"fingerprint"` // "SHA256:<base64 without padding>", as printed by OpenSSH
	ConfirmedBy string    `json:"confirmed_by"`
	PinnedAt    time.Time `json:"pinned_at"`
}

// UnknownHostKeyError reports a host that has no pin. The connection was refused.
type UnknownHostKeyError struct {
	Host        string
	KeyType     string
	Fingerprint string
}

func (e *UnknownHostKeyError) Error() string {
	return fmt.Sprintf("sftp: host %s has no pinned key (server presented %s %s); the owner must confirm and pin it first", e.Host, e.KeyType, e.Fingerprint)
}

// HostKeyMismatchError reports a host whose presented key is not one of its pins. The connection was refused.
type HostKeyMismatchError struct {
	Host      string
	KeyType   string
	Presented string
	Pinned    []string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf("sftp: host key for %s CHANGED: server presented %s %s, pinned %s", e.Host, e.KeyType, e.Presented, strings.Join(e.Pinned, ","))
}

// PinStore persists host key pins. Implementations must be safe for concurrent use.
type PinStore interface {
	Lookup(hostport string) ([]HostKeyPin, error)
	Record(hostport string, pin HostKeyPin) error
	Remove(hostport, fingerprint string) error
}

// Fingerprint returns the OpenSSH style SHA256 fingerprint of a public key.
func Fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// HostPort normalises the address used as the pin key.
func HostPort(host string, port int) string {
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(strings.ToLower(host), fmt.Sprintf("%d", port))
}

// MemPinStore is an in-memory PinStore (tests, short lived tools).
type MemPinStore struct {
	mu   sync.Mutex
	pins map[string][]HostKeyPin
}

// NewMemPinStore creates an empty in-memory store.
func NewMemPinStore() *MemPinStore { return &MemPinStore{pins: map[string][]HostKeyPin{}} }

// Lookup returns a copy of the pins of hostport.
func (s *MemPinStore) Lookup(hostport string) ([]HostKeyPin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]HostKeyPin(nil), s.pins[hostport]...), nil
}

// Record adds a pin (idempotent for an identical fingerprint).
func (s *MemPinStore) Record(hostport string, pin HostKeyPin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.pins[hostport] {
		if p.Fingerprint == pin.Fingerprint {
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
	var keep []HostKeyPin
	for _, p := range s.pins[hostport] {
		if p.Fingerprint != fingerprint {
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

// ErrPinStoreInsecure is returned when the pin file or its directory could be modified by another user: a pin file that
// someone else can write is a way to make this client trust a key of their choosing, so it is not read at all.
var ErrPinStoreInsecure = errors.New("sftp: pin store is writable by other users")

// FilePinStore keeps the pins in one JSON file (mode 0600), rewritten atomically on every change (temp file, fsync, rename,
// fsync of the directory). The file and its directory must not be group/world writable (a sticky directory is accepted)
// and must belong to the current user or root, else every operation fails with ErrPinStoreInsecure. Changes are
// serialised between goroutines by a mutex and between processes by an flock on "<path>.lock".
type FilePinStore struct {
	path string
	mu   sync.Mutex
}

// NewFilePinStore returns a store backed by path. The file is created on the first Record.
func NewFilePinStore(path string) *FilePinStore { return &FilePinStore{path: path} }

func trustedOwner(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true // not a unix stat: nothing to compare
	}
	return st.Uid == uint32(os.Getuid()) || st.Uid == 0
}

// checkTrust refuses a pin file or directory that another user could have written.
func (s *FilePinStore) checkTrust() error {
	dir := filepath.Dir(s.path)
	if di, err := os.Stat(dir); err == nil {
		if di.Mode().Perm()&0o022 != 0 && di.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%w: directory %s has mode %v", ErrPinStoreInsecure, dir, di.Mode().Perm())
		}
		if !trustedOwner(di) {
			return fmt.Errorf("%w: directory %s belongs to another user", ErrPinStoreInsecure, dir)
		}
	}
	fi, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("sftp: pin store %s: %w", s.path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrPinStoreInsecure, s.path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s has mode %v", ErrPinStoreInsecure, s.path, fi.Mode().Perm())
	}
	if !trustedOwner(fi) {
		return fmt.Errorf("%w: %s belongs to another user", ErrPinStoreInsecure, s.path)
	}
	return nil
}

// lockFile takes the cross-process lock; the returned function releases it.
func (s *FilePinStore) lockFile() (func(), error) {
	f, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("sftp: pin store lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("sftp: pin store lock: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func (s *FilePinStore) load() (map[string][]HostKeyPin, error) {
	if err := s.checkTrust(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]HostKeyPin{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sftp: read pin store: %w", err)
	}
	m := map[string][]HostKeyPin{}
	if len(strings.TrimSpace(string(data))) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(data, &m); err != nil {
		// A corrupt pin file must never read as "no pins" silently: the caller then refuses as unknown,
		// but a repair that overwrote it would drop real pins, so it is an error here.
		return nil, fmt.Errorf("sftp: pin store %s is corrupt: %w", s.path, err)
	}
	return m, nil
}

func (s *FilePinStore) save(m map[string][]HostKeyPin) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".pins-*")
	if err != nil {
		return fmt.Errorf("sftp: write pin store: %w", err)
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
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	// the rename itself must survive a crash: sync the directory entry
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sftp: sync pin store directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sftp: sync pin store directory: %w", err)
	}
	return nil
}

// Lookup returns the pins of hostport.
func (s *FilePinStore) Lookup(hostport string) ([]HostKeyPin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return nil, err
	}
	return m[hostport], nil
}

// Record adds a pin.
func (s *FilePinStore) Record(hostport string, pin HostKeyPin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkTrust(); err != nil {
		return err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	for _, p := range m[hostport] {
		if p.Fingerprint == pin.Fingerprint {
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
	if err := s.checkTrust(); err != nil {
		return err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	var keep []HostKeyPin
	for _, p := range m[hostport] {
		if p.Fingerprint != fingerprint {
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

// hostKeyAlgorithms maps a pinned key type to the signature algorithms the client should offer, so a server
// that holds several host keys presents the pinned one (what OpenSSH does for known_hosts entries).
func hostKeyAlgorithms(pins []HostKeyPin) []string {
	var out []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, p := range pins {
		switch p.KeyType {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512)
			add(ssh.KeyAlgoRSASHA256)
		default:
			add(p.KeyType)
		}
	}
	return out
}

// hostKeyCallback builds the verification callback. The first refusal is also stored in *refusal so that the
// caller can return the typed error even where the ssh library flattens it.
func hostKeyCallback(hostport string, pins []HostKeyPin, refusal *error) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := Fingerprint(key)
		if len(pins) == 0 {
			*refusal = &UnknownHostKeyError{Host: hostport, KeyType: key.Type(), Fingerprint: fp}
			return *refusal
		}
		pinned := make([]string, 0, len(pins))
		for _, p := range pins {
			if p.Fingerprint == fp {
				return nil
			}
			pinned = append(pinned, p.Fingerprint)
		}
		*refusal = &HostKeyMismatchError{Host: hostport, KeyType: key.Type(), Presented: fp, Pinned: pinned}
		return *refusal
	}
}

// Discovered is a server host key as presented, before any pin exists.
type Discovered struct {
	KeyType     string
	Fingerprint string
}

// discoverFamilies are the host key algorithm families probed one at a time: a server that holds several host
// keys presents only one per handshake, chosen by the client's algorithm preference.
var discoverFamilies = [][]string{
	{ssh.KeyAlgoED25519},
	{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521},
	{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256},
}

func discoverOne(ctx context.Context, hp string, algs []string, timeout time.Duration) (*Discovered, error) {
	var got *Discovered
	errAbort := errors.New("sftp: discovery complete")
	cfg := &ssh.ClientConfig{
		User:              "discover",
		HostKeyAlgorithms: algs,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = &Discovered{KeyType: key.Type(), Fingerprint: Fingerprint(key)}
			return errAbort
		},
		Timeout: timeout,
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", hp)
	if err != nil {
		return nil, fmt.Errorf("sftp: discover %s: %w", hp, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() }) // a cancelled ctx ends a handshake that is waiting for the server
	defer stop()
	_, _, _, err = ssh.NewClientConn(conn, hp, cfg)
	if got == nil {
		if err == nil {
			err = errors.New("no host key presented")
		}
		return nil, fmt.Errorf("sftp: discover %s: %w", hp, err)
	}
	return got, nil
}

// DiscoverAll connects to host:port only to read the host keys it presents, one handshake per key family
// (ed25519, ecdsa, rsa). Each handshake is aborted before any authentication, so no credential is ever sent to a
// host that is not pinned. Families the server does not hold are skipped; an error is returned only when no key
// at all could be read.
func DiscoverAll(ctx context.Context, host string, port int, timeout time.Duration) ([]Discovered, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	hp := HostPort(host, port)
	var out []Discovered
	var firstErr error
	for _, fam := range discoverFamilies {
		d, err := discoverOne(ctx, hp, fam, timeout)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, *d)
	}
	if len(out) == 0 {
		return nil, firstErr
	}
	return out, nil
}

// Discover returns the first host key DiscoverAll finds.
func Discover(ctx context.Context, host string, port int, timeout time.Duration) (*Discovered, error) {
	all, err := DiscoverAll(ctx, host, port, timeout)
	if err != nil {
		return nil, err
	}
	return &all[0], nil
}

// Confirmation is the explicit owner step of the pin workflow.
type Confirmation struct {
	Owner       string // who confirmed; recorded with the pin
	Fingerprint string // the fingerprint the owner compared out of band; must equal what the server presents now
}

// ErrPinNotConfirmed is returned by Pin when the confirmation is missing or does not match the server's key.
var ErrPinNotConfirmed = errors.New("sftp: host key pin not confirmed by the owner")

// Pin records the host key currently presented by host:port, but only when the owner confirmed exactly that
// fingerprint. A missing owner, a missing fingerprint or a different fingerprint refuses and writes nothing.
func Pin(ctx context.Context, store PinStore, host string, port int, conf Confirmation) (*HostKeyPin, error) {
	if store == nil {
		return nil, ErrNoPinStore
	}
	if strings.TrimSpace(conf.Owner) == "" || strings.TrimSpace(conf.Fingerprint) == "" {
		return nil, fmt.Errorf("%w: owner and fingerprint are required", ErrPinNotConfirmed)
	}
	all, err := DiscoverAll(ctx, host, port, 0)
	if err != nil {
		return nil, err
	}
	var d *Discovered
	var presented []string
	for i := range all {
		presented = append(presented, all[i].Fingerprint)
		if all[i].Fingerprint == conf.Fingerprint {
			d = &all[i]
		}
	}
	if d == nil {
		return nil, fmt.Errorf("%w: owner confirmed %s but the server presents %s", ErrPinNotConfirmed, conf.Fingerprint, strings.Join(presented, ", "))
	}
	pin := HostKeyPin{KeyType: d.KeyType, Fingerprint: d.Fingerprint, ConfirmedBy: conf.Owner, PinnedAt: time.Now().UTC()}
	if err := store.Record(HostPort(host, port), pin); err != nil {
		return nil, err
	}
	return &pin, nil
}

// DefaultPinStore is the store the factory hands to clients it creates. The application sets it at start
// (typically a FilePinStore). It is nil by default, so a factory-built client refuses every host until a store
// with a confirmed pin is installed (ErrNoPinStore).
var DefaultPinStore PinStore
