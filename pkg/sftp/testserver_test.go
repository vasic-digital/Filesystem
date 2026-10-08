package sftp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gosftp "github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// testServer is a REAL ssh server with the real pkg/sftp request server behind it, bound to 127.0.0.1. It is the
// unit-level peer of the client (nothing in the client is replaced); the integration tests use OpenSSH instead.
type testServer struct {
	t        *testing.T
	ln       net.Listener
	Addr     string
	Host     string
	Port     int
	Dir      string // served directory (the sftp server has no chroot; the client Root points here)
	Password string
	HostKey  ssh.Signer
	// AuthKey, when set, is accepted for user alice by public key.
	AuthKey ssh.PublicKey

	authAttempts atomic.Int32
	conns        atomic.Int32
	// dropFirst closes this many TCP connections immediately after accept (simulates a transient network fault).
	dropFirst atomic.Int32
	// readOnlyServer makes the sftp server itself refuse writes.
	wg sync.WaitGroup

	cmu      sync.Mutex
	accepted []net.Conn
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startServer(t *testing.T) *testServer {
	t.Helper()
	dir := t.TempDir()
	return startServerIn(t, dir, newSigner(t))
}

func startServerIn(t *testing.T, dir string, hk ssh.Signer) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	s := &testServer{t: t, ln: ln, Addr: ln.Addr().String(), Host: host, Port: port, Dir: dir, Password: "pw-" + filepath.Base(dir), HostKey: hk}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			s.authAttempts.Add(1)
			if c.User() == "alice" && string(pw) == s.Password {
				return nil, nil
			}
			return nil, os.ErrPermission
		},
	}
	cfg.PublicKeyCallback = func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		s.authAttempts.Add(1)
		if s.AuthKey != nil && c.User() == "alice" && bytes.Equal(k.Marshal(), s.AuthKey.Marshal()) {
			return nil, nil
		}
		return nil, os.ErrPermission
	}
	cfg.AddHostKey(hk)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			s.cmu.Lock()
			s.accepted = append(s.accepted, conn)
			s.cmu.Unlock()
			if s.dropFirst.Load() > 0 && s.dropFirst.Add(-1) >= 0 {
				_ = conn.Close()
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serve(conn, cfg)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		s.cmu.Lock()
		for _, c := range s.accepted {
			_ = c.Close()
		}
		s.cmu.Unlock()
		s.wg.Wait()
	})
	return s
}

func (s *testServer) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range creqs {
				ok := r.Type == "subsystem" && len(r.Payload) >= 4 && strings.HasSuffix(string(r.Payload), "sftp")
				_ = r.Reply(ok, nil)
				if ok {
					h := roHandlers{}
					srv := gosftp.NewRequestServer(ch, gosftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h})
					_ = srv.Serve()
					_ = srv.Close()
					return
				}
			}
		}()
	}
}

// pinned returns a store holding the pin of this server's real host key.
func (s *testServer) pinned() *MemPinStore {
	st := NewMemPinStore()
	_ = st.Record(HostPort(s.Host, s.Port), HostKeyPin{
		KeyType: s.HostKey.PublicKey().Type(), Fingerprint: Fingerprint(s.HostKey.PublicKey()), ConfirmedBy: "test-owner",
	})
	return st
}

// mapResolver is a real CredentialResolver over a map; it returns a fresh copy per call (the contract: the
// client wipes what it receives).
type mapResolver map[string]Credential

func (m mapResolver) Resolve(_ context.Context, ref string) (*Credential, error) {
	c, ok := m[ref]
	if !ok {
		return nil, ErrCredentialUnavailable
	}
	return &Credential{Password: c.Password, PrivateKeyPEM: append([]byte(nil), c.PrivateKeyPEM...), Passphrase: append([]byte(nil), c.Passphrase...)}, nil
}

// roHandlers serves the real filesystem read only through pkg/sftp's RequestServer. Unlike the plain Server, its
// RealPath resolves symbolic links the way OpenSSH's sftp-server does, which the confinement check relies on.
type roHandlers struct{}

func (roHandlers) Fileread(r *gosftp.Request) (io.ReaderAt, error) { return os.Open(r.Filepath) }
func (roHandlers) Filewrite(*gosftp.Request) (io.WriterAt, error)  { return nil, os.ErrPermission }
func (roHandlers) Filecmd(*gosftp.Request) error                   { return os.ErrPermission }
func (roHandlers) RealPath(p string) (string, error)               { return filepath.EvalSymlinks(p) }

type listerAt []os.FileInfo

func (l listerAt) ListAt(f []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(f, l[off:])
	if n < len(f) {
		return n, io.EOF
	}
	return n, nil
}

func (roHandlers) Filelist(r *gosftp.Request) (gosftp.ListerAt, error) {
	switch r.Method {
	case "List":
		d, err := os.Open(r.Filepath)
		if err != nil {
			return nil, err
		}
		defer d.Close()
		fis, err := d.Readdir(-1)
		if err != nil {
			return nil, err
		}
		return listerAt(fis), nil
	case "Stat":
		fi, err := os.Stat(r.Filepath)
		if err != nil {
			return nil, err
		}
		return listerAt{fi}, nil
	case "Lstat":
		fi, err := os.Lstat(r.Filepath)
		if err != nil {
			return nil, err
		}
		return listerAt{fi}, nil
	}
	return nil, gosftp.ErrSSHFxOpUnsupported
}
