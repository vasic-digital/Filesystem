package factory

// WF24 REVIEWER PROBE N5 (cross-boundary sftp -> fabric pool): the pool's "never log in again after a rejected login" latch
// (the NAS auto-block protection) depends on fabric.Classify recognising the error the sftp client returns for a wrong password.
// Author-independent: own ssh server; the real factory, the real pool, the real sftp client and its default env resolver.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/fabric"
	"digital.vasic.filesystem/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// wfAuthServer counts every authentication attempt. kbd=true advertises keyboard-interactive and answers it with a plain
// failure (OpenSSH without a PAM/BSD-auth device; the shape the author found against the real OpenSSH fixture).
func wfAuthServer(t *testing.T, kbd bool) (host string, port int, hk ssh.PublicKey, attempts *atomic.Int32) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	attempts = &atomic.Int32{}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		attempts.Add(1)
		return nil, os.ErrPermission
	}}
	if kbd {
		cfg.KeyboardInteractiveCallback = func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			attempts.Add(1)
			return nil, os.ErrPermission
		}
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer nc.Close()
				_, _, _, _ = ssh.NewServerConn(nc, cfg)
			}()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, signer.PublicKey(), attempts
}

func TestWF24_N5_PoolAuthLatchMissesTheSFTPWrongPasswordShape(t *testing.T) {
	for _, kbd := range []bool{false, true} {
		host, port, hk, attempts := wfAuthServer(t, kbd)
		store := sftp.NewMemPinStore()
		if err := store.Record(sftp.HostPort(host, port), sftp.HostKeyPin{KeyType: hk.Type(), Fingerprint: sftp.Fingerprint(hk), ConfirmedBy: "wf24"}); err != nil {
			t.Fatal(err)
		}
		old := sftp.DefaultPinStore
		sftp.DefaultPinStore = store
		t.Setenv("SFTP_CRED_WF24REF_PASSWORD", "definitely-wrong")
		pool, err := fabric.NewPool(NewDefaultFactory(), fabric.PoolOptions{MaxPerKey: 2, ConnectTimeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		cfg := &client.StorageConfig{ID: "nas", Protocol: "sftp", Settings: map[string]interface{}{
			"host": host, "port": port, "username": "alice", "credential_ref": "WF24REF", "path": "/"}}
		ctx := context.Background()
		_, err1 := pool.GetClientContext(ctx, cfg)
		a1 := attempts.Load()
		var inner error = err1
		for {
			u, ok := inner.(interface{ Unwrap() error })
			if !ok || u.Unwrap() == nil {
				break
			}
			inner = u.Unwrap()
		}
		var ae *sftp.AuthError
		isAuthErr := false
		for e := err1; e != nil; {
			if a, ok := e.(*sftp.AuthError); ok {
				ae, isAuthErr = a, true
				break
			}
			u, ok := e.(interface{ Unwrap() error })
			if !ok {
				break
			}
			e = u.Unwrap()
		}
		_, err2 := pool.GetClientContext(ctx, cfg)
		a2 := attempts.Load()
		_ = pool.CloseAll()
		sftp.DefaultPinStore = old
		latched := err2 != nil && strings.Contains(err2.Error(), "not logging in")
		t.Logf("WF24-PROBE N5 kbd_advertised=%v first_err_is_sftp.AuthError=%v classify(first_err)=%v leaf=%q server_auth_attempts_after_1st=%d after_2nd=%d second_call_latched=%v",
			kbd, isAuthErr, fabric.Classify(err1), inner.Error(), a1, a2, latched)
		_ = ae
		if !isAuthErr {
			t.Fatalf("control: the wrong password must surface as *sftp.AuthError (kbd=%v): %v", kbd, err1)
		}
		if a2 != a1 || !latched {
			t.Errorf("DEFECT N5 (kbd=%v): the pool logged in AGAIN with a password the server already rejected (attempts %d -> %d): fabric.Classify(*sftp.AuthError) = %v, so the NAS auto-block latch did not engage",
				kbd, a1, a2, fabric.Classify(err1))
		}
	}
}
