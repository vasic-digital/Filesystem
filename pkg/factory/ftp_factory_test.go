package factory

// WF21 F16: the factory builds the hardened FTP/FTPS client (ftp.NewScanClient) from the stored settings, with the
// process-wide pin store. These tests drive a real socket peer (a minimal FTP/TLS responder) so that every wiring
// claim is observed on the wire: what the client sends, and what it refuses to send.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/fabric"
	"digital.vasic.filesystem/pkg/ftp"
)

type ftpPeer struct {
	port int
	cert tls.Certificate
	mu   sync.Mutex
	seen []string
	ln   net.Listener
}

func (p *ftpPeer) commands() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func (p *ftpPeer) log(s string) {
	p.mu.Lock()
	p.seen = append(p.seen, s)
	p.mu.Unlock()
}

// startFTPPeer answers: 220, AUTH TLS (when tlsOn), then a TLS handshake, then USER with 331 and PASS with 530 (so a
// login attempt is visible and ends at once; a USER-phase 530 would NOT be an authentication failure, WF24 G2). In clear
// mode it answers 220 and the same USER/PASS pair directly.
func startFTPPeer(t *testing.T, tlsOn bool) *ftpPeer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "peer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &ftpPeer{port: ln.Addr().(*net.TCPAddr).Port, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var out io.Writer = c
				in := bufio.NewReader(c)
				_, _ = io.WriteString(out, "220 peer ready\r\n")
				for {
					line, err := in.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					verb, _, _ := strings.Cut(line, " ")
					if strings.EqualFold(verb, "PASS") {
						p.log("PASS ***")
					} else {
						p.log(line)
					}
					switch strings.ToUpper(verb) {
					case "AUTH":
						if !tlsOn {
							_, _ = io.WriteString(out, "502 no\r\n")
							continue
						}
						_, _ = io.WriteString(out, "234 go\r\n")
						tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{p.cert}, MinVersion: tls.VersionTLS12})
						if err := tc.Handshake(); err != nil {
							return
						}
						out, in = tc, bufio.NewReader(tc)
					case "USER":
						_, _ = io.WriteString(out, "331 password please\r\n")
					case "PASS":
						_, _ = io.WriteString(out, "530 Login incorrect\r\n")
						return
					default:
						_, _ = io.WriteString(out, "502 no\r\n")
					}
				}
			}(c)
		}
	}()
	return p
}

func (p *ftpPeer) fingerprint(t *testing.T) string {
	x, err := x509.ParseCertificate(p.cert.Certificate[0])
	require.NoError(t, err)
	return ftp.Fingerprint(x)
}

func ftpSettings(p *ftpPeer, extra map[string]interface{}) *client.StorageConfig {
	s := map[string]interface{}{"host": "127.0.0.1", "port": p.port, "username": "alice", "credential_ref": "fxftp", "path": "/"}
	for k, v := range extra {
		s[k] = v
	}
	return &client.StorageConfig{Protocol: "ftp", Settings: s}
}

func withPinStore(t *testing.T, st ftp.PinStore) {
	t.Helper()
	old := ftp.DefaultPinStore
	ftp.DefaultPinStore = st
	t.Cleanup(func() { ftp.DefaultPinStore = old })
}

func ftpCtx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestFTPFactory_ReturnsTheReadOnlyScanClient_NoMutationCanReachTheServer(t *testing.T) {
	c, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "h", "credential_ref": "x"}})
	require.NoError(t, err)
	assert.Equal(t, "ftp", c.GetProtocol())
	assert.ErrorIs(t, c.DeleteFile(context.Background(), "/x"), decorators.ErrReadOnly)
	assert.ErrorIs(t, c.WriteFile(context.Background(), "/x", strings.NewReader("a")), decorators.ErrReadOnly)
	assert.ErrorIs(t, c.CreateDirectory(context.Background(), "/d"), decorators.ErrReadOnly)
	_, isSeek := c.(client.SeekableClient)
	assert.True(t, isSeek)
}

func TestFTPFactory_RejectsEverySecretLikeSetting_AndBadTypes(t *testing.T) {
	for _, k := range []string{"password", "passphrase", "private_key", "privatekey", "key", "secret", "token"} {
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "h", k: "s3cret"}})
		require.Error(t, err, k)
		assert.Contains(t, err.Error(), "credential_ref")
		assert.NotContains(t, err.Error(), "s3cret")
	}
	for _, bad := range []interface{}{0, -1, 65536, "21", 21.5, nil} {
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "h", "port": bad}})
		assert.Error(t, err, "port %v", bad)
	}
	for _, good := range []interface{}{21, 2121, float64(990)} {
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "h", "port": good}})
		assert.NoError(t, err, "port %v", good)
	}
	for _, k := range []string{"trusted_lan", "allow_degraded_list", "disable_epsv"} {
		_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "h", k: "false"}})
		assert.Error(t, err, "a quoted boolean must not silently read as true: %s", k)
	}
	_, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "h", "tls_mode": true}})
	assert.Error(t, err)
}

func TestFTPFactory_NoPinStoreInstalled_RefusesToConnect_FailClosed(t *testing.T) {
	withPinStore(t, nil)
	t.Setenv("FTP_CRED_FXFTP_PASSWORD", "pw-fx")
	p := startFTPPeer(t, true)
	c, err := NewDefaultFactory().CreateClient(ftpSettings(p, nil))
	require.NoError(t, err)
	require.ErrorIs(t, c.Connect(ftpCtx(t)), ftp.ErrNoPinStore)
	assert.Empty(t, p.commands(), "nothing reached the server")
}

func TestFTPFactory_UsesTheInstalledPinStore_UnknownThenPinned_EndToEnd(t *testing.T) {
	t.Setenv("FTP_CRED_FXFTP_PASSWORD", "pw-fx")
	p := startFTPPeer(t, true)
	store := ftp.NewMemPinStore()
	withPinStore(t, store)
	c, err := NewDefaultFactory().CreateClient(ftpSettings(p, nil))
	require.NoError(t, err)
	err = c.Connect(ftpCtx(t))
	var unknown *ftp.UnknownCertError
	require.ErrorAs(t, err, &unknown, "an empty installed store reaches the client: the certificate is refused as unknown, with its fingerprint")
	assert.Equal(t, p.fingerprint(t), unknown.Fingerprint)
	for _, cmd := range p.commands() {
		assert.NotContains(t, cmd, "USER", "no credential before the certificate is pinned")
	}

	_, err = ftp.Pin(ftpCtx(t), store, "127.0.0.1", p.port, ftp.Confirmation{Fingerprint: p.fingerprint(t), ConfirmedBy: "owner"})
	require.NoError(t, err)
	c2, err := NewDefaultFactory().CreateClient(ftpSettings(p, nil))
	require.NoError(t, err)
	err = c2.Connect(ftpCtx(t))
	require.Error(t, err, "the peer rejects the user")
	assert.Equal(t, fabric.ClassAuth, fabric.Classify(err), "past the pin check the login really happened: %v", err)
	cmds := p.commands()
	assert.Contains(t, cmds, "AUTH TLS")
	assert.Contains(t, cmds, "USER alice", "username from the settings reached the server")
	assert.NotContains(t, strings.Join(cmds, " "), "pw-fx", "the password never appears in clear on the wire before the verified handshake")
}

func TestFTPFactory_ClearText_NeedsTrustedLAN_AndIsHonouredWhenSet(t *testing.T) {
	t.Setenv("FTP_CRED_FXFTP_PASSWORD", "pw-fx")
	p := startFTPPeer(t, false)
	withPinStore(t, ftp.NewMemPinStore())
	c, err := NewDefaultFactory().CreateClient(ftpSettings(p, map[string]interface{}{"tls_mode": "none"}))
	require.NoError(t, err)
	require.ErrorIs(t, c.Connect(ftpCtx(t)), ftp.ErrClearTextRefused)
	assert.Empty(t, p.commands())

	c, err = NewDefaultFactory().CreateClient(ftpSettings(p, map[string]interface{}{"tls_mode": "none", "trusted_lan": true}))
	require.NoError(t, err)
	err = c.Connect(ftpCtx(t))
	require.Error(t, err)
	assert.Equal(t, fabric.ClassAuth, fabric.Classify(err))
	assert.Contains(t, p.commands(), "USER alice")
	assert.NotContains(t, p.commands(), "AUTH TLS", "tls_mode none sends no AUTH")

	_, err = NewDefaultFactory().CreateClient(ftpSettings(p, map[string]interface{}{"tls_mode": "implicit"}))
	require.NoError(t, err)
	c, _ = NewDefaultFactory().CreateClient(ftpSettings(p, map[string]interface{}{"tls_mode": "implicit"}))
	require.ErrorIs(t, c.Connect(ftpCtx(t)), ftp.ErrUnsupportedTLSMode)
}

func TestFTPFactory_SettingsReachTheClient_Config(t *testing.T) {
	c, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{
		"host": "nas.local", "port": 2121, "username": "bob", "credential_ref": "ref-1", "path": "/media",
		"tls_mode": "none", "trusted_lan": true, "allow_degraded_list": true}})
	require.NoError(t, err)
	cfg := fmt.Sprintf("%+v", c.GetConfig())
	for _, want := range []string{"Host:nas.local", "Port:2121", "Username:bob", "Path:/media", "TLSMode:none", "TrustedLAN:true", "AllowDegradedList:true"} {
		assert.Contains(t, cfg, want)
	}
	assert.NotContains(t, strings.ToLower(cfg), "password")
	d, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "nas.local", "credential_ref": "r"}})
	require.NoError(t, err)
	def := fmt.Sprintf("%+v", d.GetConfig())
	for _, want := range []string{"Port:21", "TLSMode:explicit", "TrustedLAN:false", "AllowDegradedList:false"} {
		assert.Contains(t, def, want, "defaults: explicit TLS, no trusted LAN, no degraded listing")
	}
}
