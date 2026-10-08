package ftp

// An in-process FTP/FTPS server for the UNIT tests only (constitution 11.4.27: fakes are allowed in unit tests,
// the integration tests in integration_test.go talk to a real pure-ftpd). It speaks just enough of RFC 959,
// 2228, 2389, 2428 and 3659 to drive the client, and it records every command so that tests can assert what was
// (and what was never) sent.

import (
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
	"net/textproto"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeFile struct {
	data  []byte
	mtime time.Time
	dir   bool
}

type fakeServer struct {
	t  *testing.T
	ln net.Listener

	cert       tls.Certificate
	tlsOn      bool // AUTH TLS offered
	mlst       bool // MLST/MLSD offered
	utf8Feat   bool
	legacyName bool // non-ASCII names come out as 0x7f until OPTS UTF8 ON (Synology behaviour)
	user, pass string
	loginCode  int // reply code of a failed PASS (default 530)
	noModify   bool
	tlsOnly11  bool
	tcfg       *tls.Config
	home       string // the login directory of a session ("/" when empty)

	mu        sync.Mutex
	files     map[string]fakeFile
	cmds      []string
	drops     map[string]int // command verb -> number of times to drop the control connection instead of answering
	ctrlConns int
	curCtrl   int
	maxCtrl   int
	dataConns int
	resumed   int
	dataTLS   int
	dataClear int
	conns     []net.Conn // every accepted control connection: the cleanup closes them (a leaked connection must fail ITS test, not stall the suite)
	wg        sync.WaitGroup
	// hook, when set, sees every command BEFORE the built-in handler. It returns handled=true to take the command over
	// and cont=false to end the session (it can stall, send extra replies, 421, a permission 550, a cut transfer ...).
	hook func(ss *session, verb, arg string) (handled, cont bool)
}

func genCert(t *testing.T) tls.Certificate {
	t.Helper()
	return genCertNames(t, []string{"fake-ftp.test"}, []net.IP{net.ParseIP("127.0.0.1")})
}

func genCertNames(t *testing.T, dns []string, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "fake-ftp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func certFingerprint(t *testing.T, c tls.Certificate) string {
	t.Helper()
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return Fingerprint(x)
}

var t0 = time.Date(2020, 5, 17, 10, 30, 0, 0, time.UTC)

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{
		t: t, ln: ln, cert: genCert(t), tlsOn: true, mlst: true, utf8Feat: true,
		user: "u", pass: "pw", loginCode: 530, drops: map[string]int{},
		files: map[string]fakeFile{
			"/":                {dir: true, mtime: t0},
			"/data":            {dir: true, mtime: t0},
			"/data/a.txt":      {data: []byte("hello ftp\n"), mtime: t0},
			"/data/big.bin":    {data: seqBytes(100000), mtime: t0.Add(24 * time.Hour)},
			"/data/sub":        {dir: true, mtime: t0.Add(48 * time.Hour)},
			"/data/sub/c.txt":  {data: []byte("c\n"), mtime: t0.Add(72 * time.Hour)},
			"/data/Čšž_日本.txt": {data: []byte("utf8"), mtime: t0},
		},
	}
	s.wg.Add(1)
	go s.acceptLoop()
	t.Cleanup(func() {
		_ = ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func seqBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// serverTLS returns the ONE tls.Config of the server: session ticket keys live in the Config, so control and data
// connections must share it for a session to be resumable (as in a real server).
func (s *fakeServer) serverTLS() *tls.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcfg == nil {
		s.tcfg = &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12}
		if s.tlsOnly11 {
			s.tcfg.MinVersion, s.tcfg.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
		}
	}
	return s.tcfg
}

// resetCounters forgets what happened so far (the pin discovery), so tests count only the client under test.
func (s *fakeServer) resetCounters() {
	s.mu.Lock()
	s.cmds, s.ctrlConns, s.maxCtrl, s.dataConns, s.resumed, s.dataTLS, s.dataClear = nil, 0, 0, 0, 0, 0, 0
	s.mu.Unlock()
}

func (s *fakeServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *fakeServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...)
}

func (s *fakeServer) count(verb string) int {
	n := 0
	for _, c := range s.commands() {
		if c == verb || strings.HasPrefix(c, verb+" ") {
			n++
		}
	}
	return n
}

func (s *fakeServer) index(prefix string) int {
	for i, c := range s.commands() {
		if c == prefix || strings.HasPrefix(c, prefix+" ") {
			return i
		}
	}
	return -1
}

func (s *fakeServer) dropNext(verb string, n int) {
	s.mu.Lock()
	s.drops[verb] += n
	s.mu.Unlock()
}

func (s *fakeServer) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.serve(c) }()
	}
}

func (s *fakeServer) log(line string) {
	s.mu.Lock()
	s.cmds = append(s.cmds, line)
	s.mu.Unlock()
}

type session struct {
	s      *fakeServer
	conn   net.Conn
	tc     *textproto.Conn
	user   string
	authed bool
	protP  bool
	utf8   bool
	cwd    string
	rest   int64
	pasv   net.Listener
	wasTLS bool
}

func (s *fakeServer) serve(raw net.Conn) {
	s.mu.Lock()
	s.ctrlConns++
	s.curCtrl++
	if s.curCtrl > s.maxCtrl {
		s.maxCtrl = s.curCtrl
	}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.curCtrl--; s.mu.Unlock() }()
	s.mu.Lock()
	home := s.home
	s.mu.Unlock()
	if home == "" {
		home = "/"
	}
	ss := &session{s: s, conn: raw, tc: textproto.NewConn(raw), cwd: home}
	defer func() {
		if ss.pasv != nil {
			_ = ss.pasv.Close()
		}
		_ = ss.conn.Close()
	}()
	ss.reply("220 fake ftp ready")
	for {
		_ = ss.conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		line, err := ss.tc.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		if verb == "PASS" {
			s.log("PASS ***")
		} else if arg != "" {
			s.log(verb + " " + arg)
		} else {
			s.log(verb)
		}
		s.mu.Lock()
		if s.drops[verb] > 0 {
			s.drops[verb]--
			s.mu.Unlock()
			return
		}
		h := s.hook
		s.mu.Unlock()
		if h != nil {
			if handled, cont := h(ss, verb, arg); handled {
				if !cont {
					return
				}
				continue
			}
		}
		if !ss.handle(verb, arg) {
			return
		}
	}
}

func (ss *session) reply(format string, a ...any) {
	_ = ss.tc.PrintfLine(format, a...)
}

func (ss *session) name(n string) string {
	if ss.s.legacyName && !ss.utf8 {
		var b strings.Builder
		for _, r := range n {
			if r > 127 {
				b.WriteByte(0x7f)
			} else {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return n
}

func (s *fakeServer) lookup(p string) (fakeFile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == "" {
		p = "/"
	}
	p = path.Clean(p)
	f, ok := s.files[p]
	return f, ok
}

// abs resolves a path argument against the session's working directory (an empty argument is the directory itself).
func (ss *session) abs(arg string) string {
	if arg == "" {
		return ss.cwd
	}
	if !strings.HasPrefix(arg, "/") {
		arg = path.Join(ss.cwd, arg)
	}
	return path.Clean(arg)
}

func (s *fakeServer) setHome(h string) {
	s.mu.Lock()
	s.home = h
	s.mu.Unlock()
}

func (s *fakeServer) setHook(h func(ss *session, verb, arg string) (bool, bool)) {
	s.mu.Lock()
	s.hook = h
	s.mu.Unlock()
}

// openCtrl is the number of control connections the server holds open right now.
func (s *fakeServer) openCtrl() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.curCtrl
}

// waitCtrl waits until the server holds exactly n control connections (the leak oracle: a client that does not close
// a connection keeps this above n).
func (s *fakeServer) waitCtrl(n int, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if s.openCtrl() == n {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s.openCtrl() == n
}

func (s *fakeServer) children(dir string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for p := range s.files {
		if p != dir && p != "/" && strings.HasPrefix(p, prefix) && !strings.Contains(strings.TrimPrefix(p, prefix), "/") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func (ss *session) facts(f fakeFile, full string) string {
	typ := "file"
	if f.dir {
		typ = "dir"
	}
	b := fmt.Sprintf("Type=%s;Size=%d;", typ, len(f.data))
	if !ss.s.noModify {
		b += "Modify=" + f.mtime.UTC().Format("20060102150405") + ";"
	}
	return b
}

func (ss *session) handle(verb, arg string) bool {
	s := ss.s
	switch verb {
	case "AUTH":
		if !s.tlsOn || !strings.EqualFold(arg, "TLS") {
			ss.reply("502 no")
			return true
		}
		ss.reply("234 AUTH TLS ok")
		tc := tls.Server(ss.conn, s.serverTLS())
		ss.conn = tc
		ss.tc = textproto.NewConn(tc)
		ss.wasTLS = true
	case "USER":
		ss.user = arg
		ss.reply("331 password please")
	case "PASS":
		if ss.user == s.user && arg == s.pass {
			ss.authed = true
			ss.reply("230 logged in")
		} else {
			ss.reply("%d Login incorrect", s.loginCode)
		}
	case "FEAT":
		feats := []string{"EPSV", "SIZE", "REST STREAM"}
		if s.mlst {
			feats = append(feats, "MLST Type*;Size*;Modify*;")
		}
		if s.utf8Feat {
			feats = append(feats, "UTF8")
		}
		if s.tlsOn {
			feats = append(feats, "AUTH TLS", "PBSZ", "PROT")
		}
		ss.reply("211-Features:")
		for _, f := range feats {
			ss.reply(" %s", f)
		}
		ss.reply("211 End")
	case "TYPE":
		ss.reply("200 type set")
	case "OPTS":
		if strings.EqualFold(arg, "UTF8 ON") {
			ss.utf8 = true
			ss.reply("200 UTF8 on")
		} else {
			ss.reply("501 no")
		}
	case "PBSZ":
		ss.reply("200 PBSZ=0")
	case "PROT":
		ss.protP = strings.EqualFold(arg, "P")
		ss.reply("200 PROT %s", arg)
	case "NOOP":
		ss.reply("200 ok")
	case "PWD":
		ss.reply(`257 "%s" is the current directory`, strings.ReplaceAll(ss.cwd, `"`, `""`))
	case "CWD":
		if f, ok := s.lookup(ss.abs(arg)); ok && f.dir {
			ss.cwd = ss.abs(arg)
			ss.reply("250 ok")
		} else {
			ss.reply("550 No such file or directory")
		}
	case "SIZE":
		f, ok := s.lookup(ss.abs(arg))
		switch {
		case ok && !f.dir:
			ss.reply("213 %d", len(f.data))
		case ok:
			ss.reply("550 not a plain file")
		default:
			ss.reply("550 No such file or directory")
		}
	case "MLST":
		if !s.mlst {
			ss.reply("500 unknown")
			return true
		}
		f, ok := s.lookup(ss.abs(arg))
		if !ok {
			ss.reply("550 not found")
			return true
		}
		ss.reply("250-Listing %s", arg)
		ss.reply(" %s %s", ss.facts(f, arg), ss.name(arg))
		ss.reply("250 End")
	case "EPSV", "PASV":
		if ss.pasv != nil {
			_ = ss.pasv.Close()
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			ss.reply("425 no")
			return true
		}
		ss.pasv = ln
		port := ln.Addr().(*net.TCPAddr).Port
		if verb == "EPSV" {
			ss.reply("229 Entering Extended Passive Mode (|||%d|)", port)
		} else {
			ss.reply("227 Entering Passive Mode (127,0,0,1,%d,%d)", port/256, port%256)
		}
	case "REST":
		var n int64
		fmt.Sscanf(arg, "%d", &n)
		ss.rest = n
		ss.reply("350 restarting at %d", n)
	case "MLSD", "LIST", "RETR":
		return ss.transfer(verb, arg)
	case "STOR":
		ss.reply("150 ok to send")
		dc, err := ss.openData()
		if err != nil {
			ss.reply("425 cannot open data connection")
			return true
		}
		b, _ := io.ReadAll(dc)
		_ = dc.Close()
		s.mu.Lock()
		s.files[ss.abs(arg)] = fakeFile{data: b, mtime: time.Now()}
		s.mu.Unlock()
		ss.reply("226 stored")
	case "DELE", "RMD":
		s.mu.Lock()
		_, ok := s.files[ss.abs(arg)]
		delete(s.files, ss.abs(arg))
		s.mu.Unlock()
		if ok {
			ss.reply("250 deleted")
		} else {
			ss.reply("550 not found")
		}
	case "MKD":
		s.mu.Lock()
		s.files[ss.abs(arg)] = fakeFile{dir: true, mtime: time.Now()}
		s.mu.Unlock()
		ss.reply("257 created")
	case "QUIT":
		ss.reply("221 bye")
		return false
	default:
		ss.reply("502 not implemented")
	}
	return true
}

func (ss *session) openData() (net.Conn, error) {
	if ss.pasv == nil {
		return nil, fmt.Errorf("no passive listener")
	}
	if tl, ok := ss.pasv.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(10 * time.Second))
	}
	c, err := ss.pasv.Accept()
	_ = ss.pasv.Close()
	ss.pasv = nil
	if err != nil {
		return nil, err
	}
	s := ss.s
	s.mu.Lock()
	s.dataConns++
	s.mu.Unlock()
	if ss.protP {
		tc := tls.Server(c, s.serverTLS())
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			_ = c.Close()
			return nil, err
		}
		_ = tc.SetDeadline(time.Time{})
		s.mu.Lock()
		s.dataTLS++
		if tc.ConnectionState().DidResume {
			s.resumed++
		}
		s.mu.Unlock()
		return tc, nil
	}
	s.mu.Lock()
	s.dataClear++
	s.mu.Unlock()
	return c, nil
}

func (ss *session) transfer(verb, arg string) bool {
	s := ss.s
	rest := ss.rest
	ss.rest = 0
	var payload []byte
	switch verb {
	case "RETR":
		arg = ss.abs(arg)
		f, ok := s.lookup(arg)
		if !ok || f.dir {
			ss.reply("550 not found")
			return true
		}
		if rest > int64(len(f.data)) {
			rest = int64(len(f.data))
		}
		payload = f.data[rest:]
	case "MLSD", "LIST":
		if verb == "MLSD" && !s.mlst {
			ss.reply("500 unknown")
			return true
		}
		arg = ss.abs(arg)
		f, ok := s.lookup(arg)
		if !ok {
			ss.reply("550 No such file or directory")
			return true
		}
		if !f.dir {
			ss.reply("550 not a directory")
			return true
		}
		var b strings.Builder
		if verb == "MLSD" {
			fmt.Fprintf(&b, "Type=cdir;Modify=%s; .\r\n", f.mtime.UTC().Format("20060102150405"))
			fmt.Fprintf(&b, "Type=pdir;Modify=%s; ..\r\n", f.mtime.UTC().Format("20060102150405"))
		}
		for _, p := range s.children(strings.TrimSuffix(arg, "/")) {
			cf, _ := s.lookup(p)
			base := p[strings.LastIndex(p, "/")+1:]
			if verb == "MLSD" {
				fmt.Fprintf(&b, "%s %s\r\n", ss.facts(cf, p), ss.name(base))
			} else {
				kind := "-"
				if cf.dir {
					kind = "d"
				}
				fmt.Fprintf(&b, "%srw-r--r-- 1 u g %d %s %s\r\n", kind, len(cf.data), cf.mtime.Format("Jan 02  2006"), ss.name(base))
			}
		}
		payload = []byte(b.String())
	}
	ss.reply("150 opening data connection")
	dc, err := ss.openData()
	if err != nil {
		ss.reply("425 cannot open data connection")
		return true
	}
	_, werr := dc.Write(payload)
	_ = dc.Close()
	if werr != nil {
		ss.reply("426 transfer aborted")
		return true
	}
	ss.reply("226 transfer complete")
	return true
}

var _ = io.EOF
