package main

// AUTH_SYS oracle. go-nfs ignores the credential body, so on its own it cannot prove that the
// client's AUTH_SYS credential is well formed. This file puts a tap between the TCP socket and
// go-nfs: every complete RPC call record is decoded with go-nfs-client's XDR reader (a different
// implementation from pkg/nfs3's encoder, written by other people) and the credential is
// checked field by field against RFC 5531 appendix A:
//
//	struct authsys_parms {
//	    unsigned int stamp; string machinename<255>;
//	    unsigned int uid; unsigned int gid; unsigned int gids<16>;
//	};
//
// A malformed or unexpected credential closes the connection (the client's call then fails) and is
// logged as VIOLATION; every accepted credential is logged as OK, which the integration test reads
// as its positive control.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"
	"github.com/willscott/go-nfs-client/nfs/xdr"
)

type authCheck struct {
	uid, gid uint32
	machine  string
	log      *os.File
	mu       sync.Mutex
}

func (a *authCheck) logf(format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fmt.Fprintf(a.log, format+"\n", args...)
}

// sysHandler is the null-auth handler that advertises AUTH_SYS in the MOUNT reply.
type sysHandler struct{ nfs.Handler }

func (h sysHandler) Mount(ctx context.Context, conn net.Conn, req nfs.MountRequest) (nfs.MountStatus, billy.Filesystem, []nfs.AuthFlavor) {
	st, fs, _ := h.Handler.Mount(ctx, conn, req)
	return st, fs, []nfs.AuthFlavor{nfs.AuthFlavorUnix}
}

type tapListener struct {
	net.Listener
	chk *authCheck
}

func (l tapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tapConn{Conn: c, chk: l.chk}, nil
}

type tapConn struct {
	net.Conn
	chk  *authCheck
	buf  []byte // bytes received, not yet consumed by the record parser
	frag []byte // fragments of the record being assembled
}

func (t *tapConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.buf = append(t.buf, p[:n]...)
		t.parse()
	}
	return n, err
}

func (t *tapConn) parse() {
	for len(t.buf) >= 4 {
		h := uint32(t.buf[0])<<24 | uint32(t.buf[1])<<16 | uint32(t.buf[2])<<8 | uint32(t.buf[3])
		n := int(h & 0x7fffffff)
		if len(t.buf) < 4+n {
			return
		}
		t.frag = append(t.frag, t.buf[4:4+n]...)
		t.buf = t.buf[4+n:]
		if h&0x80000000 != 0 {
			rec := t.frag
			t.frag = nil
			if err := t.chk.verify(rec); err != nil {
				t.chk.logf("VIOLATION %v", err)
				_ = t.Conn.Close()
				return
			}
		}
	}
}

func (a *authCheck) verify(rec []byte) error {
	r := bytes.NewReader(rec)
	var hdr [6]uint32 // xid, msg type, rpcvers, prog, vers, proc
	for i := 0; i < 6; i++ {
		v, err := xdr.ReadUint32(r)
		if err != nil {
			return fmt.Errorf("call header: %w", err)
		}
		hdr[i] = v
	}
	if hdr[1] != 0 { // not a CALL
		return nil
	}
	flavor, err := xdr.ReadUint32(r)
	if err != nil {
		return fmt.Errorf("credential flavor: %w", err)
	}
	body, err := xdr.ReadOpaque(r)
	if err != nil {
		return fmt.Errorf("credential body: %w", err)
	}
	if flavor != 1 {
		return fmt.Errorf("prog %d proc %d: credential flavor %d, want AUTH_SYS (1)", hdr[3], hdr[5], flavor)
	}
	if len(body) > 400 {
		return fmt.Errorf("credential body of %d bytes exceeds the 400-byte opaque_auth limit", len(body))
	}
	b := bytes.NewReader(body)
	if _, err := xdr.ReadUint32(b); err != nil { // stamp
		return fmt.Errorf("stamp: %w", err)
	}
	// xdr.Read of a string honours the 4-byte padding; the package's ReadOpaque helper does not.
	var mach string
	if err := xdr.Read(b, &mach); err != nil {
		return fmt.Errorf("machinename: %w", err)
	}
	if len(mach) > 255 {
		return fmt.Errorf("machinename of %d bytes exceeds 255", len(mach))
	}
	uid, err := xdr.ReadUint32(b)
	if err != nil {
		return fmt.Errorf("uid: %w", err)
	}
	gid, err := xdr.ReadUint32(b)
	if err != nil {
		return fmt.Errorf("gid: %w", err)
	}
	gids, err := xdr.ReadUint32List(b)
	if err != nil {
		return fmt.Errorf("gids: %w", err)
	}
	if len(gids) > 16 {
		return fmt.Errorf("%d gids, at most 16", len(gids))
	}
	if rest, _ := io.ReadAll(b); len(rest) != 0 {
		return fmt.Errorf("%d trailing bytes after the AUTH_SYS body", len(rest))
	}
	if uid != a.uid || gid != a.gid || mach != a.machine {
		return fmt.Errorf("prog %d proc %d: credential uid=%d gid=%d machine=%q, want %d/%d/%q", hdr[3], hdr[5], uid, gid, mach, a.uid, a.gid, a.machine)
	}
	a.logf("OK prog=%d proc=%d uid=%d gid=%d machine=%s gids=%d", hdr[3], hdr[5], uid, gid, mach, len(gids))
	return nil
}
