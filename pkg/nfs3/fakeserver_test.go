package nfs3

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeServer is an in-process NFSv3 + MOUNT v3 + portmapper v2 server used by
// the unit tests. It is a TEST fixture; the real-server leg is the go-nfs
// container fixture (integration_test.go).
type fnode struct {
	id     uint64
	typ    FileType
	name   string
	data   []byte
	kids   []*fnode
	mode   uint32
	mtime  time.Time
	target string
}

type fakeServer struct {
	t *testing.T

	pmLn, mntLn, nfsLn net.Listener
	root               *fnode
	byID               map[uint64]*fnode
	exports            []string
	nextID             uint64

	mu   sync.Mutex
	gen  uint32 // directory generation: becomes the cookie verifier
	opts fakeOpts

	procs                 [32]atomic.Int64 // NFS procedure counters
	mntProcs              [8]atomic.Int64
	conns                 atomic.Int64
	inflight, maxInflight atomic.Int64
	lastFlavor            atomic.Uint32
	maxReadCount          atomic.Int64
	xidMu                 sync.Mutex
	xidLog                []uint32 // xids of the NFS-port calls, in arrival order
	readLog               []uint32 // the count of every READ, in arrival order (guarded by xidMu)
	wg                    sync.WaitGroup
}

type fakeOpts struct {
	PortOK        func(remotePort int) bool // nil = accept all
	MaxRead       int                       // clamp bytes returned per READ (short reads)
	PageEntries   int                       // max entries per READDIRPLUS page (0 = fill dircount)
	OmitAttrs     bool                      // entryplus3 without name_attributes
	OmitHandles   bool                      // entryplus3 without handle
	DropEveryN    int                       // close the nfs connection before answering every Nth call
	Jukebox       int                       // answer the next N NFS calls with NFS3ERR_JUKEBOX
	BadCookieOnce bool                      // answer first resumed READDIRPLUS with BAD_COOKIE and bump the verifier
	StaleOnce     bool                      // answer the first LOOKUP of a cached parent with STALE
	Shuffle       bool                      // answer pipelined calls out of order
	Delay         time.Duration             // per-call delay
	NoReply       bool                      // never answer NFS calls
	Corrupt       func(proc uint32, reply []byte) []byte
	AuthFlavors   []uint32
	WrongXID      bool // reply with xid+1 first, then the right one
	FSInfoRTPref  uint32
	FSInfoRTMax   uint32 // 0 = 1 MiB
	ShortAtRead   int    // the Nth READ (1-based, counted from server start) is answered with half of its data
	RPCDeny       int    // 0 none, 1 AUTH_ERROR on NFS calls, 2 RPC_MISMATCH
	MountStatus   uint32
	NFSNotListed  bool // portmapper returns 0 for NFS
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	s := &fakeServer{t: t, byID: map[uint64]*fnode{}, exports: []string{"/export"}, nextID: 100, gen: 1}
	s.opts.FSInfoRTPref = 32768
	s.root = s.mk(nil, "", TypeDir, nil)
	docs := s.mk(s.root, "docs", TypeDir, nil)
	s.mk(docs, "a.txt", TypeRegular, []byte("alpha\n"))
	s.mk(docs, "b.txt", TypeRegular, []byte("bravo bravo\n"))
	s.mk(s.root, "empty.txt", TypeRegular, nil)
	s.mk(s.root, "ünï.txt", TypeRegular, []byte("unicode name"))
	big := make([]byte, 3<<20+13)
	for i := range big {
		big[i] = byte(i*7 + i>>8)
	}
	s.mk(s.root, "big.bin", TypeRegular, big)
	ln := s.mk(s.root, "link", TypeSymlink, nil)
	ln.target = "docs/a.txt"
	many := s.mk(s.root, "many", TypeDir, nil)
	for i := 0; i < 250; i++ {
		s.mk(many, fmt.Sprintf("f%04d", i), TypeRegular, []byte(fmt.Sprintf("file %d", i)))
	}
	d := s.root
	for _, n := range []string{"deep", "a", "b", "c"} {
		d = s.mk(d, n, TypeDir, nil)
	}
	s.mk(d, "leaf.txt", TypeRegular, []byte("leaf"))
	s.start()
	t.Cleanup(s.close)
	return s
}

func (s *fakeServer) mk(parent *fnode, name string, typ FileType, data []byte) *fnode {
	s.nextID++
	n := &fnode{id: s.nextID, typ: typ, name: name, data: data, mode: 0o644, mtime: time.Unix(1700000000+int64(s.nextID), 123456789).UTC()}
	if typ == TypeDir {
		n.mode = 0o755
	}
	s.byID[n.id] = n
	if parent != nil {
		parent.kids = append(parent.kids, n)
	}
	return n
}

func (s *fakeServer) set(f func(o *fakeOpts)) {
	s.mu.Lock()
	f(&s.opts)
	s.mu.Unlock()
}
func (s *fakeServer) o() fakeOpts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts
}

func (s *fakeServer) start() {
	var err error
	if s.pmLn, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		s.t.Fatal(err)
	}
	if s.mntLn, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		s.t.Fatal(err)
	}
	if s.nfsLn, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		s.t.Fatal(err)
	}
	for _, x := range []struct {
		ln   net.Listener
		kind int
	}{{s.pmLn, 0}, {s.mntLn, 1}, {s.nfsLn, 2}} {
		x := x
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				c, err := x.ln.Accept()
				if err != nil {
					return
				}
				s.conns.Add(1)
				go s.serve(c, x.kind)
			}
		}()
	}
}

func (s *fakeServer) close() {
	s.pmLn.Close()
	s.mntLn.Close()
	s.nfsLn.Close()
}

func port(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }

func (s *fakeServer) cfg() Config {
	return Config{Host: "127.0.0.1", Export: "/export", PortmapPort: port(s.pmLn), CallTimeout: 2 * time.Second, RetryBackoff: time.Millisecond, JukeboxBackoff: time.Millisecond, DialTimeout: 2 * time.Second}
}

func (s *fakeServer) writeRec(c net.Conn, wmu *sync.Mutex, b []byte) {
	h := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(h, 0x80000000|uint32(len(b)))
	wmu.Lock()
	_, _ = c.Write(append(h, b...))
	wmu.Unlock()
}

func (s *fakeServer) serve(c net.Conn, kind int) {
	defer c.Close()
	br := bufio.NewReader(c)
	var wmu sync.Mutex
	var calls int
	rport := c.RemoteAddr().(*net.TCPAddr).Port
	for {
		rec, err := readRecord(br, 8<<20)
		if err != nil {
			return
		}
		calls++
		d := newDecoder(rec)
		xid, _ := d.u32()
		_, _ = d.u32() // type
		rv, _ := d.u32()
		prog, _ := d.u32()
		vers, _ := d.u32()
		proc, _ := d.u32()
		cflav, _ := d.u32() // cred flavor
		if kind == 2 {
			s.lastFlavor.Store(cflav)
			s.xidMu.Lock()
			s.xidLog = append(s.xidLog, xid)
			s.xidMu.Unlock()
		}
		_, _ = d.opaque(1 << 12)
		_, _ = d.u32() // verf flavor
		_, _ = d.opaque(1 << 12)
		args := rec[d.off:]
		o := s.o()
		if kind == 2 && o.NoReply {
			continue
		}
		if kind == 2 && o.DropEveryN > 0 && calls%o.DropEveryN == 0 {
			return
		}
		if kind == 2 && o.Delay > 0 {
			time.Sleep(o.Delay)
		}
		handle := func() {
			var once sync.Once
			release := func() {}
			if kind == 2 && proc == procRead {
				cur := s.inflight.Add(1)
				release = func() { once.Do(func() { s.inflight.Add(-1) }) }
				defer release()
				for {
					m := s.maxInflight.Load()
					if cur <= m || s.maxInflight.CompareAndSwap(m, cur) {
						break
					}
				}
			}
			w := func(b []byte) {
				release() // the request counts as in flight until its reply is written
				s.writeRec(c, &wmu, b)
			}
			var res []byte
			var perr uint32 = 99 // 99 = success marker
			switch {
			case rv != 2:
				s.denyMismatch(c, &wmu, xid)
				return
			case kind == 2 && o.RPCDeny == 1:
				e := encoder{}
				e.u32(xid)
				e.u32(rpcReply)
				e.u32(msgDenied)
				e.u32(rejectAuthError)
				e.u32(1) // AUTH_BADCRED
				w(e.b)
				return
			case kind == 2 && o.RPCDeny == 2:
				s.denyMismatch(c, &wmu, xid)
				return
			case kind == 0:
				res, perr = s.portmap(prog, vers, proc, args)
			case kind == 1:
				res, perr = s.mount(prog, vers, proc, args, rport, o)
			default:
				res, perr = s.nfs(prog, vers, proc, args, rport, o)
			}
			if perr != 99 {
				e := encoder{}
				e.u32(xid)
				e.u32(rpcReply)
				e.u32(msgAccepted)
				e.u32(0)
				e.u32(0)
				e.u32(perr)
				if perr == acceptProgMismatch {
					e.u32(3)
					e.u32(3)
				}
				w(e.b)
				return
			}
			if o.Corrupt != nil && kind == 2 {
				res = o.Corrupt(proc, res)
			}
			e := encoder{}
			if o.WrongXID && kind == 2 {
				e.u32(xid + 1000)
				e.u32(rpcReply)
				e.u32(msgAccepted)
				e.u32(0)
				e.u32(0)
				e.u32(acceptSuccess)
				e.b = append(e.b, res...)
				w(e.b)
				e = encoder{}
			}
			e.u32(xid)
			e.u32(rpcReply)
			e.u32(msgAccepted)
			e.u32(0)
			e.u32(0)
			e.u32(acceptSuccess)
			e.b = append(e.b, res...)
			if o.Shuffle && kind == 2 {
				time.Sleep(time.Duration(rand.Intn(6)) * time.Millisecond)
			}
			w(e.b)
		}
		if o.Shuffle {
			go handle()
		} else {
			handle()
		}
	}
}

func (s *fakeServer) denyMismatch(c net.Conn, wmu *sync.Mutex, xid uint32) {
	e := encoder{}
	e.u32(xid)
	e.u32(rpcReply)
	e.u32(msgDenied)
	e.u32(rejectRPCMismatch)
	e.u32(2)
	e.u32(2)
	s.writeRec(c, wmu, e.b)
}

func (s *fakeServer) portmap(prog, vers, proc uint32, args []byte) ([]byte, uint32) {
	if prog != progPortmap {
		return nil, acceptProgUnavail
	}
	if proc == 0 {
		return nil, 99
	}
	if proc != procPmapGetport {
		return nil, acceptProcUnavail
	}
	d := newDecoder(args)
	p, _ := d.u32()
	v, _ := d.u32()
	e := encoder{}
	switch {
	case p == progMount && v == 3:
		e.u32(uint32(port(s.mntLn)))
	case p == progNFS && v == 3 && !s.o().NFSNotListed:
		e.u32(uint32(port(s.nfsLn)))
	default:
		e.u32(0)
	}
	return e.b, 99
}

func (s *fakeServer) mount(prog, vers, proc uint32, args []byte, rport int, o fakeOpts) ([]byte, uint32) {
	if prog != progMount {
		return nil, acceptProgUnavail
	}
	if vers != 3 {
		return nil, acceptProgMismatch
	}
	if proc < 8 {
		s.mntProcs[proc].Add(1)
	}
	e := encoder{}
	switch proc {
	case procMntNull:
		return nil, 99
	case procMnt:
		d := newDecoder(args)
		p, _ := d.str(1024)
		if o.PortOK != nil && !o.PortOK(rport) {
			e.u32(mnt3ErrAcces)
			return e.b, 99
		}
		if o.MountStatus != 0 {
			e.u32(o.MountStatus)
			return e.b, 99
		}
		ok := false
		for _, x := range s.exports {
			ok = ok || x == p
		}
		if !ok {
			e.u32(mnt3ErrNoEnt)
			return e.b, 99
		}
		e.u32(0)
		e.opaque(s.fh(s.root))
		fl := o.AuthFlavors
		if fl == nil {
			fl = []uint32{authSys}
		}
		e.u32(uint32(len(fl)))
		for _, f := range fl {
			e.u32(f)
		}
		return e.b, 99
	case procUmnt:
		return nil, 99
	case procMntExport:
		for _, x := range s.exports {
			e.boolean(true)
			e.str(x)
			e.boolean(true)
			e.str("10.0.0.0/8")
			e.boolean(false)
		}
		e.boolean(false)
		return e.b, 99
	}
	return nil, acceptProcUnavail
}

func (s *fakeServer) fh(n *fnode) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b, n.id)
	copy(b[8:], "FH01")
	return b
}

func (s *fakeServer) node(fh []byte) *fnode {
	if len(fh) != 12 {
		return nil
	}
	return s.byID[binary.BigEndian.Uint64(fh)]
}

func (s *fakeServer) attr(e *encoder, n *fnode) {
	size := uint64(len(n.data))
	if n.typ == TypeDir {
		size = 4096
	}
	if n.typ == TypeSymlink {
		size = uint64(len(n.target))
	}
	e.fattr(Attr{Type: n.typ, Mode: n.mode, Nlink: 1, UID: 1000, GID: 1000, Size: size, Used: size, FSID: 7, FileID: n.id, ATime: n.mtime, MTime: n.mtime, CTime: n.mtime})
}

func (s *fakeServer) postOp(e *encoder, n *fnode) {
	if n == nil {
		e.boolean(false)
		return
	}
	e.boolean(true)
	s.attr(e, n)
}

func (s *fakeServer) nfs(prog, vers, proc uint32, args []byte, rport int, o fakeOpts) ([]byte, uint32) {
	if prog != progNFS {
		return nil, acceptProgUnavail
	}
	if vers != 3 {
		return nil, acceptProgMismatch
	}
	if proc < 32 {
		s.procs[proc].Add(1)
	}
	e := encoder{}
	if o.PortOK != nil && !o.PortOK(rport) && proc != procNull {
		// Linux knfsd answers a request from an insecure source port with nfserr_perm
		// (fs/nfsd/nfsfh.c nfsd_setuser_and_check_port), not with NFS3ERR_ACCES.
		e.u32(NFS3ErrPerm)
		e.boolean(false)
		return e.b, 99
	}
	s.mu.Lock()
	if s.opts.Jukebox > 0 && proc != procNull {
		s.opts.Jukebox--
		s.mu.Unlock()
		e.u32(NFS3ErrJukebox)
		return e.b, 99
	}
	s.mu.Unlock()
	d := newDecoder(args)
	switch proc {
	case procNull:
		return nil, 99
	case procGetattr:
		fh, _ := d.opaque(64)
		n := s.node(fh)
		if n == nil {
			e.u32(NFS3ErrStale)
			return e.b, 99
		}
		e.u32(0)
		s.attr(&e, n)
	case procLookup:
		fh, _ := d.opaque(64)
		name, _ := d.str(1024)
		dir := s.node(fh)
		if dir == nil {
			e.u32(NFS3ErrStale)
			e.boolean(false)
			return e.b, 99
		}
		if dir.typ != TypeDir {
			e.u32(NFS3ErrNotDir)
			e.boolean(false)
			return e.b, 99
		}
		s.mu.Lock()
		if s.opts.StaleOnce && dir != s.root {
			s.opts.StaleOnce = false
			s.mu.Unlock()
			e.u32(NFS3ErrStale)
			e.boolean(false)
			return e.b, 99
		}
		s.mu.Unlock()
		for _, k := range dir.kids {
			if k.name == name {
				e.u32(0)
				e.opaque(s.fh(k))
				if o.OmitAttrs {
					e.boolean(false)
				} else {
					s.postOp(&e, k)
				}
				s.postOp(&e, dir)
				return e.b, 99
			}
		}
		e.u32(NFS3ErrNoEnt)
		s.postOp(&e, dir)
	case procAccess:
		fh, _ := d.opaque(64)
		mask, _ := d.u32()
		n := s.node(fh)
		if n == nil {
			e.u32(NFS3ErrStale)
			e.boolean(false)
			return e.b, 99
		}
		e.u32(0)
		s.postOp(&e, n)
		e.u32(mask & (Access3Read | Access3Lookup | Access3Execute)) // read-only export: no modify/extend/delete
	case procRead:
		fh, _ := d.opaque(64)
		off, _ := d.u64()
		cnt, _ := d.u32()
		s.xidMu.Lock()
		s.readLog = append(s.readLog, cnt)
		s.xidMu.Unlock()
		for {
			m := s.maxReadCount.Load()
			if int64(cnt) <= m || s.maxReadCount.CompareAndSwap(m, int64(cnt)) {
				break
			}
		}
		n := s.node(fh)
		if n == nil {
			e.u32(NFS3ErrStale)
			e.boolean(false)
			return e.b, 99
		}
		if n.typ == TypeDir {
			e.u32(NFS3ErrIsDir)
			e.boolean(false)
			return e.b, 99
		}
		var data []byte
		if off < uint64(len(n.data)) {
			data = n.data[off:]
		}
		if uint32(len(data)) > cnt {
			data = data[:cnt]
		}
		if o.MaxRead > 0 && len(data) > o.MaxRead {
			data = data[:o.MaxRead]
		}
		s.xidMu.Lock()
		ordinal := len(s.readLog)
		s.xidMu.Unlock()
		if o.ShortAtRead > 0 && ordinal == o.ShortAtRead && len(data) > 1 {
			data = data[:len(data)/2]
		}
		eof := off+uint64(len(data)) >= uint64(len(n.data))
		e.u32(0)
		s.postOp(&e, n)
		e.u32(uint32(len(data)))
		e.boolean(eof)
		e.opaque(data)
	case procReaddirplus:
		fh, _ := d.opaque(64)
		cookie, _ := d.u64()
		var verf [8]byte
		copy(verf[:], d.b[d.off:d.off+8])
		d.off += 8
		dircount, _ := d.u32()
		_, _ = d.u32()
		dir := s.node(fh)
		if dir == nil {
			e.u32(NFS3ErrStale)
			e.boolean(false)
			return e.b, 99
		}
		s.mu.Lock()
		gen := s.gen
		if s.opts.BadCookieOnce && cookie != 0 {
			s.opts.BadCookieOnce = false
			s.gen++
			s.mu.Unlock()
			e.u32(NFS3ErrBadCookie)
			e.boolean(false)
			return e.b, 99
		}
		s.mu.Unlock()
		if cookie != 0 && binary.BigEndian.Uint64(verf[:]) != uint64(gen) {
			e.u32(NFS3ErrBadCookie)
			e.boolean(false)
			return e.b, 99
		}
		kids := append([]*fnode{}, dir.kids...)
		sort.Slice(kids, func(i, j int) bool { return kids[i].id < kids[j].id })
		type ent struct {
			n      *fnode
			cookie uint64
			name   string
		}
		all := []ent{{dir, 1, "."}, {dir, 2, ".."}}
		for i, k := range kids {
			all = append(all, ent{k, uint64(i + 3), k.name})
		}
		e.u32(0)
		s.postOp(&e, dir)
		var vb [8]byte
		binary.BigEndian.PutUint64(vb[:], uint64(gen))
		e.fixed(vb[:])
		sent, budget := 0, int(dircount)
		eof := true
		for _, en := range all {
			if en.cookie <= cookie {
				continue
			}
			if o.PageEntries > 0 && sent >= o.PageEntries || budget < 120 {
				eof = false
				break
			}
			e.boolean(true)
			e.u64(en.n.id)
			e.str(en.name)
			e.u64(en.cookie)
			if o.OmitAttrs {
				e.boolean(false)
			} else {
				s.postOp(&e, en.n)
			}
			if o.OmitHandles {
				e.boolean(false)
			} else {
				e.boolean(true)
				e.opaque(s.fh(en.n))
			}
			sent++
			budget -= 100
		}
		e.boolean(false)
		e.boolean(eof)
	case procFsinfo:
		fh, _ := d.opaque(64)
		n := s.node(fh)
		if n == nil {
			e.u32(NFS3ErrStale)
			e.boolean(false)
			return e.b, 99
		}
		e.u32(0)
		s.postOp(&e, n)
		rtmax := uint32(1 << 20)
		if o.FSInfoRTMax > 0 {
			rtmax = o.FSInfoRTMax
		}
		for _, v := range []uint32{rtmax, o.FSInfoRTPref, 4096, 1 << 20, 32768, 4096, 8192} {
			e.u32(v)
		}
		e.u64(1 << 40)
		e.u32(0)
		e.u32(1)
		e.u32(0x1b)
	default:
		return nil, acceptProcUnavail
	}
	return e.b, 99
}

// writeProcCalls sums the counters of every procedure that would mutate state.
func (s *fakeServer) writeProcCalls() int64 {
	var n int64
	for _, p := range []int{2, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 21} { // SETATTR READLINK(not a write) .. COMMIT
		if p == 5 {
			continue
		}
		n += s.procs[p].Load()
	}
	return n
}

var _ = io.EOF
var _ = strings.TrimSpace
