package nfs3

import (
	"errors"
	"fmt"
	"math"
	"os"
	"time"
)

// Procedure numbers. ONLY read procedures exist here; see doc.go.
const (
	// NFS version 3, RFC 1813 section 3.
	procNull        = 0
	procGetattr     = 1
	procLookup      = 3
	procAccess      = 4
	procRead        = 6
	procReaddirplus = 17
	procFsinfo      = 19

	// MOUNT version 3, RFC 1813 appendix I.
	procMntNull   = 0
	procMnt       = 1
	procUmnt      = 3
	procMntExport = 5

	// Port mapper version 2, RFC 1833 section 3.
	procPmapGetport = 3
)

// ipprotoTCP is IPPROTO_TCP for the portmapper (RFC 1833 section 3.1).
const ipprotoTCP = 6

// NFS status codes, RFC 1813 section 2.6.
const (
	NFS3OK             = 0
	NFS3ErrPerm        = 1
	NFS3ErrNoEnt       = 2
	NFS3ErrIO          = 5
	NFS3ErrAcces       = 13
	NFS3ErrNotDir      = 20
	NFS3ErrIsDir       = 21
	NFS3ErrInval       = 22
	NFS3ErrNameTooLong = 63
	NFS3ErrStale       = 70
	NFS3ErrBadHandle   = 10001
	NFS3ErrBadCookie   = 10003
	NFS3ErrNotSupp     = 10004
	NFS3ErrTooSmall    = 10005
	NFS3ErrServerFault = 10006
	NFS3ErrJukebox     = 10008
)

// MOUNT status codes, RFC 1813 appendix I (mountstat3).
const (
	mnt3OK        = 0
	mnt3ErrPerm   = 1
	mnt3ErrNoEnt  = 2
	mnt3ErrIO     = 5
	mnt3ErrAcces  = 13
	mnt3ErrNotDir = 20
)

// ACCESS3 bits, RFC 1813 section 3.3.4.
const (
	Access3Read    = 0x0001
	Access3Lookup  = 0x0002
	Access3Modify  = 0x0004
	Access3Extend  = 0x0008
	Access3Delete  = 0x0010
	Access3Execute = 0x0020
)

// ErrReadOnly is returned by every mutating method of the client.Client
// interface. Nothing is sent to the server.
var ErrReadOnly = errors.New("nfs3: read-only client: write procedures are not implemented")

// NFSError is a non-OK NFS3 status.
type NFSError struct {
	Op     string
	Status uint32
}

func (e *NFSError) Error() string {
	return fmt.Sprintf("nfs3: %s: %s (status %d)", e.Op, statusText(e.Status), e.Status)
}

// Is maps a few statuses onto the os package sentinels.
func (e *NFSError) Is(target error) bool {
	switch target {
	case os.ErrNotExist:
		return e.Status == NFS3ErrNoEnt
	case os.ErrPermission:
		return e.Status == NFS3ErrAcces || e.Status == NFS3ErrPerm
	}
	return false
}

func statusText(s uint32) string {
	switch s {
	case NFS3ErrPerm:
		return "NFS3ERR_PERM"
	case NFS3ErrNoEnt:
		return "NFS3ERR_NOENT"
	case NFS3ErrIO:
		return "NFS3ERR_IO"
	case NFS3ErrAcces:
		return "NFS3ERR_ACCES"
	case NFS3ErrNotDir:
		return "NFS3ERR_NOTDIR"
	case NFS3ErrIsDir:
		return "NFS3ERR_ISDIR"
	case NFS3ErrInval:
		return "NFS3ERR_INVAL"
	case NFS3ErrNameTooLong:
		return "NFS3ERR_NAMETOOLONG"
	case NFS3ErrStale:
		return "NFS3ERR_STALE"
	case NFS3ErrBadHandle:
		return "NFS3ERR_BADHANDLE"
	case NFS3ErrBadCookie:
		return "NFS3ERR_BAD_COOKIE"
	case NFS3ErrNotSupp:
		return "NFS3ERR_NOTSUPP"
	case NFS3ErrTooSmall:
		return "NFS3ERR_TOOSMALL"
	case NFS3ErrServerFault:
		return "NFS3ERR_SERVERFAULT"
	case NFS3ErrJukebox:
		return "NFS3ERR_JUKEBOX"
	}
	return "status"
}

// MountError is a non-OK MOUNT status.
type MountError struct {
	Path   string
	Status uint32
}

func (e *MountError) Error() string {
	name := "MNT3ERR"
	switch e.Status {
	case mnt3ErrPerm:
		name = "MNT3ERR_PERM"
	case mnt3ErrNoEnt:
		name = "MNT3ERR_NOENT"
	case mnt3ErrIO:
		name = "MNT3ERR_IO"
	case mnt3ErrAcces:
		name = "MNT3ERR_ACCES"
	case mnt3ErrNotDir:
		name = "MNT3ERR_NOTDIR"
	}
	return fmt.Sprintf("nfs3: mount %q refused: %s (status %d)", e.Path, name, e.Status)
}

// FileType is ftype3, RFC 1813 section 2.5.
type FileType uint32

// File types.
const (
	TypeRegular FileType = 1
	TypeDir     FileType = 2
	TypeBlock   FileType = 3
	TypeChar    FileType = 4
	TypeSymlink FileType = 5
	TypeSocket  FileType = 6
	TypeFIFO    FileType = 7
)

// Attr is fattr3 (RFC 1813 section 2.5).
type Attr struct {
	Type                 FileType
	Mode                 uint32
	Nlink, UID, GID      uint32
	Size, Used           uint64
	RdevMajor, RdevMinor uint32
	FSID, FileID         uint64
	ATime, MTime, CTime  time.Time
}

// FileMode converts the attributes to an os.FileMode.
func (a Attr) FileMode() os.FileMode {
	m := os.FileMode(a.Mode & 0o777)
	if a.Mode&0o4000 != 0 {
		m |= os.ModeSetuid
	}
	if a.Mode&0o2000 != 0 {
		m |= os.ModeSetgid
	}
	if a.Mode&0o1000 != 0 {
		m |= os.ModeSticky
	}
	switch a.Type {
	case TypeDir:
		m |= os.ModeDir
	case TypeSymlink:
		m |= os.ModeSymlink
	case TypeBlock:
		m |= os.ModeDevice
	case TypeChar:
		m |= os.ModeDevice | os.ModeCharDevice
	case TypeSocket:
		m |= os.ModeSocket
	case TypeFIFO:
		m |= os.ModeNamedPipe
	}
	return m
}

// Handle is an opaque NFS file handle (nfs_fh3, at most 64 bytes).
type Handle []byte

func (h Handle) key() string { return string(h) }

func (d *decoder) handle() (Handle, error) {
	p, err := d.opaque(fhSizeMax)
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, fmt.Errorf("%w: empty file handle", ErrBadXDR)
	}
	return Handle(p), nil
}

// fattr decodes fattr3: 21 words, RFC 1813 section 2.5.
func (d *decoder) fattr() (Attr, error) {
	var a Attr
	var err error
	t, err := d.u32()
	if err != nil {
		return a, err
	}
	if t < 1 || t > 7 {
		return a, fmt.Errorf("%w: ftype3 %d", ErrBadXDR, t)
	}
	a.Type = FileType(t)
	if a.Mode, err = d.u32(); err != nil {
		return a, err
	}
	if a.Nlink, err = d.u32(); err != nil {
		return a, err
	}
	if a.UID, err = d.u32(); err != nil {
		return a, err
	}
	if a.GID, err = d.u32(); err != nil {
		return a, err
	}
	if a.Size, err = d.u64(); err != nil {
		return a, err
	}
	// Sizes travel as int64 in client.FileInfo and in the reader; a value at or above 2^63 would
	// turn negative there and read back as an empty file without any error.
	if a.Size > math.MaxInt64 {
		return a, fmt.Errorf("%w: file size %d exceeds the signed 64-bit range", ErrBadXDR, a.Size)
	}
	if a.Used, err = d.u64(); err != nil {
		return a, err
	}
	if a.RdevMajor, err = d.u32(); err != nil {
		return a, err
	}
	if a.RdevMinor, err = d.u32(); err != nil {
		return a, err
	}
	if a.FSID, err = d.u64(); err != nil {
		return a, err
	}
	if a.FileID, err = d.u64(); err != nil {
		return a, err
	}
	if a.ATime, err = d.nfstime(); err != nil {
		return a, err
	}
	if a.MTime, err = d.nfstime(); err != nil {
		return a, err
	}
	if a.CTime, err = d.nfstime(); err != nil {
		return a, err
	}
	return a, nil
}

// postOpAttr decodes post_op_attr: a bool, then fattr3 when true.
func (d *decoder) postOpAttr() (*Attr, error) {
	ok, err := d.boolean()
	if err != nil || !ok {
		return nil, err
	}
	a, err := d.fattr()
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (e *encoder) fattr(a Attr) {
	e.u32(uint32(a.Type))
	e.u32(a.Mode)
	e.u32(a.Nlink)
	e.u32(a.UID)
	e.u32(a.GID)
	e.u64(a.Size)
	e.u64(a.Used)
	e.u32(a.RdevMajor)
	e.u32(a.RdevMinor)
	e.u64(a.FSID)
	e.u64(a.FileID)
	for _, t := range []time.Time{a.ATime, a.MTime, a.CTime} {
		e.u32(uint32(t.Unix()))
		e.u32(uint32(t.Nanosecond()))
	}
}

// status reads the leading nfsstat3 and converts a non-OK value into an error.
func (d *decoder) status(op string) error {
	s, err := d.u32()
	if err != nil {
		return err
	}
	if s != NFS3OK {
		return &NFSError{Op: op, Status: s}
	}
	return nil
}

// ---- portmapper (RFC 1833) ----

func encodeGetport(prog, vers uint32) []byte {
	var e encoder
	e.u32(prog)
	e.u32(vers)
	e.u32(ipprotoTCP)
	e.u32(0) // port: ignored in a GETPORT call
	return e.b
}

func decodeGetport(b []byte) (uint16, error) {
	d := newDecoder(b)
	p, err := d.u32()
	if err != nil {
		return 0, err
	}
	if p > 65535 {
		return 0, fmt.Errorf("%w: port %d out of range", ErrBadXDR, p)
	}
	return uint16(p), nil
}

// ---- MOUNT v3 ----

func encodeDirpath(p string) []byte {
	var e encoder
	e.str(p)
	return e.b
}

// decodeMnt decodes mountres3. A non-OK status is returned as a *MountError.
func decodeMnt(path string, b []byte) (Handle, []uint32, error) {
	d := newDecoder(b)
	st, err := d.u32()
	if err != nil {
		return nil, nil, err
	}
	if st != mnt3OK {
		return nil, nil, &MountError{Path: path, Status: st}
	}
	fh, err := d.handle()
	if err != nil {
		return nil, nil, err
	}
	n, err := d.u32()
	if err != nil {
		return nil, nil, err
	}
	if n > flavorsMax {
		return nil, nil, fmt.Errorf("%w: %d auth flavors", ErrBadXDR, n)
	}
	fl := make([]uint32, 0, n)
	for i := uint32(0); i < n; i++ {
		f, err := d.u32()
		if err != nil {
			return nil, nil, err
		}
		fl = append(fl, f)
	}
	return fh, fl, nil
}

// Export is one entry of the MOUNT EXPORT list (exportnode, RFC 1813 appendix I).
type Export struct {
	Path   string
	Groups []string
}

func decodeExports(b []byte) ([]Export, error) {
	d := newDecoder(b)
	var out []Export
	for {
		more, err := d.boolean()
		if err != nil {
			return nil, err
		}
		if !more {
			return out, nil
		}
		if len(out) >= exportsMax {
			return nil, fmt.Errorf("%w: more than %d exports", ErrBadXDR, exportsMax)
		}
		p, err := d.str(pathMax)
		if err != nil {
			return nil, err
		}
		ex := Export{Path: p}
		for {
			g, err := d.boolean()
			if err != nil {
				return nil, err
			}
			if !g {
				break
			}
			if len(ex.Groups) >= exportsMax {
				return nil, fmt.Errorf("%w: too many groups", ErrBadXDR)
			}
			name, err := d.str(nameMax)
			if err != nil {
				return nil, err
			}
			ex.Groups = append(ex.Groups, name)
		}
		out = append(out, ex)
	}
}

// ---- NFS v3 ----

func encodeFH(h Handle) []byte {
	var e encoder
	e.opaque(h)
	return e.b
}

func decodeGetattr(b []byte) (Attr, error) {
	d := newDecoder(b)
	if err := d.status("GETATTR"); err != nil {
		return Attr{}, err
	}
	return d.fattr()
}

func encodeLookup(dir Handle, name string) []byte {
	var e encoder
	e.opaque(dir)
	e.str(name)
	return e.b
}

// decodeLookup: object handle and, when the server supplied it, its attributes.
func decodeLookup(b []byte) (Handle, *Attr, error) {
	d := newDecoder(b)
	if err := d.status("LOOKUP"); err != nil {
		return nil, nil, err
	}
	fh, err := d.handle()
	if err != nil {
		return nil, nil, err
	}
	a, err := d.postOpAttr()
	if err != nil {
		return nil, nil, err
	}
	return fh, a, nil
}

func encodeAccess(h Handle, mask uint32) []byte {
	var e encoder
	e.opaque(h)
	e.u32(mask)
	return e.b
}

func decodeAccess(b []byte) (uint32, error) {
	d := newDecoder(b)
	if err := d.status("ACCESS"); err != nil {
		return 0, err
	}
	if _, err := d.postOpAttr(); err != nil {
		return 0, err
	}
	return d.u32()
}

func encodeRead(h Handle, off uint64, count uint32) []byte {
	var e encoder
	e.opaque(h)
	e.u64(off)
	e.u32(count)
	return e.b
}

// decodeRead returns the data and eof flag. The announced count must equal the
// data length and must not exceed what was asked for (RFC 1813 section 3.3.6).
func decodeRead(b []byte, asked uint32) ([]byte, bool, error) {
	d := newDecoder(b)
	if err := d.status("READ"); err != nil {
		return nil, false, err
	}
	if _, err := d.postOpAttr(); err != nil {
		return nil, false, err
	}
	cnt, err := d.u32()
	if err != nil {
		return nil, false, err
	}
	eof, err := d.boolean()
	if err != nil {
		return nil, false, err
	}
	if cnt > asked {
		return nil, false, fmt.Errorf("%w: server returned %d bytes for a %d-byte READ", ErrBadXDR, cnt, asked)
	}
	data, err := d.opaque(int(asked))
	if err != nil {
		return nil, false, err
	}
	if uint32(len(data)) != cnt {
		return nil, false, fmt.Errorf("%w: READ count %d does not match data length %d", ErrBadXDR, cnt, len(data))
	}
	return data, eof, nil
}

func encodeReaddirplus(dir Handle, cookie uint64, verf [8]byte, dircount, maxcount uint32) []byte {
	var e encoder
	e.opaque(dir)
	e.u64(cookie)
	e.fixed(verf[:])
	e.u32(dircount)
	e.u32(maxcount)
	return e.b
}

// DirEntry is one entryplus3 (RFC 1813 section 3.3.17).
type DirEntry struct {
	FileID uint64
	Name   string
	Cookie uint64
	Attr   *Attr  // nil when the server did not return attributes for the name
	Handle Handle // nil when the server did not return a handle
}

type dirPage struct {
	Verf    [8]byte
	Entries []DirEntry
	EOF     bool
}

func decodeReaddirplus(b []byte) (dirPage, error) {
	var pg dirPage
	d := newDecoder(b)
	if err := d.status("READDIRPLUS"); err != nil {
		return pg, err
	}
	if _, err := d.postOpAttr(); err != nil {
		return pg, err
	}
	if d.remaining() < 8 {
		return pg, ErrShortXDR
	}
	copy(pg.Verf[:], d.b[d.off:d.off+8])
	d.off += 8
	for {
		more, err := d.boolean()
		if err != nil {
			return pg, err
		}
		if !more {
			break
		}
		// Each entry takes at least 8+4+8+4+4 = 28 bytes, so the reply size bounds the count.
		var en DirEntry
		if en.FileID, err = d.u64(); err != nil {
			return pg, err
		}
		if en.Name, err = d.str(nameMax); err != nil {
			return pg, err
		}
		if en.Cookie, err = d.u64(); err != nil {
			return pg, err
		}
		if en.Attr, err = d.postOpAttr(); err != nil {
			return pg, err
		}
		hasFH, err := d.boolean()
		if err != nil {
			return pg, err
		}
		if hasFH {
			if en.Handle, err = d.handle(); err != nil {
				return pg, err
			}
		}
		pg.Entries = append(pg.Entries, en)
	}
	eof, err := d.boolean()
	if err != nil {
		return pg, err
	}
	pg.EOF = eof
	return pg, nil
}

// FSInfo is FSINFO3resok (RFC 1813 section 3.3.19).
type FSInfo struct {
	RTMax, RTPref, RTMult uint32
	WTMax, WTPref, WTMult uint32
	DTPref                uint32
	MaxFileSize           uint64
	Properties            uint32
}

func decodeFsinfo(b []byte) (FSInfo, error) {
	var f FSInfo
	d := newDecoder(b)
	if err := d.status("FSINFO"); err != nil {
		return f, err
	}
	if _, err := d.postOpAttr(); err != nil {
		return f, err
	}
	var err error
	for _, p := range []*uint32{&f.RTMax, &f.RTPref, &f.RTMult, &f.WTMax, &f.WTPref, &f.WTMult, &f.DTPref} {
		if *p, err = d.u32(); err != nil {
			return f, err
		}
	}
	if f.MaxFileSize, err = d.u64(); err != nil {
		return f, err
	}
	if err = d.skip(8); err != nil { // time_delta
		return f, err
	}
	if f.Properties, err = d.u32(); err != nil {
		return f, err
	}
	return f, nil
}
