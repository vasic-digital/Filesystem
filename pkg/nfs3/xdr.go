package nfs3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrShortXDR is returned when a reply ends before a field is complete.
var ErrShortXDR = errors.New("nfs3: short or truncated XDR data")

// ErrBadXDR is returned for a structurally invalid field (bad bool, bad enum,
// oversize variable-length item). RFC 4506 sections 4.4, 4.10.
var ErrBadXDR = errors.New("nfs3: malformed XDR data")

// Limits on variable-length items. An item longer than its limit is rejected
// BEFORE any allocation, so a hostile reply cannot make the client allocate
// more than the bytes it actually received.
const (
	fhSizeMax    = 64   // NFS3_FHSIZE, RFC 1813 section 2.5
	nameMax      = 4096 // generous filename/path limit (NFS3 names are server-defined)
	authBodyMax  = 400  // RFC 5531 section 8.2: opaque_auth body is at most 400 bytes
	flavorsMax   = 64
	exportsMax   = 1 << 16
	machineMax   = 255
	gidsMax      = 16
	pathMax      = 1024 // dirpath, RFC 1813 appendix I: MNTPATHLEN
	maxXDRRepeat = 1 << 24
)

type encoder struct{ b []byte }

func (e *encoder) u32(v uint32) { e.b = binary.BigEndian.AppendUint32(e.b, v) }
func (e *encoder) u64(v uint64) { e.b = binary.BigEndian.AppendUint64(e.b, v) }
func (e *encoder) boolean(v bool) {
	if v {
		e.u32(1)
		return
	}
	e.u32(0)
}

// fixed writes n opaque bytes padded to a multiple of four (RFC 4506 4.9).
func (e *encoder) fixed(p []byte) {
	e.b = append(e.b, p...)
	for i := len(p); i%4 != 0; i++ {
		e.b = append(e.b, 0)
	}
}

// opaque writes variable-length opaque data (RFC 4506 4.10).
func (e *encoder) opaque(p []byte) {
	e.u32(uint32(len(p)))
	e.fixed(p)
}
func (e *encoder) str(s string) { e.opaque([]byte(s)) }

type decoder struct {
	b   []byte
	off int
}

func newDecoder(b []byte) *decoder { return &decoder{b: b} }

func (d *decoder) remaining() int { return len(d.b) - d.off }

func (d *decoder) u32() (uint32, error) {
	if d.remaining() < 4 {
		return 0, ErrShortXDR
	}
	v := binary.BigEndian.Uint32(d.b[d.off:])
	d.off += 4
	return v, nil
}

func (d *decoder) u64() (uint64, error) {
	if d.remaining() < 8 {
		return 0, ErrShortXDR
	}
	v := binary.BigEndian.Uint64(d.b[d.off:])
	d.off += 8
	return v, nil
}

// boolean is strict: only 0 and 1 are valid (RFC 4506 4.4).
func (d *decoder) boolean() (bool, error) {
	v, err := d.u32()
	if err != nil {
		return false, err
	}
	switch v {
	case 0:
		return false, nil
	case 1:
		return true, nil
	}
	return false, fmt.Errorf("%w: bool value %d", ErrBadXDR, v)
}

func pad4(n int) int { return (n + 3) &^ 3 }

// opaque reads variable-length opaque data of at most max bytes. The returned
// slice is a copy, so it does not pin the reply buffer.
func (d *decoder) opaque(max int) ([]byte, error) {
	n, err := d.u32()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(max) {
		return nil, fmt.Errorf("%w: opaque length %d exceeds limit %d", ErrBadXDR, n, max)
	}
	padded := pad4(int(n))
	if d.remaining() < padded {
		return nil, ErrShortXDR
	}
	out := make([]byte, n)
	copy(out, d.b[d.off:d.off+int(n)])
	d.off += padded
	return out, nil
}

func (d *decoder) str(max int) (string, error) {
	p, err := d.opaque(max)
	return string(p), err
}

func (d *decoder) skip(n int) error {
	if n < 0 || d.remaining() < n {
		return ErrShortXDR
	}
	d.off += n
	return nil
}

// nfstime3 (RFC 1813 section 2.5): seconds and nanoseconds since the epoch.
func (d *decoder) nfstime() (time.Time, error) {
	s, err := d.u32()
	if err != nil {
		return time.Time{}, err
	}
	ns, err := d.u32()
	if err != nil {
		return time.Time{}, err
	}
	// Lenient on purpose: an out-of-range nseconds (>= 1e9) is normalised by
	// time.Unix instead of failing a whole directory listing over one stamp.
	return time.Unix(int64(s), int64(ns)).UTC(), nil
}
