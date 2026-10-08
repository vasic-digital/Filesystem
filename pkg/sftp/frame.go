package sftp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Wire validation of the server's replies.
//
// github.com/pkg/sftp v1.13.11 parses most replies with unchecked readers (unmarshalUint32, unmarshalString, data[:l]): a
// reply that is shorter than its own length fields panics. Some of those parsers run in goroutines that pkg/sftp starts
// itself (the workers of the pipelined read), so no recover() in this package can reach them. The only boundary that covers
// every parse site is the wire: every reply frame is parsed here, completely and with bounds checks, BEFORE pkg/sftp sees
// its first byte. A frame that does not parse ends the connection and fails every call with ErrMalformedReply.
//
// This is a structural check of the SFTP version 3 reply grammar (draft-ietf-secsh-filexfer-02 section 7); it does not
// judge whether a reply is plausible, only whether pkg/sftp can safely read it.

// ErrMalformedReply is returned when the server sent a reply that does not follow the SFTP reply grammar. The connection
// is closed; the error is never retried (a hostile or broken server would answer the same way again).
var ErrMalformedReply = errors.New("sftp: malformed reply from the server")

// ErrDirTooLarge is returned when a directory listing delivers more entries than Config.MaxDirEntries.
var ErrDirTooLarge = errors.New("sftp: directory listing exceeds the entry limit")

// SFTP v3 packet types a client may receive.
const (
	fxpVersion       = 2
	fxpStatus        = 101
	fxpHandle        = 102
	fxpData          = 103
	fxpName          = 104
	fxpAttrs         = 105
	fxpExtendedReply = 201

	// maxFrame is the largest frame pkg/sftp accepts (packet.go maxMsgLength); a longer frame is malformed here too.
	maxFrame = 256 * 1024

	attrSize     = 0x00000001
	attrUIDGID   = 0x00000002
	attrPerms    = 0x00000004
	attrACModTim = 0x00000008
	attrExtended = 0x80000000
)

// wireReader is a bounds-checked cursor over one frame body.
type wireReader struct {
	b   []byte
	err string
}

func (w *wireReader) fail(what string) {
	if w.err == "" {
		w.err = what
	}
}

func (w *wireReader) u32(what string) uint32 {
	if w.err != "" {
		return 0
	}
	if len(w.b) < 4 {
		w.fail("short " + what)
		return 0
	}
	v := binary.BigEndian.Uint32(w.b)
	w.b = w.b[4:]
	return v
}

func (w *wireReader) skip(n uint64, what string) {
	if w.err != "" {
		return
	}
	if n > uint64(len(w.b)) {
		w.fail("short " + what)
		return
	}
	w.b = w.b[n:]
}

func (w *wireReader) str(what string) {
	n := w.u32(what + " length")
	w.skip(uint64(n), what)
}

func (w *wireReader) attrs() {
	flags := w.u32("attribute flags")
	if flags&attrSize != 0 {
		w.skip(8, "attribute size")
	}
	if flags&attrUIDGID != 0 {
		w.skip(8, "attribute uid/gid")
	}
	if flags&attrPerms != 0 {
		w.skip(4, "attribute permissions")
	}
	if flags&attrACModTim != 0 {
		w.skip(8, "attribute times")
	}
	if flags&attrExtended != 0 {
		n := w.u32("attribute extension count")
		if w.err == "" && uint64(n) > uint64(len(w.b))/8 {
			w.fail("attribute extension count exceeds the frame")
			return
		}
		for i := uint32(0); i < n && w.err == ""; i++ {
			w.str("attribute extension name")
			w.str("attribute extension data")
		}
	}
}

// validateFrame checks one reply frame (type byte already split from body). It returns the number of NAME entries the frame
// announces (for the listing limit). A nil error means pkg/sftp can parse the frame without reading past its end.
func validateFrame(typ byte, body []byte) (names int, err error) {
	w := &wireReader{b: body}
	switch typ {
	case fxpVersion:
		w.u32("version")
		for len(w.b) > 0 && w.err == "" {
			w.str("extension name")
			w.str("extension data")
		}
	case fxpStatus:
		w.u32("id")
		w.u32("status code")
		// message and language tag are read by pkg/sftp with the safe parsers and may be absent.
	case fxpHandle, fxpData:
		w.u32("id")
		w.str("payload")
	case fxpName:
		w.u32("id")
		n := w.u32("name count")
		// a name entry is at least filename length + longname length + attribute flags = 12 bytes
		if w.err == "" && uint64(n) > uint64(len(w.b))/12 {
			w.fail("name count exceeds the frame")
		}
		for i := uint32(0); i < n && w.err == ""; i++ {
			w.str("filename")
			w.str("longname")
			w.attrs()
		}
		names = int(n)
	case fxpAttrs:
		w.u32("id")
		w.attrs()
	case fxpExtendedReply:
		w.u32("id")
	default:
		return 0, fmt.Errorf("%w: unexpected packet type %d", ErrMalformedReply, typ)
	}
	if w.err != "" {
		return 0, fmt.Errorf("%w: packet type %d: %s", ErrMalformedReply, typ, w.err)
	}
	return names, nil
}

// frameReader sits between the ssh channel and pkg/sftp: it reads one whole frame, validates it, then hands the bytes on.
type frameReader struct {
	r       io.Reader
	buf     []byte
	pos     int
	err     error
	onNames func(n int) error // listing limit; may be nil
	onFault func(error)       // called once with the reason a frame was rejected
}

func newFrameReader(r io.Reader, onNames func(int) error, onFault func(error)) *frameReader {
	return &frameReader{r: r, onNames: onNames, onFault: onFault}
}

func (f *frameReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for f.pos >= len(f.buf) {
		if f.err != nil {
			return 0, f.err
		}
		if err := f.next(); err != nil {
			f.err = err
			return 0, err
		}
	}
	n := copy(p, f.buf[f.pos:])
	f.pos += n
	return n, nil
}

func (f *frameReader) reject(err error) error {
	if f.onFault != nil {
		f.onFault(err)
	}
	return err
}

func (f *frameReader) next() error {
	f.buf, f.pos = f.buf[:0], 0 // an error below leaves nothing readable
	var hdr [4]byte
	if _, err := io.ReadFull(f.r, hdr[:]); err != nil {
		return err // io.EOF between frames is a clean end; io.ErrUnexpectedEOF inside the header is a lost connection
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 1 || n > maxFrame {
		return f.reject(fmt.Errorf("%w: frame length %d", ErrMalformedReply, n))
	}
	need := 4 + int(n)
	b := f.buf
	if cap(b) < need {
		b = make([]byte, need)
	}
	b = b[:need]
	copy(b, hdr[:])
	if _, err := io.ReadFull(f.r, b[4:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		f.buf = b[:0]
		return err
	}
	names, err := validateFrame(b[4], b[5:])
	if err == nil && names > 0 && f.onNames != nil {
		err = f.onNames(names)
	}
	if err != nil {
		f.buf = b[:0]
		return f.reject(err)
	}
	f.buf = b
	return nil
}
