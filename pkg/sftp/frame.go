package sftp

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
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

// ErrDirTooLarge is returned when ONE directory listing delivers more entries than Config.MaxDirEntries. Only that listing fails.
var ErrDirTooLarge = errors.New("sftp: directory listing exceeds the entry limit")

// SFTP v3 packet types a client may receive.
const (
	fxpVersion       = 2
	fxpStatus        = 101
	fxpHandle        = 102
	fxpData          = 103
	fxpClose         = 4
	fxpReaddir       = 12
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
	tr      *wireTracker // per-listing entry accounting; may be nil
	onFault func(error)  // called once with the reason a frame was rejected
}

func newFrameReader(r io.Reader, tr *wireTracker, onFault func(error)) *frameReader {
	return &frameReader{r: r, tr: tr, onFault: onFault}
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
	if err != nil {
		f.buf = b[:0]
		return f.reject(err)
	}
	if f.tr != nil && (b[4] == fxpName || b[4] == fxpStatus) {
		id := binary.BigEndian.Uint32(b[5:9]) // validated: both frame types start with the request id
		if b[4] == fxpStatus {
			f.tr.replied(id)
		} else if f.tr.name(id, names) {
			b = f.tr.limitStatus(id) // the listing is over its budget: this reply becomes a failure of THAT listing only
		}
	}
	f.buf = b
	return nil
}

// ---------------------------------------------------------------------------------------------------------
// per-listing entry accounting

// wireTracker counts the entries each directory listing receives. pkg/sftp issues one READDIR per page with a fresh request id and
// the id comes back on the NAME reply, so the tracker watches the OUTGOING frames (trackedWriter) to learn which handle an id belongs
// to and the incoming NAME frames (frameReader) to count against that handle. A listing is one handle: the budget starts at zero when
// the handle is opened and ends with its CLOSE, so overlapping listings never share a budget and a REALPATH reply (also a NAME frame)
// is never counted. A listing over the budget gets a STATUS failure instead of the NAME frame; the connection stays up.
type wireTracker struct {
	max    int    // 0 = unlimited
	marker string // the message of the synthetic failure; random per connection so that a server cannot forge it

	mu      sync.Mutex
	readdir map[uint32]string // READDIR request id -> handle, until the reply
	count   map[string]int    // handle -> entries delivered
	over    map[string]bool

	// outgoing stream parser (frames are written as header then payload, possibly in several Writes)
	cur  []byte // bytes of the frame being collected
	skip int    // bytes of an uninteresting frame still to skip
}

func newWireTracker(max int) *wireTracker {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	return &wireTracker{
		max:     max,
		marker:  "sftp-client: listing exceeds the entry limit [" + hex.EncodeToString(nonce[:]) + "]",
		readdir: map[uint32]string{},
		count:   map[string]int{},
		over:    map[string]bool{},
	}
}

// outFrameCap bounds what is collected of one outgoing frame: READDIR and CLOSE carry a handle the server chose in a frame of at most
// maxFrame bytes.
const outFrameCap = maxFrame + 64

// observe parses the stream of frames this client sends.
func (t *wireTracker) observe(p []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(p) > 0 {
		if t.skip > 0 {
			n := t.skip
			if n > len(p) {
				n = len(p)
			}
			t.skip -= n
			p = p[n:]
			continue
		}
		// collect the length and the type byte first
		if len(t.cur) < 5 {
			n := 5 - len(t.cur)
			if n > len(p) {
				n = len(p)
			}
			t.cur = append(t.cur, p[:n]...)
			p = p[n:]
			if len(t.cur) < 5 {
				continue
			}
			flen := int(binary.BigEndian.Uint32(t.cur))
			typ := t.cur[4]
			if flen < 1 || flen > outFrameCap || (typ != fxpReaddir && typ != fxpClose) {
				t.skip = flen - 1 // not interesting (or implausible: nothing to track)
				if t.skip < 0 {
					t.skip = 0
				}
				t.cur = t.cur[:0]
				continue
			}
		}
		need := 4 + int(binary.BigEndian.Uint32(t.cur)) - len(t.cur)
		n := need
		if n > len(p) {
			n = len(p)
		}
		t.cur = append(t.cur, p[:n]...)
		p = p[n:]
		if n == need {
			t.frame(t.cur[4], t.cur[5:])
			t.cur = t.cur[:0]
		}
	}
}

// frame handles one complete READDIR or CLOSE request body (after the type byte): id, handle string.
func (t *wireTracker) frame(typ byte, body []byte) {
	if len(body) < 8 {
		return
	}
	id := binary.BigEndian.Uint32(body)
	hl := binary.BigEndian.Uint32(body[4:])
	if uint64(hl) > uint64(len(body)-8) {
		return
	}
	h := string(body[8 : 8+hl])
	switch typ {
	case fxpReaddir:
		t.readdir[id] = h
	case fxpClose:
		delete(t.count, h)
		delete(t.over, h)
	}
}

// replied forgets the request id of a STATUS reply (a READDIR ends with EOF or an error STATUS).
func (t *wireTracker) replied(id uint32) {
	t.mu.Lock()
	delete(t.readdir, id)
	t.mu.Unlock()
}

// name counts n entries of the NAME reply to request id against the handle of that READDIR and reports whether the listing is
// over its budget (the reply must then be replaced). A NAME reply of any other request is not a listing page and is not counted.
func (t *wireTracker) name(id uint32, n int) (over bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h, ok := t.readdir[id]
	if !ok {
		return false
	}
	delete(t.readdir, id)
	if t.max <= 0 {
		return false
	}
	if t.over[h] {
		return true
	}
	t.count[h] += n
	if t.count[h] > t.max {
		t.over[h] = true
		return true
	}
	return false
}

// limitStatus builds the frame that replaces an over-budget NAME reply: STATUS SSH_FX_FAILURE (4) carrying the marker.
func (t *wireTracker) limitStatus(id uint32) []byte {
	body := []byte{fxpStatus}
	body = binary.BigEndian.AppendUint32(body, id)
	body = binary.BigEndian.AppendUint32(body, 4)
	body = binary.BigEndian.AppendUint32(body, uint32(len(t.marker)))
	body = append(body, t.marker...)
	body = binary.BigEndian.AppendUint32(body, 0) // empty language tag
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}

// isLimitError reports whether err is the synthetic failure of this connection.
func (t *wireTracker) isLimitError(err error) bool {
	return err != nil && strings.Contains(err.Error(), t.marker)
}

// trackedWriter feeds every byte pkg/sftp sends to the tracker before it goes on the wire.
type trackedWriter struct {
	io.WriteCloser
	tr *wireTracker
}

func (w *trackedWriter) Write(p []byte) (int, error) {
	w.tr.observe(p)
	return w.WriteCloser.Write(p)
}
