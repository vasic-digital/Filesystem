package guard

import (
	"io"

	"digital.vasic.filesystem/pkg/client"
)

// Hooks are the observation points of a wrapped stream. Both may be nil.
type Hooks struct {
	// OnRead is called with the byte count of every read that returned data
	// (Read, ReadAt and WriteTo alike).
	OnRead func(n int)
	// OnClose is called after the inner Close, on every Close call; the hook
	// itself must be idempotent.
	OnClose func()
}

func (h Hooks) read(n int) {
	if n > 0 && h.OnRead != nil {
		h.OnRead(n)
	}
}

// Wrap returns a stream that exposes ONLY the capabilities rc really has,
// out of io.Reader+io.Closer (always), io.Seeker, io.ReaderAt and
// io.WriterTo, and nothing else: methods of the concrete inner type such as
// (*os.File).Chmod, Fd or Stat are not reachable through the result, and a
// consumer that type-asserts io.ReaderAt / io.Seeker / io.WriterTo gets the
// same answer it would get from the inner stream.
func Wrap(rc io.ReadCloser, h Hooks) io.ReadCloser {
	if IsNil(rc) {
		// A nil (or typed-nil) stream stays nil: a non-nil wrapper around it
		// would panic on Close and could never release what its caller holds.
		return nil
	}
	_, ra := rc.(io.ReaderAt)
	_, sk := rc.(io.Seeker)
	_, wt := rc.(io.WriterTo)
	b := &base{rc: rc, h: h}
	m := 0
	if ra {
		m |= 1
	}
	if sk {
		m |= 2
	}
	if wt {
		m |= 4
	}
	at, sek, wto := raMix{rc: rc, h: h}, skMix{rc: rc}, wtMix{rc: rc, h: h}
	switch m {
	case 0:
		return b
	case 1:
		return struct {
			*base
			raMix
		}{b, at}
	case 2:
		return struct {
			*base
			skMix
		}{b, sek}
	case 3:
		return struct {
			*base
			raMix
			skMix
		}{b, at, sek}
	case 4:
		return struct {
			*base
			wtMix
		}{b, wto}
	case 5:
		return struct {
			*base
			raMix
			wtMix
		}{b, at, wto}
	case 6:
		return struct {
			*base
			skMix
			wtMix
		}{b, sek, wto}
	default:
		return struct {
			*base
			raMix
			skMix
			wtMix
		}{b, at, sek, wto}
	}
}

// WrapSeekable is Wrap for a stream that is a client.ReadSeekCloser; the
// result is one too (the Seek capability is never lost), and nil for a nil or
// typed-nil stream.
func WrapSeekable(rc client.ReadSeekCloser, h Hooks) client.ReadSeekCloser {
	w, _ := Wrap(rc, h).(client.ReadSeekCloser) // Wrap returns nil for a nil or typed-nil stream
	return w
}

type base struct {
	rc io.ReadCloser
	h  Hooks
}

func (b *base) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.h.read(n)
	return n, err
}

func (b *base) Close() error {
	err := b.rc.Close()
	if b.h.OnClose != nil {
		b.h.OnClose()
	}
	return err
}

type raMix struct {
	rc io.ReadCloser
	h  Hooks
}

func (m raMix) ReadAt(p []byte, off int64) (int, error) {
	n, err := m.rc.(io.ReaderAt).ReadAt(p, off)
	m.h.read(n)
	return n, err
}

type skMix struct{ rc io.ReadCloser }

func (m skMix) Seek(off int64, whence int) (int64, error) { return m.rc.(io.Seeker).Seek(off, whence) }

type wtMix struct {
	rc io.ReadCloser
	h  Hooks
}

// WriteTo reports the bytes AS THEY ARE WRITTEN (not once at the end), so an
// idle-based lease sees a long WriteTo copy as the activity it is. Without an
// OnRead hook the destination is passed through untouched, which keeps the
// inner stream's own fast paths (sendfile, copy_file_range).
func (m wtMix) WriteTo(w io.Writer) (int64, error) {
	if m.h.OnRead == nil {
		return m.rc.(io.WriterTo).WriteTo(w)
	}
	hw := &hookWriter{w: w, h: m.h}
	n, err := m.rc.(io.WriterTo).WriteTo(hw)
	if rest := n - hw.n; rest > 0 { // bytes the inner WriteTo reports but did not push through w
		m.h.read(int(rest))
	}
	return n, err
}

// hookWriter forwards writes and reports each accepted byte count.
type hookWriter struct {
	w io.Writer
	h Hooks
	n int64
}

func (x *hookWriter) Write(p []byte) (int, error) {
	n, err := x.w.Write(p)
	x.n += int64(n)
	x.h.read(n)
	return n, err
}
