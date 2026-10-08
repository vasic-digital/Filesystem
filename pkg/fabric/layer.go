package fabric

import (
	"context"
	"io"
	"sync"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators/guard"
)

// callState lets an around-function attach behaviour to the stream returned by
// a successful ReadFile/OpenSeekable and to the data reader of WriteFile.
type callState struct {
	op      Op
	onClose []func()      // run once when the returned stream is closed
	onRead  []func(n int) // observe bytes read from the returned stream
	// wrapSrc, if set by the around-function before it calls call, wraps the
	// data reader handed to WriteFile.
	wrapSrc   func(io.Reader) io.Reader
	closeOnce sync.Once
}

func (s *callState) runClose() {
	s.closeOnce.Do(func() {
		for _, f := range s.onClose {
			f()
		}
	})
}

// around runs call, possibly several times, possibly with rewritten paths.
// It must return call's final error. For stream operations a nil error means
// the stream is open and st.onClose will run when it is closed; around must
// itself release anything it holds if it returns a non-nil error.
type around func(ctx context.Context, st *callState, paths []string, call func(ctx context.Context, paths []string) error) error

// layer implements client.Client by forwarding to in through ar. It does not
// embed client.Client: a method added to the interface later fails to
// compile here instead of being promoted unguarded.
type layer struct {
	in client.Client
	ar around
}

type layerSeekable struct {
	*layer
	seek client.SeekableClient
}

var (
	_ client.Client         = (*layer)(nil)
	_ client.Client         = (*layerSeekable)(nil)
	_ client.SeekableClient = (*layerSeekable)(nil)
)

// newLayer builds the decorator; the result is a client.SeekableClient iff
// inner is.
func newLayer(inner client.Client, ar around) client.Client {
	if guard.IsNil(inner) {
		panic("fabric: nil inner client")
	}
	l := &layer{in: inner, ar: ar}
	if s, ok := inner.(client.SeekableClient); ok {
		return &layerSeekable{layer: l, seek: s}
	}
	return l
}

func (l *layer) simple(ctx context.Context, op Op, call func(ctx context.Context) error) error {
	st := &callState{op: op}
	return l.ar(ctx, st, nil, func(ctx context.Context, _ []string) error { return call(ctx) })
}

func (l *layer) Connect(ctx context.Context) error {
	return l.simple(ctx, OpConnect, l.in.Connect)
}

func (l *layer) Disconnect(ctx context.Context) error {
	return l.simple(ctx, OpDisconnect, l.in.Disconnect)
}

func (l *layer) TestConnection(ctx context.Context) error {
	return l.simple(ctx, OpTestConnection, l.in.TestConnection)
}

func (l *layer) IsConnected() bool   { return l.in.IsConnected() }
func (l *layer) GetProtocol() string { return l.in.GetProtocol() }

// GetConfig returns a redacted defensive copy of the inner configuration (no
// secret field, no pointer to the live config): see guard.RedactConfig.
func (l *layer) GetConfig() interface{} { return guard.RedactConfig(l.in.GetConfig()) }

func (l *layer) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	st := &callState{op: OpReadFile}
	var rc io.ReadCloser
	err := l.ar(ctx, st, []string{path}, func(ctx context.Context, ps []string) error {
		r, e := l.in.ReadFile(ctx, ps[0])
		if e != nil {
			if r != nil {
				_ = r.Close()
			}
			rc = nil
			return e
		}
		rc = r
		return nil
	})
	if err != nil {
		if rc != nil {
			_ = rc.Close()
		}
		return nil, err
	}
	return l.wrap(rc, st), nil
}

func (l *layer) WriteFile(ctx context.Context, path string, data io.Reader) error {
	st := &callState{op: OpWriteFile}
	return l.ar(ctx, st, []string{path}, func(ctx context.Context, ps []string) error {
		src := data
		if st.wrapSrc != nil {
			src = st.wrapSrc(data)
		}
		return l.in.WriteFile(ctx, ps[0], src)
	})
}

func (l *layer) GetFileInfo(ctx context.Context, path string) (*client.FileInfo, error) {
	st := &callState{op: OpGetFileInfo}
	var fi *client.FileInfo
	err := l.ar(ctx, st, []string{path}, func(ctx context.Context, ps []string) error {
		var e error
		fi, e = l.in.GetFileInfo(ctx, ps[0])
		return e
	})
	if err != nil {
		return nil, err
	}
	return fi, nil
}

func (l *layer) FileExists(ctx context.Context, path string) (bool, error) {
	st := &callState{op: OpFileExists}
	var ok bool
	err := l.ar(ctx, st, []string{path}, func(ctx context.Context, ps []string) error {
		var e error
		ok, e = l.in.FileExists(ctx, ps[0])
		return e
	})
	if err != nil {
		return false, err
	}
	return ok, nil
}

func (l *layer) DeleteFile(ctx context.Context, path string) error {
	st := &callState{op: OpDeleteFile}
	return l.ar(ctx, st, []string{path}, func(ctx context.Context, ps []string) error {
		return l.in.DeleteFile(ctx, ps[0])
	})
}

func (l *layer) CopyFile(ctx context.Context, src, dst string) error {
	st := &callState{op: OpCopyFile}
	return l.ar(ctx, st, []string{src, dst}, func(ctx context.Context, ps []string) error {
		return l.in.CopyFile(ctx, ps[0], ps[1])
	})
}

func (l *layer) ListDirectory(ctx context.Context, path string) ([]*client.FileInfo, error) {
	st := &callState{op: OpListDirectory}
	var out []*client.FileInfo
	err := l.ar(ctx, st, []string{path}, func(ctx context.Context, ps []string) error {
		var e error
		out, e = l.in.ListDirectory(ctx, ps[0])
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (l *layer) CreateDirectory(ctx context.Context, path string) error {
	st := &callState{op: OpCreateDirectory}
	return l.ar(ctx, st, []string{path}, func(ctx context.Context, ps []string) error {
		return l.in.CreateDirectory(ctx, ps[0])
	})
}

func (l *layer) DeleteDirectory(ctx context.Context, path string) error {
	st := &callState{op: OpDeleteDirectory}
	return l.ar(ctx, st, []string{path}, func(ctx context.Context, ps []string) error {
		return l.in.DeleteDirectory(ctx, ps[0])
	})
}

func (l *layerSeekable) OpenSeekable(ctx context.Context, path string) (client.ReadSeekCloser, error) {
	st := &callState{op: OpOpenSeekable}
	var rc client.ReadSeekCloser
	err := l.ar(ctx, st, []string{path}, func(ctx context.Context, ps []string) error {
		r, e := l.seek.OpenSeekable(ctx, ps[0])
		if e != nil {
			if r != nil {
				_ = r.Close()
			}
			rc = nil
			return e
		}
		rc = r
		return nil
	})
	if err != nil {
		if rc != nil {
			_ = rc.Close()
		}
		return nil, err
	}
	w, _ := l.wrap(rc, st).(client.ReadSeekCloser)
	return w, nil
}

// wrap returns the stream handed to the caller: it meters reads (Read,
// ReadAt and WriteTo alike), runs the close hooks once, and exposes exactly
// the capabilities (io.Seeker, io.ReaderAt, io.WriterTo) the inner stream has,
// so a layer never degrades a ranged read into a whole-file read.
func (l *layer) wrap(rc io.ReadCloser, st *callState) io.ReadCloser {
	return guard.Wrap(rc, guard.Hooks{
		OnRead: func(n int) {
			for _, f := range st.onRead {
				f(n)
			}
		},
		OnClose: st.runClose,
	})
}

// Decorator wraps a client.
type Decorator func(client.Client) client.Client

// Chain applies decorators so that the FIRST one is outermost:
// Chain(c, A, B) == A(B(c)).
func Chain(c client.Client, decorators ...Decorator) client.Client {
	for i := len(decorators) - 1; i >= 0; i-- {
		c = decorators[i](c)
	}
	return c
}
