// Package decorators holds composable wrappers around client.Client that
// change what a client is allowed to do without touching the protocol
// implementations.
//
// ReadOnly (PA-02) is the guarantee that a catalog scan can never modify a
// storage host: every mutating method returns ErrReadOnly and the wrapped
// client is not called, its reader is not consumed.
//
// The guarantee covers the whole client.Client surface, including what the
// read methods hand out: GetConfig returns a redacted defensive copy (no
// password, no pointer to the live config, so the handle can neither leak the
// credentials nor re-target the inner client), and ReadFile / OpenSeekable
// return a stream that exposes only Read, Close and the capabilities Seek,
// ReadAt and WriteTo when the inner stream has them - the inner stream's own
// metadata mutators (for an *os.File: Chmod, Chown, Truncate, Fd, ...) are not
// reachable. Limits: a client that offers a second, non client.Client write
// path is not covered, and the protection of the server side (an SMB open
// mask, an NFS export) is the protocol client's job.
package decorators

import (
	"context"
	"errors"
	"fmt"
	"io"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators/guard"
)

// ErrReadOnly is returned by every mutating method of a ReadOnly client.
// Test with errors.Is.
var ErrReadOnly = errors.New("filesystem: client is read-only")

// readOnly wraps a client.Client. It deliberately does NOT embed the
// interface: a method added to client.Client later would otherwise be
// promoted silently and reach the inner client unguarded. With explicit
// methods the compile-time assertion below fails instead, and
// TestReadOnly_ClassifiesEveryInterfaceMethod fails if the new method is
// not classified.
type readOnly struct {
	in client.Client
}

// readOnlySeekable adds OpenSeekable when (and only when) the inner client
// has it. Opening for reading is not a mutation.
type readOnlySeekable struct {
	readOnly
	seek client.SeekableClient
}

var (
	_ client.Client         = (*readOnly)(nil)
	_ client.Client         = (*readOnlySeekable)(nil)
	_ client.SeekableClient = (*readOnlySeekable)(nil)
)

// ReadOnly returns a client that forwards reads to inner and refuses every
// mutation with ErrReadOnly. A nil inner - including a typed nil such as
// (*local.Client)(nil) - panics at construction, not on first use. If inner
// implements client.SeekableClient so does the result.
func ReadOnly(inner client.Client) client.Client {
	if guard.IsNil(inner) { // also a typed nil such as (*local.Client)(nil)
		panic("decorators.ReadOnly: nil inner client")
	}
	ro := readOnly{in: inner}
	if s, ok := inner.(client.SeekableClient); ok {
		return &readOnlySeekable{readOnly: ro, seek: s}
	}
	return &ro
}

func refuse(op string) error { return fmt.Errorf("%s: %w", op, ErrReadOnly) }

// --- connection management and reads: forwarded ---

func (r *readOnly) Connect(ctx context.Context) error    { return r.in.Connect(ctx) }
func (r *readOnly) Disconnect(ctx context.Context) error { return r.in.Disconnect(ctx) }
func (r *readOnly) IsConnected() bool                    { return r.in.IsConnected() }
func (r *readOnly) TestConnection(ctx context.Context) error {
	return r.in.TestConnection(ctx)
}
func (r *readOnly) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	rc, err := r.in.ReadFile(ctx, path)
	if err != nil {
		return rc, err
	}
	return guard.Wrap(rc, guard.Hooks{}), nil // a nil or typed-nil stream stays nil (guard.Wrap)
}
func (r *readOnly) GetFileInfo(ctx context.Context, path string) (*client.FileInfo, error) {
	return r.in.GetFileInfo(ctx, path)
}
func (r *readOnly) FileExists(ctx context.Context, path string) (bool, error) {
	return r.in.FileExists(ctx, path)
}
func (r *readOnly) ListDirectory(ctx context.Context, path string) ([]*client.FileInfo, error) {
	return r.in.ListDirectory(ctx, path)
}
func (r *readOnly) GetProtocol() string { return r.in.GetProtocol() }

// GetConfig returns a redacted defensive copy of the inner configuration, see
// guard.RedactConfig.
func (r *readOnly) GetConfig() interface{} { return guard.RedactConfig(r.in.GetConfig()) }
func (r *readOnlySeekable) OpenSeekable(ctx context.Context, path string) (client.ReadSeekCloser, error) {
	rc, err := r.seek.OpenSeekable(ctx, path)
	if err != nil {
		return rc, err
	}
	return guard.WrapSeekable(rc, guard.Hooks{}), nil // a nil or typed-nil stream stays nil
}

// --- mutations: refused, inner never called, data reader never consumed ---

func (r *readOnly) WriteFile(_ context.Context, _ string, _ io.Reader) error {
	return refuse("WriteFile")
}
func (r *readOnly) DeleteFile(_ context.Context, _ string) error  { return refuse("DeleteFile") }
func (r *readOnly) CopyFile(_ context.Context, _, _ string) error { return refuse("CopyFile") }
func (r *readOnly) CreateDirectory(_ context.Context, _ string) error {
	return refuse("CreateDirectory")
}
func (r *readOnly) DeleteDirectory(_ context.Context, _ string) error {
	return refuse("DeleteDirectory")
}
