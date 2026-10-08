package nfs3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"digital.vasic.filesystem/pkg/client"
)

// maxReadChunk caps one READ regardless of what the server advertises.
const maxReadChunk = 1 << 20

// firstReadChunk is the size of the first READ of a freshly opened or freshly seeked reader.
// The chunk size and the number of READs in flight then double with every chunk that is
// consumed in sequence, up to the configured ceilings: a caller that reads a header and closes
// the file moves kilobytes, not megabytes, while a caller that streams the whole file reaches
// the full pipeline after four chunks.
const firstReadChunk = 64 << 10

// recordHeadroom is the room a reply record needs around its payload (RPC header, status,
// post-op attributes, counts). A configured size that leaves less than this below MaxRecord
// would make every reply exceed the record cap.
const recordHeadroom = 4096

// readChunkSize is the ceiling for one READ: the configured ReadSize or the server's preferred
// size, never more than the server's maximum (FSINFO rtmax), 1 MiB, or what fits one record.
func (c *Client) readChunkSize() uint32 {
	var chunk uint32
	c.mu.Lock()
	pref, rtmax := c.fsinfo.RTPref, c.fsinfo.RTMax
	c.mu.Unlock()
	if c.cfg.ReadSize > 0 {
		chunk = c.cfg.ReadSize
	} else {
		chunk = pref
		if chunk == 0 {
			chunk = 32768 // FSINFO gave no preference: the classic 32 KiB
		}
	}
	if chunk > maxReadChunk {
		chunk = maxReadChunk
	}
	if rtmax > 0 && chunk > rtmax {
		chunk = rtmax
	}
	if lim := c.cfg.MaxRecord - recordHeadroom; lim > 0 && int64(chunk) > int64(lim) {
		chunk = uint32(lim)
	}
	if chunk == 0 {
		chunk = 1
	}
	return chunk
}

type chunkResult struct {
	data []byte
	eof  bool
	err  error
}

type future struct {
	off    int64
	count  uint32
	ch     chan chunkResult
	cancel context.CancelFunc // ends this READ only; the reader's own context ends all of them
}

// fileReader is a sequential, adaptive read-ahead, seekable reader over NFS READ.
// Up to cw READs are in flight (cw grows from 1 to window as chunks are consumed in order);
// results are consumed strictly in order.
type fileReader struct {
	c      *Client
	ctx    context.Context
	cancel context.CancelFunc
	fh     Handle
	size   int64
	chunk  uint32 // ceiling for one READ
	window int    // ceiling for READs in flight
	limit  int64  // read-ahead never goes past this offset (ReadRange sets it; math.MaxInt64 = none)

	mu   sync.Mutex
	pos  int64
	next int64 // next offset to prefetch
	cur  uint32
	cw   int
	// lastShort is the length of the last short (non-EOF) reply, 0 when there was none.
	lastShort uint32
	q         []*future
	buf       []byte
	closed    bool
	err       error
}

var _ client.ReadSeekCloser = (*fileReader)(nil)

// ReadFile opens p for streaming. The returned reader is also an
// io.Seeker (see OpenSeekable). ctx must stay alive while the reader is used:
// cancelling it aborts in-flight READs.
func (c *Client) ReadFile(ctx context.Context, p string) (io.ReadCloser, error) {
	return c.OpenSeekable(ctx, p)
}

// OpenSeekable opens p for random-access reads.
func (c *Client) OpenSeekable(ctx context.Context, p string) (client.ReadSeekCloser, error) {
	r, err := c.openReader(ctx, p)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (c *Client) openReader(ctx context.Context, p string) (*fileReader, error) {
	h, a, _, err := c.resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	if a.Type != TypeRegular {
		return nil, fmt.Errorf("%w: %q has type %d", ErrNotRegular, p, a.Type)
	}
	if a.Size > math.MaxInt64 { // the fattr decoder already refuses this; kept as a second line
		return nil, fmt.Errorf("%w: file size %d exceeds the signed 64-bit range", ErrBadXDR, a.Size)
	}
	rctx, cancel := context.WithCancel(ctx)
	r := &fileReader{c: c, ctx: rctx, cancel: cancel, fh: h, size: int64(a.Size), chunk: c.readChunkSize(), window: c.cfg.MaxPipeline, limit: math.MaxInt64}
	r.restartRamp()
	return r, nil
}

// restartRamp returns the read-ahead to its small start (called on open and after a seek).
func (r *fileReader) restartRamp() {
	r.cur = r.chunk
	if r.cur > firstReadChunk {
		r.cur = firstReadChunk
	}
	r.cw = 1
}

// grow doubles the chunk size and the window after a chunk was consumed in sequence.
func (r *fileReader) grow() {
	if r.cur < r.chunk {
		r.cur *= 2
		if r.cur > r.chunk || r.cur == 0 {
			r.cur = r.chunk
		}
	}
	if r.cw < r.window {
		r.cw *= 2
		if r.cw > r.window {
			r.cw = r.window
		}
	}
}

// end is the offset past which nothing is requested.
func (r *fileReader) end() int64 {
	if r.limit < r.size {
		return r.limit
	}
	return r.size
}

// issue starts one READ and returns its future.
func (r *fileReader) issue(off int64, count uint32) *future {
	fctx, cancel := context.WithCancel(r.ctx)
	f := &future{off: off, count: count, ch: make(chan chunkResult, 1), cancel: cancel}
	go func() {
		defer cancel()
		res, err := r.c.callNFS(fctx, procRead, encodeRead(r.fh, uint64(f.off), f.count), "READ")
		if err != nil {
			f.ch <- chunkResult{err: err}
			return
		}
		data, eof, err := decodeRead(res, f.count)
		f.ch <- chunkResult{data: data, eof: eof, err: err}
	}()
	return f
}

func (r *fileReader) topUp() {
	end := r.end()
	for len(r.q) < r.cw && r.next < end {
		n := int64(r.cur)
		if r.next+n > end {
			n = end - r.next
		}
		r.q = append(r.q, r.issue(r.next, uint32(n)))
		r.next += n
	}
}

// dropQueue discards the read-ahead and CANCELS the READs still in flight: their results can never
// be used (a Seek, an error or the end of the file made them stale), so they must not keep working
// against the server.
func (r *fileReader) dropQueue() {
	for _, f := range r.q {
		if f.cancel != nil { // futures are made by issue; a hand-built one has nothing to cancel
			f.cancel()
		}
	}
	r.q = nil
}

// truncateAt records that the file ends at size: the read-ahead behind it asks for bytes that do not
// exist, so it is dropped and its READs are cancelled.
func (r *fileReader) truncateAt(size int64) {
	r.size = size
	r.dropQueue()
	r.next = size
}

func (r *fileReader) reset(at int64) {
	r.dropQueue()
	r.buf = nil
	r.pos = at
	r.next = at
	r.restartRamp()
}

// fail records a sticky error and drops every read-ahead, so that the position is clean when a
// caller clears the error with Seek and reads again.
func (r *fileReader) fail(err error) error {
	r.err = err
	r.dropQueue()
	r.buf = nil
	r.next = r.pos
	return err
}

// Read implements io.Reader.
func (r *fileReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, errors.New("nfs3: read on closed file")
	}
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.buf) == 0 {
		if r.pos >= r.end() {
			return 0, io.EOF
		}
		r.topUp()
		if len(r.q) == 0 {
			return 0, io.EOF
		}
		f := r.q[0]
		var res chunkResult
		select {
		case res = <-f.ch:
		case <-r.ctx.Done():
			return 0, r.fail(r.ctx.Err())
		}
		r.q = r.q[1:]
		if res.err != nil {
			return 0, r.fail(res.err)
		}
		if f.off != r.pos {
			// Defensive: a prefetch that no longer matches the position is stale.
			r.reset(r.pos)
			continue
		}
		if len(res.data) == 0 {
			if res.eof {
				r.truncateAt(r.pos) // the file is shorter than GETATTR said
				return 0, io.EOF
			}
			return 0, r.fail(fmt.Errorf("%w: READ at offset %d returned 0 bytes without EOF", ErrNotProgressing, f.off))
		}
		r.buf = res.data
		got := uint32(len(res.data))
		switch {
		case got >= f.count:
			r.grow()
		case res.eof:
			// Short because the file ends here: nothing beyond this offset exists.
			r.truncateAt(f.off + int64(got))
		default:
			// Short for another reason, typically the server's maximum reply size (rtmax) is
			// below what was asked. The prefetches behind this one are still at valid offsets
			// and are kept; only the gap is requested again. Later READs are sized to what the
			// server returned; when the SAME short length comes back twice it is a limit of
			// the server, and the ceiling itself is lowered to it (a single odd reply only
			// restarts the ramp from that size).
			if got == r.lastShort && got < r.chunk {
				r.chunk = got
			}
			r.lastShort = got
			if r.cur > got {
				r.cur = got
			}
			gap := r.issue(f.off+int64(got), f.count-got)
			r.q = append([]*future{gap}, r.q...)
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	r.pos += int64(n)
	return n, nil
}

// Seek implements io.Seeker. Seeking drops the read-ahead window and clears a sticky error.
func (r *fileReader) Seek(offset int64, whence int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var np int64
	switch whence {
	case io.SeekStart:
		np = offset
	case io.SeekCurrent:
		np = r.pos + offset
	case io.SeekEnd:
		np = r.size + offset
	default:
		return 0, fmt.Errorf("nfs3: invalid whence %d", whence)
	}
	if np < 0 {
		return 0, fmt.Errorf("nfs3: negative seek position %d", np)
	}
	if np != r.pos || r.err != nil {
		r.reset(np)
	}
	r.err = nil
	return np, nil
}

// Close stops the read-ahead.
func (r *fileReader) Close() error {
	r.cancel() // first: unblocks a Read that is waiting for a READ reply
	r.mu.Lock()
	r.closed = true
	r.dropQueue()
	r.buf = nil
	r.mu.Unlock()
	return nil
}

// MaxRangeBytes bounds ReadRange.
const MaxRangeBytes = 64 << 20

// ReadRange reads up to n bytes at offset off with pipelined READs. A short
// result means EOF was reached.
func (c *Client) ReadRange(ctx context.Context, p string, off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || n > MaxRangeBytes {
		return nil, fmt.Errorf("nfs3: invalid range off=%d n=%d (max %d)", off, n, MaxRangeBytes)
	}
	f, err := c.openReader(ctx, p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Never read ahead past the range: a 100-byte probe issues one 100-byte READ.
	if off > math.MaxInt64-n {
		f.limit = math.MaxInt64
	} else {
		f.limit = off + n
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, min64(n, 1<<20))
	lr := io.LimitReader(f, n)
	b := make([]byte, 64<<10)
	for {
		m, err := lr.Read(b)
		buf = append(buf, b[:m]...)
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
