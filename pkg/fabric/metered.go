package fabric

import (
	"context"
	"io"
	"sync"
	"time"

	"digital.vasic.filesystem/pkg/client"
)

// Sample is one finished operation, reported to a Sink.
type Sample struct {
	Op       Op
	Protocol string
	Duration time.Duration // for streams: open to Close
	Bytes    int64         // bytes read from a stream or consumed by WriteFile
	Err      error
}

// Sink receives samples. Implementations must be safe for concurrent use and
// must not block.
type Sink interface{ Observe(Sample) }

// Metered returns a client that reports one Sample per operation to sink.
// Streams are reported when they are closed, with the byte count read. Place
// it outermost so a Sample describes the final outcome including retries.
func Metered(inner client.Client, sink Sink, clk Clock) client.Client {
	if sink == nil {
		panic("fabric.Metered: nil sink")
	}
	if clk == nil {
		clk = SystemClock()
	}
	return newLayer(inner, func(ctx context.Context, st *callState, paths []string, call func(context.Context, []string) error) error {
		start := clk.Now()
		var bytes int64
		var mu sync.Mutex
		add := func(n int) { mu.Lock(); bytes += int64(n); mu.Unlock() }
		report := func(err error) {
			mu.Lock()
			b := bytes
			mu.Unlock()
			sink.Observe(Sample{Op: st.op, Protocol: inner.GetProtocol(), Duration: clk.Now().Sub(start), Bytes: b, Err: err})
		}
		if st.op == OpWriteFile {
			st.wrapSrc = func(r io.Reader) io.Reader { return &countingReader{r: r, add: add} }
		}
		err := call(ctx, paths)
		if err != nil || !st.op.stream() {
			report(err)
			return err
		}
		st.onRead = append(st.onRead, add)
		st.onClose = append(st.onClose, func() { report(nil) })
		return nil
	})
}

type countingReader struct {
	r   io.Reader
	add func(int)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.add(n)
	}
	return n, err
}

// OpCounters is the aggregate of the samples of one Op.
type OpCounters struct {
	Calls         uint64
	Errors        uint64
	Bytes         int64
	TotalDuration time.Duration
}

// CounterSink is a ready-made Sink that aggregates per Op. The catalog-api
// metrics package can implement Sink directly; this is the dependency-free
// default and the one the tests use.
type CounterSink struct {
	mu  sync.Mutex
	ops [opCount]OpCounters
}

// Observe implements Sink. An out-of-range Op is ignored.
func (s *CounterSink) Observe(x Sample) {
	if !x.Op.valid() {
		return
	}
	s.mu.Lock()
	c := &s.ops[x.Op]
	c.Calls++
	if x.Err != nil {
		c.Errors++
	}
	c.Bytes += x.Bytes
	c.TotalDuration += x.Duration
	s.mu.Unlock()
}

// Snapshot returns the counters of op.
func (s *CounterSink) Snapshot(op Op) OpCounters {
	if !op.valid() {
		return OpCounters{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ops[op]
}
