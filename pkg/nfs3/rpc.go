package nfs3

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RPC constants, RFC 5531 section 9 and appendix A.
const (
	rpcCall     = 0
	rpcReply    = 1
	rpcVersion  = 2
	msgAccepted = 0
	msgDenied   = 1

	authNone = 0
	authSys  = 1

	acceptSuccess      = 0
	acceptProgUnavail  = 1
	acceptProgMismatch = 2
	acceptProcUnavail  = 3
	acceptGarbageArgs  = 4
	acceptSystemErr    = 5

	rejectRPCMismatch = 0
	rejectAuthError   = 1
)

// Program numbers and versions.
const (
	progPortmap = 100000
	progNFS     = 100003
	progMount   = 100005
	versPortmap = 2
	versNFS     = 3
	versMount   = 3
)

// Errors of the RPC layer.
var (
	// ErrConnClosed: the connection was closed or lost; the call may be retried on a new connection.
	ErrConnClosed = errors.New("nfs3: connection closed")
	// ErrCallTimeout: no reply within the per-call timeout.
	ErrCallTimeout = errors.New("nfs3: RPC call timed out")
	// ErrProtocol: the peer violated RPC framing or sent an undecodable reply.
	ErrProtocol = errors.New("nfs3: RPC protocol violation")
)

// RPCError is a well-formed RPC refusal (denied or not accepted).
type RPCError struct {
	Proc       uint32
	Denied     bool
	AcceptStat uint32 // when !Denied
	RejectStat uint32 // when Denied
	AuthStat   uint32 // when RejectStat == AUTH_ERROR
	Low, High  uint32 // supported version range for the mismatch cases
}

func (e *RPCError) Error() string {
	if e.Denied {
		if e.RejectStat == rejectAuthError {
			return fmt.Sprintf("nfs3: RPC call denied: authentication error %d", e.AuthStat)
		}
		return fmt.Sprintf("nfs3: RPC call denied: version mismatch (server supports %d..%d)", e.Low, e.High)
	}
	switch e.AcceptStat {
	case acceptProgUnavail:
		return "nfs3: RPC program unavailable"
	case acceptProgMismatch:
		return fmt.Sprintf("nfs3: RPC program version mismatch (server supports %d..%d)", e.Low, e.High)
	case acceptProcUnavail:
		return "nfs3: RPC procedure unavailable"
	case acceptGarbageArgs:
		return "nfs3: RPC server could not decode the arguments"
	case acceptSystemErr:
		return "nfs3: RPC server system error"
	}
	return fmt.Sprintf("nfs3: RPC accept status %d", e.AcceptStat)
}

// isAuth reports an authentication refusal (the reserved-port heuristic input).
func (e *RPCError) isAuth() bool { return e.Denied && e.RejectStat == rejectAuthError }

// authSysCred is the AUTH_SYS credential body, RFC 5531 appendix A.
type authSysCred struct {
	Stamp    uint32
	Machine  string
	UID, GID uint32
	GIDs     []uint32
	// None sends AUTH_NONE (RFC 5531 section 10.1) instead of AUTH_SYS: used when
	// the export lists only AUTH_NULL (e.g. user-space servers such as go-nfs).
	None bool
}

func (a authSysCred) encode() []byte {
	var e encoder
	e.u32(a.Stamp)
	m := a.Machine
	if len(m) > machineMax {
		m = m[:machineMax]
	}
	e.str(m)
	e.u32(a.UID)
	e.u32(a.GID)
	g := a.GIDs
	if len(g) > gidsMax {
		g = g[:gidsMax]
	}
	e.u32(uint32(len(g)))
	for _, x := range g {
		e.u32(x)
	}
	return e.b
}

// maxRecord bounds one reassembled RPC record (header + results).
const defaultMaxRecord = 8 << 20

// rpcConn multiplexes pipelined calls over one TCP connection, matching
// replies to calls by xid (RFC 5531 section 8.1).
type rpcConn struct {
	nc        net.Conn
	cred      authSysCred
	maxRecord int

	// wsem serialises record writes. It is a channel rather than a mutex so that a caller
	// waiting for its turn still honours its own context (a blocked writer would otherwise
	// hold every other caller for up to the write deadline).
	wsem chan struct{}

	mu      sync.Mutex
	pending map[uint32]chan []byte
	closed  bool
	err     error // why the connection ended

	// xid is the transaction id source. A Client shares ONE counter across all of its
	// connections, so a reconnect never reuses the xids of an earlier connection.
	xid      *atomic.Uint32
	dropped  atomic.Uint64 // replies with no matching call (late, duplicate, unsolicited)
	localEnd net.Addr
}

// newRPCConn starts a connection with a private xid counter whose first call uses firstXID+1.
func newRPCConn(nc net.Conn, cred authSysCred, maxRecord int, firstXID uint32) *rpcConn {
	ctr := new(atomic.Uint32)
	ctr.Store(firstXID)
	return newRPCConnShared(nc, cred, maxRecord, ctr)
}

// newRPCConnShared starts a connection that draws its xids from ctr.
func newRPCConnShared(nc net.Conn, cred authSysCred, maxRecord int, ctr *atomic.Uint32) *rpcConn {
	if maxRecord <= 0 {
		maxRecord = defaultMaxRecord
	}
	c := &rpcConn{nc: nc, cred: cred, maxRecord: maxRecord, pending: map[uint32]chan []byte{}, localEnd: nc.LocalAddr(), xid: ctr, wsem: make(chan struct{}, 1)}
	go c.readLoop()
	return c
}

// localPort is the local TCP port of the connection, 0 when unknown.
func (c *rpcConn) localPort() int {
	if ta, ok := c.localEnd.(*net.TCPAddr); ok {
		return ta.Port
	}
	return 0
}

// callKey names one remote procedure.
type callKey struct{ prog, proc uint32 }

// allowedCalls is the complete set of remote procedures this client may put on the wire. It is
// enforced at the single choke point (rpcConn.call) before anything is written, so a new code
// path that names a write procedure (by constant, by literal or through a variable) is refused
// at run time with ErrReadOnly and cannot reach the server.
var allowedCalls = map[callKey]bool{
	{progPortmap, procPmapGetport}: true,
	{progMount, procMnt}:           true,
	{progMount, procUmnt}:          true,
	{progMount, procMntExport}:     true,
	{progNFS, procNull}:            true,
	{progNFS, procGetattr}:         true,
	{progNFS, procLookup}:          true,
	{progNFS, procAccess}:          true,
	{progNFS, procRead}:            true,
	{progNFS, procReaddirplus}:     true,
	{progNFS, procFsinfo}:          true,
}

func (c *rpcConn) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.err = err
	pend := c.pending
	c.pending = map[uint32]chan []byte{}
	c.mu.Unlock()
	_ = c.nc.Close()
	for _, ch := range pend {
		close(ch) // a closed channel without a record means "connection failed"
	}
}

func (c *rpcConn) connErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return ErrConnClosed
}

func (c *rpcConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *rpcConn) close() { c.fail(ErrConnClosed) }

// readRecord reassembles one record from fragments (RFC 5531 section 11).
func readRecord(r *bufio.Reader, max int) ([]byte, error) {
	var rec []byte
	var hdr [4]byte
	for frags := 0; ; frags++ {
		if frags > 1<<14 {
			return nil, fmt.Errorf("%w: too many record fragments", ErrProtocol)
		}
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		h := binary.BigEndian.Uint32(hdr[:])
		last := h&0x80000000 != 0
		n := int(h & 0x7fffffff)
		if len(rec)+n > max {
			return nil, fmt.Errorf("%w: record exceeds %d bytes", ErrProtocol, max)
		}
		if n > 0 {
			// Allocate as the bytes arrive, never trusting the announced length up front.
			start := len(rec)
			remaining := n
			for remaining > 0 {
				chunk := remaining
				if chunk > 64<<10 {
					chunk = 64 << 10
				}
				rec = append(rec, make([]byte, chunk)...)
				if _, err := io.ReadFull(r, rec[start:start+chunk]); err != nil {
					return nil, err
				}
				start += chunk
				remaining -= chunk
			}
		}
		if last {
			return rec, nil
		}
	}
}

func (c *rpcConn) readLoop() {
	br := bufio.NewReaderSize(c.nc, 64<<10)
	for {
		rec, err := readRecord(br, c.maxRecord)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
				c.fail(fmt.Errorf("%w: %v", ErrConnClosed, err))
			} else {
				c.fail(err)
			}
			return
		}
		if len(rec) < 8 {
			c.fail(fmt.Errorf("%w: record of %d bytes cannot hold xid and message type", ErrProtocol, len(rec)))
			return
		}
		xid := binary.BigEndian.Uint32(rec[0:4])
		if binary.BigEndian.Uint32(rec[4:8]) != rpcReply {
			c.dropped.Add(1) // a CALL from the server: not part of this client's protocol
			continue
		}
		c.mu.Lock()
		ch, ok := c.pending[xid]
		if ok {
			delete(c.pending, xid)
		}
		c.mu.Unlock()
		if !ok {
			c.dropped.Add(1) // late reply to a cancelled call, a duplicate, or an unsolicited xid
			continue
		}
		ch <- rec // buffered 1
		close(ch)
	}
}

func (c *rpcConn) buildCall(xid, prog, vers, proc uint32, args []byte) []byte {
	var e encoder
	e.u32(0) // record header placeholder
	e.u32(xid)
	e.u32(rpcCall)
	e.u32(rpcVersion)
	e.u32(prog)
	e.u32(vers)
	e.u32(proc)
	if c.cred.None {
		e.u32(authNone)
		e.u32(0)
	} else {
		e.u32(authSys)
		e.opaque(c.cred.encode())
	}
	e.u32(authNone) // verifier
	e.u32(0)
	e.b = append(e.b, args...)
	binary.BigEndian.PutUint32(e.b[0:4], 0x80000000|uint32(len(e.b)-4))
	return e.b
}

// call sends one request and waits for its reply. perCall bounds the wait.
// It returns the procedure results (after the accepted-reply header).
func (c *rpcConn) call(ctx context.Context, perCall time.Duration, prog, vers, proc uint32, args []byte) ([]byte, error) {
	if !allowedCalls[callKey{prog, proc}] {
		return nil, fmt.Errorf("%w: program %d procedure %d is not on the allow-list", ErrReadOnly, prog, proc)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	xid := c.xid.Add(1)
	ch := make(chan []byte, 1)
	c.mu.Lock()
	if c.closed {
		err := c.err
		c.mu.Unlock()
		if err == nil {
			err = ErrConnClosed
		}
		return nil, err
	}
	c.pending[xid] = ch
	c.mu.Unlock()

	msg := c.buildCall(xid, prog, vers, proc, args)
	// Take the write slot, but give up when the caller's context ends first.
	select {
	case c.wsem <- struct{}{}:
	case <-ctx.Done():
		c.forget(xid)
		return nil, ctx.Err()
	}
	if perCall > 0 {
		_ = c.nc.SetWriteDeadline(time.Now().Add(perCall))
	} else {
		_ = c.nc.SetWriteDeadline(time.Time{})
	}
	stop := c.abortWriteOnCancel(ctx)
	_, werr := c.nc.Write(msg)
	stop()
	<-c.wsem
	if werr != nil {
		c.forget(xid)
		// A write that failed or was interrupted may have left half a record on the stream:
		// the connection cannot be reused.
		c.fail(fmt.Errorf("%w: write: %v", ErrConnClosed, werr))
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, c.connErr()
	}

	var timer <-chan time.Time
	if perCall > 0 {
		t := time.NewTimer(perCall)
		defer t.Stop()
		timer = t.C
	}
	select {
	case rec, ok := <-ch:
		if !ok {
			return nil, c.connErr()
		}
		return parseReply(rec, xid, proc)
	case <-ctx.Done():
		c.forget(xid)
		return nil, ctx.Err()
	case <-timer:
		c.forget(xid)
		return nil, ErrCallTimeout
	}
}

// abortWriteOnCancel arranges that a Write blocked on a full send buffer is interrupted as soon
// as ctx ends (by moving the write deadline into the past). The returned stop function waits
// for the watcher to exit, so the deadline is never touched after the write slot is released.
func (c *rpcConn) abortWriteOnCancel(ctx context.Context) (stop func()) {
	done := ctx.Done()
	if done == nil {
		return func() {}
	}
	fin := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-done:
			_ = c.nc.SetWriteDeadline(time.Unix(1, 0))
		case <-fin:
		}
	}()
	return func() {
		close(fin)
		<-exited
	}
}

func (c *rpcConn) forget(xid uint32) {
	c.mu.Lock()
	delete(c.pending, xid)
	c.mu.Unlock()
}

// parseReply decodes an RPC reply record and returns the procedure results.
// RFC 5531 section 9: rpc_msg / reply_body / accepted_reply / rejected_reply.
func parseReply(rec []byte, wantXID, proc uint32) ([]byte, error) {
	d := newDecoder(rec)
	xid, err := d.u32()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if xid != wantXID {
		return nil, fmt.Errorf("%w: xid %d does not match call %d", ErrProtocol, xid, wantXID)
	}
	mtype, err := d.u32()
	if err != nil || mtype != rpcReply {
		return nil, fmt.Errorf("%w: not a reply message", ErrProtocol)
	}
	stat, err := d.u32()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	switch stat {
	case msgAccepted:
		if _, err = d.u32(); err != nil { // verifier flavor
			return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		if _, err = d.opaque(authBodyMax); err != nil {
			return nil, fmt.Errorf("%w: verifier: %v", ErrProtocol, err)
		}
		as, err := d.u32()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		if as == acceptSuccess {
			return rec[d.off:], nil
		}
		re := &RPCError{Proc: proc, AcceptStat: as}
		if as == acceptProgMismatch {
			re.Low, _ = d.u32()
			re.High, _ = d.u32()
		}
		return nil, re
	case msgDenied:
		rs, err := d.u32()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		re := &RPCError{Proc: proc, Denied: true, RejectStat: rs}
		switch rs {
		case rejectRPCMismatch:
			re.Low, _ = d.u32()
			re.High, _ = d.u32()
		case rejectAuthError:
			re.AuthStat, _ = d.u32()
		default:
			return nil, fmt.Errorf("%w: reject_stat %d", ErrProtocol, rs)
		}
		return nil, re
	}
	return nil, fmt.Errorf("%w: reply_stat %d", ErrProtocol, stat)
}
