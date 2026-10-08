package sftp

// Tests of the reply validator (frame.go). These cover a NEW function: on the pre-fix tree they do not compile, which is
// the RED for them; the black-box consequences (a malformed reply from a real ssh channel does not panic the process) are in
// fix_r2_test.go and are RED on the pre-fix tree by behaviour.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateFrame_Table(t *testing.T) {
	fullAttrs := attrsB(attrSize|attrUIDGID|attrPerms|attrACModTim, u64b(10), u32b(1), u32b(2), u32b(0o644), u32b(3), u32b(4))
	extAttrs := attrsB(attrExtended, u32b(1), strb("n"), strb("d"))
	cases := []struct {
		name  string
		typ   byte
		body  []byte
		names int
		ok    bool
	}{
		{"status id+code only", fxpStatus, cat(u32b(1), u32b(1)), 0, true},
		{"status full", fxpStatus, cat(u32b(1), u32b(1), strb("m"), strb("en")), 0, true},
		{"status empty", fxpStatus, nil, 0, false},
		{"status id only (the review's P7)", fxpStatus, u32b(1), 0, false},
		{"status 7 bytes", fxpStatus, make([]byte, 7), 0, false},
		{"handle", fxpHandle, cat(u32b(1), strb("h")), 0, true},
		{"handle short string", fxpHandle, cat(u32b(1), u32b(5), []byte("ab")), 0, false},
		{"handle no string", fxpHandle, u32b(1), 0, false},
		{"data", fxpData, cat(u32b(1), strb("0123456789")), 0, true},
		{"data empty payload", fxpData, cat(u32b(1), strb("")), 0, true},
		{"data length lies (worker goroutine panic site)", fxpData, cat(u32b(1), u32b(1<<20), []byte("0123456789")), 0, false},
		{"data length 0xffffffff", fxpData, cat(u32b(1), u32b(0xffffffff)), 0, false},
		{"attrs", fxpAttrs, cat(u32b(1), fullAttrs), 0, true},
		{"attrs none", fxpAttrs, cat(u32b(1), attrsB(0)), 0, true},
		{"attrs ext", fxpAttrs, cat(u32b(1), extAttrs), 0, true},
		{"attrs truncated size", fxpAttrs, cat(u32b(1), attrsB(attrSize, []byte{0, 0, 0, 0})), 0, false},
		{"attrs truncated times", fxpAttrs, cat(u32b(1), attrsB(attrACModTim, u32b(1))), 0, false},
		{"attrs ext count too big", fxpAttrs, cat(u32b(1), attrsB(attrExtended, u32b(1000))), 0, false},
		{"attrs ext string truncated", fxpAttrs, cat(u32b(1), attrsB(attrExtended, u32b(1), strb("n"), u32b(9))), 0, false},
		{"attrs no flags", fxpAttrs, u32b(1), 0, false},
		{"name two entries", fxpName, cat(u32b(1), u32b(2), strb("a"), strb("-rw"), fullAttrs, strb("b"), strb(""), attrsB(0)), 2, true},
		{"name zero entries", fxpName, cat(u32b(1), u32b(0)), 0, true},
		{"name count exceeds frame", fxpName, cat(u32b(1), u32b(1<<30)), 0, false},
		{"name entry truncated", fxpName, cat(u32b(1), u32b(1), strb("a"), strb("l")), 0, false},
		{"name attrs truncated", fxpName, cat(u32b(1), u32b(1), strb("a"), strb("l"), attrsB(attrSize)), 0, false},
		{"version", fxpVersion, u32b(3), 0, true},
		{"version with extension", fxpVersion, cat(u32b(3), strb("posix-rename@openssh.com"), strb("1")), 0, true},
		{"version odd extension", fxpVersion, cat(u32b(3), strb("posix-rename@openssh.com")), 0, false},
		{"version short", fxpVersion, []byte{0, 0}, 0, false},
		{"extended reply", fxpExtendedReply, cat(u32b(1), []byte("anything")), 0, true},
		{"extended reply no id", fxpExtendedReply, []byte{1}, 0, false},
		{"unknown type 3", 3, u32b(1), 0, false},
		{"unknown type 200", 200, u32b(1), 0, false},
	}
	for _, tc := range cases {
		names, err := validateFrame(tc.typ, tc.body)
		if tc.ok {
			require.NoError(t, err, tc.name)
			assert.Equal(t, tc.names, names, tc.name)
		} else {
			require.Error(t, err, tc.name)
			assert.ErrorIs(t, err, ErrMalformedReply, tc.name)
		}
	}
}

// The validator must never panic or loop on arbitrary bytes (it sits on the wire of a possibly hostile server).
func TestValidateFrame_NeverPanicsOnRandomInput(t *testing.T) {
	rng := rand.New(rand.NewSource(20261007))
	types := []byte{fxpVersion, fxpStatus, fxpHandle, fxpData, fxpName, fxpAttrs, fxpExtendedReply, 0, 1, 3, 99, 255}
	for i := 0; i < 30000; i++ {
		b := make([]byte, rng.Intn(80))
		rng.Read(b)
		if rng.Intn(3) == 0 && len(b) >= 8 { // bias towards plausible counts/lengths
			binary.BigEndian.PutUint32(b[4:], uint32(rng.Intn(6)))
		}
		_, _ = validateFrame(types[rng.Intn(len(types))], b)
	}
}

func TestFrameReader_PassesValidFramesUnchangedEvenByteByByte(t *testing.T) {
	stream := cat(
		wireFrame(fxpVersion, u32b(3)),
		wireFrame(fxpHandle, u32b(1), strb("h")),
		wireFrame(fxpData, u32b(2), strb("hello world")),
		wireFrame(fxpStatus, u32b(3), u32b(1), strb("eof"), strb("")),
		wireFrame(fxpName, u32b(4), u32b(1), strb("f"), strb("l"), attrsB(0)),
	)
	for name, rd := range map[string]io.Reader{
		"whole":        bytes.NewReader(stream),
		"byte by byte": iotest.OneByteReader(bytes.NewReader(stream)),
		"half reads":   iotest.HalfReader(bytes.NewReader(stream)),
	} {
		var faults int
		fr := newFrameReader(rd, newWireTracker(100), func(error) { faults++ })
		got, err := io.ReadAll(fr)
		require.NoError(t, err, name)
		assert.Equal(t, stream, got, name)
		assert.Zero(t, faults, name)
	}
}

func TestFrameReader_RejectsAndStaysRejected(t *testing.T) {
	good := wireFrame(fxpHandle, u32b(1), strb("h"))
	bad := wireFrame(fxpStatus, u32b(1)) // 4-byte status
	var faults []error
	fr := newFrameReader(bytes.NewReader(cat(good, bad, good)), nil, func(err error) { faults = append(faults, err) })
	buf := make([]byte, len(good))
	_, err := io.ReadFull(fr, buf)
	require.NoError(t, err)
	assert.Equal(t, good, buf)
	_, err = fr.Read(make([]byte, 64))
	require.ErrorIs(t, err, ErrMalformedReply)
	// nothing of the bad frame, and nothing after it, ever reaches the consumer
	for i := 0; i < 3; i++ {
		n, err := fr.Read(make([]byte, 64))
		assert.Zero(t, n)
		assert.ErrorIs(t, err, ErrMalformedReply)
	}
	assert.Len(t, faults, 1, "the fault is reported once")
}

func TestFrameReader_LengthAndEOFHandling(t *testing.T) {
	for name, stream := range map[string][]byte{
		"zero length": u32b(0),
		"too long":    u32b(maxFrame + 1),
		"huge length": u32b(0xffffffff),
	} {
		fr := newFrameReader(bytes.NewReader(stream), nil, nil)
		_, err := fr.Read(make([]byte, 8))
		assert.ErrorIs(t, err, ErrMalformedReply, name)
	}
	// clean EOF between frames is io.EOF, a cut inside a frame is io.ErrUnexpectedEOF (a lost connection, not a malformed reply)
	fr := newFrameReader(bytes.NewReader(nil), nil, nil)
	_, err := fr.Read(make([]byte, 8))
	assert.Equal(t, io.EOF, err)
	whole := wireFrame(fxpHandle, u32b(1), strb("h"))
	for cut := 1; cut < len(whole); cut++ {
		fr = newFrameReader(bytes.NewReader(whole[:cut]), nil, nil)
		_, err = io.ReadAll(fr)
		require.Error(t, err, "cut at %d", cut)
		assert.False(t, errors.Is(err, ErrMalformedReply), "cut at %d is a lost connection, not a malformed reply: %v", cut, err)
	}
}

// An over-budget listing page is replaced by a STATUS failure of THAT listing (fix-r3, review S03): no fault, the connection's frames
// keep flowing, and the replacement is itself a frame pkg/sftp can parse.
func TestFrameReader_OverBudgetPageBecomesAStatusFailureNotAFault(t *testing.T) {
	tr := newWireTracker(3)
	tr.observe(wireFrame(fxpReaddir, u32b(7), strb("H1")))
	two := func(id uint32) []byte {
		return wireFrame(fxpName, u32b(id), u32b(2), strb("a"), strb(""), attrsB(0), strb("b"), strb(""), attrsB(0))
	}
	tail := wireFrame(fxpHandle, u32b(9), strb("h"))
	var faults []error
	fr := newFrameReader(bytes.NewReader(cat(two(7), tail)), tr, func(err error) { faults = append(faults, err) })
	// page 1 (2 entries, budget 3): passes through unchanged
	buf := make([]byte, len(two(7)))
	_, err := io.ReadFull(fr, buf)
	require.NoError(t, err)
	assert.Equal(t, two(7), buf)
	// page 2 for the same handle (2 more, 4 > 3): replaced
	tr.observe(wireFrame(fxpReaddir, u32b(8), strb("H1")))
	fr = newFrameReader(bytes.NewReader(cat(two(8), tail)), tr, func(err error) { faults = append(faults, err) })
	got, err := io.ReadAll(fr)
	require.NoError(t, err)
	assert.Empty(t, faults, "a listing over its budget is not a connection fault")
	repl := tr.limitStatus(8)
	require.True(t, bytes.HasPrefix(got, repl), "the NAME frame is replaced by the failure status")
	assert.Equal(t, tail, got[len(repl):], "the frames after it are untouched")
	_, verr := validateFrame(repl[4], repl[5:])
	assert.NoError(t, verr, "the replacement is a well-formed STATUS frame")
	assert.Equal(t, byte(fxpStatus), repl[4])
	assert.Contains(t, string(repl), tr.marker)
	assert.True(t, tr.isLimitError(errors.New("sftp: \""+tr.marker+"\" (SSH_FX_FAILURE)")))
	assert.False(t, tr.isLimitError(errors.New("sftp: \"some other server message\" (SSH_FX_FAILURE)")), "a server cannot forge the marker without knowing it")
}

// The tracker's budget is per directory handle; REALPATH replies and other handles are not counted; CLOSE ends a handle's budget.
func TestWireTracker_BudgetIsPerHandle(t *testing.T) {
	tr := newWireTracker(10)
	rd := func(id uint32, h string) []byte { return wireFrame(fxpReaddir, u32b(id), strb(h)) }
	tr.observe(rd(1, "A"))
	tr.observe(rd(2, "B"))
	assert.False(t, tr.name(1, 6), "A: 6 of 10")
	assert.False(t, tr.name(2, 6), "B: 6 of 10 - a different handle has its own budget")
	tr.observe(rd(3, "A"))
	assert.True(t, tr.name(3, 6), "A: 12 > 10")
	tr.observe(rd(4, "A"))
	assert.True(t, tr.name(4, 0), "A stays over budget until it is closed")
	assert.False(t, tr.name(99, 1000), "a NAME reply to a request that is not a READDIR (REALPATH) is not counted")
	tr.observe(wireFrame(fxpClose, u32b(5), strb("A")))
	tr.observe(rd(6, "A")) // the same handle string reused by the server after the close: a new listing
	assert.False(t, tr.name(6, 10))
	// ids are forgotten at the reply: a STATUS reply (EOF) removes the READDIR entry
	tr.observe(rd(7, "C"))
	tr.replied(7)
	assert.False(t, tr.name(7, 1000))
	// unlimited
	un := newWireTracker(0)
	un.observe(rd(1, "A"))
	assert.False(t, un.name(1, 1<<30))
}

// Frames are written as header and payload in separate Writes, and may be split anywhere: the stream parser must not care.
func TestWireTracker_StreamParserSurvivesAnySplit(t *testing.T) {
	stream := cat(
		wireFrame(fxpOpendir, u32b(1), strb("/d")),     // not tracked: skipped
		wireFrame(fxpReaddir, u32b(2), strb("HANDLE")), // tracked
		wireFrame(fxpRead, u32b(3), strb("H"), u32b(0), u32b(0), u32b(32768)),
		wireFrame(fxpClose, u32b(4), strb("OTHER")),
		wireFrame(fxpReaddir, u32b(5), strb("H2")),
	)
	for _, chunk := range []int{1, 2, 3, 5, 7, 13, len(stream)} {
		tr := newWireTracker(5)
		for off := 0; off < len(stream); off += chunk {
			end := off + chunk
			if end > len(stream) {
				end = len(stream)
			}
			tr.observe(stream[off:end])
		}
		assert.False(t, tr.name(2, 5), "chunk %d: HANDLE has 5 of 5", chunk)
		assert.False(t, tr.name(5, 5), "chunk %d: H2 has its own budget", chunk)
		assert.Empty(t, tr.cur, "chunk %d: nothing left half parsed", chunk)
		assert.Zero(t, tr.skip, "chunk %d", chunk)
	}
	// garbage lengths never panic and never wedge the parser into tracking nonsense
	tr := newWireTracker(1)
	tr.observe(cat(u32b(0), u32b(0xffffffff), []byte{12, 1, 2, 3}))
	assert.NotPanics(t, func() { tr.observe(bytes.Repeat([]byte{0xff}, 100)) })
}

func TestConn_ListingBudgetAccessorsFollowTheConfig(t *testing.T) {
	assert.Equal(t, DefaultMaxDirEntries, NewSFTPClient(&Config{}).maxDirEntries())
	assert.Equal(t, 0, NewSFTPClient(&Config{MaxDirEntries: -1}).maxDirEntries(), "negative disables the limit")
	assert.Equal(t, 7, NewSFTPClient(&Config{MaxDirEntries: 7}).maxDirEntries())
}
