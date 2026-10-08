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
		var names, faults int
		fr := newFrameReader(rd, func(n int) error { names += n; return nil }, func(error) { faults++ })
		got, err := io.ReadAll(fr)
		require.NoError(t, err, name)
		assert.Equal(t, stream, got, name)
		assert.Equal(t, 1, names, name)
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

func TestFrameReader_ListingLimitIsReportedAsFault(t *testing.T) {
	stream := cat(wireFrame(fxpName, u32b(1), u32b(2), strb("a"), strb(""), attrsB(0), strb("b"), strb(""), attrsB(0)))
	limit := errors.New("limit")
	var fault error
	fr := newFrameReader(bytes.NewReader(stream), func(n int) error { return limit }, func(err error) { fault = err })
	_, err := fr.Read(make([]byte, 8))
	assert.ErrorIs(t, err, limit)
	assert.ErrorIs(t, fault, limit)
}

func TestConn_ListingBudget(t *testing.T) {
	cn := &conn{maxEntries: 10}
	assert.NoError(t, cn.countNames(1000), "outside a listing nothing is counted (REALPATH replies are NAME frames too)")
	cn.beginList()
	assert.NoError(t, cn.countNames(6))
	err := cn.countNames(6)
	assert.ErrorIs(t, err, ErrDirTooLarge)
	cn.endList()
	cn.beginList() // a new listing starts a new budget
	assert.NoError(t, cn.countNames(10))
	cn.endList()
	unlimited := &conn{}
	unlimited.beginList()
	assert.NoError(t, unlimited.countNames(1<<30))
}
