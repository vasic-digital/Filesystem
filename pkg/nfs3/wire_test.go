package nfs3

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// ---- XDR (RFC 4506) ----

func TestXDROpaquePadding(t *testing.T) {
	// RFC 4506 section 4.10: length, bytes, zero padding to a multiple of four.
	cases := map[string]string{
		"":      "00000000",
		"a":     "0000000161000000",
		"ab":    "000000026162" + "0000",
		"abc":   "00000003616263" + "00",
		"abcd":  "0000000461626364",
		"abcde": "000000056162636465" + "000000",
	}
	for in, want := range cases {
		var e encoder
		e.str(in)
		if got := hex.EncodeToString(e.b); got != want {
			t.Errorf("encode %q: got %s want %s", in, got, want)
		}
		d := newDecoder(e.b)
		out, err := d.str(16)
		if err != nil || out != in || d.remaining() != 0 {
			t.Errorf("decode %q: %q %v rem=%d", in, out, err, d.remaining())
		}
	}
}

func TestXDRLimitsAndStrictness(t *testing.T) {
	var e encoder
	e.u32(1 << 30) // announces a gigabyte but carries nothing
	if _, err := newDecoder(e.b).opaque(1 << 20); !errors.Is(err, ErrBadXDR) {
		t.Fatalf("oversize opaque: want ErrBadXDR, got %v", err)
	}
	e = encoder{}
	e.u32(100) // within the limit but the data is missing
	if _, err := newDecoder(e.b).opaque(1 << 20); !errors.Is(err, ErrShortXDR) {
		t.Fatalf("truncated opaque: want ErrShortXDR, got %v", err)
	}
	e = encoder{}
	e.u32(2)
	if _, err := newDecoder(e.b).boolean(); !errors.Is(err, ErrBadXDR) {
		t.Fatalf("bool 2: want ErrBadXDR, got %v", err)
	}
	if _, err := newDecoder([]byte{0, 0}).u32(); !errors.Is(err, ErrShortXDR) {
		t.Fatalf("short u32: %v", err)
	}
	// opaque must not alias the input buffer
	e = encoder{}
	e.opaque([]byte("xyz"))
	buf := append([]byte(nil), e.b...)
	out, _ := newDecoder(buf).opaque(8)
	buf[4] = 'Q'
	if string(out) != "xyz" {
		t.Fatalf("opaque aliases the reply buffer: %q", out)
	}
}

func sampleAttr() Attr {
	ts := time.Unix(1700000001, 999999999).UTC()
	return Attr{Type: TypeRegular, Mode: 0o100644 & 0o7777, Nlink: 2, UID: 1000, GID: 100, Size: 1<<33 + 5, Used: 8192, RdevMajor: 1, RdevMinor: 2, FSID: 9, FileID: 1<<40 + 3, ATime: ts, MTime: ts.Add(time.Second), CTime: ts.Add(2 * time.Second)}
}

func TestFattrRoundTripAndBadType(t *testing.T) {
	a := sampleAttr()
	var e encoder
	e.fattr(a)
	if len(e.b) != 84 { // 21 words, RFC 1813 section 2.5
		t.Fatalf("fattr3 is %d bytes, want 84", len(e.b))
	}
	got, err := newDecoder(e.b).fattr()
	if err != nil || got != a {
		t.Fatalf("round trip: %v\n%+v\n%+v", err, got, a)
	}
	for _, bad := range []uint32{0, 8, 99} {
		b := append([]byte(nil), e.b...)
		binary.BigEndian.PutUint32(b, bad)
		if _, err := newDecoder(b).fattr(); !errors.Is(err, ErrBadXDR) {
			t.Errorf("ftype3 %d accepted", bad)
		}
	}
	if _, err := newDecoder(e.b[:83]).fattr(); !errors.Is(err, ErrShortXDR) {
		t.Errorf("truncated fattr3: %v", err)
	}
}

func TestAttrFileMode(t *testing.T) {
	if m := (Attr{Type: TypeDir, Mode: 0o755}).FileMode(); !m.IsDir() || m.Perm() != 0o755 {
		t.Errorf("dir mode %v", m)
	}
	if m := (Attr{Type: TypeSymlink, Mode: 0o777}).FileMode(); m&os.ModeSymlink == 0 {
		t.Errorf("symlink mode %v", m)
	}
	if m := (Attr{Type: TypeRegular, Mode: 0o4755}).FileMode(); m&os.ModeSetuid == 0 {
		t.Errorf("setuid lost: %v", m)
	}
}

// ---- RPC call encoding against a hand-assembled golden (RFC 5531 sections 8, 9, appendix A) ----

func TestBuildCallGolden(t *testing.T) {
	c := &rpcConn{cred: authSysCred{Stamp: 0x01020304, Machine: "m", UID: 1000, GID: 100, GIDs: []uint32{4, 5}}}
	got := hex.EncodeToString(c.buildCall(0xAABBCCDD, progNFS, versNFS, procGetattr, []byte{0xde, 0xad, 0xbe, 0xef}))
	want := strings.Join([]string{
		"8000004c",                         // last fragment, 0x4c = 76 bytes
		"aabbccdd", "00000000", "00000002", // xid, CALL, rpcvers 2
		"000186a3", "00000003", "00000001", // prog 100003, vers 3, proc 1
		"00000001", "00000020", // cred flavor AUTH_SYS, body length 32
		"01020304",             // stamp
		"00000001", "6d000000", // machinename "m" padded
		"000003e8", "00000064", // uid 1000, gid 100
		"00000002", "00000004", "00000005", // gids
		"00000000", "00000000", // verifier AUTH_NONE, length 0
		"deadbeef",
	}, "")
	if got != want {
		t.Fatalf("call bytes differ\n got %s\nwant %s", got, want)
	}
}

func TestAuthSysClampsGidsAndMachine(t *testing.T) {
	a := authSysCred{Machine: strings.Repeat("x", 300), GIDs: make([]uint32, 40)}
	d := newDecoder(a.encode())
	_, _ = d.u32()
	m, err := d.str(1000)
	if err != nil || len(m) != 255 {
		t.Fatalf("machine name %d %v", len(m), err)
	}
	_, _ = d.u32()
	_, _ = d.u32()
	n, _ := d.u32()
	if n != 16 {
		t.Fatalf("gids %d, RFC 5531 appendix A allows at most 16", n)
	}
}

// ---- record marking (RFC 5531 section 11) ----

func frag(last bool, p []byte) []byte {
	h := uint32(len(p))
	if last {
		h |= 0x80000000
	}
	b := binary.BigEndian.AppendUint32(nil, h)
	return append(b, p...)
}

func TestReadRecordFragments(t *testing.T) {
	var in []byte
	in = append(in, frag(false, []byte("hel"))...)
	in = append(in, frag(false, nil)...) // empty fragment is legal
	in = append(in, frag(true, []byte("lo"))...)
	in = append(in, frag(true, []byte("second"))...)
	br := bufio.NewReader(bytes.NewReader(in))
	r1, err := readRecord(br, 1024)
	if err != nil || string(r1) != "hello" {
		t.Fatalf("first record %q %v", r1, err)
	}
	r2, err := readRecord(br, 1024)
	if err != nil || string(r2) != "second" {
		t.Fatalf("second record %q %v", r2, err)
	}
	if _, err := readRecord(br, 1024); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF expected, got %v", err)
	}
}

func TestReadRecordLimits(t *testing.T) {
	// Announces 2 GiB but sends nothing: must fail on the limit, not allocate.
	in := binary.BigEndian.AppendUint32(nil, 0x80000000|0x7fffffff)
	if _, err := readRecord(bufio.NewReader(bytes.NewReader(in)), 1<<20); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversize record: %v", err)
	}
	// Truncated body.
	in = append(binary.BigEndian.AppendUint32(nil, 0x80000000|100), 1, 2, 3)
	if _, err := readRecord(bufio.NewReader(bytes.NewReader(in)), 1<<20); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated record: %v", err)
	}
	// Endless empty fragments.
	var many []byte
	for i := 0; i < 1<<15; i++ {
		many = append(many, frag(false, nil)...)
	}
	if _, err := readRecord(bufio.NewReader(bytes.NewReader(many)), 1<<20); !errors.Is(err, ErrProtocol) {
		t.Fatalf("fragment flood: %v", err)
	}
}

// ---- reply parsing (RFC 5531 section 9) ----

func replyHdr(xid, stat uint32, rest ...uint32) []byte {
	var e encoder
	e.u32(xid)
	e.u32(rpcReply)
	e.u32(stat)
	for _, r := range rest {
		e.u32(r)
	}
	return e.b
}

func TestParseReply(t *testing.T) {
	ok := append(replyHdr(7, msgAccepted, 0, 0, acceptSuccess), 1, 2, 3, 4)
	if res, err := parseReply(ok, 7, 1); err != nil || !bytes.Equal(res, []byte{1, 2, 3, 4}) {
		t.Fatalf("success: %v %v", res, err)
	}
	if _, err := parseReply(ok, 8, 1); !errors.Is(err, ErrProtocol) {
		t.Errorf("xid mismatch accepted: %v", err)
	}
	var re *RPCError
	if _, err := parseReply(replyHdr(7, msgAccepted, 0, 0, acceptProgMismatch, 2, 3), 7, 1); !errors.As(err, &re) || re.Low != 2 || re.High != 3 {
		t.Errorf("prog mismatch: %v", err)
	}
	if _, err := parseReply(replyHdr(7, msgAccepted, 0, 0, acceptProcUnavail), 7, 1); !errors.As(err, &re) || re.AcceptStat != acceptProcUnavail {
		t.Errorf("proc unavail: %v", err)
	}
	if _, err := parseReply(replyHdr(7, msgDenied, rejectAuthError, 1), 7, 1); !errors.As(err, &re) || !re.isAuth() || re.AuthStat != 1 {
		t.Errorf("auth denied: %v", err)
	}
	if _, err := parseReply(replyHdr(7, msgDenied, rejectRPCMismatch, 2, 2), 7, 1); !errors.As(err, &re) || re.isAuth() || re.Low != 2 {
		t.Errorf("rpc mismatch: %v", err)
	}
	for name, b := range map[string][]byte{
		"empty":      nil,
		"xid only":   {0, 0, 0, 7},
		"a CALL":     append(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 7), rpcCall), 0, 0, 0, 0),
		"bad stat":   replyHdr(7, 9),
		"bad reject": replyHdr(7, msgDenied, 9),
		"short verf": replyHdr(7, msgAccepted, 0),
		"huge verf":  replyHdr(7, msgAccepted, 0, 1<<20),
		// The announced body is really present, so only the 400-byte limit of opaque_auth
		// (RFC 5531 section 8.2) can refuse it.
		"oversize verf with its data": append(replyHdr(7, msgAccepted, 0, 404), make([]byte, 404+4)...),
	} {
		if _, err := parseReply(b, 7, 1); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: want ErrProtocol, got %v", name, err)
		}
	}
}

// ---- portmapper / mount / NFS result decoders ----

func TestDecodeGetport(t *testing.T) {
	if p, err := decodeGetport(binary.BigEndian.AppendUint32(nil, 2049)); err != nil || p != 2049 {
		t.Fatal(p, err)
	}
	if _, err := decodeGetport(binary.BigEndian.AppendUint32(nil, 70000)); !errors.Is(err, ErrBadXDR) {
		t.Fatal("port above 65535 accepted")
	}
	if got := hex.EncodeToString(encodeGetport(100005, 3)); got != "000186a50000000300000006"+"00000000" {
		t.Fatalf("GETPORT args %s (prot must be IPPROTO_TCP=6)", got)
	}
}

func TestDecodeMnt(t *testing.T) {
	var e encoder
	e.u32(0)
	e.opaque([]byte{1, 2, 3, 4, 5})
	e.u32(2)
	e.u32(1)
	e.u32(390003)
	fh, fl, err := decodeMnt("/x", e.b)
	if err != nil || !bytes.Equal(fh, []byte{1, 2, 3, 4, 5}) || len(fl) != 2 || fl[1] != 390003 {
		t.Fatalf("%v %v %v", fh, fl, err)
	}
	var me *MountError
	e = encoder{}
	e.u32(mnt3ErrAcces)
	if _, _, err = decodeMnt("/x", e.b); !errors.As(err, &me) || me.Status != 13 {
		t.Fatalf("access refusal: %v", err)
	}
	e = encoder{}
	e.u32(0)
	e.opaque(make([]byte, 65)) // handle longer than NFS3_FHSIZE
	e.u32(0)
	if _, _, err = decodeMnt("/x", e.b); !errors.Is(err, ErrBadXDR) {
		t.Fatalf("65-byte handle accepted: %v", err)
	}
	e = encoder{}
	e.u32(0)
	e.opaque(nil)
	e.u32(0)
	if _, _, err = decodeMnt("/x", e.b); !errors.Is(err, ErrBadXDR) {
		t.Fatalf("empty handle accepted: %v", err)
	}
}

func TestDecodeExports(t *testing.T) {
	var e encoder
	e.boolean(true)
	e.str("/a")
	e.boolean(true)
	e.str("10.0.0.0/8")
	e.boolean(true)
	e.str("host")
	e.boolean(false)
	e.boolean(true)
	e.str("/b")
	e.boolean(false)
	e.boolean(false)
	ex, err := decodeExports(e.b)
	if err != nil || len(ex) != 2 || ex[0].Path != "/a" || len(ex[0].Groups) != 2 || ex[1].Path != "/b" || len(ex[1].Groups) != 0 {
		t.Fatalf("%+v %v", ex, err)
	}
	if _, err := decodeExports(e.b[:len(e.b)-4]); err == nil {
		t.Fatal("truncated export list accepted")
	}
	if ex, err := decodeExports([]byte{0, 0, 0, 0}); err != nil || len(ex) != 0 {
		t.Fatalf("empty list: %v %v", ex, err)
	}
}

func TestDecodeReadChecks(t *testing.T) {
	mk := func(count uint32, eof bool, data []byte) []byte {
		var e encoder
		e.u32(0)
		e.boolean(false)
		e.u32(count)
		e.boolean(eof)
		e.opaque(data)
		return e.b
	}
	d, eof, err := decodeRead(mk(3, true, []byte("abc")), 10)
	if err != nil || string(d) != "abc" || !eof {
		t.Fatal(string(d), eof, err)
	}
	if _, _, err = decodeRead(mk(3, true, []byte("abcd")), 10); !errors.Is(err, ErrBadXDR) {
		t.Errorf("count/data mismatch accepted: %v", err)
	}
	if _, _, err = decodeRead(mk(11, true, make([]byte, 11)), 10); !errors.Is(err, ErrBadXDR) {
		t.Errorf("more data than asked accepted: %v", err)
	}
	var e encoder
	e.u32(NFS3ErrStale)
	var ne *NFSError
	if _, _, err = decodeRead(e.b, 10); !errors.As(err, &ne) || ne.Status != NFS3ErrStale {
		t.Errorf("status: %v", err)
	}
}

func TestDecodeReaddirplusEntries(t *testing.T) {
	var e encoder
	e.u32(0)
	e.boolean(false)
	e.fixed([]byte("VERF1234"))
	for i, n := range []string{"x", "yy"} {
		e.boolean(true)
		e.u64(uint64(i + 10))
		e.str(n)
		e.u64(uint64(i + 100))
		e.boolean(true)
		e.fattr(sampleAttr())
		e.boolean(i == 0)
		if i == 0 {
			e.opaque([]byte{9, 9})
		}
	}
	e.boolean(false)
	e.boolean(true)
	pg, err := decodeReaddirplus(e.b)
	if err != nil || !pg.EOF || string(pg.Verf[:]) != "VERF1234" || len(pg.Entries) != 2 {
		t.Fatalf("%+v %v", pg, err)
	}
	if pg.Entries[0].Handle == nil || pg.Entries[1].Handle != nil || pg.Entries[1].Name != "yy" || pg.Entries[0].Cookie != 100 || pg.Entries[0].Attr == nil {
		t.Fatalf("entries %+v", pg.Entries)
	}
	for cut := 0; cut < len(e.b); cut += 7 {
		if _, err := decodeReaddirplus(e.b[:cut]); err == nil {
			t.Fatalf("truncation at %d accepted", cut)
		}
	}
}
