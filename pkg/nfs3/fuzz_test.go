package nfs3

import (
	"bufio"
	"bytes"
	"testing"
)

// seedReplies are valid encodings the fuzzer mutates.
func seedReplies() [][]byte {
	var out [][]byte
	var e encoder
	e.u32(0)
	e.boolean(true)
	e.fattr(sampleAttr())
	e.fixed([]byte("VERF1234"))
	e.boolean(true)
	e.u64(5)
	e.str("name")
	e.u64(6)
	e.boolean(true)
	e.fattr(sampleAttr())
	e.boolean(true)
	e.opaque([]byte{1, 2, 3})
	e.boolean(false)
	e.boolean(true)
	out = append(out, e.b)
	e = encoder{}
	e.u32(0)
	e.opaque([]byte{1, 2, 3, 4})
	e.u32(1)
	e.u32(1)
	out = append(out, e.b)
	e = encoder{}
	e.boolean(true)
	e.str("/export")
	e.boolean(true)
	e.str("grp")
	e.boolean(false)
	e.boolean(false)
	out = append(out, e.b)
	e = encoder{}
	e.u32(0)
	e.boolean(false)
	e.u32(4)
	e.boolean(true)
	e.opaque([]byte("data"))
	out = append(out, e.b)
	out = append(out, append(replyHdr(1, msgAccepted, 0, 0, acceptSuccess), 0, 0, 0, 1))
	return out
}

// FuzzDecoders feeds arbitrary bytes to every decoder. Invariants: no panic,
// and nothing returned is larger than the input (no allocation amplification).
func FuzzDecoders(f *testing.F) {
	for _, s := range seedReplies() {
		f.Add(s)
	}
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		if a, err := newDecoder(data).fattr(); err == nil && a.Type == 0 {
			t.Fatal("fattr accepted ftype3 0")
		}
		_, _ = newDecoder(data).postOpAttr()
		if pg, err := decodeReaddirplus(data); err == nil {
			total := 0
			for _, en := range pg.Entries {
				total += len(en.Name) + len(en.Handle)
			}
			if total > len(data) {
				t.Fatalf("readdirplus amplification: %d bytes from %d", total, len(data))
			}
		}
		if fh, fl, err := decodeMnt("/p", data); err == nil && (len(fh) > fhSizeMax || len(fl) > flavorsMax) {
			t.Fatal("mnt limits exceeded")
		}
		if ex, err := decodeExports(data); err == nil && len(ex) > len(data) {
			t.Fatalf("exports amplification")
		}
		if d, _, err := decodeRead(data, 1<<16); err == nil && len(d) > len(data) {
			t.Fatal("read amplification")
		}
		_, _, _ = decodeLookup(data)
		_, _ = decodeAccess(data)
		_, _ = decodeGetattr(data)
		_, _ = decodeFsinfo(data)
		_, _ = decodeGetport(data)
		if res, err := parseReply(data, 1, 1); err == nil && len(res) > len(data) {
			t.Fatal("reply amplification")
		}
	})
}

// FuzzReadRecord checks the record-marking reader: bounded output, no panic.
func FuzzReadRecord(f *testing.F) {
	f.Add(frag(true, []byte("abc")))
	f.Add(append(frag(false, []byte("ab")), frag(true, []byte("cd"))...))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		br := bufio.NewReader(bytes.NewReader(data))
		for i := 0; i < 8; i++ {
			rec, err := readRecord(br, 1<<16)
			if err != nil {
				return
			}
			if len(rec) > len(data) {
				t.Fatalf("record %d bytes from %d", len(rec), len(data))
			}
		}
	})
}
