package sftp

// Byte-level builders for scripted SFTP replies (used by frame_test.go and fix_r2_test.go).

import "encoding/binary"

func u32b(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64b(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
func strb(s string) []byte { return append(u32b(uint32(len(s))), s...) }
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// wireFrame builds a complete frame: length, type, body.
func wireFrame(typ byte, body ...[]byte) []byte {
	b := cat(body...)
	return cat(u32b(uint32(1+len(b))), []byte{typ}, b)
}

func attrsB(flags uint32, parts ...[]byte) []byte { return cat(u32b(flags), cat(parts...)) }
