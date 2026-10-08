package fabric

import (
	"context"
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"digital.vasic.filesystem/pkg/client"
)

// Confined returns a client that only lets paths inside root reach inner.
//
// Every path argument is normalised first: backslashes are treated as
// separators (SMB), any control character (Unicode category Cc: C0 including
// NUL, CR, LF and ESC, DEL, and the C1 controls U+0080..U+009F such as NEL and
// CSI) and any byte sequence that is not valid UTF-8 (a raw 0x85 or 0x9B is the
// 8-bit form of NEL and CSI on some terminals) is refused, relative paths are taken relative
// to root, and the result is path.Clean-ed. The cleaned path must equal root
// or lie below root at a segment boundary ("/data/media2" is NOT inside
// "/data/media"). The inner client receives the cleaned path, so it never
// sees "." or ".." segments. An escaping path fails with ErrOutsideRoot and
// the inner client is not called; CopyFile checks both paths before touching
// either. Connection-level operations carry no path and pass through.
//
// root must be absolute ("/" allows any absolute path); it is cleaned the
// same way. Case is compared exactly, which is stricter than case-insensitive
// servers and therefore safe.
func Confined(inner client.Client, root string) (client.Client, error) {
	r, err := normalise("", root, true)
	if err != nil {
		return nil, fmt.Errorf("fabric: invalid confinement root %q: %w", root, err)
	}
	return newLayer(inner, func(ctx context.Context, st *callState, paths []string, call func(context.Context, []string) error) error {
		if len(paths) == 0 {
			return call(ctx, paths)
		}
		clean := make([]string, len(paths))
		for i, p := range paths {
			c, err := normalise(r, p, false)
			if err != nil {
				return fmt.Errorf("%w: %s %q: %w", ErrOutsideRoot, st.op, p, err)
			}
			clean[i] = c
		}
		return call(ctx, clean)
	}), nil
}

// normalise returns the cleaned absolute form of p, resolved against root when
// p is relative, and checks containment when root != "". For the root itself
// (isRoot) p must be absolute.
func normalise(root, p string, isRoot bool) (string, error) {
	if !utf8.ValidString(p) {
		return "", fmt.Errorf("path is not valid UTF-8")
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			// NUL, CR, LF, ESC and the rest of C0, DEL and C1: a protocol that
			// frames commands as text could read them as a second command, and a
			// terminal that shows the path could read them as an escape sequence.
			return "", fmt.Errorf("control character %U in path", r)
		}
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if isRoot && !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("root must be absolute")
	}
	if !strings.HasPrefix(p, "/") {
		p = root + "/" + p
	}
	c := path.Clean(p)
	if isRoot {
		return c, nil
	}
	if root == "/" || c == root || strings.HasPrefix(c, root+"/") {
		return c, nil
	}
	return "", fmt.Errorf("resolves to %q", c)
}
