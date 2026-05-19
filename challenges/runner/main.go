// Round-246 challenge runner for Filesystem.
//
// Builds the bilingual fixture set from challenges/fixtures/{en,sr-Latn}.yaml,
// constructs a real local-protocol Filesystem client via the public factory,
// writes every declared file + directory into a freshly-created temp tree,
// reads every file back, and verifies content bytes match the source bytes
// byte-for-byte (including UTF-8 multi-byte sequences in filenames + bodies).
//
// Anti-bluff invariants enforced by this runner (Article XI §11.9 / CONST-035):
//
//   - No metadata-only / grep-only PASS. Every PASS line is preceded by
//     the actual file path, the actual byte count, and the actual UTF-8
//     comparison outcome.
//   - Failing to write, byte-corrupting a body, losing a file, or returning
//     wrong FileInfo is a hard FAIL — exit non-zero.
//   - The runner runs in process, real Filesystem `local` client, real
//     os.File reads/writes — no mocks, no stubs, no "for now" placeholders.
//   - The temp tree is cleaned up only on PASS; on FAIL it is preserved
//     under /tmp for forensic inspection per §11.4.2.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/factory"
)

// fixture is a minimal YAML subset we can parse without an external dep —
// the schema is deliberately small (locale + description + files[] +
// directories[]) so a 60-line hand-roll parser suffices and we avoid
// pulling gopkg.in/yaml.v3 into the runner's dependency surface.
type fixture struct {
	Locale      string
	Description string
	Files       []fixtureFile
	Directories []string
}

type fixtureFile struct {
	Path    string
	Content string
}

func main() {
	dir := flag.String(
		"fixtures",
		"",
		"directory holding *.yaml fixture files",
	)
	flag.Parse()

	if *dir == "" {
		fail("missing -fixtures <dir>")
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		fail("cannot read fixtures dir %q: %v", *dir, err)
	}

	var fixtures []fixture
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(*dir, e.Name())
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			fail("cannot read fixture %q: %v", path, rerr)
		}
		fix, perr := parseFixture(string(raw))
		if perr != nil {
			fail("cannot parse fixture %q: %v", path, perr)
		}
		fixtures = append(fixtures, fix)
	}
	if len(fixtures) == 0 {
		fail("no fixtures found under %q", *dir)
	}

	pass := 0
	failures := 0
	preservedRoot := ""

	for _, fx := range fixtures {
		root, err := os.MkdirTemp("", "fs-round246-"+fx.Locale+"-")
		if err != nil {
			fail("mkdir temp: %v", err)
		}

		f := factory.NewDefaultFactory()
		cl, err := f.CreateClient(&client.StorageConfig{
			ID:       "round-246-" + fx.Locale,
			Name:     "Round-246 " + fx.Locale,
			Protocol: "local",
			Enabled:  true,
			Settings: map[string]interface{}{"base_path": root},
		})
		if err != nil {
			fmt.Printf("FAIL [%s] factory.CreateClient: %v\n", fx.Locale, err)
			failures++
			preservedRoot = root
			continue
		}

		ctx := context.Background()
		if cerr := cl.Connect(ctx); cerr != nil {
			fmt.Printf("FAIL [%s] Connect: %v\n", fx.Locale, cerr)
			failures++
			preservedRoot = root
			continue
		}

		localeFailed := false

		// Create declared directories.
		for _, d := range fx.Directories {
			if derr := cl.CreateDirectory(ctx, d); derr != nil {
				fmt.Printf(
					"FAIL [%s] CreateDirectory %q: %v\n",
					fx.Locale, d, derr,
				)
				failures++
				localeFailed = true
				continue
			}
		}

		// Write + read-back + byte-compare every fixture file.
		for _, ff := range fx.Files {
			body := []byte(ff.Content)
			if werr := cl.WriteFile(ctx, ff.Path, bytes.NewReader(body)); werr != nil {
				fmt.Printf(
					"FAIL [%s] WriteFile %q: %v\n",
					fx.Locale, ff.Path, werr,
				)
				failures++
				localeFailed = true
				continue
			}

			exists, exerr := cl.FileExists(ctx, ff.Path)
			if exerr != nil || !exists {
				fmt.Printf(
					"FAIL [%s] FileExists %q: exists=%v err=%v\n",
					fx.Locale, ff.Path, exists, exerr,
				)
				failures++
				localeFailed = true
				continue
			}

			rc, rerr := cl.ReadFile(ctx, ff.Path)
			if rerr != nil {
				fmt.Printf(
					"FAIL [%s] ReadFile %q: %v\n",
					fx.Locale, ff.Path, rerr,
				)
				failures++
				localeFailed = true
				continue
			}
			got, gerr := io.ReadAll(rc)
			_ = rc.Close()
			if gerr != nil {
				fmt.Printf(
					"FAIL [%s] ReadAll %q: %v\n",
					fx.Locale, ff.Path, gerr,
				)
				failures++
				localeFailed = true
				continue
			}
			if !bytes.Equal(got, body) {
				fmt.Printf(
					"FAIL [%s] byte-drift %q: want=%d got=%d bytes\n",
					fx.Locale, ff.Path, len(body), len(got),
				)
				failures++
				localeFailed = true
				continue
			}

			info, ierr := cl.GetFileInfo(ctx, ff.Path)
			if ierr != nil || info == nil {
				fmt.Printf(
					"FAIL [%s] GetFileInfo %q: %v\n",
					fx.Locale, ff.Path, ierr,
				)
				failures++
				localeFailed = true
				continue
			}
			if info.Size != int64(len(body)) {
				fmt.Printf(
					"FAIL [%s] GetFileInfo size drift %q: want=%d got=%d\n",
					fx.Locale, ff.Path, len(body), info.Size,
				)
				failures++
				localeFailed = true
				continue
			}

			fmt.Printf(
				"PASS [%s] path=%q bytes=%d utf8=ok size-info=%d\n",
				fx.Locale, ff.Path, len(body), info.Size,
			)
			pass++
		}

		// List directory root to prove ListDirectory works on the
		// tree we just built.
		entries, lerr := cl.ListDirectory(ctx, ".")
		if lerr != nil {
			fmt.Printf("FAIL [%s] ListDirectory root: %v\n", fx.Locale, lerr)
			failures++
			localeFailed = true
		} else {
			fmt.Printf(
				"PASS [%s] ListDirectory root entries=%d\n",
				fx.Locale, len(entries),
			)
			pass++
		}

		_ = cl.Disconnect(ctx)

		if localeFailed {
			preservedRoot = root
		} else {
			_ = os.RemoveAll(root)
		}
	}

	fmt.Printf(
		"\nSummary: %d PASS, %d FAIL across %d locale(s)\n",
		pass, failures, len(fixtures),
	)
	if preservedRoot != "" {
		fmt.Printf("Forensic temp tree preserved at: %s\n", preservedRoot)
	}
	if failures > 0 {
		os.Exit(1)
	}
}

// parseFixture parses the minimal hand-rolled YAML subset used by the
// round-246 fixtures. Supported shape:
//
//   locale: <string>
//   description: <string>
//   files:
//     - path: <string>
//       content: |
//         <line>
//         <line>
//   directories:
//     - <string>
//
// Comments starting with '#' are stripped. Indentation must be 2 spaces.
func parseFixture(src string) (fixture, error) {
	var fx fixture
	lines := strings.Split(src, "\n")

	type section int
	const (
		sectionNone section = iota
		sectionFiles
		sectionDirs
	)

	var cur section
	var curFile *fixtureFile
	var inBlockScalar bool
	var blockBuf strings.Builder
	var blockIndent int

	flushBlock := func() {
		if curFile != nil && inBlockScalar {
			curFile.Content = blockBuf.String()
			blockBuf.Reset()
			inBlockScalar = false
		}
	}

	for _, raw := range lines {
		// Block-scalar mode: capture until a non-indented line appears.
		if inBlockScalar {
			if strings.TrimSpace(raw) == "" {
				blockBuf.WriteString("\n")
				continue
			}
			leading := len(raw) - len(strings.TrimLeft(raw, " "))
			if leading >= blockIndent {
				blockBuf.WriteString(raw[blockIndent:])
				blockBuf.WriteString("\n")
				continue
			}
			flushBlock()
			// fall through to normal parsing of this line
		}

		// Strip full-line comments.
		trimmed := strings.TrimRight(raw, " \t")
		if t := strings.TrimSpace(trimmed); strings.HasPrefix(t, "#") || t == "" {
			continue
		}

		// Top-level keys.
		if strings.HasPrefix(trimmed, "locale:") {
			fx.Locale = strings.TrimSpace(strings.TrimPrefix(trimmed, "locale:"))
			cur = sectionNone
			continue
		}
		if strings.HasPrefix(trimmed, "description:") {
			fx.Description = strings.TrimSpace(strings.TrimPrefix(trimmed, "description:"))
			cur = sectionNone
			continue
		}
		if trimmed == "files:" {
			cur = sectionFiles
			curFile = nil
			continue
		}
		if trimmed == "directories:" {
			cur = sectionDirs
			curFile = nil
			continue
		}

		switch cur {
		case sectionFiles:
			if strings.HasPrefix(trimmed, "  - path:") {
				// Start of new file entry.
				flushBlock()
				path := strings.TrimSpace(strings.TrimPrefix(trimmed, "  - path:"))
				path = strings.Trim(path, "\"'")
				fx.Files = append(fx.Files, fixtureFile{Path: path})
				curFile = &fx.Files[len(fx.Files)-1]
			} else if strings.HasPrefix(trimmed, "    content:") {
				if curFile == nil {
					return fx, fmt.Errorf("content without preceding path")
				}
				value := strings.TrimSpace(strings.TrimPrefix(trimmed, "    content:"))
				if value == "|" {
					inBlockScalar = true
					blockBuf.Reset()
					blockIndent = 6 // 4 spaces + 2 for the block indent
				} else {
					// Inline string value.
					value = strings.Trim(value, "\"'")
					curFile.Content = value
				}
			}
		case sectionDirs:
			if strings.HasPrefix(trimmed, "  - ") {
				dir := strings.TrimSpace(strings.TrimPrefix(trimmed, "  - "))
				dir = strings.Trim(dir, "\"'")
				fx.Directories = append(fx.Directories, dir)
			}
		}
	}
	// Final flush.
	if inBlockScalar && curFile != nil {
		curFile.Content = blockBuf.String()
	}

	if fx.Locale == "" {
		return fx, fmt.Errorf("missing required key: locale")
	}
	if len(fx.Files) == 0 {
		return fx, fmt.Errorf("fixture has zero files")
	}
	return fx, nil
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "runner-error: "+format+"\n", args...)
	os.Exit(2)
}
