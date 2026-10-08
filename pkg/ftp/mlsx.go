package ftp

// Listing parsers. RFC 3659 (MLSD / MLST) is parsed here, not by the FTP library, because the library drops
// every line it cannot parse without a signal (WF21 F6). Rules (all measured against the library as defects):
//
//   - the facts end at the first "; " (a semicolon followed by the separator space); a fact VALUE may contain
//     spaces ("UNIX.group=Domain Users") and the name may start with spaces;
//   - fact names and the values of "type" are case-insensitive;
//   - "size" is decimal (a leading zero is not octal), an unreadable size is an ERROR, never a dropped entry;
//   - "type=cdir" / "pdir" are the directory itself and its parent: skipped by TYPE, whatever name they carry;
//   - "type=OS.unix=symlink" / "slink" is a symbolic link;
//   - an entry with an empty fact list (" name") is legal;
//   - "modify" is UTC, with optional fractional seconds; an unreadable or absent value is the zero time, never "now".
//
// A line that cannot be understood makes the listing fail with ErrListingIncomplete after the transfer was read to
// its end: a partial listing is never returned as complete.

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type entryKind int

const (
	kindFile entryKind = iota
	kindDir
	kindLink
	kindOther
	kindSelf   // cdir
	kindParent // pdir
)

type entry struct {
	name  string
	size  int64
	kind  entryKind
	mtime time.Time
}

func (e *entry) mode() os.FileMode {
	switch e.kind {
	case kindDir, kindSelf, kindParent:
		return os.ModeDir
	case kindLink:
		return os.ModeSymlink
	case kindOther:
		return os.ModeIrregular
	}
	return 0
}

func parseMLTime(v string) (time.Time, bool) {
	if len(v) < 14 {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("20060102150405", v[:14], time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	if rest := v[14:]; rest != "" {
		if rest[0] != '.' || len(rest) == 1 || !isDigits(rest[1:]) {
			return time.Time{}, false
		}
		frac, err := strconv.ParseFloat("0"+rest, 64)
		if err != nil {
			return time.Time{}, false
		}
		t = t.Add(time.Duration(frac * float64(time.Second)))
	}
	return t, true
}

func classifyMLType(v string) entryKind {
	switch l := strings.ToLower(v); {
	case l == "file":
		return kindFile
	case l == "dir":
		return kindDir
	case l == "cdir":
		return kindSelf
	case l == "pdir":
		return kindParent
	case strings.HasPrefix(l, "os.unix=slink"), strings.HasPrefix(l, "os.unix=symlink"):
		return kindLink
	}
	return kindOther
}

// parseMLEntry parses one MLSD data line or one MLST entry line (without its single leading space).
func parseMLEntry(line string) (*entry, error) {
	var facts, name string
	if strings.HasPrefix(line, " ") {
		name = line[1:] // no facts at all
	} else {
		i := strings.Index(line, "; ")
		if i < 0 {
			return nil, fmt.Errorf("%w: %q", ErrListingIncomplete, flat(line))
		}
		facts, name = line[:i], line[i+2:]
	}
	if name == "" {
		return nil, fmt.Errorf("%w: entry without a name: %q", ErrListingIncomplete, flat(line))
	}
	e := &entry{name: name, kind: kindFile}
	for _, f := range strings.Split(facts, ";") {
		if f == "" {
			continue
		}
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return nil, fmt.Errorf("%w: fact without a value in %q", ErrListingIncomplete, flat(line))
		}
		switch strings.ToLower(k) {
		case "type":
			e.kind = classifyMLType(v)
		case "size":
			u, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: unreadable size %q for %q", ErrListingIncomplete, flat(v), flat(name))
			}
			e.size = clampSize(u)
		case "modify":
			if t, ok := parseMLTime(v); ok {
				e.mtime = t
			}
		}
	}
	return e, nil
}

// mlstEntries extracts the entries of an MLST reply (the lines between the first and the last).
func mlstEntries(lines []string) ([]*entry, error) {
	if len(lines) < 3 {
		return nil, fmt.Errorf("%w: MLST reply has no entry", ErrListingIncomplete)
	}
	var out []*entry
	for _, l := range lines[1 : len(lines)-1] {
		if l == "" {
			continue
		}
		e, err := parseMLEntry(strings.TrimPrefix(l, " "))
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

var (
	unixList = regexp.MustCompile(`^([\-dlbcps])[rwxsStTl\-]{9}[+@.]?\s+\d+\s+\S+\s+\S+\s+(\d+)\s+[A-Za-z]{3}\s+\d{1,2}\s+(?:\d{1,2}:\d{2}|\d{4})\s(.+)$`)
	dosList  = regexp.MustCompile(`^\d{2}-\d{2}-\d{2,4}\s+\d{1,2}:\d{2}(?:AM|PM)?\s+(<DIR>|\d+)\s+(.+)$`)
)

// parseListLine parses one line of a LIST reply (Unix "ls -l" and DOS formats). Times are never read: the
// degraded listing reports no modification time. ok=false with a nil error means "not an entry" (a "total" line).
func parseListLine(line string) (e *entry, skip bool, err error) {
	line = strings.TrimRight(line, " ")
	if strings.HasPrefix(line, "total ") || line == "" {
		return nil, true, nil
	}
	if m := unixList.FindStringSubmatch(line); m != nil {
		size, _ := strconv.ParseUint(m[2], 10, 64)
		e = &entry{name: m[3], size: clampSize(size)}
		switch m[1] {
		case "d":
			e.kind = kindDir
		case "l":
			e.kind = kindLink
			if i := strings.Index(e.name, " -> "); i >= 0 {
				e.name = e.name[:i]
			}
		case "-":
			e.kind = kindFile
		default:
			e.kind = kindOther
		}
		return e, false, nil
	}
	if m := dosList.FindStringSubmatch(line); m != nil {
		e = &entry{name: m[2]}
		if m[1] == "<DIR>" {
			e.kind = kindDir
		} else {
			size, _ := strconv.ParseUint(m[1], 10, 64)
			e.size = clampSize(size)
		}
		return e, false, nil
	}
	return nil, false, fmt.Errorf("%w: %q", ErrListingIncomplete, flat(line))
}

// classify550 decides what a 550 reply says: the object is absent, access is denied, or the text does not tell.
type kind550 int

const (
	k550Unknown kind550 = iota
	k550Absent
	k550Denied
)

func classify550(msg string) kind550 {
	m := strings.ToLower(msg)
	for _, s := range []string{"permission", "denied", "not permitted", "forbidden", "not allowed", "privilege", "read-only", "read only"} {
		if strings.Contains(m, s) {
			return k550Denied
		}
	}
	for _, s := range []string{"no such", "not found", "does not exist", "doesn't exist", "not exist", "no file", "nonexistent", "non-existent"} {
		if strings.Contains(m, s) {
			return k550Absent
		}
	}
	return k550Unknown
}
