package ftp

// WF21 fix round 2: listing parsers (F6, MX08, MX14), 550 mapping (F7), degraded stat (F8) and the real-composition
// checks that need the fake server to model cwd, permission 550 and odd MLSD output.

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
)

func mlsdHook(lines []string, tail string) hookFn {
	return func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLSD" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = io.WriteString(dc, strings.Join(lines, "\r\n")+"\r\n")
		_ = dc.Close()
		ss.reply("%s", tail)
		return true, true
	}
}

func TestParseMLEntry_Table_F6(t *testing.T) {
	ts := time.Date(2020, 5, 17, 10, 30, 0, 0, time.UTC)
	cases := []struct {
		line   string
		name   string
		kind   entryKind
		size   int64
		mtime  time.Time
		failed bool
	}{
		{"Type=file;Size=5;Modify=20200517103000; plain.txt", "plain.txt", kindFile, 5, ts, false},
		{"type=file;size=7;modify=20200517103000; lower.txt", "lower.txt", kindFile, 7, ts, false},
		{"Type=file;Size=10;Modify=20200517103000.123; frac.txt", "frac.txt", kindFile, 10, ts.Add(123 * time.Millisecond), false},
		{"Type=Dir;Modify=20200517103000; UpperDir", "UpperDir", kindDir, 0, ts, false},
		{"TYPE=DIR;Modify=20200517103000; U2", "U2", kindDir, 0, ts, false},
		{"Type=OS.unix=symlink;Modify=20200517103000; link", "link", kindLink, 0, ts, false},
		{"Type=OS.unix=slink:/target;Modify=20200517103000; link2", "link2", kindLink, 0, ts, false},
		{"Type=file;Size=010;Modify=20200517103000; octal.txt", "octal.txt", kindFile, 10, ts, false}, // decimal, never octal
		{"Type=file;Size=08;Modify=20200517103000; zero8.txt", "zero8.txt", kindFile, 8, ts, false},
		{"Type=cdir;Modify=20200517103000; data", "data", kindSelf, 0, ts, false}, // named by its basename
		{"Type=pdir;Modify=20200517103000; up", "up", kindParent, 0, ts, false},
		{"Type=file;Size=3;UNIX.group=Domain Users;Modify=20200517103000; spaced.txt", "spaced.txt", kindFile, 3, ts, false},
		{" nofacts.txt", "nofacts.txt", kindFile, 0, time.Time{}, false},
		{"Type=file;Size=4;Modify=20200517103000;  two leading spaces.txt", " two leading spaces.txt", kindFile, 4, ts, false},
		{"Type=file;Size=4;Modify=20200517103000; trailing dot.", "trailing dot.", kindFile, 4, ts, false},
		{"Type=file;Size=4;Modify=20200517103000; a; b.txt", "a; b.txt", kindFile, 4, ts, false}, // "; " inside the name
		{"Type=file;Size=1;Modify=garbage; badtime.txt", "badtime.txt", kindFile, 1, time.Time{}, false},
		{"Type=file;Size=1; nomodify.txt", "nomodify.txt", kindFile, 1, time.Time{}, false},
		{"Type=OS.unix=socket; sock", "sock", kindOther, 0, time.Time{}, false},
		{"Type=file;Size=-1; neg.txt", "", 0, 0, time.Time{}, true},
		{"Type=file;Size=12x; bad.txt", "", 0, 0, time.Time{}, true},
		{"Type=file;Size=1;Modify=20200517103000 noseparator.txt", "", 0, 0, time.Time{}, true},
		{"Type=file;Size", "", 0, 0, time.Time{}, true},
		{"Type=file; ", "", 0, 0, time.Time{}, true},
	}
	for _, c := range cases {
		e, err := parseMLEntry(c.line)
		if c.failed {
			require.ErrorIs(t, err, ErrListingIncomplete, c.line)
			continue
		}
		require.NoError(t, err, c.line)
		assert.Equal(t, c.name, e.name, c.line)
		assert.Equal(t, c.kind, e.kind, c.line)
		assert.Equal(t, c.size, e.size, c.line)
		assert.True(t, e.mtime.Equal(c.mtime), "%s: %v", c.line, e.mtime)
	}
	assert.Equal(t, os.ModeSymlink, (&entry{kind: kindLink}).mode())
	assert.Equal(t, os.ModeDir, (&entry{kind: kindDir}).mode())
	assert.Equal(t, os.FileMode(0), (&entry{kind: kindFile}).mode())
	assert.Equal(t, os.ModeIrregular, (&entry{kind: kindOther}).mode())
}

func TestParseListLine_UnixDosAndGarbage(t *testing.T) {
	e, skip, err := parseListLine("-rw-r--r-- 1 u g 10 May 17  2020 a.txt")
	require.NoError(t, err)
	require.False(t, skip)
	assert.Equal(t, "a.txt", e.name)
	assert.Equal(t, int64(10), e.size)
	assert.Equal(t, kindFile, e.kind)
	e, _, err = parseListLine("drwxr-xr-x 2 root root 4096 Jan 01 12:30 My Dir")
	require.NoError(t, err)
	assert.Equal(t, "My Dir", e.name)
	assert.Equal(t, kindDir, e.kind)
	e, _, err = parseListLine("lrwxrwxrwx 1 u g 4 Jan 01 12:30 link -> target")
	require.NoError(t, err)
	assert.Equal(t, "link", e.name)
	assert.Equal(t, kindLink, e.kind)
	e, _, err = parseListLine("05-17-20  10:30AM       <DIR>          sub dir")
	require.NoError(t, err)
	assert.Equal(t, "sub dir", e.name)
	assert.Equal(t, kindDir, e.kind)
	e, _, err = parseListLine("05-17-2020  01:30PM              1234 file.bin")
	require.NoError(t, err)
	assert.Equal(t, int64(1234), e.size)
	_, skip, err = parseListLine("total 12")
	require.NoError(t, err)
	assert.True(t, skip)
	_, _, err = parseListLine("this is not a listing line")
	require.ErrorIs(t, err, ErrListingIncomplete)
}

func TestClassify550(t *testing.T) {
	for msg, want := range map[string]kind550{
		"No such file or directory":              k550Absent,
		"/x: file not found":                     k550Absent,
		"File does not exist":                    k550Absent,
		"Permission denied":                      k550Denied,
		"/data/a.txt: Permission denied":         k550Denied,
		"Access is denied":                       k550Denied,
		"Operation not permitted":                k550Denied,
		"Failed to open file.":                   k550Unknown,
		"Can't open file":                        k550Unknown,
		"Not found, permission denied for guest": k550Denied, // denial wins: never report an ACL problem as absence
	} {
		assert.Equal(t, want, classify550(msg), msg)
	}
}

func TestList_RealisticMLSD_ParsedWithoutLoss_D7(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	lines := []string{
		"Type=cdir;Modify=20200517103000; .",
		"Type=pdir;Modify=20200517103000; ..",
		"Type=cdir;Modify=20200517103000; data",
		"Type=file;Size=5;Modify=20200517103000; plain.txt",
		"type=file;size=7;modify=20200517103000; lower.txt",
		"Type=file;Size=10;Modify=20200517103000.123; frac.txt",
		"Type=Dir;Modify=20200517103000; UpperDir",
		"Type=OS.unix=symlink;Modify=20200517103000; link",
		"Type=file;Size=010;Modify=20200517103000; octal.txt",
		"Type=file;Size=08;Modify=20200517103000; badoctal.txt",
		"Type=file;Size=3;UNIX.group=Domain Users;Modify=20200517103000; spaced.txt",
		" nofacts.txt",
		"Type=file;Size=4;Modify=20200517103000;  two leading spaces.txt",
		"Type=file;Size=4;Modify=20200517103000; trailing dot.",
		"Type=file;Size=1;Modify=20200517103000; evil/../x",
		"Type=file;Size=1;Modify=20200517103000; nul\x00x",
		"Type=file;Size=1;Modify=20200517103000; ..",
	}
	s.setHook(mlsdHook(lines, "226 done"))
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	by := map[string]*client.FileInfo{}
	for _, f := range got {
		by[f.Name] = f
	}
	for _, n := range []string{"plain.txt", "lower.txt", "frac.txt", "UpperDir", "link", "octal.txt", "badoctal.txt", "spaced.txt", "nofacts.txt", " two leading spaces.txt", "trailing dot."} {
		require.Contains(t, by, n)
	}
	assert.NotContains(t, by, "data", "the cdir entry is the directory itself, not a child")
	assert.NotContains(t, by, ".")
	assert.NotContains(t, by, "..")
	assert.Len(t, got, 11, "a name with '/' or NUL is a hostile entry and is skipped (MX08); nothing else is lost")
	assert.True(t, by["UpperDir"].IsDir)
	assert.Equal(t, os.ModeDir, by["UpperDir"].Mode)
	assert.False(t, by["link"].IsDir)
	assert.Equal(t, os.ModeSymlink, by["link"].Mode, "MX14: symlinks carry ModeSymlink")
	assert.Equal(t, int64(10), by["octal.txt"].Size, "decimal, not octal")
	assert.Equal(t, int64(8), by["badoctal.txt"].Size)
	assert.True(t, by["spaced.txt"].ModTime.Equal(t0), "a space inside a fact value does not corrupt the name or lose Modify: %v", by["spaced.txt"].ModTime)
	assert.True(t, by["frac.txt"].ModTime.Equal(t0.Add(123*time.Millisecond)))
	assert.True(t, by["nofacts.txt"].ModTime.IsZero())
	assert.Equal(t, "/spaced.txt", by["spaced.txt"].Path)
}

func TestList_UnparseableLine_FailsTheListing_ButKeepsTheConnectionInStep_F6(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(mlsdHook([]string{"Type=file;Size=5;Modify=20200517103000; ok.txt", "Type=file;Size=zz; broken.txt", "Type=file;Size=6; also-ok.txt"}, "226 done"))
	got, err := c.ListDirectory(ctx5(t), "/")
	require.ErrorIs(t, err, ErrListingIncomplete, "a partial listing is never returned as complete")
	assert.Nil(t, got)
	s.setHook(nil)
	assert.True(t, c.IsConnected(), "the transfer was read to its end: the control channel is in step")
	_, err = c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.Equal(t, 1, s.ctrlConns)
}

func TestMLST_OddFacts_Parsed_F6(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLST" {
			return false, true
		}
		ss.reply("250-Listing %s", arg)
		ss.reply(" Type=Dir;Size=0;UNIX.group=Domain Users;Modify=20200517103000.5; %s", arg)
		ss.reply("250 End")
		return true, true
	})
	fi, err := c.GetFileInfo(ctx5(t), "sub")
	require.NoError(t, err)
	assert.True(t, fi.IsDir)
	assert.Equal(t, "sub", fi.Name)
	assert.True(t, fi.ModTime.Equal(t0.Add(500*time.Millisecond)), "%v", fi.ModTime)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "MLST" {
			ss.reply("250-Listing")
			ss.reply(" Type=file;Size=1x; %s", arg)
			ss.reply("250 End")
			return true, true
		}
		return false, true
	})
	_, err = c.GetFileInfo(ctx5(t), "a.txt")
	require.ErrorIs(t, err, ErrListingIncomplete)
}

// ---- F7: 550 ------------------------------------------------------------------------------------------------------

func TestPermission550_IsNotNonExistence_D18(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if (verb == "MLST" || verb == "RETR") && arg == "/data/a.txt" {
			ss.reply("550 /data/a.txt: Permission denied")
			return true, true
		}
		return false, true
	})
	ok, err := c.FileExists(ctx5(t), "a.txt")
	require.Error(t, err, "an existing file we may not read is not 'absent'")
	assert.False(t, ok)
	assert.ErrorIs(t, err, os.ErrPermission)
	assert.NotErrorIs(t, err, os.ErrNotExist)
	_, rerr := c.ReadFile(ctx5(t), "a.txt")
	require.Error(t, rerr)
	assert.ErrorIs(t, rerr, os.ErrPermission)
	assert.NotErrorIs(t, rerr, os.ErrNotExist)
	ok, err = c.FileExists(ctx5(t), "missing.txt")
	require.NoError(t, err)
	assert.False(t, ok, "a genuinely absent file is still false")
}

func TestAmbiguous550_IsSettledByTheParentListing(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "MLST" {
			ss.reply("550 Failed to open file.") // vsftpd style: says nothing
			return true, true
		}
		if verb == "RETR" {
			ss.reply("550 Failed to open file.")
			return true, true
		}
		return false, true
	})
	ok, err := c.FileExists(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.True(t, ok, "present in the parent listing: it exists")
	fi, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(10), fi.Size)
	ok, err = c.FileExists(ctx5(t), "nope.txt")
	require.NoError(t, err)
	assert.False(t, ok, "absent from a readable parent listing: it does not exist")
	_, rerr := c.ReadFile(ctx5(t), "a.txt")
	require.Error(t, rerr)
	assert.NotErrorIs(t, rerr, os.ErrNotExist, "an unreadable 550 is never reported as non-existence")
	// when the parent cannot be listed either, the ambiguity stays an error
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "MLST" || verb == "MLSD" {
			ss.reply("550 Failed to open file.")
			return true, true
		}
		return false, true
	})
	ok, err = c.FileExists(ctx5(t), "a.txt")
	require.Error(t, err)
	assert.False(t, ok)
	assert.NotErrorIs(t, err, os.ErrNotExist)
}

func TestListing550_Mapping(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	_, err := c.ListDirectory(ctx5(t), "missing-dir")
	require.Error(t, err)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "MLSD" {
			ss.reply("550 Permission denied")
			return true, true
		}
		return false, true
	})
	_, err = c.ListDirectory(ctx5(t), "/")
	assert.ErrorIs(t, err, os.ErrPermission)
	assert.True(t, c.IsConnected(), "an ordinary negative reply keeps the connection")
}

// ---- F8: degraded stat ---------------------------------------------------------------------------------------------

func TestDegradedStat_RootAndTopLevel_NeverUsesTheLoginDirectory_D10(t *testing.T) {
	t.Run("root_with_Path", func(t *testing.T) {
		s := newFakeServer(t)
		s.mlst = false
		c := connected(t, s, func(cfg *Config) { cfg.AllowDegradedList = true })
		fi, err := c.GetFileInfo(ctx5(t), "a.txt")
		require.NoError(t, err)
		assert.Equal(t, int64(10), fi.Size)
		root, err := c.GetFileInfo(ctx5(t), "/")
		require.NoError(t, err, "the scan root itself must exist")
		assert.True(t, root.IsDir)
		ok, err := c.FileExists(ctx5(t), "/")
		require.NoError(t, err)
		assert.True(t, ok)
		for _, cmd := range s.commands() {
			assert.NotEqual(t, "LIST", cmd, "LIST is never sent without an argument")
		}
	})
	t.Run("root_is_slash", func(t *testing.T) {
		s := newFakeServer(t)
		s.mlst = false
		c := connected(t, s, func(cfg *Config) { cfg.AllowDegradedList = true; cfg.Path = "" })
		root, err := c.GetFileInfo(ctx5(t), "/")
		require.NoError(t, err, "the FTP root itself exists; there is no parent to find it in")
		assert.True(t, root.IsDir)
		ok, err := c.FileExists(ctx5(t), "/")
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("no_Path_login_dir_is_not_the_ftp_root", func(t *testing.T) {
		s := newFakeServer(t)
		s.mlst = false
		s.setHome("/data") // the login directory is /data, the FTP root is /
		c := connected(t, s, func(cfg *Config) { cfg.AllowDegradedList = true; cfg.Path = "" })
		top, err := c.ListDirectory(ctx5(t), "/")
		require.NoError(t, err)
		var names []string
		for _, f := range top {
			names = append(names, f.Name)
		}
		require.NotContains(t, names, "a.txt", "control: /a.txt does not exist")
		_, err = c.GetFileInfo(ctx5(t), "a.txt")
		require.ErrorIs(t, err, os.ErrNotExist, "/a.txt does not exist; /data/a.txt is a different file")
		for _, cmd := range s.commands() {
			assert.NotEqual(t, "LIST", cmd)
		}
		assert.Contains(t, s.commands(), "LIST /")
	})
	t.Run("missing_root", func(t *testing.T) {
		s := newFakeServer(t)
		s.mlst = false
		c := connected(t, s, func(cfg *Config) { cfg.AllowDegradedList = true })
		_, err := c.GetFileInfo(ctx5(t), "nope/deeper.txt")
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestDegradedList_ParsesLISTLines(t *testing.T) {
	s := newFakeServer(t)
	s.mlst = false
	c := connected(t, s, func(cfg *Config) { cfg.AllowDegradedList = true })
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "LIST" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = io.WriteString(dc, "total 3\r\n-rw-r--r-- 1 u g 10 May 17  2020 a.txt\r\ndrwxr-xr-x 2 u g 4096 Jan 01 12:30 sub dir\r\nlrwxrwxrwx 1 u g 3 Jan 01 12:30 l -> a.txt\r\n")
		_ = dc.Close()
		ss.reply("226 done")
		return true, true
	})
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "sub dir", got[1].Name)
	assert.True(t, got[1].IsDir)
	assert.Equal(t, os.ModeSymlink, got[2].Mode)
	for _, f := range got {
		assert.True(t, f.ModTime.IsZero())
	}
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "LIST" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = io.WriteString(dc, "-rw-r--r-- 1 u g 10 May 17  2020 a.txt\r\nthis line is not a listing\r\n")
		_ = dc.Close()
		ss.reply("226 done")
		return true, true
	})
	_, err = c.ListDirectory(ctx5(t), "/")
	require.ErrorIs(t, err, ErrListingIncomplete)
}

// ---- misc ---------------------------------------------------------------------------------------------------------------

func TestSeekable_OpenAndReadWholeFile_NoSpuriousErrors(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	sk, err := c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	all, err := io.ReadAll(sk)
	require.NoError(t, err)
	assert.Equal(t, seqBytes(100000), all)
	require.NoError(t, sk.Close())
	// seek-heavy use keeps ONE control connection while the server answers an early close with one reply
	sk, err = c.OpenSeekable(ctx5(t), "big.bin")
	require.NoError(t, err)
	buf := make([]byte, 100)
	for _, off := range []int64{0, 5000, 90000, 100, 99000} {
		_, err = sk.Seek(off, io.SeekStart)
		require.NoError(t, err)
		_, err = io.ReadFull(sk, buf)
		require.NoError(t, err)
		assert.Equal(t, seqBytes(100000)[off:off+100], buf)
	}
	require.NoError(t, sk.Close())
	assert.Equal(t, 1, s.ctrlConns)
}

func TestWriteFile_ZeroByteUploadOverTLS_AndFailureModes(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	require.NoError(t, c.WriteFile(ctx5(t), "empty.bin", strings.NewReader("")))
	f, ok := s.has("/data/empty.bin")
	require.True(t, ok)
	assert.Empty(t, f.data)
	// a failing source reader aborts the upload and the connection is not reused
	err := c.WriteFile(ctx5(t), "bad.bin", errReader{})
	require.Error(t, err)
	assert.False(t, c.IsConnected())
	require.NoError(t, c.WriteFile(ctx5(t), "again.bin", strings.NewReader("x")))
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("source failed") }

func TestEPSVRefused_FallsBackToPASV_AndStaysInStep(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb == "EPSV" {
			ss.reply("500 EPSV not understood")
			return true, true
		}
		return false, true
	})
	for i := 0; i < 2; i++ {
		_, err := c.ListDirectory(ctx5(t), "/")
		require.NoError(t, err)
	}
	assert.Equal(t, 1, s.count("EPSV"), "after one refusal EPSV is not tried again")
	assert.Equal(t, 2, s.count("PASV"))
	assert.Equal(t, 1, s.ctrlConns)
}

func TestDisableEPSV_UsesPASVOnly(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, func(cfg *Config) { cfg.DisableEPSV = true })
	_, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	assert.Zero(t, s.count("EPSV"))
	assert.Equal(t, 1, s.count("PASV"))
}

func TestPASVAndEPSV_ReplyParsing(t *testing.T) {
	port, ok := parsePASV("227 Entering Passive Mode (10,99,99,99,4,1).")
	require.True(t, ok)
	assert.Equal(t, 1025, port, "only the PORT is taken from a PASV reply; the host in it is never dialled (SSRF)")
	for _, bad := range []string{"227 garbage", "227 (1,2,3,4,300,300)", "227 (1,2,3,4,0,0)", "227 (1,2,3,4,5)"} {
		_, ok = parsePASV(bad)
		assert.False(t, ok, bad)
	}
	port, ok = parseEPSV("229 Entering Extended Passive Mode (|||2021|)")
	assert.True(t, ok)
	assert.Equal(t, 2021, port)
	for _, bad := range []string{"229 nothing", "229 (|||0|)", "229 (|||70000|)", "229 (|||x|)", "229 (||||)"} {
		_, ok = parseEPSV(bad)
		assert.False(t, ok, bad)
	}
	s := newFakeServer(t)
	c := connected(t, s, func(cfg *Config) { cfg.DisableEPSV = true })
	_, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
}

func TestPWDParsing_QuotedNames(t *testing.T) {
	s := newFakeServer(t)
	s.mu.Lock()
	s.files[`/we"ird`] = fakeFile{dir: true, mtime: t0}
	s.files[`/we"ird/a.txt`] = fakeFile{data: []byte("q"), mtime: t0}
	s.mu.Unlock()
	c := connected(t, s, func(cfg *Config) { cfg.Path = `/we"ird` })
	fi, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err, "a doubled quote in the PWD reply is one quote in the name (RFC 959)")
	assert.Equal(t, int64(1), fi.Size)
	assert.Contains(t, s.commands(), `MLST /we"ird/a.txt`)
}

func TestReadReplyEdge_Cases(t *testing.T) {
	cases := map[string]struct {
		in   string
		code int
		err  bool
	}{
		"single":                  {"220 hello\r\n", 220, false},
		"bare_lf":                 {"220 hello\n", 220, false},
		"multiline":               {"211-Features:\r\n EPSV\r\n SIZE\r\n211 End\r\n", 211, false},
		"inner_code_line_is_text": {"211-start\r\n211-not the end\r\n  text\r\n211 End\r\n", 211, false},
		"code_only":               {"200\r\n", 200, false},
		"garbage":                 {"hello\r\n", 0, true},
		"short":                   {"22\r\n", 0, true},
		"truncated":               {"211-start\r\n EPSV\r\n", 0, true},
	}
	for name, k := range cases {
		t.Run(name, func(t *testing.T) {
			srv, cli := netPipe(t)
			go func() { _, _ = io.WriteString(srv, k.in); _ = srv.Close() }()
			p := &proto{o: protoOpts{ioTimeout: time.Second, maxReply: 1 << 16}, raw: cli, ctl: cli, feats: map[string]string{}}
			p.br = newReader(cli)
			code, lines, err := p.readReply(context.Background())
			if k.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, k.code, code)
			assert.NotEmpty(t, lines)
		})
	}
}

func netPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func newReader(c net.Conn) *bufio.Reader { return bufio.NewReaderSize(c, 4096) }

func TestMLST_WrongNumberOfEntries_IsAnError(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLST" {
			return false, true
		}
		ss.reply("250-Listing")
		ss.reply(" Type=file;Size=1; one")
		ss.reply(" Type=file;Size=2; two")
		ss.reply("250 End")
		return true, true
	})
	_, err := c.GetFileInfo(ctx5(t), "a.txt")
	require.ErrorIs(t, err, ErrListingIncomplete, "two entries for one path: not silently the first")
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLST" {
			return false, true
		}
		ss.reply("250-Listing")
		ss.reply("")
		ss.reply("250 End")
		return true, true
	})
	_, err = c.GetFileInfo(ctx5(t), "a.txt")
	require.ErrorIs(t, err, ErrListingIncomplete, "no entry at all: not a nil FileInfo with a nil error")
}
