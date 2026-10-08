package ftp

// Fix round 3 (WF24 + the NAS leg of WP-12, constitution 11.4.276): class K6 - a name accepted from the server is checked
// against what the client can address. The NAS defect: ONE file name with a line feed in a Synology directory made the
// MLSD line split in two, the second half is not a listing line, and the whole directory failed with ErrListingIncomplete
// (189 other entries lost; SFTP lists the same directory fine). Evidence: evidence/wp12/nas-clients/diag-ftp-6.json
// (names_recorded=false: the fixtures below are synthetic names).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/fabric"
)

func lineFor(i int) string {
	return fmt.Sprintf("Type=file;Size=%d;Modify=20200517103000; entry-%03d.dat", i, i)
}

func collectWarnings(cfg *Config) *[]ListingWarning {
	var got []ListingWarning
	cfg.OnWarning = func(w ListingWarning) { got = append(got, w) }
	return &got
}

// The NAS case: 189 normal entries and one name with a line feed -> the 189 are listed, the split name is skipped and counted.
func TestR3_K6a_NameWithALineFeed_DoesNotFailTheDirectory_NASLeg(t *testing.T) {
	s := newFakeServer(t)
	var warns *[]ListingWarning
	c := connected(t, s, func(cfg *Config) { warns = collectWarnings(cfg) })
	lines := []string{"Type=cdir;Modify=20200517103000; .", "Type=pdir;Modify=20200517103000; .."}
	for i := 0; i < 100; i++ {
		lines = append(lines, lineFor(i))
	}
	lines = append(lines, "Type=file;Size=7;Modify=20200517103000; SECRET-head-of-a-split-name", "SECRET-tail-of-the-split-name")
	for i := 100; i < 189; i++ {
		lines = append(lines, lineFor(i))
	}
	s.setHook(mlsdHook(lines, "226 done"))
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err, "one odd name must not cost the other 189 entries")
	require.Len(t, got, 189)
	for _, f := range got {
		assert.True(t, strings.HasPrefix(f.Name, "entry-"), f.Name)
	}
	require.Len(t, *warns, 1, "a typed warning is delivered")
	w := (*warns)[0]
	assert.Equal(t, ListingWarning{Dir: "/", Fragments: 1, Truncated: 1, Listed: 189}, w)
	assert.Equal(t, 2, w.Skipped())
	assert.ErrorIs(t, w, ErrEntriesSkipped)
	assert.NotContains(t, w.Error(), "SECRET", "a warning carries counts and the directory, never a name")
	assert.EqualValues(t, 2, c.SkippedEntries())
	require.Len(t, c.Warnings(), 1)
	assert.True(t, c.IsConnected(), "the transfer was read to its end: the channel is in step")
	s.setHook(nil)
	_, err = c.GetFileInfo(ctx5(t), "a.txt")
	require.NoError(t, err)
	assert.Equal(t, 1, s.wfCtrl())
}

func TestR3_K6a_SeveralLineBreaksInOneName_AreOneSkippedName(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(mlsdHook([]string{lineFor(1), "Type=file;Size=7;Modify=20200517103000; head", "middle", "tail", lineFor(2)}, "226 done"))
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	require.Len(t, got, 2)
	w := c.Warnings()
	require.Len(t, w, 1)
	assert.Equal(t, 2, w[0].Fragments)
	assert.Equal(t, 1, w[0].Truncated)
}

// Fail closed where the channel is desynchronised and not merely odd.
func TestR3_K6a_Desynchronised_Listings_StillFailClosed(t *testing.T) {
	t.Run("first_line_is_not_a_listing_line", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, nil)
		s.setHook(mlsdHook([]string{"this is not a listing", lineFor(1)}, "226 done"))
		got, err := c.ListDirectory(ctx5(t), "/")
		require.ErrorIs(t, err, ErrListingIncomplete)
		assert.Nil(t, got)
		assert.True(t, c.IsConnected(), "read to its end: in step")
	})
	t.Run("a_damaged_entry_that_has_facts_is_not_a_fragment", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, nil)
		s.setHook(mlsdHook([]string{lineFor(1), "Type=file;Size=zz; broken.txt", lineFor(2)}, "226 done"))
		_, err := c.ListDirectory(ctx5(t), "/")
		require.ErrorIs(t, err, ErrListingIncomplete, "per-line safety is kept: a line with the fact structure that cannot be parsed fails the listing")
	})
	t.Run("more_than_a_tenth_of_the_lines_are_fragments", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, nil)
		lines := []string{lineFor(1)}
		for i := 0; i < 12; i++ {
			lines = append(lines, fmt.Sprintf("garbage %d", i))
		}
		s.setHook(mlsdHook(lines, "226 done"))
		_, err := c.ListDirectory(ctx5(t), "/")
		require.ErrorIs(t, err, ErrListingIncomplete)
		assert.Contains(t, err.Error(), "12 of 13")
	})
	t.Run("a_few_fragments_among_many_lines_are_fine", func(t *testing.T) {
		s := newFakeServer(t)
		c := connected(t, s, nil)
		var lines []string
		for i := 0; i < 100; i++ {
			lines = append(lines, lineFor(i))
			if i%11 == 5 { // 9 split names
				lines = append(lines, "fragment")
			}
		}
		s.setHook(mlsdHook(lines, "226 done"))
		got, err := c.ListDirectory(ctx5(t), "/")
		require.NoError(t, err)
		assert.Len(t, got, 100-9)
	})
}

// A name with CR, LF or NUL cannot be addressed by any later command (confine refuses it).
func TestR3_K6b_UnaddressableNames_AreSkippedAndCounted(t *testing.T) {
	s := newFakeServer(t)
	var warns *[]ListingWarning
	c := connected(t, s, func(cfg *Config) { warns = collectWarnings(cfg) })
	s.setHook(mlsdHook([]string{lineFor(1), "Type=file;Size=1; has\rcr.txt", "Type=file;Size=1; has\x00nul.txt", lineFor(2)}, "226 done"))
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Len(t, *warns, 1)
	assert.Equal(t, ListingWarning{Dir: "/", Unaddressable: 2, Listed: 2}, (*warns)[0])
}

func TestR3_K6a_DegradedLIST_SplitName_IsSkippedToo(t *testing.T) {
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
		_, _ = io.WriteString(dc, "total 3\r\n-rw-r--r-- 1 u g 10 May 17  2020 a.txt\r\n-rw-r--r-- 1 u g 10 May 17  2020 head\r\ntail\r\n-rw-r--r-- 1 u g 10 May 17  2020 z.txt\r\n")
		_ = dc.Close()
		ss.reply("226 done")
		return true, true
	})
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "a.txt", got[0].Name)
	assert.Equal(t, "z.txt", got[1].Name)
	assert.EqualValues(t, 2, c.SkippedEntries())
	// a first line that is no listing line still fails closed
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "LIST" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = io.WriteString(dc, "this line is not a listing\r\n-rw-r--r-- 1 u g 10 May 17  2020 a.txt\r\n")
		_ = dc.Close()
		ss.reply("226 done")
		return true, true
	})
	_, err = c.ListDirectory(ctx5(t), "/")
	require.ErrorIs(t, err, ErrListingIncomplete)
}

// The scan client reports through Config.OnWarning too (the wrapped client does not expose the counters).
func TestR3_K6a_ScanClient_ReportsThroughOnWarning(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	warns := collectWarnings(cfg)
	sc, err := NewScanClient(cfg, ScanOptions{})
	require.NoError(t, err)
	require.NoError(t, sc.Connect(ctx5(t)))
	defer sc.Disconnect(ctx5(t))
	s.setHook(mlsdHook([]string{lineFor(1), "Type=file;Size=1; head", "tail"}, "226 done"))
	got, err := sc.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	assert.Len(t, got, 1)
	require.Len(t, *warns, 1)
}

// G9 (reviewer N7 inverted): a server that does not offer UTF8 and sends 0x7f for non-ASCII names.
func TestR3_K6c_GarbledNames_AreRefused_WhateverTheReasonUTF8IsNotOn_G9(t *testing.T) {
	s := newFakeServer(t)
	s.utf8Feat = false
	s.legacyName = true
	c := connected(t, s, nil)
	_, err := c.ListDirectory(ctx5(t), "/")
	require.ErrorIs(t, err, ErrUTF8Refused)
	assert.Zero(t, s.count("OPTS"), "UTF8 was not offered: no OPTS")
	assert.True(t, c.IsConnected())

	// valid UTF-8 names from a server that never advertised UTF8 are fine
	s2 := newFakeServer(t)
	s2.utf8Feat = false
	c2 := connected(t, s2, nil)
	got, err := c2.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	found := false
	for _, f := range got {
		found = found || f.Name == "Čšž_日本.txt"
	}
	assert.True(t, found, "a valid non-ASCII name is not a garbled one")
}

// NM12: after a refused OPTS UTF8 ON, a name that is not valid UTF-8 (without any 0x7f) is refused as well.
func TestR3_K6c_InvalidUTF8Name_AfterARefusedOPTS_IsRefused_NM12(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		switch verb {
		case "MLSD":
			ss.reply("150 opening")
			dc, err := ss.openData()
			if err != nil {
				return true, true
			}
			_, _ = dc.Write([]byte("Type=file;Size=1;Modify=20200517103000; caf\xe9.txt\r\n"))
			_ = dc.Close()
			ss.reply("226 done")
			return true, true
		}
		return false, true
	})
	// the session negotiated UTF-8 (OPTS accepted): agreed, the name is trusted as the server's
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err)
	assert.Len(t, got, 1)

	s2 := newFakeServer(t)
	s2.setHook(func(ss *session, verb, arg string) (bool, bool) {
		switch verb {
		case "OPTS":
			ss.reply("504 Unknown command")
			return true, true
		case "MLSD":
			ss.reply("150 opening")
			dc, err := ss.openData()
			if err != nil {
				return true, true
			}
			_, _ = dc.Write([]byte("Type=file;Size=1;Modify=20200517103000; caf\xe9.txt\r\n"))
			_ = dc.Close()
			ss.reply("226 done")
			return true, true
		}
		return false, true
	})
	c2 := NewFTPClient(cfgFor(s2, pinned(t, s2)))
	require.NoError(t, c2.Connect(ctx5(t)))
	defer c2.Disconnect(ctx5(t))
	_, err = c2.ListDirectory(ctx5(t), "/")
	require.ErrorIs(t, err, ErrUTF8Refused, "invalid UTF-8 without 0x7f: only the utf8.ValidString arm catches it")
	assert.Equal(t, fabric.ClassPermanent, fabric.Classify(err))
}

// ---- pins (G10) and the deferred default store ---------------------------------------------------------------------

// Reviewer N13 inverted. The second pin with another name is refused by the stores; a hand-built list picks the first name.
func TestR3_K6d_TwoPinsWithDifferentNames_G10(t *testing.T) {
	s := newFakeServer(t)
	x := mustCert(t, s.cert)
	other := genCertNames(t, []string{"other.test"}, nil)
	ox := mustCert(t, other)
	hp := HostPort("127.0.0.1", s.port())
	first := CertPin{Fingerprint: Fingerprint(x), ServerName: "127.0.0.1", CertDER: x.Raw}
	second := CertPin{Fingerprint: Fingerprint(ox), ServerName: "other.test", CertDER: ox.Raw}

	mem := NewMemPinStore()
	require.NoError(t, mem.Record(hp, first))
	require.ErrorIs(t, mem.Record(hp, second), ErrPinNameConflict, "Record enforces one name per host, like Pin")
	require.NoError(t, mem.Record(hp, first), "the identical pin stays idempotent")
	pins, _ := mem.Lookup(hp)
	assert.Len(t, pins, 1)

	fp := NewFilePinStore(t.TempDir() + "/pins.json")
	require.NoError(t, fp.Record(hp, first))
	require.ErrorIs(t, fp.Record(hp, second), ErrPinNameConflict)

	// a pin file edited or imported by hand can still hold two names: the FIRST named pin wins, even when its name is the host
	both := []CertPin{first, second}
	assert.Equal(t, "127.0.0.1", newTLSConfig("127.0.0.1", both).ServerName)
	assert.Equal(t, "other.test", newTLSConfig("127.0.0.1", []CertPin{{Fingerprint: second.Fingerprint, CertDER: second.CertDER}, second}).ServerName,
		"a pin without a name is skipped, the next named one wins")
	hand := NewMemPinStore()
	hand.pins[hp] = both
	require.NoError(t, NewFTPClient(cfgFor(s, hand)).Connect(ctx5(t)), "the first pin's name verifies the certificate the server presents")
}

func TestR3_K6d_CertificateRotationWithTheSameName_IsStillRecorded(t *testing.T) {
	mem := NewMemPinStore()
	a := genCertNames(t, []string{"nas.test"}, nil)
	b := genCertNames(t, []string{"nas.test"}, nil)
	ax, bx := mustCert(t, a), mustCert(t, b)
	require.NoError(t, mem.Record("h:21", CertPin{Fingerprint: Fingerprint(ax), ServerName: "nas.test", CertDER: ax.Raw}))
	require.NoError(t, mem.Record("h:21", CertPin{Fingerprint: Fingerprint(bx), ServerName: "nas.test", CertDER: bx.Raw}))
	pins, _ := mem.Lookup("h:21")
	assert.Len(t, pins, 2)
}

// P3: the process-wide store is read when the client connects, not when it was created.
func TestR3_K6e_DeferredDefaultPinStore_ReadsTheVariableAtCallTime(t *testing.T) {
	old := DefaultPinStore
	t.Cleanup(func() { DefaultPinStore = old })
	DefaultPinStore = nil
	_, err := DeferredDefaultPinStore.Lookup("h:21")
	require.ErrorIs(t, err, ErrNoPinStore)
	require.ErrorIs(t, DeferredDefaultPinStore.Record("h:21", CertPin{}), ErrNoPinStore)
	require.ErrorIs(t, DeferredDefaultPinStore.Remove("h:21", "x"), ErrNoPinStore)

	s := newFakeServer(t)
	cfg := cfgFor(s, DeferredDefaultPinStore)
	c := NewFTPClient(cfg) // created while no store is installed
	require.ErrorIs(t, c.Connect(ctx5(t)), ErrNoPinStore)
	st := NewMemPinStore()
	DefaultPinStore = st // installed after the client was created, before it connects
	var unknown *UnknownCertError
	require.ErrorAs(t, c.Connect(ctx5(t)), &unknown, "now the installed (empty) store is consulted")
	_, err = Pin(ctx5(t), DeferredDefaultPinStore, "127.0.0.1", s.port(), Confirmation{Fingerprint: certFingerprint(t, s.cert), ConfirmedBy: "o"})
	require.NoError(t, err)
	pins, _ := st.Lookup(HostPort("127.0.0.1", s.port()))
	require.Len(t, pins, 1, "Record went to the installed store")
	require.NoError(t, c.Connect(ctx5(t)))
	require.NoError(t, DeferredDefaultPinStore.Remove(HostPort("127.0.0.1", s.port()), pins[0].Fingerprint))
	pins, _ = st.Lookup(HostPort("127.0.0.1", s.port()))
	assert.Empty(t, pins)
	_ = c.Disconnect(ctx5(t))
}

func TestR3_PublicConfig_ShowsDisableEPSV_NM06(t *testing.T) {
	c := NewFTPClient(&Config{Host: "h", DisableEPSV: true})
	assert.True(t, c.GetConfig().(*PublicConfig).DisableEPSV)
	c = NewFTPClient(&Config{Host: "h"})
	assert.False(t, c.GetConfig().(*PublicConfig).DisableEPSV)
}

// ---- killers of the surviving reviewer mutants (T5) ---------------------------------------------------------------

// NM03: a multi-line reply ends at ITS OWN code only.
func TestR3_NM03_MultiLineReply_EndsAtItsOwnCode(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "NOOP" {
			return false, true
		}
		ss.reply("200-start")
		ss.reply("123 this looks like an end but is a text line")
		ss.reply("200 the real end")
		return true, true
	})
	require.NoError(t, c.TestConnection(ctx5(t)))
	require.NoError(t, c.TestConnection(ctx5(t)), "the next reply is not one line behind")
	assert.Equal(t, 1, s.wfCtrl())
}

// NM04: a TLS data connection that is cut in the middle of a record (no close_notify) is a plain EOF; the verdict is the
// final reply on the control channel. (Cut exactly between records, Go already reports a clean EOF: the mapping only
// matters for a cut inside a record, which is what the server does here.)
func TestR3_NM04_TLSDataConnection_CutInsideARecord_IsEOF(t *testing.T) {
	s := newFakeServer(t)
	c := connected(t, s, nil)
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "MLSD" {
			return false, true
		}
		ss.reply("150 opening")
		dc, err := ss.openData()
		if err != nil {
			return true, true
		}
		_, _ = io.WriteString(dc, "Type=file;Size=1;Modify=20200517103000; one.txt\r\n")
		if tc, ok := dc.(interface{ NetConn() net.Conn }); ok {
			raw := tc.NetConn()
			_, _ = raw.Write([]byte{0x17, 0x03, 0x03, 0x01, 0x00}) // the header of a 256-byte record ...
			_ = raw.Close()                                        // ... and the connection is cut: io.ErrUnexpectedEOF, no close_notify
		} else {
			_ = dc.Close()
		}
		ss.reply("226 done")
		return true, true
	})
	got, err := c.ListDirectory(ctx5(t), "/")
	require.NoError(t, err, "a truncation signal on the data channel must not fail a transfer whose control channel says 226")
	require.Len(t, got, 1)
}

// NM08: FEAT keys are case-insensitive.
func TestR3_NM08_LowerCaseFEATKeys_AreRecognised(t *testing.T) {
	s := newFakeServer(t)
	cfg := cfgFor(s, pinned(t, s))
	s.setHook(func(ss *session, verb, arg string) (bool, bool) {
		if verb != "FEAT" {
			return false, true
		}
		ss.reply("211-Features:")
		ss.reply(" mlst Type*;Size*;Modify*;")
		ss.reply(" utf8")
		ss.reply(" auth tls")
		ss.reply("211 End")
		return true, true
	})
	c := NewFTPClient(cfg)
	require.NoError(t, c.Connect(ctx5(t)))
	defer c.Disconnect(ctx5(t))
	assert.False(t, c.Degraded(), "a lower-case 'mlst' is MLST")
	assert.Equal(t, 1, s.count("OPTS"), "a lower-case 'utf8' is UTF8")
}

// NM16: DiscoverCert closes its connection (observed on the CLIENT side: the server closes its end on the failed
// handshake whatever the client does).
type closeSpy struct {
	net.Conn
	closed *atomic.Bool
}

func (c closeSpy) Close() error { c.closed.Store(true); return c.Conn.Close() }

func TestR3_NM16_DiscoverCert_ClosesItsConnection(t *testing.T) {
	var closed atomic.Bool
	old := dialTCP
	t.Cleanup(func() { dialTCP = old })
	dialTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		c, err := old(ctx, d, addr)
		if err != nil {
			return nil, err
		}
		return closeSpy{Conn: c, closed: &closed}, nil
	}
	s := newFakeServer(t)
	_, err := DiscoverCert(ctx5(t), "127.0.0.1", s.port(), 5*time.Second)
	require.NoError(t, err)
	assert.True(t, closed.Load(), "DiscoverCert left its control connection open")
}

func mustCert(t *testing.T, c tls.Certificate) *x509.Certificate {
	t.Helper()
	x, err := x509.ParseCertificate(c.Certificate[0])
	require.NoError(t, err)
	return x
}
