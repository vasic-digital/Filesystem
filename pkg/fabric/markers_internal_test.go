package fabric

// Round 3 (N7): the 4yz text rule is enumerated over the REAL marker lists, not
// over a hand-picked sample (11.4.276(C)).

import (
	"fmt"
	"net/textproto"
	"testing"
)

func TestMarkersEveryMarkerInAPathNeverMakesA4yzReplyAuth(t *testing.T) {
	if len(credentialMarkers) < 10 || len(genericAuthMarkers) < 3 || len(authMarkers) != len(credentialMarkers)+len(genericAuthMarkers) {
		t.Fatalf("control: marker lists are not what the test enumerates: %d + %d = %d", len(credentialMarkers), len(genericAuthMarkers), len(authMarkers))
	}
	for _, m := range authMarkers {
		for _, code := range []int{421, 450, 451, 452} {
			for _, msg := range []string{
				"/Movies/" + m + " (2019).mkv: Resource temporarily unavailable",
				`\\nas\share\` + m + ".txt: busy",
				"/" + m,
			} {
				e := &textproto.Error{Code: code, Msg: msg}
				if got := Classify(fmt.Errorf("ftp: x: %w", e)); got != ClassTransient {
					t.Errorf("%d %q -> %v, want transient (a marker inside a path is a file name)", code, msg, got)
				}
			}
		}
	}
}

func TestMarkersCredentialMarkersAtTheHeadOfA4yzReplyAreAuthGenericOnesAreNot(t *testing.T) {
	for _, m := range credentialMarkers {
		e := &textproto.Error{Code: 430, Msg: m}
		if got := Classify(e); got != ClassAuth {
			t.Errorf("credential marker %q at the head of a 4yz reply -> %v, want auth", m, got)
		}
	}
	for _, m := range genericAuthMarkers {
		e := &textproto.Error{Code: 450, Msg: m}
		if got := Classify(e); got != ClassTransient {
			t.Errorf("generic marker %q alone in a 4yz reply -> %v, want transient", m, got)
		}
	}
	// and in a LEAF error text every marker (credential or generic) is still auth
	for _, m := range authMarkers {
		if got := Classify(fmt.Errorf("x: %w", fmt.Errorf("server said: %s", m))); got != ClassAuth {
			t.Errorf("leaf text %q -> %v, want auth", m, got)
		}
	}
}

func TestMarkersEverySMBCredentialStatusIsInTheTableAndNothingElse(t *testing.T) {
	if len(smbCredentialStatuses) != 12 {
		t.Errorf("the SMB credential status table has %d entries, the enumeration in the tests has 12", len(smbCredentialStatuses))
	}
	for _, code := range []uint32{0xC0000022, 0xC0000034, 0xC000003A, 0xC0000043} {
		if smbCredentialStatuses[code] {
			t.Errorf("file-level status %#x is in the credential table", code)
		}
	}
}
