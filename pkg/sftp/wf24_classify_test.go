package sftp

import (
	"context"
	"fmt"
	"testing"
)

// N1 root cause (a): context errors are not connection losses, and the invariant isConnectionLoss => IsTransient holds for them.
func TestWF24_N1a_ContextErrorsAreNotConnectionLoss(t *testing.T) {
	for _, e := range []error{context.DeadlineExceeded, context.Canceled, fmt.Errorf("w: %w", context.DeadlineExceeded)} {
		t.Logf("WF24-PROBE N1a err=%q isConnectionLoss=%v IsTransient=%v", e, isConnectionLoss(e), IsTransient(e))
		if isConnectionLoss(e) && !IsTransient(e) {
			t.Errorf("DEFECT N1a: %v is a connection loss but not transient (the documented invariant 'every connection loss is transient' is broken)", e)
		}
	}
}
