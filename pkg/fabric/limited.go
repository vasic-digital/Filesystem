package fabric

import (
	"context"
	"fmt"

	"digital.vasic.filesystem/pkg/client"
)

// Limited returns a client whose every operation first takes a slot from the
// host budget. Read streams (ReadFile, OpenSeekable) keep their slot until
// the stream is closed, so MaxConcurrent bounds open streams too.
//
// TestConnection - the pool's health probe - is budgeted WITHOUT WAITING
// (HostBudget.TryAcquire): with a free slot and a due start slot the probe runs
// inside MaxConcurrent and the rate; with a busy budget it is not run and
// returns ErrProbeSkipped. A probe is not exempt, because for some protocols
// it is not cheap (SMB lists the share root, WebDAV sends a PROPFIND) and an
// exempt probe would let every borrow add unbudgeted load; and it must not
// wait, because waiting would turn a busy host into a blocked GetClient, and an
// error would turn it into an "unhealthy" verdict that retires a good
// connection. Disconnect is the one budget-exempt call: closing a connection
// must always be possible. IsConnected, GetProtocol and GetConfig are local and
// not counted. Connect IS budgeted (it is a login). A leaked stream keeps its
// slot until closed, unless the budget has a WithStreamLease (idle-based).
func Limited(inner client.Client, budget *HostBudget) client.Client {
	if budget == nil {
		panic("fabric.Limited: nil budget")
	}
	return newLayer(inner, func(ctx context.Context, st *callState, paths []string, call func(context.Context, []string) error) error {
		if st.op == OpDisconnect {
			return call(ctx, paths)
		}
		if st.op == OpTestConnection {
			release, ok := budget.TryAcquire()
			if !ok {
				return ErrProbeSkipped
			}
			defer release()
			return call(ctx, paths)
		}
		release, err := budget.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("fabric: host budget for %s: %w", st.op, err)
		}
		err = call(ctx, paths)
		if err != nil || !st.op.stream() {
			release()
			return err
		}
		onClose, touch := budget.leaseRelease(release)
		st.onClose = append(st.onClose, onClose)
		if touch != nil {
			st.onRead = append(st.onRead, func(int) { touch() })
		}
		return nil
	})
}
