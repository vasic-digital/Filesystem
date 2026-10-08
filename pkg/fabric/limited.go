package fabric

import (
	"context"
	"fmt"

	"digital.vasic.filesystem/pkg/client"
)

// Limited returns a client whose every operation first takes a slot from the
// host budget. Read streams (ReadFile, OpenSeekable) keep their slot until
// the stream is closed, so MaxConcurrent bounds open streams too. Disconnect
// and TestConnection are never throttled: closing a connection must always be
// possible, and TestConnection is the pool's health probe, which would
// otherwise report a busy host as an unhealthy connection (a probe is a
// keepalive, not a unit of catalog load). IsConnected, GetProtocol and
// GetConfig are local and not counted. Connect IS budgeted (it is a login).
// A leaked stream keeps its slot until closed, unless the budget has a
// WithStreamLease.
func Limited(inner client.Client, budget *HostBudget) client.Client {
	if budget == nil {
		panic("fabric.Limited: nil budget")
	}
	return newLayer(inner, func(ctx context.Context, st *callState, paths []string, call func(context.Context, []string) error) error {
		if st.op == OpDisconnect || st.op == OpTestConnection {
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
		st.onClose = append(st.onClose, budget.leaseRelease(release))
		return nil
	})
}
