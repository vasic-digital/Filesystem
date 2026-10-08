package ftp

import (
	"time"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/fabric"
)

// ScanOptions configures the read-only scan path.
type ScanOptions struct {
	// Retry is the retry policy for reads; nil selects 3 attempts, 200ms base delay, 2s cap. Authentication
	// failures are never retried whatever the policy.
	Retry *fabric.RetryPolicy
	// Budget, if set, bounds the concurrent connections and the request rate towards the host (fabric.Limited).
	Budget *fabric.HostBudget
}

func (o ScanOptions) retry() fabric.RetryPolicy {
	if o.Retry != nil {
		return *o.Retry
	}
	return fabric.RetryPolicy{MaxAttempts: 3, BaseDelay: 200 * time.Millisecond, MaxDelay: 2 * time.Second}
}

// NewScanClient returns the client a catalog scan uses: the FTP client behind decorators.ReadOnly (every mutation
// is refused and never reaches the server), with transient read failures retried and, optionally, the host budget.
func NewScanClient(cfg *Config, opts ScanOptions) (client.Client, error) {
	var c client.Client = decorators.ReadOnly(NewFTPClient(cfg))
	if opts.Budget != nil {
		c = fabric.Limited(c, opts.Budget)
	}
	return fabric.Retrying(c, opts.retry())
}

// scanFactory holds the config by POINTER: a pointer prints as an address under fmt (%+v of a pool or of the factory
// would otherwise print an inline Config.Password through the unexported value field, where fmt cannot call
// Config.String), and String / GoString redact the rest.
type scanFactory struct {
	cfg  *Config
	opts ScanOptions
}

func (f scanFactory) String() string {
	if f.cfg == nil {
		return "ftp.scanFactory(nil)"
	}
	return "ftp.scanFactory(" + f.cfg.String() + ")"
}

// GoString redacts for %#v.
func (f scanFactory) GoString() string { return f.String() }

func (f scanFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	cfg := *f.cfg // a copy: every worker has its own client and control connection
	return NewScanClient(&cfg, f.opts)
}

func (scanFactory) SupportedProtocols() []string { return []string{"ftp"} }

// NewWorkerPool returns a fabric.Pool of scan clients: one control connection per borrowed client, at most
// po.MaxPerKey per storage root, which is how a scan runs several workers within the server's per-IP limit.
func NewWorkerPool(cfg *Config, po fabric.PoolOptions, opts ScanOptions) (*fabric.Pool, error) {
	own := *cfg // the pool keeps its own copy: the caller may change or drop theirs
	return fabric.NewPool(scanFactory{cfg: &own, opts: opts}, po)
}
