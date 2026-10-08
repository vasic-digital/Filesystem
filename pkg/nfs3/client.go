package nfs3

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"digital.vasic.filesystem/pkg/client"
)

// Errors specific to the client.
var (
	// ErrNotConnected: Connect has not completed.
	ErrNotConnected = errors.New("nfs3: not connected")
	// ErrInvalidPath: the path contains a ".." segment, a NUL byte, or is not a path.
	ErrInvalidPath = errors.New("nfs3: invalid path")
	// ErrPrivilegedPortUnavailable: a reserved source port (<1024) is required but this
	// process may not bind one (needs root, CAP_NET_BIND_SERVICE, or a lowered
	// net.ipv4.ip_unprivileged_port_start).
	ErrPrivilegedPortUnavailable = errors.New("nfs3: cannot bind a privileged (<1024) source port")
	// ErrProgramNotRegistered: the port mapper has no TCP registration for a required program.
	ErrProgramNotRegistered = errors.New("nfs3: RPC program not registered with the port mapper over TCP")
	// ErrAuthFlavor: the export accepts neither AUTH_SYS nor AUTH_NULL, the only flavors this client speaks.
	ErrAuthFlavor = errors.New("nfs3: export does not accept AUTH_SYS")
	// ErrNotRegular: ReadFile on something that is not a regular file.
	ErrNotRegular = errors.New("nfs3: not a regular file")
	// ErrNotProgressing: the server's READDIRPLUS or READ answers did not advance.
	ErrNotProgressing = errors.New("nfs3: server reply does not make progress")
)

// AccessError reports a refusal that is consistent with the server requiring a
// reserved (privileged) source port, or with a plain permission failure. It
// states the source port actually used so the operator can tell the cases apart.
type AccessError struct {
	Layer      string // "mount", "nfs" or "rpc"
	SourcePort int    // local TCP port of the refused connection, 0 when unknown
	Privileged bool   // the connection was dialled from a reserved port
	Err        error  // the underlying MountError / NFSError / RPCError
}

func (e *AccessError) Error() string {
	hint := "the export may restrict clients by address or UID, or require a reserved source port (an export option usually called 'secure'/'insecure')"
	if e.Privileged {
		hint = "the connection already used a reserved source port; check the export's client list and squash options"
	} else if e.SourcePort >= 1024 {
		hint = fmt.Sprintf("this client connected from unprivileged source port %d; the server may require a source port below 1024 (set TryPrivilegedPort and run with CAP_NET_BIND_SERVICE or root), or restrict clients by address/UID", e.SourcePort)
	}
	return fmt.Sprintf("nfs3: access denied during %s: %v; %s", e.Layer, e.Err, hint)
}
func (e *AccessError) Unwrap() error { return e.Err }

// Config configures a Client.
type Config struct {
	Host   string // server host name or address
	Export string // exported path to mount, e.g. "/volume1/video"

	// Ports. 0 means "ask the port mapper". PortmapPort 0 means 111.
	PortmapPort, MountPort, NFSPort int

	// AUTH_SYS identity. GIDs is truncated to 16 entries (RFC 5531 appendix A).
	// A zero UID or GID is NOT sent as root: unless AsRoot is set it becomes 65534 (nobody),
	// because on a no_root_squash export an unset identity would otherwise read as root.
	UID, GID uint32
	GIDs     []uint32
	AsRoot   bool   // send UID 0 / GID 0 as given (root)
	Machine  string // AUTH_SYS machine name; default "catalogizer"

	DialTimeout  time.Duration // default 10s
	CallTimeout  time.Duration // per RPC, default 30s
	MaxRetries   int           // extra attempts on transient errors; 0 means the default 2, negative means none (at most 1000)
	RetryBackoff time.Duration // first backoff, doubled per attempt (cap 5s); default 100ms

	// NFS3ERR_JUKEBOX ("the data is being made available, try later", RFC 1813 section 2.6)
	// has its own schedule, independent of the transport retries above, because tiered or
	// spun-down storage needs seconds, not milliseconds.
	JukeboxRetries int           // waits before giving up; 0 means the default 4, negative means none
	JukeboxBackoff time.Duration // first wait, doubled per attempt (cap 30s); default 2s

	// HandleCacheTTL bounds how long a cached directory handle is trusted. NFS handles survive
	// renames, so nothing ever turns stale on its own; the TTL is what makes changes made by
	// other clients visible. 0 means the default 10s, negative disables the cache of
	// intermediate directories (every path is walked from the root).
	HandleCacheTTL time.Duration

	MaxPipeline int    // concurrent READs per open file; default 8
	ReadSize    uint32 // bytes per READ; 0 = min(FSINFO rtpref, 1 MiB)
	DirCount    uint32 // READDIRPLUS dircount; default 32768
	DirMaxCount uint32 // READDIRPLUS maxcount; default 131072
	MaxEntries  int    // cap on entries per directory listing; default 5,000,000
	MaxRecord   int    // cap on one RPC record; default 8 MiB. ReadSize and DirMaxCount (plus 4 KiB) must fit in it

	// TryPrivilegedPort: when Connect fails with an access error (MOUNT, or the first NFS
	// calls: MNT3ERR_ACCES/PERM, NFS3ERR_ACCES/PERM, RPC AUTH_ERROR) from an unprivileged
	// port, retry once from a reserved port (needs privilege).
	TryPrivilegedPort bool

	// Dial replaces the TCP dialler (tests). privileged reports whether a
	// reserved source port is wanted.
	Dial func(ctx context.Context, network, addr string, privileged bool) (net.Conn, error)
}

func (c *Config) defaults() {
	if c.PortmapPort == 0 {
		c.PortmapPort = 111
	}
	if c.Machine == "" {
		c.Machine = "catalogizer"
	}
	if !c.AsRoot {
		if c.UID == 0 {
			c.UID = nobodyID
		}
		if c.GID == 0 {
			c.GID = nobodyID
		}
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.CallTimeout <= 0 {
		c.CallTimeout = 30 * time.Second
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = 2
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = 100 * time.Millisecond
	}
	if c.JukeboxRetries == 0 {
		c.JukeboxRetries = 4
	}
	if c.JukeboxBackoff <= 0 {
		c.JukeboxBackoff = 2 * time.Second
	}
	if c.HandleCacheTTL == 0 {
		c.HandleCacheTTL = 10 * time.Second
	}
	if c.MaxPipeline <= 0 {
		c.MaxPipeline = 8
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = 5_000_000
	}
	if c.MaxRecord <= 0 {
		c.MaxRecord = defaultMaxRecord
	}
	if c.DirMaxCount == 0 {
		c.DirMaxCount = 131072
		if lim := c.MaxRecord - recordHeadroom; lim > 0 && int(c.DirMaxCount) > lim {
			c.DirMaxCount = uint32(lim)
		}
	}
	if c.DirCount == 0 {
		c.DirCount = 32768
		if c.DirCount > c.DirMaxCount {
			c.DirCount = c.DirMaxCount
		}
	}
}

// nobodyID is the AUTH_SYS uid/gid used when none is configured.
const nobodyID = 65534

// maxPipelineLimit bounds Config.MaxPipeline: READs in flight per open file, each up to maxReadChunk.
const maxPipelineLimit = 64

// validate refuses limits that cannot work together.
func (c *Config) validate() error {
	if c.MaxPipeline > maxPipelineLimit {
		return fmt.Errorf("nfs3: MaxPipeline %d exceeds the limit %d (every in-flight READ can hold up to 1 MiB)", c.MaxPipeline, maxPipelineLimit)
	}
	if c.DirCount > c.DirMaxCount {
		return fmt.Errorf("nfs3: DirCount %d exceeds DirMaxCount %d (RFC 1813 3.3.17: dircount is the directory-information part of maxcount)", c.DirCount, c.DirMaxCount)
	}
	if c.MaxRecord < 4*recordHeadroom {
		return fmt.Errorf("nfs3: MaxRecord %d is below the minimum %d", c.MaxRecord, 4*recordHeadroom)
	}
	if int64(c.DirMaxCount)+recordHeadroom > int64(c.MaxRecord) {
		return fmt.Errorf("nfs3: DirMaxCount %d plus %d bytes of headroom exceeds MaxRecord %d: every READDIRPLUS reply would be refused", c.DirMaxCount, recordHeadroom, c.MaxRecord)
	}
	rs := int64(c.ReadSize)
	if rs > maxReadChunk {
		rs = maxReadChunk
	}
	if rs+recordHeadroom > int64(c.MaxRecord) {
		return fmt.Errorf("nfs3: ReadSize %d plus %d bytes of headroom exceeds MaxRecord %d: every READ reply would be refused", rs, recordHeadroom, c.MaxRecord)
	}
	return nil
}

// Client is a read-only NFSv3 client. It implements client.Client and
// client.SeekableClient. Safe for concurrent use after Connect.
type Client struct {
	cfg Config

	mu         sync.Mutex
	connected  bool
	privileged bool
	authNone   bool // the export lists AUTH_NULL but not AUTH_SYS
	nfsAddr    string
	nfs        *rpcConn
	root       Handle
	rootAttr   Attr
	fsinfo     FSInfo
	cache      map[string]cacheEntry // directory path -> handle

	xid         atomic.Uint32    // one xid sequence for every connection of this client
	lastNFSPort atomic.Int64     // local port of the most recent NFS connection
	vanished    atomic.Int64     // listing entries that disappeared between READDIRPLUS and LOOKUP
	remountSem  chan struct{}    // one remount at a time; a channel so that a waiter honours its context
	cacheGen    uint64           // last handle-cache generation handed out (under mu)
	now         func() time.Time // clock of the handle cache (tests replace it)
}

// cacheEntry is one remembered directory handle and when it was learned. gen identifies the
// handle: it changes whenever the path gets a handle that differs from the remembered one (or none
// was remembered). pgen is the gen of the PARENT entry this entry was learned under. An entry is
// trusted only while its parent entry still has that gen (see Client.validLocked): a child learned
// under an old directory can never be reached through a new directory of the same path.
type cacheEntry struct {
	h    Handle
	at   time.Time
	gen  uint64
	pgen uint64
}

var (
	_ client.Client         = (*Client)(nil)
	_ client.SeekableClient = (*Client)(nil)
)

const handleCacheMax = 8192

// New creates a client; nothing is sent until Connect.
func New(cfg Config) (*Client, error) {
	if cfg.Host == "" {
		return nil, errors.New("nfs3: host is required")
	}
	if cfg.Export == "" || !strings.HasPrefix(cfg.Export, "/") {
		return nil, errors.New("nfs3: export must be an absolute path such as /volume1/data")
	}
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	c := &Client{cfg: cfg, cache: map[string]cacheEntry{}, now: time.Now, remountSem: make(chan struct{}, 1)}
	c.xid.Store(binary.BigEndian.Uint32(b[:]))
	return c, nil
}

// VanishedEntries counts listing entries that were skipped because they disappeared between the
// READDIRPLUS that named them and the call that fetched their attributes: NOENT answering the
// LOOKUP, or NOENT, STALE or BADHANDLE answering the GETATTR of the entry's handle (a STALE or
// BADHANDLE answering the LOOKUP names the directory and fails the listing instead).
func (c *Client) VanishedEntries() int64 { return c.vanished.Load() }

func (c *Client) cred() authSysCred {
	var b [4]byte
	_, _ = rand.Read(b[:])
	c.mu.Lock()
	none := c.authNone
	c.mu.Unlock()
	return authSysCred{Stamp: binary.BigEndian.Uint32(b[:]), Machine: c.cfg.Machine, UID: c.cfg.UID, GID: c.cfg.GID, GIDs: c.cfg.GIDs, None: none}
}

func (c *Client) dial(ctx context.Context, addr string) (net.Conn, error) {
	c.mu.Lock()
	priv := c.privileged
	c.mu.Unlock()
	return c.dialMode(ctx, addr, priv)
}

func (c *Client) dialMode(ctx context.Context, addr string, priv bool) (net.Conn, error) {
	if c.cfg.Dial != nil {
		return c.cfg.Dial(ctx, "tcp", addr, priv)
	}
	if !priv {
		d := net.Dialer{Timeout: c.cfg.DialTimeout}
		return d.DialContext(ctx, "tcp", addr)
	}
	return dialPrivileged(ctx, addr, c.cfg.DialTimeout)
}

// dialPrivileged binds a source port in 512..1023, descending from 1023 as
// mount.nfs does, and connects from it.
func dialPrivileged(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	return dialPrivilegedFrom(ctx, func(ctx context.Context, port int) (net.Conn, error) {
		d := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{Port: port}}
		return d.DialContext(ctx, "tcp", addr)
	})
}

// dialPrivilegedFrom is the port-selection loop of dialPrivileged with the actual bind-and-connect
// injected (tests drive the loop without the privilege to bind a reserved port).
func dialPrivilegedFrom(ctx context.Context, dialFrom func(ctx context.Context, port int) (net.Conn, error)) (net.Conn, error) {
	var last error
	for p, tries := 1023, 0; p >= 512 && tries < 64; p, tries = p-1, tries+1 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := dialFrom(ctx, p)
		if err == nil {
			return conn, nil
		}
		last = err
		switch {
		case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
			return nil, fmt.Errorf("%w: %v", ErrPrivilegedPortUnavailable, err)
		case errors.Is(err, syscall.EADDRINUSE), errors.Is(err, syscall.EADDRNOTAVAIL):
			continue
		default:
			return nil, err
		}
	}
	return nil, fmt.Errorf("nfs3: no free privileged source port: %w", last)
}

func (c *Client) hostPort(port int) string {
	return net.JoinHostPort(c.cfg.Host, strconv.Itoa(port))
}

// oneShot runs a single RPC on a fresh connection to addr (port mapper, MOUNT).
func (c *Client) oneShot(ctx context.Context, addr string, prog, vers, proc uint32, args []byte) ([]byte, int, error) {
	nc, err := c.dial(ctx, addr)
	if err != nil {
		return nil, 0, err
	}
	local := 0
	if ta, ok := nc.LocalAddr().(*net.TCPAddr); ok {
		local = ta.Port
	}
	rc := newRPCConnShared(nc, c.cred(), c.cfg.MaxRecord, &c.xid)
	defer rc.close()
	res, err := rc.call(ctx, c.cfg.CallTimeout, prog, vers, proc, args)
	return res, local, err
}

func (c *Client) lookupPort(ctx context.Context, prog, vers uint32) (int, error) {
	res, _, err := c.oneShot(ctx, c.hostPort(c.cfg.PortmapPort), progPortmap, versPortmap, procPmapGetport, encodeGetport(prog, vers))
	if err != nil {
		return 0, fmt.Errorf("nfs3: portmapper GETPORT(%d v%d): %w", prog, vers, err)
	}
	p, err := decodeGetport(res)
	if err != nil {
		return 0, fmt.Errorf("nfs3: portmapper GETPORT(%d v%d): %w", prog, vers, err)
	}
	if p == 0 {
		return 0, fmt.Errorf("%w (program %d version %d)", ErrProgramNotRegistered, prog, vers)
	}
	return int(p), nil
}

func isAccess(err error) bool {
	var me *MountError
	if errors.As(err, &me) {
		return me.Status == mnt3ErrAcces || me.Status == mnt3ErrPerm
	}
	var ne *NFSError
	if errors.As(err, &ne) {
		return ne.Status == NFS3ErrAcces || ne.Status == NFS3ErrPerm
	}
	var re *RPCError
	if errors.As(err, &re) {
		return re.isAuth()
	}
	return false
}

// Exports lists the server's exports (MOUNT EXPORT). It does not need Connect.
func (c *Client) Exports(ctx context.Context) ([]Export, error) {
	port := c.cfg.MountPort
	var err error
	if port == 0 {
		if port, err = c.lookupPort(ctx, progMount, versMount); err != nil {
			return nil, err
		}
	}
	res, _, err := c.oneShot(ctx, c.hostPort(port), progMount, versMount, procMntExport, nil)
	if err != nil {
		return nil, fmt.Errorf("nfs3: MOUNT EXPORT: %w", err)
	}
	return decodeExports(res)
}

// Connect resolves the ports, mounts the export and reads FSINFO. Every Connect starts from an
// ordinary source port; with TryPrivilegedPort a reserved port is used for ONE retry after an
// access error, and the client goes back to ordinary ports if that retry fails too.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	c.privileged = false
	c.mu.Unlock()
	err := c.connectOnce(ctx)
	if err != nil && c.cfg.TryPrivilegedPort && isAccess(err) {
		c.mu.Lock()
		c.privileged = true
		c.mu.Unlock()
		err2 := c.connectOnce(ctx)
		if err2 != nil {
			// The privileged attempt failed: do not stay in privileged mode (a later Connect,
			// after the operator fixed the export, must be free to use an ordinary port).
			c.mu.Lock()
			c.privileged = false
			c.mu.Unlock()
			if isAccess(err2) {
				return err2 // the server refused the reserved-port attempt as well: that error says so
			}
			// The retry failed for another reason (typically: this process may not bind a reserved
			// port). The server's ORIGINAL refusal is the operator's real problem and is kept, first.
			return fmt.Errorf("%w; the retry from a reserved source port then failed: %w", err, err2)
		}
		return nil
	}
	return err
}

// maxRetries is MaxRetries normalised: negative means none, and a silly value is bounded.
func (c *Client) maxRetries() int {
	n := c.cfg.MaxRetries
	if n < 0 {
		return 0
	}
	if n > 1000 {
		return 1000
	}
	return n
}

// jukeboxRetries is JukeboxRetries normalised.
func (c *Client) jukeboxRetries() int {
	n := c.cfg.JukeboxRetries
	if n < 0 {
		return 0
	}
	if n > 1000 {
		return 1000
	}
	return n
}

const (
	maxBackoff        = 5 * time.Second
	maxJukeboxBackoff = 30 * time.Second
)

// callBudget is the longest one callNFS can take: every attempt may use the whole CallTimeout,
// plus the back-offs between attempts, plus the JUKEBOX waits.
func (c *Client) callBudget() time.Duration {
	n := c.maxRetries()
	total := time.Duration(n+1) * c.cfg.CallTimeout
	b := c.cfg.RetryBackoff
	for i := 0; i < n; i++ {
		total += b
		if b *= 2; b > maxBackoff {
			b = maxBackoff
		}
	}
	jn := c.jukeboxRetries()
	jb := c.cfg.JukeboxBackoff
	total += time.Duration(jn) * c.cfg.CallTimeout
	for i := 0; i < jn; i++ {
		total += jb
		if jb *= 2; jb > maxJukeboxBackoff {
			jb = maxJukeboxBackoff
		}
	}
	return total
}

func (c *Client) connectOnce(ctx context.Context) (err error) {
	c.dropAll()
	mountPort, nfsPort := c.cfg.MountPort, c.cfg.NFSPort
	if mountPort == 0 {
		if mountPort, err = c.lookupPort(ctx, progMount, versMount); err != nil {
			return err
		}
	}
	if nfsPort == 0 {
		if nfsPort, err = c.lookupPort(ctx, progNFS, versNFS); err != nil {
			return err
		}
	}
	res, local, err := c.oneShot(ctx, c.hostPort(mountPort), progMount, versMount, procMnt, encodeDirpath(c.cfg.Export))
	if err != nil {
		return c.wrapAccess("mount", local, fmt.Errorf("nfs3: MNT %q: %w", c.cfg.Export, err))
	}
	// The server answered MNT with status OK: it now holds a mount record (rmtab) for this client,
	// whether or not the rest of the reply decodes. From here on, any failure must not leave that
	// record behind, so a best-effort UMNT is sent on every failure path, a malformed OK reply
	// (handle longer than 64 bytes, more than 64 flavors) included.
	mounted := len(res) >= 4 && binary.BigEndian.Uint32(res) == 0
	defer func() {
		if err != nil && mounted {
			c.umnt(ctx, mountPort)
		}
	}()
	root, flavors, err := decodeMnt(c.cfg.Export, res)
	if err != nil {
		return c.wrapAccess("mount", local, err)
	}
	useNone := false
	if len(flavors) > 0 {
		hasSys, hasNone := false, false
		for _, f := range flavors {
			hasSys = hasSys || f == authSys
			hasNone = hasNone || f == authNone
		}
		switch {
		case hasSys:
		case hasNone:
			useNone = true
		default:
			return fmt.Errorf("%w: server offers flavors %v", ErrAuthFlavor, flavors)
		}
	}
	c.mu.Lock()
	c.authNone = useNone
	c.nfsAddr = c.hostPort(nfsPort)
	c.root = root
	c.cache = map[string]cacheEntry{"/": {h: root, at: c.now()}}
	c.mu.Unlock()

	// FSINFO and the root attributes double as the first NFS-port contact. They get the budget
	// of two complete callNFS runs, whatever MaxRetries is set to.
	ctx2, cancel := context.WithTimeout(ctx, 2*c.callBudget())
	defer cancel()
	c.mu.Lock()
	c.connected = true // callNFS requires it; reverted on failure below
	c.mu.Unlock()
	fail := func(err error) error {
		lp := int(c.lastNFSPort.Load())
		c.dropAll()
		return c.wrapAccess("nfs", lp, err)
	}
	fres, err := c.callNFS(ctx2, procFsinfo, encodeFH(root), "FSINFO")
	if err != nil {
		return fail(err)
	}
	fi, err := decodeFsinfo(fres)
	if err != nil {
		return fail(err)
	}
	ares, err := c.callNFS(ctx2, procGetattr, encodeFH(root), "GETATTR")
	if err != nil {
		return fail(err)
	}
	ra, err := decodeGetattr(ares)
	if err != nil {
		return fail(err)
	}
	if ra.Type != TypeDir {
		return fail(fmt.Errorf("nfs3: export %q is not a directory (type %d)", c.cfg.Export, ra.Type))
	}
	c.mu.Lock()
	c.fsinfo, c.rootAttr = fi, ra
	c.mu.Unlock()
	return nil
}

// Bounds of the best-effort UMNT that cleans up a failed Connect. The caller's context is
// honoured while it lives (the cleanup is part of the call it made); once it has ended the cleanup
// still gets a short grace so that the server's mount record is normally removed, but the caller is
// never kept waiting for a mount daemon that accepts and does not answer. The call itself is also
// bounded by CallTimeout (oneShot), so a CallTimeout below these bounds wins.
const (
	umntBound          = 2 * time.Second
	umntCancelledBound = 500 * time.Millisecond
)

// umnt sends a best-effort UMNT to the MOUNT service on mountPort; failures are ignored.
func (c *Client) umnt(ctx context.Context, mountPort int) {
	bound := umntBound
	if ctx.Err() != nil {
		ctx, bound = context.WithoutCancel(ctx), umntCancelledBound
	}
	uctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	_, _, _ = c.oneShot(uctx, c.hostPort(mountPort), progMount, versMount, procUmnt, encodeDirpath(c.cfg.Export))
}

func (c *Client) wrapAccess(layer string, localPort int, err error) error {
	if !isAccess(err) {
		return err
	}
	c.mu.Lock()
	priv := c.privileged
	c.mu.Unlock()
	return &AccessError{Layer: layer, SourcePort: localPort, Privileged: priv, Err: err}
}

func (c *Client) dropAll() {
	c.mu.Lock()
	n := c.nfs
	c.nfs = nil
	c.connected = false
	c.mu.Unlock()
	if n != nil {
		n.close()
	}
}

// Disconnect sends a best-effort UMNT and closes the connection.
func (c *Client) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	was := c.connected
	c.mu.Unlock()
	if was {
		port := c.cfg.MountPort
		if port == 0 {
			port, _ = c.lookupPort(ctx, progMount, versMount)
		}
		if port != 0 {
			uctx, cancel := context.WithTimeout(ctx, c.cfg.CallTimeout)
			_, _, _ = c.oneShot(uctx, c.hostPort(port), progMount, versMount, procUmnt, encodeDirpath(c.cfg.Export))
			cancel()
		}
	}
	c.dropAll()
	return nil
}

// IsConnected reports whether Connect succeeded and the session is open.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// FSInfo returns the FSINFO result read at Connect.
func (c *Client) FSInfo() FSInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fsinfo
}

// TestConnection sends NULL and GETATTR on the export root.
func (c *Client) TestConnection(ctx context.Context) error {
	if !c.IsConnected() {
		return ErrNotConnected
	}
	if _, err := c.callNFS(ctx, procNull, nil, "NULL"); err != nil {
		return err
	}
	res, err := c.callNFS(ctx, procGetattr, encodeFH(c.rootHandle()), "GETATTR")
	if err != nil {
		return err
	}
	_, err = decodeGetattr(res)
	return err
}

func (c *Client) rootHandle() Handle {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.root
}

// ---- transport with retries ----

func (c *Client) nfsConn(ctx context.Context) (*rpcConn, error) {
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, ErrNotConnected
	}
	if c.nfs != nil && !c.nfs.isClosed() {
		n := c.nfs
		c.mu.Unlock()
		return n, nil
	}
	addr := c.nfsAddr
	c.mu.Unlock()
	nc, err := c.dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	rc := newRPCConnShared(nc, c.cred(), c.cfg.MaxRecord, &c.xid)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.connected {
		rc.close()
		return nil, ErrNotConnected
	}
	if c.nfs != nil && !c.nfs.isClosed() { // lost a race: keep the winner
		rc.close()
		return c.nfs, nil
	}
	c.nfs = rc
	c.lastNFSPort.Store(int64(rc.localPort()))
	return rc, nil
}

func (c *Client) dropConn(bad *rpcConn) {
	c.mu.Lock()
	if c.nfs == bad {
		c.nfs = nil
	}
	c.mu.Unlock()
	bad.close()
}

// transient reports errors worth retrying on a fresh connection. Every NFS
// procedure this client uses is a read, so a repeat is always safe.
func transient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, ErrConnClosed) || errors.Is(err, ErrCallTimeout) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne *NFSError
	if errors.As(err, &ne) {
		return ne.Status == NFS3ErrJukebox
	}
	var re *RPCError
	if errors.As(err, &re) {
		return !re.Denied && re.AcceptStat == acceptSystemErr
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return true
	}
	return false
}

// callNFS performs one NFS procedure with bounded retries. It returns the raw
// result bytes (status not yet interpreted) except that NFS3ERR_JUKEBOX is
// turned into a wait-and-retry on its own schedule (JukeboxRetries/JukeboxBackoff).
func (c *Client) callNFS(ctx context.Context, proc uint32, args []byte, op string) ([]byte, error) {
	max := c.maxRetries()
	jmax := c.jukeboxRetries()
	backoff := c.cfg.RetryBackoff
	jbackoff := c.cfg.JukeboxBackoff
	var last error
	failures, jukeboxWaits, attempts := 0, 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attempts++
		jukebox := false
		conn, err := c.nfsConn(ctx)
		if err == nil {
			var res []byte
			res, err = conn.call(ctx, c.cfg.CallTimeout, progNFS, versNFS, proc, args)
			if err == nil {
				if proc != procNull && len(res) >= 4 && binary.BigEndian.Uint32(res) == NFS3ErrJukebox {
					err = &NFSError{Op: op, Status: NFS3ErrJukebox}
					jukebox = true
				} else {
					return res, nil
				}
			} else if errors.Is(err, ErrConnClosed) || errors.Is(err, ErrCallTimeout) || errors.Is(err, ErrProtocol) {
				c.dropConn(conn)
			}
		}
		last = err
		var wait time.Duration
		switch {
		case jukebox:
			if jukeboxWaits >= jmax {
				return nil, fmt.Errorf("nfs3: %s failed after %d attempts: %w", op, attempts, last)
			}
			jukeboxWaits++
			wait = jbackoff
			if jbackoff *= 2; jbackoff > maxJukeboxBackoff {
				jbackoff = maxJukeboxBackoff
			}
		case transient(err) && failures < max:
			failures++
			wait = backoff
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
		default:
			if attempts > 1 && transient(last) {
				return nil, fmt.Errorf("nfs3: %s failed after %d attempts: %w", op, attempts, last)
			}
			return nil, last
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// ---- path handling ----

func cleanPath(p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: NUL byte", ErrInvalidPath)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: %q contains '..'", ErrInvalidPath, p)
		}
	}
	return path.Clean("/" + p), nil
}

func splitPath(p string) []string {
	if p == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

// cached returns the remembered handle of directory p. The root handle is always valid; every
// other entry is trusted only while validLocked says so.
func (c *Client) cached(p string) (Handle, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[p]
	if !ok {
		return nil, false
	}
	if p == "/" {
		return e.h, true
	}
	if !c.validLocked(p, e, c.now()) {
		return nil, false
	}
	return e.h, true
}

// validLocked reports whether the entry e of directory p may be trusted. Validity is a property of
// the whole chain from p up to the root, not of p alone: p's own age is within HandleCacheTTL, its
// parent entry exists with the generation p was learned under, and that parent is valid in turn. A
// directory that was replaced (new handle, new generation) therefore takes every entry learned
// below the old one out of reach, whatever order the entries expired or were evicted in.
func (c *Client) validLocked(p string, e cacheEntry, now time.Time) bool {
	for p != "/" {
		if c.cfg.HandleCacheTTL < 0 || now.Sub(e.at) > c.cfg.HandleCacheTTL {
			return false
		}
		pp := path.Dir(p)
		pe, ok := c.cache[pp]
		if !ok || pe.gen != e.pgen {
			return false
		}
		p, e = pp, pe
	}
	return true
}

// remember records the handle of directory p, learned under the entry of its parent. When p
// already held the same handle it keeps its generation (the entries below it stay valid); when the
// handle differs, or p was not remembered, p gets a NEW generation: every entry learned below the
// old one carries the old generation in pgen and is out of reach from this moment (validLocked),
// whether it is still in the map or not. A path whose parent is not remembered gets pgen 0, which
// no remembered directory below the root can have, so it is unreachable until its parent is learned
// again under a new generation.
func (c *Client) remember(p string, h Handle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.HandleCacheTTL < 0 || p == "/" {
		return
	}
	if len(c.cache) >= handleCacheMax {
		// Full: start over from the root, keeping the chain of p so that p can still be linked.
		keep := map[string]cacheEntry{"/": {h: c.root, at: c.now()}}
		for a := path.Dir(p); a != "/"; a = path.Dir(a) {
			if e, ok := c.cache[a]; ok {
				keep[a] = e
			}
		}
		c.cache = keep
	}
	old, had := c.cache[p]
	gen := old.gen
	if !had || !bytes.Equal(old.h, h) {
		c.cacheGen++
		gen = c.cacheGen
	}
	c.cache[p] = cacheEntry{h: h, at: c.now(), gen: gen, pgen: c.cache[path.Dir(p)].gen}
}

func (c *Client) forgetCache() {
	c.mu.Lock()
	c.cache = map[string]cacheEntry{"/": {h: c.root, at: c.now()}}
	c.mu.Unlock()
}

// remount asks the MOUNT service for the root handle again (MNT) and replaces the root and the
// handle cache. It is the recovery for a server that re-exported the filesystem or lost its
// handles; a failure leaves the client unchanged.
func (c *Client) remount(ctx context.Context) error {
	select { // one remount at a time; a waiter still honours its own context
	case c.remountSem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.remountSem }()
	var err error
	mountPort := c.cfg.MountPort
	if mountPort == 0 {
		if mountPort, err = c.lookupPort(ctx, progMount, versMount); err != nil {
			return err
		}
	}
	res, local, err := c.oneShot(ctx, c.hostPort(mountPort), progMount, versMount, procMnt, encodeDirpath(c.cfg.Export))
	if err != nil {
		return c.wrapAccess("mount", local, fmt.Errorf("nfs3: remount MNT %q: %w", c.cfg.Export, err))
	}
	root, _, err := decodeMnt(c.cfg.Export, res)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.root = root
	c.cache = map[string]cacheEntry{"/": {h: root, at: c.now()}}
	c.mu.Unlock()
	return nil
}

func (c *Client) lookup(ctx context.Context, dir Handle, name string) (Handle, *Attr, error) {
	res, err := c.callNFS(ctx, procLookup, encodeLookup(dir, name), "LOOKUP")
	if err != nil {
		return nil, nil, err
	}
	return decodeLookup(res)
}

func (c *Client) getattr(ctx context.Context, h Handle) (Attr, error) {
	res, err := c.callNFS(ctx, procGetattr, encodeFH(h), "GETATTR")
	if err != nil {
		return Attr{}, err
	}
	return decodeGetattr(res)
}

// resolve returns the handle and fresh attributes of p. Parent directories use
// the handle cache (bounded by HandleCacheTTL); the last component is always looked up so the
// attributes are current. A stale handle is answered in two steps: the handle cache is dropped
// and the walk repeated once, and if the walk is still stale the root is mounted again (MNT)
// and the walk repeated one last time.
func (c *Client) resolve(ctx context.Context, p string) (Handle, Attr, string, error) {
	cp, err := cleanPath(p)
	if err != nil {
		return nil, Attr{}, "", err
	}
	if !c.IsConnected() {
		return nil, Attr{}, "", ErrNotConnected
	}
	for round := 0; ; round++ {
		h, a, err := c.walk(ctx, cp)
		var ne *NFSError
		if err != nil && round < 2 && errors.As(err, &ne) && (ne.Status == NFS3ErrStale || ne.Status == NFS3ErrBadHandle) {
			if round == 0 {
				c.forgetCache()
				continue
			}
			rerr := c.remount(ctx)
			if rerr == nil {
				continue
			}
			if cerr := ctx.Err(); cerr != nil {
				return nil, Attr{}, "", cerr
			}
		}
		return h, a, cp, err
	}
}

func (c *Client) walk(ctx context.Context, cp string) (Handle, Attr, error) {
	segs := splitPath(cp)
	if len(segs) == 0 {
		root := c.rootHandle()
		a, err := c.getattr(ctx, root)
		return root, a, err
	}
	cur := c.rootHandle()
	curPath := ""
	for i, seg := range segs {
		curPath += "/" + seg
		last := i == len(segs)-1
		if !last {
			if h, ok := c.cached(curPath); ok {
				cur = h
				continue
			}
		}
		h, a, err := c.lookup(ctx, cur, seg)
		if err != nil {
			return nil, Attr{}, err
		}
		if last {
			var attr Attr
			if a != nil {
				attr = *a
			} else if attr, err = c.getattr(ctx, h); err != nil {
				return nil, Attr{}, err
			}
			if attr.Type == TypeDir {
				c.remember(curPath, h)
			}
			return h, attr, nil
		}
		if a != nil && a.Type != TypeDir {
			return nil, Attr{}, &NFSError{Op: "LOOKUP", Status: NFS3ErrNotDir}
		}
		c.remember(curPath, h)
		cur = h
	}
	return nil, Attr{}, errors.New("nfs3: unreachable")
}

func toFileInfo(name, p string, a Attr) *client.FileInfo {
	return &client.FileInfo{Name: name, Size: int64(a.Size), ModTime: a.MTime, IsDir: a.Type == TypeDir, Mode: a.FileMode(), Path: p}
}

// ---- client.Client: reads ----

// GetFileInfo returns current attributes of p (GETATTR / LOOKUP).
func (c *Client) GetFileInfo(ctx context.Context, p string) (*client.FileInfo, error) {
	_, a, cp, err := c.resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	name := path.Base(cp)
	return toFileInfo(name, cp, a), nil
}

// FileExists reports whether p exists.
func (c *Client) FileExists(ctx context.Context, p string) (bool, error) {
	_, err := c.GetFileInfo(ctx, p)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// Access asks the server which of the ACCESS3_* bits in mask the configured
// AUTH_SYS identity holds on p (RFC 1813 section 3.3.4).
func (c *Client) Access(ctx context.Context, p string, mask uint32) (uint32, error) {
	h, _, _, err := c.resolve(ctx, p)
	if err != nil {
		return 0, err
	}
	res, err := c.callNFS(ctx, procAccess, encodeAccess(h, mask), "ACCESS")
	if err != nil {
		return 0, err
	}
	return decodeAccess(res)
}

// ListDirectory lists p with READDIRPLUS, paged with the cookie and cookie
// verifier. "." and ".." are omitted.
func (c *Client) ListDirectory(ctx context.Context, p string) ([]*client.FileInfo, error) {
	dir, attr, cp, err := c.resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	if attr.Type != TypeDir {
		return nil, &NFSError{Op: "READDIRPLUS", Status: NFS3ErrNotDir}
	}
	for restart := 0; ; restart++ {
		out, err := c.listOnce(ctx, dir, cp)
		var ne *NFSError
		if errors.As(err, &ne) && ne.Status == NFS3ErrBadCookie && restart < 2 {
			continue // the directory changed under the cookie: start over (RFC 1813 3.3.17)
		}
		return out, err
	}
}

// attrLeg names the procedure of the attribute fallback of a listing whose error is being judged.
// Which handle an NFS3ERR_STALE / NFS3ERR_BADHANDLE refers to depends on it (RFC 1813):
type attrLeg int

const (
	// legLookup: LOOKUP(dir, name). The only handle in the arguments is the DIRECTORY (section
	// 3.3.3, diropargs3), so STALE/BADHANDLE means the directory itself is invalid; only NOENT
	// means that the ENTRY is gone.
	legLookup attrLeg = iota
	// legGetattr: GETATTR(h) of the handle the LOOKUP just returned for the entry: any of the
	// three means the ENTRY is gone.
	legGetattr
)

// vanishedErr reports an error that means "this entry no longer exists": a file deleted between
// the READDIRPLUS that listed it and the call that asked for its attributes. leg says which call
// failed, because the same status names a different handle in each.
func vanishedErr(err error, leg attrLeg) bool {
	var ne *NFSError
	if !errors.As(err, &ne) {
		return false
	}
	switch leg {
	case legLookup:
		return ne.Status == NFS3ErrNoEnt
	case legGetattr:
		return ne.Status == NFS3ErrNoEnt || ne.Status == NFS3ErrStale || ne.Status == NFS3ErrBadHandle
	}
	return false
}

func (c *Client) listOnce(ctx context.Context, dir Handle, cp string) ([]*client.FileInfo, error) {
	var (
		cookie       uint64
		verf         [8]byte
		out          []*client.FileInfo
		dotOnlyPages int
	)
	// A cookie that was already used as a request cookie means the server is not advancing (a page
	// that does not move the cookie asks for the same cookie again on the next round): stop
	// instead of looping against the NAS.
	usedReq := map[uint64]struct{}{}
	maxPages := c.cfg.MaxEntries
	if maxPages < math.MaxInt-8 {
		maxPages += 8
	}
	for pages := 0; ; pages++ {
		if pages > maxPages {
			return nil, fmt.Errorf("%w: READDIRPLUS of %q needed more than %d pages", ErrNotProgressing, cp, maxPages)
		}
		reqCookie := cookie
		if _, dup := usedReq[reqCookie]; dup {
			return nil, fmt.Errorf("%w: READDIRPLUS of %q asked for cookie %d a second time", ErrNotProgressing, cp, reqCookie)
		}
		usedReq[reqCookie] = struct{}{}
		res, err := c.callNFS(ctx, procReaddirplus, encodeReaddirplus(dir, cookie, verf, c.cfg.DirCount, c.cfg.DirMaxCount), "READDIRPLUS")
		if err != nil {
			return nil, err
		}
		pg, err := decodeReaddirplus(res)
		if err != nil {
			return nil, err
		}
		verf = pg.Verf
		real := 0
		for _, en := range pg.Entries {
			cookie = en.Cookie
			if en.Name == "." || en.Name == ".." {
				continue
			}
			if strings.ContainsRune(en.Name, '/') || strings.ContainsRune(en.Name, 0) || en.Name == "" {
				return nil, fmt.Errorf("%w: server returned entry name %q", ErrBadXDR, en.Name)
			}
			real++
			if len(out) >= c.cfg.MaxEntries {
				return nil, fmt.Errorf("nfs3: directory %q has more than %d entries", cp, c.cfg.MaxEntries)
			}
			var a Attr
			if en.Attr != nil {
				a = *en.Attr
			} else { // attributes are optional in entryplus3: ask for them
				h, la, err := c.lookup(ctx, dir, en.Name)
				if err != nil {
					if vanishedErr(err, legLookup) { // deleted while we were listing: it is not in the directory any more
						c.vanished.Add(1)
						continue
					}
					// Everything else, STALE and BADHANDLE included, names the DIRECTORY handle (see attrLeg):
					// the listing fails with that error, it is never reported as an empty directory.
					return nil, err
				}
				if la != nil {
					a = *la
				} else if a, err = c.getattr(ctx, h); err != nil {
					if vanishedErr(err, legGetattr) {
						c.vanished.Add(1)
						continue
					}
					return nil, err
				}
				en.Handle = h
			}
			full := path.Join(cp, en.Name)
			if a.Type == TypeDir && en.Handle != nil {
				c.remember(full, en.Handle)
			}
			out = append(out, toFileInfo(en.Name, full, a))
		}
		if pg.EOF {
			return out, nil
		}
		if len(pg.Entries) == 0 {
			return nil, fmt.Errorf("%w: READDIRPLUS returned no entries and no EOF", ErrNotProgressing)
		}
		if real == 0 {
			// "." and ".." are two entries: more than two pages made of nothing else is a loop.
			if dotOnlyPages++; dotOnlyPages > 2 {
				return nil, fmt.Errorf("%w: READDIRPLUS keeps returning only '.' and '..'", ErrNotProgressing)
			}
		}
	}
}

// ---- client.Client: refused mutations ----

// WriteFile always returns ErrReadOnly; nothing is sent.
func (c *Client) WriteFile(ctx context.Context, p string, data io.Reader) error { return ErrReadOnly }

// DeleteFile always returns ErrReadOnly; nothing is sent.
func (c *Client) DeleteFile(ctx context.Context, p string) error { return ErrReadOnly }

// CopyFile always returns ErrReadOnly; nothing is sent.
func (c *Client) CopyFile(ctx context.Context, src, dst string) error { return ErrReadOnly }

// CreateDirectory always returns ErrReadOnly; nothing is sent.
func (c *Client) CreateDirectory(ctx context.Context, p string) error { return ErrReadOnly }

// DeleteDirectory always returns ErrReadOnly; nothing is sent.
func (c *Client) DeleteDirectory(ctx context.Context, p string) error { return ErrReadOnly }

// GetProtocol returns "nfs3".
func (c *Client) GetProtocol() string { return "nfs3" }

// GetConfig returns the configuration (it holds no secret: AUTH_SYS has no password).
func (c *Client) GetConfig() interface{} {
	cfg := c.cfg
	cfg.Dial = nil
	return cfg
}
