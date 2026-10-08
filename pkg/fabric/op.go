// Package fabric is the connection fabric shared by every storage protocol
// client: a connection Pool, a per-host HostBudget that is shared across
// protocols, and composable client.Client decorators (Limited, Retrying,
// Confined, Metered). It contains no protocol code; it only wraps
// client.Client, so a new protocol client inherits all of it.
//
// Composition order matters. The recommended chain, outermost first, is
//
//	Metered( Retrying( Limited( Confined( ReadOnly( protocolClient )))))
//
// so that metrics see the final outcome, every retry attempt takes a fresh
// budget slot, and the path guard and read-only guard sit next to the wire.
package fabric

import (
	"fmt"
	"net/netip"
	"strings"
)

// Op identifies one operation of client.Client (plus client.SeekableClient).
type Op int

// The Op values. The order is the order of opTable.
const (
	OpConnect Op = iota
	OpDisconnect
	OpTestConnection
	OpReadFile
	OpWriteFile
	OpGetFileInfo
	OpFileExists
	OpDeleteFile
	OpCopyFile
	OpListDirectory
	OpCreateDirectory
	OpDeleteDirectory
	OpOpenSeekable
	opCount
)

type opInfo struct {
	name      string
	mutating  bool // changes the remote file system
	retryable bool // safe to repeat when the failure was transient
	stream    bool // returns a stream that outlives the call
	paths     int  // number of path arguments
}

// opTable is the reviewed classification of every operation. TestOpTable_*
// proves it matches client.Client and client.SeekableClient method for method;
// a method added to either interface fails that test until it is classified.
var opTable = [opCount]opInfo{
	OpConnect:         {name: "Connect", retryable: true},
	OpDisconnect:      {name: "Disconnect"},
	OpTestConnection:  {name: "TestConnection", retryable: true},
	OpReadFile:        {name: "ReadFile", retryable: true, stream: true, paths: 1},
	OpWriteFile:       {name: "WriteFile", mutating: true, paths: 1},
	OpGetFileInfo:     {name: "GetFileInfo", retryable: true, paths: 1},
	OpFileExists:      {name: "FileExists", retryable: true, paths: 1},
	OpDeleteFile:      {name: "DeleteFile", mutating: true, paths: 1},
	OpCopyFile:        {name: "CopyFile", mutating: true, paths: 2},
	OpListDirectory:   {name: "ListDirectory", retryable: true, paths: 1},
	OpCreateDirectory: {name: "CreateDirectory", mutating: true, paths: 1},
	OpDeleteDirectory: {name: "DeleteDirectory", mutating: true, paths: 1},
	OpOpenSeekable:    {name: "OpenSeekable", retryable: true, stream: true, paths: 1},
}

// AllOps returns every Op in table order.
func AllOps() []Op {
	out := make([]Op, 0, opCount)
	for o := Op(0); o < opCount; o++ {
		out = append(out, o)
	}
	return out
}

func (o Op) valid() bool { return o >= 0 && o < opCount }

// String is the client.Client method name of the operation.
func (o Op) String() string {
	if !o.valid() {
		return fmt.Sprintf("Op(%d)", int(o))
	}
	return opTable[o].name
}

// Mutating reports whether the operation changes the remote file system.
func (o Op) Mutating() bool { return o.valid() && opTable[o].mutating }

// Retryable reports whether the operation may be repeated after a transient
// failure. Mutations and Disconnect are never retryable.
func (o Op) Retryable() bool { return o.valid() && opTable[o].retryable }

// Paths is the number of path arguments of the operation.
func (o Op) Paths() int {
	if !o.valid() {
		return 0
	}
	return opTable[o].paths
}

func (o Op) stream() bool { return o.valid() && opTable[o].stream }

// HostKey normalises a host (or host:port) to the key under which a
// HostBudget is shared: lower case, no port, no IPv6 brackets, and IP literals
// in canonical form (RFC 5952 text, IPv4-mapped IPv6 unmapped to IPv4), so
// "::1" and "0:0:0:0:0:0:0:1", or "192.168.1.5" and "::ffff:192.168.1.5",
// share one key. Empty input is an error so that a missing host can never
// silently share a budget, and so is anything that is not a bare host or
// host:port (a URL, a path, user@host, whitespace or control characters): a
// URL would collapse every host of a scheme into one key.
//
// Names are NOT resolved: "nas", "nas.local" and the IP of the same machine
// get three keys. Callers that reach one machine under several names must
// pass the same name (or its IP) everywhere to share a budget.
func HostKey(hostport string) (string, error) {
	h := strings.TrimSpace(hostport)
	if h == "" {
		return "", fmt.Errorf("fabric: empty host")
	}
	for _, r := range h {
		if r <= 0x20 || r == 0x7f || r == '/' || r == '\\' || r == '@' || r == '?' || r == '#' {
			return "", fmt.Errorf("fabric: %q is not a host or host:port (URL, path, userinfo or control character)", hostport)
		}
	}
	if strings.Contains(h, "://") {
		return "", fmt.Errorf("fabric: %q is a URL, want host or host:port", hostport)
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			h = h[1:i]
		}
	} else if strings.Count(h, ":") == 1 {
		h = h[:strings.Index(h, ":")]
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" {
		return "", fmt.Errorf("fabric: empty host in %q", hostport)
	}
	if a, err := netip.ParseAddr(h); err == nil {
		h = a.Unmap().String()
	}
	return h, nil
}
