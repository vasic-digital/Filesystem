# AGENTS.md

Agent capabilities and integration guide for `digital.vasic.filesystem`.

## Module Identity

- **Module**: `digital.vasic.filesystem`
- **Language**: Go 1.24+
- **Type**: Library (no executable binary)
- **Purpose**: Unified multi-protocol filesystem abstraction

## What This Module Provides

This module exposes a single `client.Client` interface that normalizes filesystem operations across five protocols:

| Protocol | Package | Platform | Backend |
|----------|---------|----------|---------|
| SMB/CIFS | `pkg/smb` | All | `go-smb2` library |
| FTP | `pkg/ftp` | All | `jlaffaye/ftp` library |
| NFS | `pkg/nfs` | Linux only | `syscall.Mount` |
| WebDAV | `pkg/webdav` | All | `net/http` (raw HTTP) |
| Local | `pkg/local` | All | `os` package |

## Agent Capabilities

### Creating Clients

Agents that need filesystem access should use `factory.DefaultFactory` to create clients:

```go
import (
    "digital.vasic.filesystem/pkg/client"
    "digital.vasic.filesystem/pkg/factory"
)

f := factory.NewDefaultFactory()
c, err := f.CreateClient(&client.StorageConfig{
    Protocol: "local",
    Settings: map[string]interface{}{
        "base_path": "/data/media",
    },
})
```

### Available Operations

All clients support the full `client.Client` interface:

- **Connection lifecycle**: `Connect`, `Disconnect`, `IsConnected`, `TestConnection`
- **File I/O**: `ReadFile`, `WriteFile`, `GetFileInfo`, `FileExists`, `DeleteFile`, `CopyFile`
- **Directory management**: `ListDirectory`, `CreateDirectory`, `DeleteDirectory`
- **Introspection**: `GetProtocol`, `GetConfig`

### Protocol-Specific Configuration

Each protocol expects specific keys in `StorageConfig.Settings`:

**SMB**: `host`, `port` (default 445), `share`, `username`, `password`, `domain` (default "WORKGROUP")

**FTP**: `host`, `port` (default 21), `username`, `password`, `path`

**NFS**: `host`, `path`, `mount_point`, `options` (default "vers=3")

**WebDAV**: `url`, `username`, `password`, `path`

**Local**: `base_path`

## Integration Patterns

### Connection Management

All clients require explicit `Connect()` before use. Always defer `Disconnect()`:

```go
ctx := context.Background()
if err := c.Connect(ctx); err != nil {
    return err
}
defer c.Disconnect(ctx)
```

### Error Handling

- All methods return wrapped errors with `%w` formatting
- Connection-related errors indicate network or authentication failures
- File-not-found is returned as a wrapped OS-level or protocol-level error
- `FileExists()` returns `(false, nil)` for missing files rather than an error

### Context Support

All operations accept `context.Context` for cancellation and deadline propagation.

## Extending the Module

### Adding a New Protocol

1. Create `pkg/<protocol>/` with a `Config` struct and `Client` type
2. Implement all 15 methods of `client.Client`
3. Add a `var _ client.Client = (*Client)(nil)` compile-time check
4. Add a case to `factory.DefaultFactory.CreateClient()`
5. Add the protocol name to `factory.DefaultFactory.SupportedProtocols()`
6. If platform-specific, use build tags following the NFS pattern (`nfs_linux.go` / `nfs_other.go`)

## Testing

```bash
go test ./...                          # all tests
go test -v ./pkg/local/                # local adapter (full coverage, no external deps)
go test -v ./pkg/factory/              # factory + helpers
go test -v ./pkg/client/               # interface struct tests
```

The `local` package has the most comprehensive test suite since it requires no external services. SMB, FTP, WebDAV, and NFS tests are limited to unit-level construction and configuration validation without live servers.
