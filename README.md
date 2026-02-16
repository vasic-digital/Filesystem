# Filesystem

Unified multi-protocol filesystem client for Go. Part of the [Catalogizer](https://github.com/nicepkg/catalogizer) project.

**Protocols**: SMB | FTP | NFS | WebDAV | Local

**Module**: `digital.vasic.filesystem`
**Go**: 1.24+
**License**: Proprietary

---

## Installation

```bash
go get digital.vasic.filesystem
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "digital.vasic.filesystem/pkg/client"
    "digital.vasic.filesystem/pkg/factory"
)

func main() {
    // Create a factory
    f := factory.NewDefaultFactory()

    // Create a local filesystem client
    c, err := f.CreateClient(&client.StorageConfig{
        ID:       "media-local",
        Name:     "Local Media",
        Protocol: "local",
        Enabled:  true,
        Settings: map[string]interface{}{
            "base_path": "/data/media",
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    // Connect and use
    ctx := context.Background()
    if err := c.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    defer c.Disconnect(ctx)

    // List files
    files, err := c.ListDirectory(ctx, "movies")
    if err != nil {
        log.Fatal(err)
    }

    for _, file := range files {
        fmt.Printf("%s (%d bytes, dir=%v)\n", file.Name, file.Size, file.IsDir)
    }
}
```

## API Overview

### Core Interface

Every protocol adapter implements `client.Client`:

```go
type Client interface {
    // Connection management
    Connect(ctx context.Context) error
    Disconnect(ctx context.Context) error
    IsConnected() bool
    TestConnection(ctx context.Context) error

    // File operations
    ReadFile(ctx context.Context, path string) (io.ReadCloser, error)
    WriteFile(ctx context.Context, path string, data io.Reader) error
    GetFileInfo(ctx context.Context, path string) (*FileInfo, error)
    FileExists(ctx context.Context, path string) (bool, error)
    DeleteFile(ctx context.Context, path string) error
    CopyFile(ctx context.Context, srcPath, dstPath string) error

    // Directory operations
    ListDirectory(ctx context.Context, path string) ([]*FileInfo, error)
    CreateDirectory(ctx context.Context, path string) error
    DeleteDirectory(ctx context.Context, path string) error

    // Metadata
    GetProtocol() string
    GetConfig() interface{}
}
```

### Factory

The factory creates protocol-appropriate clients from a `StorageConfig`:

```go
f := factory.NewDefaultFactory()
f.SupportedProtocols() // ["smb", "ftp", "nfs", "webdav", "local"]

client, err := f.CreateClient(config)
```

### Protocol Configuration

Each protocol accepts specific settings in `StorageConfig.Settings`:

| Protocol | Settings |
|----------|----------|
| `smb` | `host`, `port`, `share`, `username`, `password`, `domain` |
| `ftp` | `host`, `port`, `username`, `password`, `path` |
| `nfs` | `host`, `path`, `mount_point`, `options` |
| `webdav` | `url`, `username`, `password`, `path` |
| `local` | `base_path` |

## Packages

| Package | Import Path | Description |
|---------|-------------|-------------|
| `client` | `digital.vasic.filesystem/pkg/client` | Core interfaces and types |
| `factory` | `digital.vasic.filesystem/pkg/factory` | Client factory implementation |
| `smb` | `digital.vasic.filesystem/pkg/smb` | SMB/CIFS protocol adapter |
| `ftp` | `digital.vasic.filesystem/pkg/ftp` | FTP protocol adapter |
| `nfs` | `digital.vasic.filesystem/pkg/nfs` | NFS protocol adapter (Linux only) |
| `webdav` | `digital.vasic.filesystem/pkg/webdav` | WebDAV protocol adapter |
| `local` | `digital.vasic.filesystem/pkg/local` | Local filesystem adapter |

## Platform Support

| Protocol | Linux | macOS | Windows |
|----------|-------|-------|---------|
| SMB | Yes | Yes | Yes |
| FTP | Yes | Yes | Yes |
| NFS | Yes | No | No |
| WebDAV | Yes | Yes | Yes |
| Local | Yes | Yes | Yes |

NFS uses Linux `syscall.Mount` and is gated behind `//go:build linux` build tags. On non-Linux platforms, the factory returns an error for NFS protocol requests.

## Testing

```bash
# All tests
go test ./...

# Verbose output
go test -v ./...

# Single package
go test -v ./pkg/local/

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Documentation

- [Architecture](docs/architecture.md) -- Design patterns, Mermaid diagrams, package relationships
- [User Guide](docs/user-guide.md) -- Step-by-step usage instructions
- [API Reference](docs/api-reference.md) -- Complete API documentation for all packages

## Dependencies

| Dependency | Purpose |
|------------|---------|
| `github.com/hirochachacha/go-smb2` | SMB2/3 protocol implementation |
| `github.com/jlaffaye/ftp` | FTP client library |
| `github.com/stretchr/testify` | Test assertions |
