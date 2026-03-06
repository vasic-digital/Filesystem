# Architecture

## Purpose

The Filesystem module (`digital.vasic.filesystem`) provides a unified multi-protocol filesystem client that abstracts SMB, FTP, NFS, WebDAV, and local filesystem operations behind a single `client.Client` interface. It is consumed by `catalog-api` to access media storage backends regardless of the underlying protocol.

## Package Overview

| Package | Path | Description |
|---------|------|-------------|
| `client` | `pkg/client/` | Core interfaces (`Client`, `Factory`, `ConnectionPool`) and types (`FileInfo`, `StorageConfig`, `CopyOperation`, `CopyResult`). Zero external dependencies. |
| `factory` | `pkg/factory/` | `DefaultFactory` implementation that routes `StorageConfig.Protocol` to the correct adapter constructor. Provides `GetStringSetting`/`GetIntSetting` helpers for typed config extraction. |
| `smb` | `pkg/smb/` | SMB2/3 adapter using `go-smb2`. NTLM auth, share mounting, file ops via `smb2.Share`. |
| `ftp` | `pkg/ftp/` | FTP adapter using `jlaffaye/ftp`. Dial with timeout, login, base directory navigation. |
| `nfs` | `pkg/nfs/` | NFS adapter (Linux-only). Uses `syscall.Mount`/`Unmount` to mount NFS shares, then delegates to `os` package for file ops. |
| `webdav` | `pkg/webdav/` | WebDAV adapter using `net/http`. PROPFIND for listing/connect, GET/PUT/DELETE/COPY/MKCOL for file and directory ops. Basic auth. |
| `local` | `pkg/local/` | Local filesystem adapter using Go `os` package. Path validation on connect, standard file I/O. |

## Design Patterns

| Pattern | Where | How |
|---------|-------|-----|
| Strategy | `client.Client` interface | All 5 protocol adapters implement the same 15-method interface, making them interchangeable at runtime. |
| Factory | `factory.DefaultFactory` | `CreateClient(StorageConfig)` switches on `Protocol` string, extracts typed settings, and returns the appropriate adapter. |
| Connection Guard | Every adapter method | All file/directory operations check `IsConnected()` first and return `"not connected"` error if the client is not connected. |
| Path Traversal Protection | `resolvePath()` / `resolveURL()` | Each adapter sanitizes input paths by stripping `..` segments and joining with the configured base path/URL. |
| Platform Build Tags | `factory/nfs_linux.go`, `factory/nfs_other.go` | NFS support is gated to Linux via `//go:build linux` / `//go:build !linux` to isolate `syscall.Mount` usage. |
| Constructor Injection | `New<Protocol>Client(config)` | Each adapter accepts its own typed `Config` struct. The factory maps generic `Settings` to these structs. |

## Key Interfaces/Types

### client.Client

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

### client.Factory

```go
type Factory interface {
    CreateClient(config *StorageConfig) (Client, error)
    SupportedProtocols() []string
}
```

### client.ConnectionPool

```go
type ConnectionPool interface {
    GetClient(config *StorageConfig) (Client, error)
    ReturnClient(client Client) error
    CloseAll() error
}
```

### client.FileInfo

```go
type FileInfo struct {
    Name    string
    Size    int64
    ModTime time.Time
    IsDir   bool
    Mode    os.FileMode
    Path    string
}
```

### client.StorageConfig

```go
type StorageConfig struct {
    ID        string                 `json:"id"`
    Name      string                 `json:"name"`
    Protocol  string                 `json:"protocol"`
    Enabled   bool                   `json:"enabled"`
    MaxDepth  int                    `json:"max_depth"`
    Settings  map[string]interface{} `json:"settings"`
    CreatedAt time.Time              `json:"created_at"`
    UpdatedAt time.Time              `json:"updated_at"`
}
```

## Usage Example

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
    f := factory.NewDefaultFactory()

    config := &client.StorageConfig{
        ID:       "nas-smb",
        Name:     "NAS Media Share",
        Protocol: "smb",
        Enabled:  true,
        Settings: map[string]interface{}{
            "host":     "192.168.0.241",
            "port":     445,
            "share":    "media",
            "username": "user",
            "password": "pass",
            "domain":   "WORKGROUP",
        },
    }

    c, err := f.CreateClient(config)
    if err != nil {
        log.Fatalf("create client: %v", err)
    }

    ctx := context.Background()
    if err := c.Connect(ctx); err != nil {
        log.Fatalf("connect: %v", err)
    }
    defer c.Disconnect(ctx)

    files, err := c.ListDirectory(ctx, "/movies")
    if err != nil {
        log.Fatalf("list: %v", err)
    }

    for _, fi := range files {
        fmt.Printf("%s  %d bytes  dir=%v\n", fi.Name, fi.Size, fi.IsDir)
    }
}
```
