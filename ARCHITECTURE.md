# Architecture -- Filesystem

## Purpose

Unified multi-protocol filesystem client for Go. Abstracts SMB, FTP, NFS, WebDAV, and local filesystem operations behind a single `client.Client` interface. Used by catalog-api for accessing media storage backends across different protocols transparently.

## Structure

```
pkg/
  client/    Core interfaces and types: Client, Factory, FileInfo, StorageConfig, ConnectionPool
  factory/   DefaultFactory implementation: creates protocol-specific clients from StorageConfig
  smb/       SMB/CIFS protocol adapter (go-smb2 library)
  ftp/       FTP protocol adapter (jlaffaye/ftp library)
  nfs/       NFS protocol adapter (Linux-only, syscall mount, build-tagged)
  webdav/    WebDAV protocol adapter (net/http-based, PROPFIND/PUT/GET/DELETE)
  local/     Local filesystem adapter (os package)
```

## Key Components

- **`client.Client`** -- 15-method interface: Connect/Disconnect, ReadFile/WriteFile/DeleteFile/CopyFile, ListDirectory/CreateDirectory/DeleteDirectory, GetFileInfo/FileExists, GetProtocol/GetConfig
- **`client.Factory`** -- Creates protocol-specific clients from StorageConfig
- **`factory.DefaultFactory`** -- Routes StorageConfig.Protocol via switch to the correct adapter constructor
- **Path resolution** -- Each adapter has private `resolvePath()` that sanitizes paths (strips `..`) and joins with base path
- **Platform build tags** -- NFS uses `//go:build linux` split files; non-Linux platforms return an error

## Data Flow

```
factory.CreateClient(config) -> switch config.Protocol:
    "smb"    -> smb.NewClient(config)
    "ftp"    -> ftp.NewClient(config)
    "nfs"    -> nfs.NewClient(config)     (Linux only)
    "webdav" -> webdav.NewClient(config)
    "local"  -> local.NewClient(config)

client.Connect(ctx) -> establish protocol connection
client.ListDirectory(ctx, path) -> resolvePath(path) -> protocol-specific listing
client.ReadFile(ctx, path) -> resolvePath(path) -> io.ReadCloser
```

## Dependencies

- `github.com/hirochachacha/go-smb2` -- SMB2/3 protocol implementation
- `github.com/jlaffaye/ftp` -- FTP client library
- `github.com/stretchr/testify` -- Test assertions

## Testing Strategy

Table-driven tests with `testify`. Local filesystem adapter has full test coverage using temporary directories. SMB, FTP, and WebDAV tests use connection guards (skip if not connected). Path traversal protection tested explicitly. Interface compliance verified with `var _ client.Client = (*Client)(nil)`.
