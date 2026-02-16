# API Reference

Complete API documentation for all packages in `digital.vasic.filesystem`.

---

## Package `client`

**Import**: `digital.vasic.filesystem/pkg/client`

Defines the core interfaces and types used across all protocol adapters. This package has zero external dependencies.

### Interface: `Client`

The primary abstraction for filesystem operations. All protocol adapters implement this interface.

```go
type Client interface {
    Connect(ctx context.Context) error
    Disconnect(ctx context.Context) error
    IsConnected() bool
    TestConnection(ctx context.Context) error

    ReadFile(ctx context.Context, path string) (io.ReadCloser, error)
    WriteFile(ctx context.Context, path string, data io.Reader) error
    GetFileInfo(ctx context.Context, path string) (*FileInfo, error)
    FileExists(ctx context.Context, path string) (bool, error)
    DeleteFile(ctx context.Context, path string) error
    CopyFile(ctx context.Context, srcPath, dstPath string) error

    ListDirectory(ctx context.Context, path string) ([]*FileInfo, error)
    CreateDirectory(ctx context.Context, path string) error
    DeleteDirectory(ctx context.Context, path string) error

    GetProtocol() string
    GetConfig() interface{}
}
```

#### `Connect(ctx context.Context) error`

Establishes the connection to the storage backend. Must be called before any file or directory operations.

- **Local**: Validates that `BasePath` exists and is a directory.
- **SMB**: Opens TCP connection, performs NTLM auth, mounts share.
- **FTP**: Dials server with 30s timeout, logs in, changes to base directory.
- **NFS**: Creates mount point directory, calls `syscall.Mount`.
- **WebDAV**: Sends `PROPFIND` with `Depth: 0` to verify server.

#### `Disconnect(ctx context.Context) error`

Closes the connection and releases resources.

- **Local**: No-op (sets connected flag to false).
- **SMB**: Unmounts share, logs off session, closes TCP connection. Collects all errors.
- **FTP**: Sends `QUIT` command.
- **NFS**: Calls `syscall.Unmount`.
- **WebDAV**: No-op (sets connected flag to false).

#### `IsConnected() bool`

Returns whether the client is currently connected. Operations fail with `"not connected"` if this returns `false`.

#### `TestConnection(ctx context.Context) error`

Verifies the connection is still alive.

- **Local**: `os.Stat` on base path.
- **SMB**: `ReadDir(".")` on the share.
- **FTP**: `CurrentDir()` call.
- **NFS**: `os.Stat` on mount point.
- **WebDAV**: Re-performs `Connect()`.

#### `ReadFile(ctx context.Context, path string) (io.ReadCloser, error)`

Opens a file for reading. The caller is responsible for closing the returned `io.ReadCloser`.

- **path**: Relative path within the storage backend.
- **Returns**: An `io.ReadCloser` wrapping the file data.

#### `WriteFile(ctx context.Context, path string, data io.Reader) error`

Writes data to a file. Creates the file if it does not exist, overwrites if it does. Some adapters auto-create parent directories (local, FTP, NFS).

- **path**: Relative path within the storage backend.
- **data**: Reader providing the file content.

#### `GetFileInfo(ctx context.Context, path string) (*FileInfo, error)`

Returns metadata about a file or directory.

- **path**: Relative path within the storage backend.
- **Returns**: `*FileInfo` with name, size, modification time, directory flag, permissions, and path.

#### `FileExists(ctx context.Context, path string) (bool, error)`

Checks whether a file or directory exists. Returns `(false, nil)` for missing files rather than an error.

#### `DeleteFile(ctx context.Context, path string) error`

Deletes a single file.

#### `CopyFile(ctx context.Context, srcPath, dstPath string) error`

Copies a file from source to destination within the same storage backend.

- **WebDAV**: Uses the HTTP `COPY` method with `Destination` header.
- **FTP**: Downloads source, uploads to destination.
- **Local/NFS**: Opens source, creates destination, `io.Copy`.
- **SMB**: Opens source, creates destination, `io.Copy`.

#### `ListDirectory(ctx context.Context, path string) ([]*FileInfo, error)`

Lists all entries in a directory.

- **path**: Relative path to the directory. Use `""` or `"."` for the root.
- **Returns**: Slice of `*FileInfo` for each entry. Does not include `.` or `..`.

#### `CreateDirectory(ctx context.Context, path string) error`

Creates a directory. Local and NFS adapters create intermediate directories (`MkdirAll`). SMB creates a single directory level.

#### `DeleteDirectory(ctx context.Context, path string) error`

Deletes a directory. Local and NFS adapters remove contents recursively (`RemoveAll`). SMB and FTP require the directory to be empty.

#### `GetProtocol() string`

Returns the protocol identifier string: `"smb"`, `"ftp"`, `"nfs"`, `"webdav"`, or `"local"`.

#### `GetConfig() interface{}`

Returns the protocol-specific configuration struct. Cast to the appropriate type:

```go
smbConfig := c.GetConfig().(*smb.Config)
localConfig := c.GetConfig().(*local.Config)
```

---

### Interface: `Factory`

Creates `Client` instances from `StorageConfig`.

```go
type Factory interface {
    CreateClient(config *StorageConfig) (Client, error)
    SupportedProtocols() []string
}
```

#### `CreateClient(config *StorageConfig) (Client, error)`

Creates a new client for the protocol specified in `config.Protocol`. Returns an error for unsupported protocols.

#### `SupportedProtocols() []string`

Returns the list of supported protocol identifiers.

---

### Interface: `ConnectionPool`

Manages a pool of reusable client connections. Defined for future implementation.

```go
type ConnectionPool interface {
    GetClient(config *StorageConfig) (Client, error)
    ReturnClient(client Client) error
    CloseAll() error
}
```

---

### Type: `FileInfo`

Represents metadata about a file or directory.

```go
type FileInfo struct {
    Name    string      // Base name of the file
    Size    int64       // Size in bytes (0 for directories on some protocols)
    ModTime time.Time   // Last modification time
    IsDir   bool        // True if the entry is a directory
    Mode    os.FileMode // Unix permissions (0644 default for remote protocols)
    Path    string      // Relative path within the storage backend
}
```

---

### Type: `StorageConfig`

Configuration for creating a storage client through the factory.

```go
type StorageConfig struct {
    ID        string                 `json:"id"`         // Unique identifier
    Name      string                 `json:"name"`       // Human-readable name
    Protocol  string                 `json:"protocol"`   // Protocol: smb, ftp, nfs, webdav, local
    Enabled   bool                   `json:"enabled"`    // Whether the storage is active
    MaxDepth  int                    `json:"max_depth"`  // Max directory traversal depth
    Settings  map[string]interface{} `json:"settings"`   // Protocol-specific configuration
    CreatedAt time.Time              `json:"created_at"` // Creation timestamp
    UpdatedAt time.Time              `json:"updated_at"` // Last update timestamp
}
```

---

### Type: `CopyOperation`

Describes a file copy request.

```go
type CopyOperation struct {
    SourcePath        string // Source file path
    DestinationPath   string // Destination file path
    OverwriteExisting bool   // Whether to overwrite if destination exists
}
```

---

### Type: `CopyResult`

Describes the outcome of a copy operation.

```go
type CopyResult struct {
    Success     bool          // Whether the copy succeeded
    BytesCopied int64         // Number of bytes copied
    Error       error         // Error if copy failed
    TimeTaken   time.Duration // Duration of the operation
}
```

---

## Package `factory`

**Import**: `digital.vasic.filesystem/pkg/factory`

Provides the `DefaultFactory` implementation of `client.Factory` and helper functions for extracting typed values from settings maps.

### Type: `DefaultFactory`

```go
type DefaultFactory struct{}
```

Implements `client.Factory`. Routes protocol strings to the appropriate adapter constructor.

#### `NewDefaultFactory() *DefaultFactory`

Creates a new factory instance.

```go
f := factory.NewDefaultFactory()
```

#### `(*DefaultFactory) CreateClient(config *client.StorageConfig) (client.Client, error)`

Creates a protocol-specific client based on `config.Protocol`:

| Protocol | Adapter Created |
|----------|----------------|
| `"smb"` | `smb.NewSMBClient` |
| `"ftp"` | `ftp.NewFTPClient` |
| `"nfs"` | `nfs.NewNFSClient` (Linux) or error (other platforms) |
| `"webdav"` | `webdav.NewWebDAVClient` |
| `"local"` | `local.NewLocalClient` |

Returns `fmt.Errorf("unsupported protocol: %s", config.Protocol)` for unknown protocols.

#### `(*DefaultFactory) SupportedProtocols() []string`

Returns `[]string{"smb", "ftp", "nfs", "webdav", "local"}`.

---

### Function: `NewSMBClient`

```go
func NewSMBClient(config *smb.Config) client.Client
```

Convenience wrapper that delegates to `smb.NewSMBClient`.

---

### Function: `GetStringSetting`

```go
func GetStringSetting(settings map[string]interface{}, key, defaultValue string) string
```

Extracts a string value from a settings map. Returns `defaultValue` if the key is missing or the value is not a string.

---

### Function: `GetIntSetting`

```go
func GetIntSetting(settings map[string]interface{}, key string, defaultValue int) int
```

Extracts an integer value from a settings map. Handles both `int` and `float64` types (JSON numbers deserialize as `float64`). Returns `defaultValue` if the key is missing or the value is not numeric.

---

## Package `smb`

**Import**: `digital.vasic.filesystem/pkg/smb`

SMB/CIFS protocol adapter using the `go-smb2` library.

### Type: `Config`

```go
type Config struct {
    Host     string `json:"host"`     // Server hostname or IP
    Port     int    `json:"port"`     // Server port (typically 445)
    Share    string `json:"share"`    // Share name
    Username string `json:"username"` // NTLM username
    Password string `json:"password"` // NTLM password
    Domain   string `json:"domain"`   // Windows domain (e.g., "WORKGROUP")
}
```

### Type: `Client`

```go
type Client struct { /* unexported fields */ }
```

Implements `client.Client`. Internal fields: `conn` (TCP connection), `session` (`smb2.Session`), `share` (`smb2.Share`), `config`.

#### `NewSMBClient(config *Config) *Client`

Creates a new SMB client. Does not connect; call `Connect()` to establish the connection.

---

## Package `ftp`

**Import**: `digital.vasic.filesystem/pkg/ftp`

FTP protocol adapter using the `jlaffaye/ftp` library.

### Type: `Config`

```go
type Config struct {
    Host     string `json:"host"`     // Server hostname or IP
    Port     int    `json:"port"`     // Server port (typically 21)
    Username string `json:"username"` // FTP username
    Password string `json:"password"` // FTP password
    Path     string `json:"path"`     // Base directory on the server
}
```

### Type: `Client`

```go
type Client struct { /* unexported fields */ }
```

Implements `client.Client`. Internal fields: `config`, `client` (`goftp.ServerConn`), `connected`.

#### `NewFTPClient(config *Config) *Client`

Creates a new FTP client. Does not connect; call `Connect()` to establish the connection.

**Connection timeout**: 30 seconds (hardcoded in `goftp.DialWithTimeout`).

---

## Package `nfs`

**Import**: `digital.vasic.filesystem/pkg/nfs`

**Platform**: Linux only (`//go:build linux`)

NFS protocol adapter using `syscall.Mount`/`syscall.Unmount`.

### Type: `Config`

```go
type Config struct {
    Host       string `json:"host"`        // NFS server hostname or IP
    Path       string `json:"path"`        // Exported path on the server
    MountPoint string `json:"mount_point"` // Local directory to mount on
    Options    string `json:"options"`     // Mount options (default: "vers=3")
}
```

### Type: `Client`

```go
type Client struct { /* unexported fields */ }
```

Implements `client.Client`. Internal fields: `config`, `mounted`, `connected`, `mountPoint`.

#### `NewNFSClient(config Config) (*Client, error)`

Creates a new NFS client. Returns an error if `MountPoint` is empty. Note: this constructor takes `Config` by value (not pointer), unlike other adapters.

**Privileges**: `Connect()` calls `syscall.Mount`, which typically requires root.

---

## Package `webdav`

**Import**: `digital.vasic.filesystem/pkg/webdav`

WebDAV protocol adapter using `net/http` for HTTP-based file operations.

### Type: `Config`

```go
type Config struct {
    URL      string `json:"url"`      // WebDAV server base URL
    Username string `json:"username"` // HTTP Basic Auth username (optional)
    Password string `json:"password"` // HTTP Basic Auth password (optional)
    Path     string `json:"path"`     // Path prefix on the server
}
```

### Type: `Client`

```go
type Client struct { /* unexported fields */ }
```

Implements `client.Client`. Internal fields: `config`, `client` (`http.Client` with 30s timeout), `baseURL` (`url.URL`), `connected`.

#### `NewWebDAVClient(config *Config) *Client`

Creates a new WebDAV client. Parses the URL and applies the path prefix. Does not connect; call `Connect()` to verify server accessibility.

**HTTP Methods Used:**

| Operation | HTTP Method |
|-----------|-------------|
| Connect / TestConnection | `PROPFIND` (Depth: 0) |
| ReadFile | `GET` |
| WriteFile | `PUT` |
| GetFileInfo | `HEAD` |
| ListDirectory | `PROPFIND` (Depth: 1) |
| FileExists | `HEAD` |
| CreateDirectory | `MKCOL` |
| DeleteFile / DeleteDirectory | `DELETE` |
| CopyFile | `COPY` (with Destination header) |

**ListDirectory response parsing**: Parses the DAV XML `multistatus` response using string splitting on `<D:response>` elements. Extracts `href`, `displayname`, `getcontentlength`, `getlastmodified`, and `resourcetype` properties.

---

## Package `local`

**Import**: `digital.vasic.filesystem/pkg/local`

Local filesystem adapter using the Go `os` package.

### Type: `Config`

```go
type Config struct {
    BasePath string `json:"base_path"` // Absolute path to the base directory
}
```

### Type: `Client`

```go
type Client struct { /* unexported fields */ }
```

Implements `client.Client`. Internal fields: `config`, `basePath`, `connected`.

#### `NewLocalClient(config *Config) *Client`

Creates a new local filesystem client. Does not validate the path; call `Connect()` to verify the base directory exists.

**Path resolution**: All relative paths are joined with `BasePath` after cleaning and stripping `..` sequences. This prevents path traversal outside the base directory.

**Auto-creation**: `WriteFile` and `CopyFile` automatically create parent directories using `os.MkdirAll`. `CreateDirectory` also creates intermediate directories.

**DeleteDirectory**: Uses `os.RemoveAll`, which recursively deletes all contents.

---

## Type Compatibility

All adapter `Client` types satisfy `client.Client` at compile time via interface compliance declarations:

```go
// In pkg/local/local_test.go
var _ client.Client = (*Client)(nil)

// In pkg/factory/factory_test.go
var _ client.Factory = (*DefaultFactory)(nil)
```
