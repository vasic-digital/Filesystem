# User Guide

## Getting Started

### Installation

Add the module to your Go project:

```bash
go get digital.vasic.filesystem
```

### Import Paths

```go
import (
    "digital.vasic.filesystem/pkg/client"   // Interfaces and types
    "digital.vasic.filesystem/pkg/factory"  // Client factory
    "digital.vasic.filesystem/pkg/local"    // Direct local client usage
    "digital.vasic.filesystem/pkg/smb"      // Direct SMB client usage
    "digital.vasic.filesystem/pkg/ftp"      // Direct FTP client usage
    "digital.vasic.filesystem/pkg/nfs"      // Direct NFS client usage (Linux only)
    "digital.vasic.filesystem/pkg/webdav"   // Direct WebDAV client usage
)
```

## Using the Factory (Recommended)

The factory approach is recommended for most use cases. It creates the appropriate client based on a `StorageConfig`, making it easy to switch protocols at runtime.

### Step 1: Create a Factory

```go
f := factory.NewDefaultFactory()
```

### Step 2: Define Storage Configuration

```go
config := &client.StorageConfig{
    ID:       "storage-1",
    Name:     "My Storage",
    Protocol: "local",
    Enabled:  true,
    MaxDepth: 10,
    Settings: map[string]interface{}{
        "base_path": "/data/media",
    },
}
```

### Step 3: Create a Client

```go
c, err := f.CreateClient(config)
if err != nil {
    log.Fatalf("Failed to create client: %v", err)
}
```

### Step 4: Connect

```go
ctx := context.Background()
if err := c.Connect(ctx); err != nil {
    log.Fatalf("Failed to connect: %v", err)
}
defer c.Disconnect(ctx)
```

### Step 5: Perform Operations

```go
// List a directory
files, err := c.ListDirectory(ctx, "movies")
if err != nil {
    log.Fatalf("Failed to list: %v", err)
}
for _, f := range files {
    fmt.Printf("  %s  %d bytes  dir=%v\n", f.Name, f.Size, f.IsDir)
}
```

## Protocol-Specific Configuration

### Local Filesystem

The simplest protocol. Operates on a base directory on the local machine.

```go
config := &client.StorageConfig{
    Protocol: "local",
    Settings: map[string]interface{}{
        "base_path": "/mnt/media",
    },
}
```

**Settings:**

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `base_path` | string | Yes | Absolute path to the base directory |

### SMB (Windows File Sharing)

Connects to SMB/CIFS shares using NTLM authentication.

```go
config := &client.StorageConfig{
    Protocol: "smb",
    Settings: map[string]interface{}{
        "host":     "192.168.1.100",
        "port":     445,
        "share":    "MediaShare",
        "username": "mediauser",
        "password": "secret",
        "domain":   "WORKGROUP",
    },
}
```

**Settings:**

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `host` | string | Yes | -- | SMB server hostname or IP |
| `port` | int | No | 445 | SMB server port |
| `share` | string | Yes | -- | Share name to mount |
| `username` | string | Yes | -- | NTLM username |
| `password` | string | Yes | -- | NTLM password |
| `domain` | string | No | "WORKGROUP" | Windows domain |

### FTP

Connects to standard FTP servers with authentication.

```go
config := &client.StorageConfig{
    Protocol: "ftp",
    Settings: map[string]interface{}{
        "host":     "ftp.example.com",
        "port":     21,
        "username": "ftpuser",
        "password": "secret",
        "path":     "/media",
    },
}
```

**Settings:**

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `host` | string | Yes | -- | FTP server hostname or IP |
| `port` | int | No | 21 | FTP server port |
| `username` | string | Yes | -- | FTP username |
| `password` | string | Yes | -- | FTP password |
| `path` | string | No | "" | Base directory on the server |

### NFS (Linux Only)

Mounts an NFS export using the Linux `mount` syscall. Requires root privileges.

```go
config := &client.StorageConfig{
    Protocol: "nfs",
    Settings: map[string]interface{}{
        "host":        "nas.local",
        "path":        "/export/media",
        "mount_point": "/mnt/nfs-media",
        "options":     "vers=3",
    },
}
```

**Settings:**

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `host` | string | Yes | -- | NFS server hostname or IP |
| `path` | string | Yes | -- | Exported path on the server |
| `mount_point` | string | Yes | -- | Local mount point directory |
| `options` | string | No | "vers=3" | NFS mount options |

**Platform note:** NFS is only available on Linux. On other platforms, the factory returns an error: `"NFS protocol is only supported on Linux"`.

### WebDAV

Connects to WebDAV servers using HTTP/HTTPS with optional Basic authentication.

```go
config := &client.StorageConfig{
    Protocol: "webdav",
    Settings: map[string]interface{}{
        "url":      "https://cloud.example.com/remote.php/dav/files/user",
        "username": "user",
        "password": "apppassword",
        "path":     "/media",
    },
}
```

**Settings:**

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `url` | string | Yes | -- | WebDAV server base URL |
| `username` | string | No | -- | HTTP Basic Auth username |
| `password` | string | No | -- | HTTP Basic Auth password |
| `path` | string | No | "" | Path prefix on the server |

## Common Operations

### Reading a File

```go
reader, err := c.ReadFile(ctx, "documents/report.pdf")
if err != nil {
    log.Fatal(err)
}
defer reader.Close()

data, err := io.ReadAll(reader)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Read %d bytes\n", len(data))
```

### Writing a File

```go
content := []byte("Hello, World!")
err := c.WriteFile(ctx, "notes/hello.txt", bytes.NewReader(content))
if err != nil {
    log.Fatal(err)
}
```

Parent directories are auto-created by most adapters (local, FTP). For SMB and WebDAV, you may need to create directories explicitly first.

### Checking File Existence

```go
exists, err := c.FileExists(ctx, "movies/inception.mkv")
if err != nil {
    log.Fatal(err)
}
if exists {
    fmt.Println("File found")
}
```

### Getting File Information

```go
info, err := c.GetFileInfo(ctx, "movies/inception.mkv")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Name: %s\n", info.Name)
fmt.Printf("Size: %d bytes\n", info.Size)
fmt.Printf("Modified: %s\n", info.ModTime)
fmt.Printf("Is directory: %v\n", info.IsDir)
fmt.Printf("Permissions: %o\n", info.Mode)
```

### Listing a Directory

```go
files, err := c.ListDirectory(ctx, "movies")
if err != nil {
    log.Fatal(err)
}
for _, f := range files {
    kind := "FILE"
    if f.IsDir {
        kind = "DIR "
    }
    fmt.Printf("[%s] %-40s %10d bytes  %s\n", kind, f.Name, f.Size, f.ModTime.Format(time.RFC3339))
}
```

### Copying a File

```go
err := c.CopyFile(ctx, "originals/photo.jpg", "backups/photo.jpg")
if err != nil {
    log.Fatal(err)
}
```

### Creating a Directory

```go
err := c.CreateDirectory(ctx, "new-collection/2024")
if err != nil {
    log.Fatal(err)
}
```

### Deleting Files and Directories

```go
// Delete a single file
err := c.DeleteFile(ctx, "temp/old-file.txt")

// Delete a directory (and contents, for local/NFS adapters)
err = c.DeleteDirectory(ctx, "temp")
```

### Testing a Connection

```go
if err := c.TestConnection(ctx); err != nil {
    fmt.Printf("Connection test failed: %v\n", err)
} else {
    fmt.Println("Connection is healthy")
}
```

## Working with Multiple Protocols

A common pattern is managing multiple storage backends:

```go
f := factory.NewDefaultFactory()

configs := []*client.StorageConfig{
    {
        ID:       "local-media",
        Protocol: "local",
        Settings: map[string]interface{}{"base_path": "/data/media"},
    },
    {
        ID:       "nas-backup",
        Protocol: "smb",
        Settings: map[string]interface{}{
            "host": "nas.local", "port": 445,
            "share": "Backup", "username": "admin", "password": "secret",
        },
    },
    {
        ID:       "cloud-storage",
        Protocol: "webdav",
        Settings: map[string]interface{}{
            "url": "https://cloud.example.com/dav", "username": "user", "password": "pass",
        },
    },
}

for _, cfg := range configs {
    c, err := f.CreateClient(cfg)
    if err != nil {
        log.Printf("Skipping %s: %v", cfg.ID, err)
        continue
    }

    ctx := context.Background()
    if err := c.Connect(ctx); err != nil {
        log.Printf("Cannot connect to %s: %v", cfg.ID, err)
        continue
    }
    defer c.Disconnect(ctx)

    files, _ := c.ListDirectory(ctx, "")
    fmt.Printf("[%s] %s: %d items\n", c.GetProtocol(), cfg.ID, len(files))
}
```

## Direct Client Construction

For cases where you know the protocol at compile time, you can construct clients directly without the factory:

### Local

```go
c := local.NewLocalClient(&local.Config{
    BasePath: "/data/media",
})
```

### SMB

```go
c := smb.NewSMBClient(&smb.Config{
    Host:     "192.168.1.100",
    Port:     445,
    Share:    "MediaShare",
    Username: "user",
    Password: "pass",
    Domain:   "WORKGROUP",
})
```

### FTP

```go
c := ftp.NewFTPClient(&ftp.Config{
    Host:     "ftp.example.com",
    Port:     21,
    Username: "user",
    Password: "pass",
    Path:     "/media",
})
```

### WebDAV

```go
c := webdav.NewWebDAVClient(&webdav.Config{
    URL:      "https://cloud.example.com/dav",
    Username: "user",
    Password: "pass",
    Path:     "/media",
})
```

### NFS (Linux only)

```go
c, err := nfs.NewNFSClient(nfs.Config{
    Host:       "nas.local",
    Path:       "/export/media",
    MountPoint: "/mnt/nfs-media",
    Options:    "vers=3",
})
```

## Error Handling

All errors are wrapped with context using `fmt.Errorf("...: %w", err)`, so you can use `errors.Is` and `errors.As` for inspection:

```go
import "errors"

_, err := c.ReadFile(ctx, "missing.txt")
if err != nil {
    if errors.Is(err, os.ErrNotExist) {
        fmt.Println("File not found")
    } else {
        fmt.Printf("Unexpected error: %v\n", err)
    }
}
```

Common error patterns:

| Scenario | Error message contains |
|----------|----------------------|
| Operation before Connect | `"not connected"` |
| Invalid base path (local) | `"not a directory"` or `"failed to access base path"` |
| SMB auth failure | `"failed to create SMB session"` |
| FTP login failure | `"failed to login to FTP server"` |
| WebDAV server error | `"WebDAV server returned status <code>"` |
| NFS mount failure | `"failed to mount NFS share"` |
| Unsupported protocol | `"unsupported protocol: <name>"` |

## Context and Cancellation

All operations accept `context.Context`. Use it for timeouts and cancellation:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

files, err := c.ListDirectory(ctx, "large-directory")
if err != nil {
    if ctx.Err() == context.DeadlineExceeded {
        fmt.Println("Operation timed out")
    }
}
```

Note: Context cancellation support varies by adapter. The WebDAV adapter passes context to HTTP requests. The FTP adapter creates connections with a fixed 30-second dial timeout. The local and NFS adapters accept context but delegate to `os` functions that do not support cancellation.
