# digital.vasic.filesystem

Unified multi-protocol filesystem client for Go. Round-246 deep-doc + paired-mutation challenge enrichment.

**Protocols**: SMB | FTP | NFS (Linux) | WebDAV | Local

**Module**: `digital.vasic.filesystem`
**Go**: 1.25+
**License**: Proprietary

---

## Features

- **Single `client.Client` interface** spanning five protocols — pick the
  backend at config time, leave call sites unchanged.
- **Factory-driven construction** (`factory.NewDefaultFactory()`) — every
  protocol selectable by string (`local`, `ftp`, `smb`, `nfs`, `webdav`)
  with `StorageConfig.Settings` carrying per-protocol parameters.
- **Optional seekable extension** (`client.SeekableClient` /
  `OpenSeekable`) for protocols that natively support random access
  (SMB via `smb2_lseek`, local via `os.File.Seek`) — enables HTTP Range
  request serving for media streaming.
- **Platform-aware NFS** — `pkg/factory/nfs_linux.go` activates the real
  syscall path on Linux; `pkg/factory/nfs_other.go` returns a clear
  error elsewhere; the protocol still appears in `SupportedProtocols`.
- **Path-traversal guards** on local backend — `../` escapes the
  configured `base_path` are rejected, verified by edge-case unit tests.
- **UTF-8 / diacritic filename support** — exercised end-to-end by the
  round-246 bilingual fixtures (Latin Serbian: `dnevnik/početak.log`).
- **Zero hidden state in the interface** — every method takes `ctx`,
  reports errors verbatim, and never silently retries.

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
    f := factory.NewDefaultFactory()

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

    ctx := context.Background()
    if err := c.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    defer c.Disconnect(ctx)

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

Every protocol adapter implements `client.Client`:

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

Optional random-access extension:

```go
type SeekableClient interface {
    OpenSeekable(ctx context.Context, path string) (ReadSeekCloser, error)
}
```

## Protocol Configuration

| Protocol | Required settings | Optional |
|----------|-------------------|----------|
| `local`  | `base_path` | — |
| `ftp`    | `host`, `username`, `password` | `port` (21), `path` |
| `smb`    | `host`, `share`, `username`, `password` | `port` (445), `domain` (`WORKGROUP`) |
| `nfs`    | `host`, `path`, `mount_point` | `options` |
| `webdav` | `url`, `username`, `password` | `path` |

Environment variable convention used by integration tests: each `<setting>` is
overridable by `FILESYSTEM_<PROTOCOL>_<SETTING>` (e.g. `FILESYSTEM_SMB_HOST`).
Real-network coverage is gated behind those env vars + `SKIP-OK:` markers per
CONST-035.

## Platform Support

| Protocol | Linux | macOS | Windows |
|----------|-------|-------|---------|
| SMB      | Yes   | Yes   | Yes     |
| FTP      | Yes   | Yes   | Yes     |
| NFS      | Yes   | No    | No      |
| WebDAV   | Yes   | Yes   | Yes     |
| Local    | Yes   | Yes   | Yes     |

NFS uses Linux `syscall.Mount` and is gated behind `//go:build linux` build
tags. On non-Linux platforms, the factory returns an error for NFS protocol
requests while still listing it in `SupportedProtocols()`.

## Edge Cases (round-246)

- **Empty body** — writing a zero-byte file succeeds; `FileInfo.Size == 0`.
- **Nested directories** — `WriteFile("a/b/c.txt", ...)` auto-creates parents.
- **UTF-8 filenames** — diacritic and non-Latin paths preserved byte-for-byte
  through write -> read round-trip (verified by `challenges/fixtures/sr-Latn.yaml`).
- **Path traversal** — `../` escapes of the configured `base_path` are rejected.
- **Symlinks** — `GetFileInfo` follows; `ReadFile` reads target content.
- **Not-connected operations** — every method returns a clear "not connected"
  error if invoked before `Connect`.
- **Double connect / double disconnect** — idempotent.
- **Non-existent paths** — every read/list/info call returns wrapped error.

## Testing

```bash
# Unit + edge tests (all packages, race-tested)
go test -count=1 -race ./...

# Verbose
go test -count=1 -race -v ./...

# Per-package
go test -count=1 -race -v ./pkg/local/

# Coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Round-246 Challenge

```bash
# Clean-mode (must exit 0 — proves docs, fixtures, runner, real-IO all green)
bash challenges/filesystem_describe_challenge.sh

# Paired-mutation mode (must exit 99 — proves gate actually catches drift)
bash challenges/filesystem_describe_challenge.sh --anti-bluff-mutate

# Run the bilingual runner directly
go run ./challenges/runner -fixtures challenges/fixtures
```

The Challenge validates: deep-doc ledger present + version-tagged + carries
the verbatim Article XI §11.9 mandate; every exported symbol from
`pkg/{client,factory,local}` is cross-referenced in the ledger; bilingual
fixtures parse and cover at least 2 locales; runner builds and round-trips
both ASCII and UTF-8 (diacritic) filenames through the real `local` client;
README declares the round-246 anti-bluff guarantees section.

## Anti-bluff guarantees (round-246)

- `go test -count=1 -race ./...` runs every package's unit + edge suite —
  zero `t.Skip()` without a `SKIP-OK: #<ticket>` marker.
- `challenges/filesystem_describe_challenge.sh` is paired-mutation aware
  (`--anti-bluff-mutate` exits 99 to prove the gate actually detects a
  planted ledger-vs-source rename).
- Bilingual fixtures (`challenges/fixtures/{en,sr-Latn}.yaml`) exercise
  non-ASCII filenames + UTF-8 file bodies; the runner asserts byte-equal
  round-trip through the real `client.Client.WriteFile` / `ReadFile`.
- `docs/test-coverage.md` enumerates every public symbol with its test
  sources — drift between the file and `go test -cover` is treated as a
  CONST-035 / Article XI §11.9 bluff at the documentation-truth layer.
- The runner's tmp tree is **preserved on FAIL** under `/tmp/fs-round246-*`
  for forensic inspection (§11.4.2); cleaned only on PASS.

## Packages

| Package | Import path | Description |
|---------|-------------|-------------|
| `client` | `digital.vasic.filesystem/pkg/client` | Core interfaces, `FileInfo`, `StorageConfig` |
| `factory` | `digital.vasic.filesystem/pkg/factory` | `DefaultFactory`, helpers, platform gates |
| `local` | `digital.vasic.filesystem/pkg/local` | Local filesystem adapter |
| `ftp` | `digital.vasic.filesystem/pkg/ftp` | FTP protocol adapter |
| `smb` | `digital.vasic.filesystem/pkg/smb` | SMB/CIFS protocol adapter |
| `nfs` | `digital.vasic.filesystem/pkg/nfs` | NFS protocol adapter (Linux only) |
| `webdav` | `digital.vasic.filesystem/pkg/webdav` | WebDAV protocol adapter |

## Documentation

- [Architecture](docs/architecture.md) — Design patterns, Mermaid diagrams, package relationships
- [User Guide](docs/user-guide.md) — Step-by-step usage instructions
- [API Reference](docs/api-reference.md) — Complete API documentation for all packages
- [Test Coverage Ledger (round-246)](docs/test-coverage.md) — symbol -> test source mapping

## Dependencies

| Dependency | Purpose |
|------------|---------|
| `github.com/hirochachacha/go-smb2` | SMB2/3 protocol implementation |
| `github.com/jlaffaye/ftp` | FTP client library |
| `github.com/stretchr/testify` | Test assertions |

## Constitutional anchors

Filesystem inherits Article XI §11.9 (anti-bluff), CONST-035 (zero-bluff),
CONST-047 (recursive submodule application), CONST-048 (full-automation-
coverage), CONST-050 (no-fakes-beyond-unit-tests + 100%-test-type-coverage),
CONST-051 (submodules-as-equal-codebase + decoupling), CONST-053 (.gitignore /
no-versioned-build-artifacts) from the constitution submodule. See
`CONSTITUTION.md`, `CLAUDE.md`, `AGENTS.md` for the verbatim mandates.

## License

See the parent project for licensing terms.
