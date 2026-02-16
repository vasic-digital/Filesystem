# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Go module (`digital.vasic.filesystem`) providing a unified multi-protocol filesystem client. Abstracts SMB, FTP, NFS, WebDAV, and local filesystem operations behind a single `client.Client` interface. Part of the Catalogizer project, used by `catalog-api` for accessing media storage backends.

## Commands

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests for a specific package
go test -v ./pkg/client/
go test -v ./pkg/factory/
go test -v ./pkg/local/

# Build (library module, no main binary)
go build ./...

# Vet and lint
go vet ./...

# Test coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Architecture

### Package Structure

```
pkg/
  client/      Core interfaces and types (Client, Factory, FileInfo, StorageConfig, ConnectionPool)
  factory/     DefaultFactory implementation - creates protocol-specific clients from StorageConfig
  smb/         SMB/CIFS protocol adapter (go-smb2 library)
  ftp/         FTP protocol adapter (jlaffaye/ftp library)
  nfs/         NFS protocol adapter (Linux-only, syscall mount)
  webdav/      WebDAV protocol adapter (net/http-based, PROPFIND/PUT/GET/DELETE)
  local/       Local filesystem adapter (os package)
```

### Key Patterns

- **Factory Pattern**: `factory.DefaultFactory` implements `client.Factory`, routing `StorageConfig.Protocol` to the correct adapter constructor via a switch statement.
- **Interface Segregation**: All protocol adapters implement `client.Client` (15 methods: connection management, file ops, directory ops, metadata).
- **Platform Build Tags**: NFS support uses `//go:build linux` / `//go:build !linux` split files in `factory/` to gate Linux-only syscall usage.
- **Path Resolution**: Each adapter has a private `resolvePath()` (or `resolveURL()` for WebDAV) that sanitizes paths (strips `..`) and joins with the base path/URL.
- **Settings Extraction**: `factory.GetStringSetting()` and `factory.GetIntSetting()` extract typed values from `map[string]interface{}` settings with defaults.

### Interface Hierarchy

- `client.Client` -- core interface implemented by all 5 protocol adapters
- `client.Factory` -- implemented by `factory.DefaultFactory`
- `client.ConnectionPool` -- defined but not yet implemented (future pooling)

## Conventions

- **Constructor naming**: `New<Protocol>Client(config)` returns `*Client` (package-scoped type)
- **Error wrapping**: All errors use `fmt.Errorf("context: %w", err)` for proper wrapping
- **Connection guards**: Every operation checks `IsConnected()` first and returns `"not connected"` error
- **Test style**: Table-driven where applicable; testify `assert`/`require` for assertions
- **Interface compliance**: Each adapter file includes `var _ client.Client = (*Client)(nil)` compile-time check
- **Config structs**: Each package defines its own `Config` struct with JSON tags; `StorageConfig.Settings` maps to these via factory helpers

## Constraints

- **NFS is Linux-only**. Do not add NFS tests that depend on actual mount operations -- they require root privileges.
- **No main package**. This is a library module. Do not add a `main.go`.
- **Do not add GitHub Actions workflows**. CI/CD is handled externally.
- **Module path is `digital.vasic.filesystem`**. Do not change the module name in `go.mod`.
- **Go 1.24+** is required. Do not lower the minimum Go version.
- **Do not vendor dependencies**. The `vendor/` directory is gitignored.
- **Path traversal protection**. All `resolvePath` functions strip `..` segments. Do not bypass this when adding new operations.
