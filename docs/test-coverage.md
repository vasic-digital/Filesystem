# Filesystem Test Coverage Ledger (round-246)

Round-246 deep-doc enrichment under CONST-035 / Article XI §11.9 / CONST-050(B).

This document is the authoritative mapping of every exported symbol in
`pkg/{client,factory,local,ftp,smb,nfs,webdav}` to the test sources that exercise
it. Drift between this file and `go test -cover` output is a CONST-035 bluff at
the documentation-truth layer — fix the document OR add the missing test, never
silently leave the gap.

## Verbatim 2026-05-19 operator mandate (CONST-049 §11.4.17)

> "all existing tests and Challenges do work in anti-bluff manner - they MUST confirm that all tested codebase really works as expected! We had been in position that all tests do execute with success and all Challenges as well, but in reality the most of the features does not work and can't be used! This MUST NOT be the case and execution of tests and Challenges MUST guarantee the quality, the completition and full usability by end users of the product!"

## Test-type matrix (CONST-050(B))

| Test type | Location | Status |
|-----------|----------|--------|
| Unit | `pkg/*/`*_test.go` | PRESENT — every package |
| Edge-case unit | `pkg/{client,local}/*_edge_test.go` | PRESENT |
| Factory | `pkg/factory/factory_test.go` + `nfs_{linux,other}_test.go` | PRESENT |
| Platform-gated | `pkg/factory/nfs_{linux,other}.go` + tests | PRESENT (Linux-only NFS) |
| Bilingual Challenge | `challenges/filesystem_describe_challenge.sh` | PRESENT (round-246) |
| Bilingual fixtures | `challenges/fixtures/{en,sr-Latn}.yaml` | PRESENT (round-246) |
| Real-IO runner | `challenges/runner/main.go` | PRESENT (round-246) |

## `pkg/client`

| Symbol | Kind | Test source(s) |
|--------|------|----------------|
| `FileInfo` | struct | `pkg/client/client_test.go` (TestFileInfo_Fields, TestFileInfo_ZeroValues, TestFileInfo_UnicodeFilename, TestFileInfo_PathWithSpacesAndSpecialChars, TestFileInfo_NegativeSize, TestFileInfo_FutureModTime, TestFileInfo_VeryOldModTime, TestFileInfo_EmptyPath, TestFileInfo_PathTraversalStrings) |
| `ReadSeekCloser` | interface | exercised via `OpenSeekable` in seekable-protocol unit tests |
| `Client` | interface | exercised by every protocol package's `*_test.go` (local, ftp, smb, nfs, webdav) |
| `SeekableClient` | interface | optional extension — exercised by SMB + local where applicable |
| `OpenSeekable` | method | seekable-protocol unit tests |
| `StorageConfig` | struct | `pkg/client/client_test.go` (TestStorageConfig_Fields, TestStorageConfig_EmptyFields, TestStorageConfig_NilSettings, TestStorageConfig_NegativeMaxDepth, TestStorageConfig_UnsupportedProtocol) |
| `Factory` | interface | exercised by `pkg/factory/factory_test.go` |
| `CopyOperation` | struct | `pkg/client/client_test.go` (TestCopyOperation_Fields, TestCopyOperation_EmptyPaths, TestCopyOperation_SameSourceAndDest) |
| `CopyResult` | struct | `pkg/client/client_test.go` (TestCopyResult_FailedCopy, TestCopyResult_ZeroBytesSuccess) |
| `ConnectionPool` | struct | exercised by integration-level scenarios; tracked as edge-case in `client_edge_test.go` |
| `Connect` / `Disconnect` / `IsConnected` / `TestConnection` | methods (interface) | per-protocol `_test.go` (TestLocalClient_Connect, TestLocalClient_DoubleConnect, TestLocalClient_DoubleDisconnect, TestLocalClient_TestConnection) |
| `ReadFile` / `WriteFile` / `GetFileInfo` / `FileExists` / `DeleteFile` / `CopyFile` | methods (interface) | per-protocol `_test.go` (TestLocalClient_ReadFile, TestLocalClient_WriteFile, TestLocalClient_GetFileInfo, TestLocalClient_FileExists, TestLocalClient_DeleteFile, TestLocalClient_CopyFile, TestLocalClient_CopyFile_NonExistentSource) |
| `ListDirectory` / `CreateDirectory` / `DeleteDirectory` | methods (interface) | per-protocol `_test.go` (TestLocalClient_ListDirectory, TestLocalClient_CreateDirectory, TestLocalClient_DeleteDirectory) |
| `GetProtocol` / `GetConfig` | methods (interface) | per-protocol `_test.go` (TestLocalClient_GetProtocol, TestLocalClient_GetConfig) |

## `pkg/factory`

| Symbol | Kind | Test source(s) |
|--------|------|----------------|
| `DefaultFactory` | struct | `pkg/factory/factory_test.go` (TestDefaultFactory_SupportedProtocols and all per-protocol creation tests) |
| `NewDefaultFactory` | constructor | `pkg/factory/factory_test.go` (every test) |
| `CreateClient` | method | `pkg/factory/factory_test.go` (TestDefaultFactory_CreateClient_SMB, TestDefaultFactory_CreateClient_FTP, TestDefaultFactory_CreateClient_NFS, TestDefaultFactory_CreateClient_WebDAV, TestDefaultFactory_CreateClient_Local, TestDefaultFactory_CreateClient_Unsupported) |
| `SupportedProtocols` | method | `pkg/factory/factory_test.go` (TestDefaultFactory_SupportedProtocols, TestDefaultFactory_CreateNFSClient_NonLinux_StillInSupportedProtocols) |
| `NewSMBClient` | wrapper | `pkg/factory/factory_test.go` (TestDefaultFactory_CreateClient_SMB) |
| `GetStringSetting` | helper | `pkg/factory/factory_test.go` (TestGetStringSetting) |
| `GetIntSetting` | helper | `pkg/factory/factory_test.go` (TestGetIntSetting) |
| NFS Linux path | platform-gated impl | `pkg/factory/nfs_linux_test.go` (TestDefaultFactory_CreateNFSClient_Linux, TestDefaultFactory_CreateNFSClient_DefaultOptions, TestDefaultFactory_CreateNFSClient_EmptyMountPoint) |
| NFS non-Linux path | platform-gated impl | `pkg/factory/nfs_other_test.go` (TestDefaultFactory_CreateNFSClient_NonLinux) |

## `pkg/local`

| Symbol | Kind | Test source(s) |
|--------|------|----------------|
| `Config` | struct | `pkg/local/local_test.go` (TestLocalClient_GetConfig) |
| `Client` | struct | every `pkg/local/*_test.go` |
| `NewLocalClient` | constructor | every `pkg/local/*_test.go` |
| `Connect` | method | TestLocalClient_Connect, TestLocalClient_Connect_InvalidPath, TestLocalClient_Connect_FileNotDirectory, TestLocalClient_Connect_NotADirectory, TestLocalClient_DoubleConnect, TestLocalClient_AllOps_NotConnected |
| `Disconnect` | method | TestLocalClient_DoubleDisconnect |
| `IsConnected` | method | exercised across every per-op test |
| `TestConnection` | method | TestLocalClient_TestConnection, TestLocalClient_TestConnection_NotConnected |
| `ReadFile` | method | TestLocalClient_ReadFile, TestLocalClient_ReadFile_NotConnected, TestLocalClient_NonExistent_ReadFile, TestLocalClient_EmptyPath_ReadFile, TestLocalClient_PathTraversal_ReadFile, TestLocalClient_Symlink_ReadFile |
| `WriteFile` | method | TestLocalClient_WriteFile, TestLocalClient_WriteFile_NotConnected, TestLocalClient_WriteFile_NestedDirectory, TestLocalClient_PathTraversal_WriteFile |
| `GetFileInfo` | method | TestLocalClient_GetFileInfo, TestLocalClient_GetFileInfo_NotConnected, TestLocalClient_GetFileInfo_Directory, TestLocalClient_NonExistent_GetFileInfo, TestLocalClient_PathTraversal_GetFileInfo, TestLocalClient_Symlink_GetFileInfo |
| `FileExists` | method | TestLocalClient_FileExists, TestLocalClient_FileExists_NotConnected |
| `DeleteFile` | method | TestLocalClient_DeleteFile, TestLocalClient_DeleteFile_NotConnected, TestLocalClient_NonExistent_DeleteFile |
| `CopyFile` | method | TestLocalClient_CopyFile, TestLocalClient_CopyFile_NotConnected, TestLocalClient_CopyFile_NonExistentSource |
| `ListDirectory` | method | TestLocalClient_ListDirectory, TestLocalClient_ListDirectory_NotConnected, TestLocalClient_NonExistent_ListDirectory, TestLocalClient_EmptyPath_ListDirectory |
| `CreateDirectory` | method | TestLocalClient_CreateDirectory, TestLocalClient_CreateDirectory_NotConnected, TestLocalClient_DeepPath |
| `DeleteDirectory` | method | TestLocalClient_DeleteDirectory, TestLocalClient_DeleteDirectory_NotConnected |
| `GetProtocol` | method | TestLocalClient_GetProtocol |
| `GetConfig` | method | TestLocalClient_GetConfig |
| UTF-8 / diacritic filename support | runtime invariant | `challenges/filesystem_describe_challenge.sh` + `challenges/fixtures/sr-Latn.yaml` (round-246) |
| Path-with-special-chars handling | runtime invariant | TestLocalClient_PathWithSpaces, TestLocalClient_PathWithSpecialChars |

## `pkg/ftp` / `pkg/smb` / `pkg/nfs` / `pkg/webdav`

| Package | Test source(s) | Coverage notes |
|---------|----------------|----------------|
| `pkg/ftp` | `pkg/ftp/ftp_test.go` | Unit-test mode (real network exercise gated to integration runs) |
| `pkg/smb` | `pkg/smb/smb_test.go` | Unit-test mode (real SMB share gated to integration runs) |
| `pkg/nfs` | `pkg/nfs/nfs_test.go` | Linux-only path; non-Linux factory returns error per platform gate |
| `pkg/webdav` | `pkg/webdav/webdav_test.go` | Unit-test mode (real WebDAV endpoint gated to integration runs) |

Real-network coverage for these adapters is tracked in their integration sweep
plans — `pkg/local` is the round-246 exerciser because it requires no external
service while still proving the full `client.Client` contract end-to-end.

## Edge cases covered (round-246)

- Empty file body — `challenges/fixtures/en.yaml` (`empty.bin`)
- Nested directory write (auto-create parent) — TestLocalClient_WriteFile_NestedDirectory + `challenges/fixtures/sr-Latn.yaml` (`podaci/brojevi.csv`)
- UTF-8 filename with diacritics — `challenges/fixtures/sr-Latn.yaml` (`dnevnik/početak.log`)
- Deep path / multi-segment directory — TestLocalClient_DeepPath
- Path traversal rejection — TestLocalClient_PathTraversal_ReadFile, TestLocalClient_PathTraversal_WriteFile, TestLocalClient_PathTraversal_GetFileInfo
- Symlink resolution — TestLocalClient_Symlink_ReadFile, TestLocalClient_Symlink_GetFileInfo
- Operations on not-connected client — TestLocalClient_AllOps_NotConnected + every `_NotConnected` variant
- Double connect / double disconnect — TestLocalClient_DoubleConnect, TestLocalClient_DoubleDisconnect
- Non-existent file paths — TestLocalClient_NonExistent_* family

## Paired-mutation Challenge

`challenges/filesystem_describe_challenge.sh` accepts `--anti-bluff-mutate` to plant a
deliberate ledger-vs-source mismatch (renames one tracked symbol in the ledger)
and asserts the gate FAILS with exit 99. Without the flag the gate runs normal
validation and MUST exit 0. Composition: CONST-035 (anti-bluff) × CONST-050(B)
(paired mutation) × CONST-047 (cascade).

## Anti-bluff acceptance criteria

1. `go test -count=1 -race ./...` exits 0 — all packages PASS (verified round-246).
2. `bash challenges/filesystem_describe_challenge.sh` exits 0 (gate PASS on clean tree).
3. `bash challenges/filesystem_describe_challenge.sh --anti-bluff-mutate` exits 99 (gate correctly fails on planted mutation).
4. Every symbol in this ledger appears in the listed test source verbatim — no metadata-only / configuration-only ledger entries.
5. Runner output preserves UTF-8 filenames byte-for-byte from `challenges/fixtures/sr-Latn.yaml` through the real `local` client back to the captured ReadFile body.
