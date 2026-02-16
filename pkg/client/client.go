// Package client defines the unified filesystem client interface
// supporting multiple protocols (SMB, FTP, NFS, WebDAV, Local).
package client

import (
	"context"
	"io"
	"os"
	"time"
)

// FileInfo represents file information from any filesystem.
type FileInfo struct {
	Name    string
	Size    int64
	ModTime time.Time
	IsDir   bool
	Mode    os.FileMode
	Path    string
}

// Client defines the interface for filesystem operations.
// This abstraction allows supporting multiple protocols.
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

// StorageConfig represents the configuration for a storage backend.
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

// Factory creates filesystem clients based on protocol.
type Factory interface {
	CreateClient(config *StorageConfig) (Client, error)
	SupportedProtocols() []string
}

// CopyOperation represents a file copy operation.
type CopyOperation struct {
	SourcePath        string
	DestinationPath   string
	OverwriteExisting bool
}

// CopyResult represents the result of a copy operation.
type CopyResult struct {
	Success     bool
	BytesCopied int64
	Error       error
	TimeTaken   time.Duration
}

// ConnectionPool manages multiple connections for a protocol.
type ConnectionPool interface {
	GetClient(config *StorageConfig) (Client, error)
	ReturnClient(client Client) error
	CloseAll() error
}
