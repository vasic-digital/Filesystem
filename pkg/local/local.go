// Package local implements the filesystem client for local filesystem operations.
package local

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"digital.vasic.filesystem/pkg/client"
)

// Config contains local filesystem configuration.
type Config struct {
	BasePath string `json:"base_path"`
}

// Client implements client.Client for local filesystem.
type Client struct {
	config    *Config
	basePath  string
	connected bool
}

// NewLocalClient creates a new local filesystem client.
func NewLocalClient(config *Config) *Client {
	return &Client{
		config:    config,
		basePath:  config.BasePath,
		connected: false,
	}
}

// Connect establishes the connection (for local filesystem, this just validates the path).
func (c *Client) Connect(ctx context.Context) error {
	info, err := os.Stat(c.basePath)
	if err != nil {
		return fmt.Errorf("failed to access base path %s: %w", c.basePath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("base path %s is not a directory", c.basePath)
	}
	c.connected = true
	return nil
}

// Disconnect closes the connection (no-op for local filesystem).
func (c *Client) Disconnect(ctx context.Context) error {
	c.connected = false
	return nil
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	return c.connected
}

// TestConnection tests the connection.
func (c *Client) TestConnection(ctx context.Context) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	_, err := os.Stat(c.basePath)
	return err
}

// resolvePath resolves a relative path to an absolute path within the base directory.
func (c *Client) resolvePath(path string) string {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		cleanPath = strings.ReplaceAll(cleanPath, "..", "")
	}
	return filepath.Join(c.basePath, cleanPath)
}

// ReadFile reads a file from the local filesystem.
func (c *Client) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open local file %s: %w", fullPath, err)
	}
	return file, nil
}

// WriteFile writes a file to the local filesystem.
func (c *Client) WriteFile(ctx context.Context, path string, data io.Reader) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)

	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	file, err := os.Create(fullPath)
	if err != nil {
		return fmt.Errorf("failed to create local file %s: %w", fullPath, err)
	}
	defer file.Close()

	_, err = io.Copy(file, data)
	if err != nil {
		return fmt.Errorf("failed to write local file %s: %w", fullPath, err)
	}

	return nil
}

// GetFileInfo gets information about a file.
func (c *Client) GetFileInfo(ctx context.Context, path string) (*client.FileInfo, error) {
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	stat, err := os.Stat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat local file %s: %w", fullPath, err)
	}

	return &client.FileInfo{
		Name:    stat.Name(),
		Size:    stat.Size(),
		ModTime: stat.ModTime(),
		IsDir:   stat.IsDir(),
		Mode:    stat.Mode(),
		Path:    path,
	}, nil
}

// ListDirectory lists files in a directory.
func (c *Client) ListDirectory(ctx context.Context, path string) ([]*client.FileInfo, error) {
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list local directory %s: %w", fullPath, err)
	}

	var files []*client.FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, &client.FileInfo{
			Name:    entry.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			IsDir:   entry.IsDir(),
			Mode:    info.Mode(),
			Path:    filepath.Join(path, entry.Name()),
		})
	}

	return files, nil
}

// FileExists checks if a file exists.
func (c *Client) FileExists(ctx context.Context, path string) (bool, error) {
	if !c.IsConnected() {
		return false, fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	_, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check local file existence %s: %w", fullPath, err)
	}
	return true, nil
}

// CreateDirectory creates a directory.
func (c *Client) CreateDirectory(ctx context.Context, path string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	err := os.MkdirAll(fullPath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create local directory %s: %w", fullPath, err)
	}
	return nil
}

// DeleteDirectory deletes a directory.
func (c *Client) DeleteDirectory(ctx context.Context, path string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	err := os.RemoveAll(fullPath)
	if err != nil {
		return fmt.Errorf("failed to delete local directory %s: %w", fullPath, err)
	}
	return nil
}

// DeleteFile deletes a file.
func (c *Client) DeleteFile(ctx context.Context, path string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	err := os.Remove(fullPath)
	if err != nil {
		return fmt.Errorf("failed to delete local file %s: %w", fullPath, err)
	}
	return nil
}

// CopyFile copies a file within the local filesystem.
func (c *Client) CopyFile(ctx context.Context, srcPath, dstPath string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	srcFullPath := c.resolvePath(srcPath)
	dstFullPath := c.resolvePath(dstPath)

	dstDir := filepath.Dir(dstFullPath)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dstDir, err)
	}

	srcFile, err := os.Open(srcFullPath)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", srcFullPath, err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstFullPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dstFullPath, err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("failed to copy file from %s to %s: %w", srcFullPath, dstFullPath, err)
	}

	return nil
}

// GetProtocol returns the protocol name.
func (c *Client) GetProtocol() string {
	return "local"
}

// GetConfig returns the local configuration.
func (c *Client) GetConfig() interface{} {
	return c.config
}
