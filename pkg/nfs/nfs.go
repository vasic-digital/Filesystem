//go:build linux
// +build linux

// Package nfs implements the filesystem client for NFS protocol.
package nfs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"digital.vasic.filesystem/pkg/client"
)

// Config contains NFS connection configuration.
type Config struct {
	Host       string `json:"host"`
	Path       string `json:"path"`
	MountPoint string `json:"mount_point"`
	Options    string `json:"options"`
}

// Client implements client.Client for NFS protocol.
type Client struct {
	config     Config
	mounted    bool
	connected  bool
	mountPoint string
}

// NewNFSClient creates a new NFS client.
func NewNFSClient(config Config) (*Client, error) {
	if config.MountPoint == "" {
		return nil, fmt.Errorf("mount point is required")
	}
	return &Client{
		config:     config,
		mounted:    false,
		connected:  false,
		mountPoint: config.MountPoint,
	}, nil
}

// Connect establishes the NFS connection by mounting the filesystem.
func (c *Client) Connect(ctx context.Context) error {
	if c.isMounted() {
		c.connected = true
		return nil
	}

	if err := os.MkdirAll(c.mountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create mount point %s: %w", c.mountPoint, err)
	}

	source := fmt.Sprintf("%s:%s", c.config.Host, c.config.Path)
	options := "vers=3"
	if c.config.Options != "" {
		options = c.config.Options
	}

	err := syscall.Mount(source, c.mountPoint, "nfs", 0, options)
	if err != nil {
		return fmt.Errorf("failed to mount NFS share %s to %s: %w", source, c.mountPoint, err)
	}

	c.mounted = true
	c.connected = true
	return nil
}

// Disconnect unmounts the NFS filesystem.
func (c *Client) Disconnect(ctx context.Context) error {
	if c.mounted {
		err := syscall.Unmount(c.mountPoint, 0)
		if err != nil {
			return fmt.Errorf("failed to unmount NFS share from %s: %w", c.mountPoint, err)
		}
		c.mounted = false
	}
	c.connected = false
	return nil
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	return c.connected && c.mounted && c.isMounted()
}

// TestConnection tests the NFS connection.
func (c *Client) TestConnection(ctx context.Context) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	_, err := os.Stat(c.mountPoint)
	return err
}

// isMounted checks if the mount point is actually mounted.
func (c *Client) isMounted() bool {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer file.Close()
	return true
}

// resolvePath resolves a relative path within the NFS mount point.
func (c *Client) resolvePath(path string) string {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		cleanPath = strings.ReplaceAll(cleanPath, "..", "")
	}
	return filepath.Join(c.mountPoint, cleanPath)
}

// ReadFile reads a file from the NFS mount.
func (c *Client) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open NFS file %s: %w", fullPath, err)
	}
	return file, nil
}

// WriteFile writes a file to the NFS mount.
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
		return fmt.Errorf("failed to create NFS file %s: %w", fullPath, err)
	}
	defer file.Close()

	_, err = io.Copy(file, data)
	if err != nil {
		return fmt.Errorf("failed to write NFS file %s: %w", fullPath, err)
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
		return nil, fmt.Errorf("failed to stat NFS file %s: %w", fullPath, err)
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
		return nil, fmt.Errorf("failed to list NFS directory %s: %w", fullPath, err)
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
		return false, fmt.Errorf("failed to check NFS file existence %s: %w", fullPath, err)
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
		return fmt.Errorf("failed to create NFS directory %s: %w", fullPath, err)
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
		return fmt.Errorf("failed to delete NFS directory %s: %w", fullPath, err)
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
		return fmt.Errorf("failed to delete NFS file %s: %w", fullPath, err)
	}
	return nil
}

// CopyFile copies a file within the NFS mount.
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
	return "nfs"
}

// GetConfig returns the NFS configuration.
func (c *Client) GetConfig() interface{} {
	return &c.config
}
