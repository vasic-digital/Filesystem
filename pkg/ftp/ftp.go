// Package ftp implements the filesystem client for FTP protocol.
package ftp

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"

	goftp "github.com/jlaffaye/ftp"

	"digital.vasic.filesystem/pkg/client"
)

// Config contains FTP connection configuration.
type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Path     string `json:"path"`
}

// Client implements client.Client for FTP protocol.
type Client struct {
	config    *Config
	client    *goftp.ServerConn
	connected bool
}

// NewFTPClient creates a new FTP client.
func NewFTPClient(config *Config) *Client {
	return &Client{
		config:    config,
		connected: false,
	}
}

// Connect establishes the FTP connection.
func (c *Client) Connect(ctx context.Context) error {
	addr := net.JoinHostPort(c.config.Host, fmt.Sprintf("%d", c.config.Port))

	ftpClient, err := goftp.Dial(addr, goftp.DialWithTimeout(30*time.Second))
	if err != nil {
		return fmt.Errorf("failed to connect to FTP server: %w", err)
	}

	err = ftpClient.Login(c.config.Username, c.config.Password)
	if err != nil {
		ftpClient.Quit()
		return fmt.Errorf("failed to login to FTP server: %w", err)
	}

	if c.config.Path != "" {
		err = ftpClient.ChangeDir(c.config.Path)
		if err != nil {
			ftpClient.Quit()
			return fmt.Errorf("failed to change to base directory %s: %w", c.config.Path, err)
		}
	}

	c.client = ftpClient
	c.connected = true
	return nil
}

// Disconnect closes the FTP connection.
func (c *Client) Disconnect(ctx context.Context) error {
	if c.client != nil {
		err := c.client.Quit()
		c.client = nil
		c.connected = false
		return err
	}
	c.connected = false
	return nil
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	return c.connected && c.client != nil
}

// TestConnection tests the FTP connection.
func (c *Client) TestConnection(ctx context.Context) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	_, err := c.client.CurrentDir()
	return err
}

// resolvePath resolves a relative path within the FTP base directory.
func (c *Client) resolvePath(path string) string {
	if c.config.Path != "" {
		return c.config.Path + "/" + path
	}
	return path
}

// ReadFile reads a file from the FTP server.
func (c *Client) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	resp, err := c.client.Retr(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve FTP file %s: %w", fullPath, err)
	}
	return resp, nil
}

// WriteFile writes a file to the FTP server.
func (c *Client) WriteFile(ctx context.Context, path string, data io.Reader) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)

	dir := filepath.Dir(fullPath)
	if dir != "." && dir != "/" {
		_ = c.client.MakeDir(dir)
	}

	err := c.client.Stor(fullPath, data)
	if err != nil {
		return fmt.Errorf("failed to store FTP file %s: %w", fullPath, err)
	}
	return nil
}

// GetFileInfo gets information about a file.
func (c *Client) GetFileInfo(ctx context.Context, path string) (*client.FileInfo, error) {
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)

	size, err := c.client.FileSize(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get FTP file info %s: %w", fullPath, err)
	}

	modTime := time.Now()

	_, listErr := c.client.List(fullPath)
	isDir := listErr == nil

	return &client.FileInfo{
		Name:    filepath.Base(path),
		Size:    size,
		ModTime: modTime,
		IsDir:   isDir,
		Mode:    0644,
		Path:    path,
	}, nil
}

// ListDirectory lists files in a directory.
func (c *Client) ListDirectory(ctx context.Context, path string) ([]*client.FileInfo, error) {
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)

	entries, err := c.client.List(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list FTP directory %s: %w", fullPath, err)
	}

	var files []*client.FileInfo
	for _, entry := range entries {
		size := int64(entry.Size)
		if entry.Size > uint64(1<<63-1) {
			size = 1<<63 - 1
		}

		files = append(files, &client.FileInfo{
			Name:    entry.Name,
			Size:    size,
			ModTime: entry.Time,
			IsDir:   entry.Type == goftp.EntryTypeFolder,
			Mode:    0644,
			Path:    path + "/" + entry.Name,
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

	_, err := c.client.FileSize(fullPath)
	if err != nil {
		dir := filepath.Dir(fullPath)
		name := filepath.Base(fullPath)
		entries, err := c.client.List(dir)
		if err != nil {
			return false, fmt.Errorf("failed to check FTP file existence %s: %w", fullPath, err)
		}
		for _, entry := range entries {
			if entry.Name == name {
				return true, nil
			}
		}
		return false, nil
	}
	return true, nil
}

// CreateDirectory creates a directory.
func (c *Client) CreateDirectory(ctx context.Context, path string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	err := c.client.MakeDir(fullPath)
	if err != nil {
		return fmt.Errorf("failed to create FTP directory %s: %w", fullPath, err)
	}
	return nil
}

// DeleteDirectory deletes a directory.
func (c *Client) DeleteDirectory(ctx context.Context, path string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	err := c.client.RemoveDir(fullPath)
	if err != nil {
		return fmt.Errorf("failed to delete FTP directory %s: %w", fullPath, err)
	}
	return nil
}

// DeleteFile deletes a file.
func (c *Client) DeleteFile(ctx context.Context, path string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	fullPath := c.resolvePath(path)
	err := c.client.Delete(fullPath)
	if err != nil {
		return fmt.Errorf("failed to delete FTP file %s: %w", fullPath, err)
	}
	return nil
}

// CopyFile copies a file on the FTP server.
func (c *Client) CopyFile(ctx context.Context, srcPath, dstPath string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}

	srcFullPath := c.resolvePath(srcPath)
	dstFullPath := c.resolvePath(dstPath)

	resp, err := c.client.Retr(srcFullPath)
	if err != nil {
		return fmt.Errorf("failed to retrieve source file %s: %w", srcFullPath, err)
	}
	defer resp.Close()

	dstDir := filepath.Dir(dstFullPath)
	if dstDir != "." && dstDir != "/" {
		_ = c.client.MakeDir(dstDir)
	}

	err = c.client.Stor(dstFullPath, resp)
	if err != nil {
		return fmt.Errorf("failed to store destination file %s: %w", dstFullPath, err)
	}

	return nil
}

// GetProtocol returns the protocol name.
func (c *Client) GetProtocol() string {
	return "ftp"
}

// GetConfig returns the FTP configuration.
func (c *Client) GetConfig() interface{} {
	return c.config
}
