// Package smb implements the filesystem client for SMB protocol.
package smb

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/hirochachacha/go-smb2"

	"digital.vasic.filesystem/pkg/client"
)

// Config contains SMB connection configuration.
type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Share    string `json:"share"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
}

// Client implements client.Client for SMB protocol.
type Client struct {
	conn    net.Conn
	session *smb2.Session
	share   *smb2.Share
	config  *Config
}

// NewSMBClient creates a new SMB client.
func NewSMBClient(config *Config) *Client {
	return &Client{
		config: config,
	}
}

// Connect establishes the SMB connection.
func (c *Client) Connect(ctx context.Context) error {
	addr := net.JoinHostPort(c.config.Host, fmt.Sprintf("%d", c.config.Port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMB server: %w", err)
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     c.config.Username,
			Password: c.config.Password,
			Domain:   c.config.Domain,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create SMB session: %w", err)
	}

	share, err := session.Mount(c.config.Share)
	if err != nil {
		session.Logoff()
		conn.Close()
		return fmt.Errorf("failed to mount SMB share: %w", err)
	}

	c.conn = conn
	c.session = session
	c.share = share
	return nil
}

// Disconnect closes the SMB connection.
func (c *Client) Disconnect(ctx context.Context) error {
	var errs []error

	if c.share != nil {
		if err := c.share.Umount(); err != nil {
			errs = append(errs, fmt.Errorf("failed to unmount share: %w", err))
		}
		c.share = nil
	}

	if c.session != nil {
		if err := c.session.Logoff(); err != nil {
			errs = append(errs, fmt.Errorf("failed to logoff session: %w", err))
		}
		c.session = nil
	}

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close connection: %w", err))
		}
		c.conn = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing SMB client: %v", errs)
	}

	return nil
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	return c.share != nil && c.session != nil && c.conn != nil
}

// TestConnection tests the SMB connection.
func (c *Client) TestConnection(ctx context.Context) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	_, err := c.share.ReadDir(".")
	return err
}

// ReadFile reads a file from the SMB share.
func (c *Client) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	file, err := c.share.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open SMB file %s: %w", path, err)
	}
	return file, nil
}

// WriteFile writes a file to the SMB share.
func (c *Client) WriteFile(ctx context.Context, path string, data io.Reader) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	file, err := c.share.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create SMB file %s: %w", path, err)
	}
	defer file.Close()

	_, err = io.Copy(file, data)
	if err != nil {
		return fmt.Errorf("failed to write SMB file %s: %w", path, err)
	}

	return nil
}

// GetFileInfo gets information about a file.
func (c *Client) GetFileInfo(ctx context.Context, path string) (*client.FileInfo, error) {
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	stat, err := c.share.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat SMB file %s: %w", path, err)
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
	entries, err := c.share.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to list SMB directory %s: %w", path, err)
	}

	var files []*client.FileInfo
	for _, entry := range entries {
		files = append(files, &client.FileInfo{
			Name:    entry.Name(),
			Size:    entry.Size(),
			ModTime: entry.ModTime(),
			IsDir:   entry.IsDir(),
			Mode:    entry.Mode(),
			Path:    path + "/" + entry.Name(),
		})
	}

	return files, nil
}

// FileExists checks if a file exists.
func (c *Client) FileExists(ctx context.Context, path string) (bool, error) {
	if !c.IsConnected() {
		return false, fmt.Errorf("not connected")
	}
	_, err := c.share.Stat(path)
	if err != nil {
		if isNotExistError(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check SMB file existence %s: %w", path, err)
	}
	return true, nil
}

// CreateDirectory creates a directory.
func (c *Client) CreateDirectory(ctx context.Context, path string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	err := c.share.Mkdir(path, 0755)
	if err != nil {
		return fmt.Errorf("failed to create SMB directory %s: %w", path, err)
	}
	return nil
}

// DeleteDirectory deletes a directory.
func (c *Client) DeleteDirectory(ctx context.Context, path string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	err := c.share.Remove(path)
	if err != nil {
		return fmt.Errorf("failed to delete SMB directory %s: %w", path, err)
	}
	return nil
}

// DeleteFile deletes a file.
func (c *Client) DeleteFile(ctx context.Context, path string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	err := c.share.Remove(path)
	if err != nil {
		return fmt.Errorf("failed to delete SMB file %s: %w", path, err)
	}
	return nil
}

// CopyFile copies a file within the SMB share.
func (c *Client) CopyFile(ctx context.Context, srcPath, dstPath string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}
	srcFile, err := c.share.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", srcPath, err)
	}
	defer srcFile.Close()

	dstFile, err := c.share.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dstPath, err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("failed to copy file from %s to %s: %w", srcPath, dstPath, err)
	}

	return nil
}

// GetProtocol returns the protocol name.
func (c *Client) GetProtocol() string {
	return "smb"
}

// GetConfig returns the SMB configuration.
func (c *Client) GetConfig() interface{} {
	return c.config
}

// isNotExistError checks if an error indicates that a file does not exist.
func isNotExistError(err error) bool {
	return err != nil && (err.Error() == "file does not exist" || err.Error() == "no such file or directory")
}
