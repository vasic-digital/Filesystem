package sftp

import (
	"time"

	"golang.org/x/crypto/ssh"
)

// Test helpers that look inside the client. They are the only place that knows how the connection is held, so the
// behavioural tests do not depend on field names.

// killConn closes the live ssh connection under the client (the network dropping it), without telling the client.
func killConn(c *Client) {
	c.mu.Lock()
	cn := c.cur
	c.mu.Unlock()
	if cn != nil {
		_ = cn.ssh.Close()
	}
}

// heldConn reports whether the client holds a connection object (live or not).
func heldConn(c *Client) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur != nil
}

// sshOf returns the live ssh connection object of the client (nil when none is held).
func sshOf(c *Client) *ssh.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur == nil {
		return nil
	}
	return c.cur.ssh
}

// killConnAndWait closes the live ssh connection and waits until it is known dead, so the next operation meets a fully closed
// channel (the state in which pkg/sftp reports the write error as io.EOF) instead of racing the close.
func killConnAndWait(c *Client) {
	c.mu.Lock()
	cn := c.cur
	c.mu.Unlock()
	if cn == nil {
		return
	}
	_ = cn.ssh.Close()
	select {
	case <-cn.dead:
	case <-time.After(3 * time.Second):
	}
}
