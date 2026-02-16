package webdav

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
)

// Verify WebDAV Client implements client.Client interface.
var _ client.Client = (*Client)(nil)

func TestNewWebDAVClient(t *testing.T) {
	config := &Config{
		URL:      "http://localhost/webdav",
		Username: "user",
		Password: "pass",
		Path:     "/files",
	}
	c := NewWebDAVClient(config)
	require.NotNil(t, c)
	assert.Equal(t, config, c.config)
	assert.NotNil(t, c.client)
	assert.NotNil(t, c.baseURL)
	assert.False(t, c.connected)
}

func TestNewWebDAVClient_WithPath(t *testing.T) {
	config := &Config{
		URL:  "http://localhost",
		Path: "/dav",
	}
	c := NewWebDAVClient(config)
	assert.Equal(t, "/dav", c.baseURL.Path)
}

func TestNewWebDAVClient_WithoutPath(t *testing.T) {
	config := &Config{
		URL:  "http://localhost/webdav",
		Path: "",
	}
	c := NewWebDAVClient(config)
	assert.Equal(t, "/webdav", c.baseURL.Path)
}

func TestNewWebDAVClient_RootPath(t *testing.T) {
	config := &Config{
		URL:  "http://localhost",
		Path: "/",
	}
	c := NewWebDAVClient(config)
	// Root path "/" should not override
	assert.Equal(t, "", c.baseURL.Path)
}

func TestWebDAVClient_GetProtocol(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	assert.Equal(t, "webdav", c.GetProtocol())
}

func TestWebDAVClient_GetConfig(t *testing.T) {
	config := &Config{
		URL:      "http://dav.example.com",
		Username: "admin",
		Password: "secret",
		Path:     "/",
	}
	c := NewWebDAVClient(config)
	assert.Equal(t, config, c.GetConfig())
}

func TestWebDAVClient_IsConnected_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	assert.False(t, c.IsConnected())
}

func TestWebDAVClient_Disconnect(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	c.connected = true
	err := c.Disconnect(context.Background())
	assert.NoError(t, err)
	assert.False(t, c.connected)
}

func TestWebDAVClient_TestConnection_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	err := c.TestConnection(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestWebDAVClient_ReadFile_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	reader, err := c.ReadFile(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "not connected")
}

func TestWebDAVClient_WriteFile_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	err := c.WriteFile(context.Background(), "test.txt", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestWebDAVClient_GetFileInfo_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	info, err := c.GetFileInfo(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "not connected")
}

func TestWebDAVClient_ListDirectory_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	files, err := c.ListDirectory(context.Background(), "/")
	assert.Error(t, err)
	assert.Nil(t, files)
	assert.Contains(t, err.Error(), "not connected")
}

func TestWebDAVClient_FileExists_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	exists, err := c.FileExists(context.Background(), "test.txt")
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "not connected")
}

func TestWebDAVClient_CreateDirectory_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	err := c.CreateDirectory(context.Background(), "newdir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestWebDAVClient_DeleteDirectory_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	err := c.DeleteDirectory(context.Background(), "olddir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestWebDAVClient_DeleteFile_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	err := c.DeleteFile(context.Background(), "file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestWebDAVClient_CopyFile_NotConnected(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost"})
	err := c.CopyFile(context.Background(), "src.txt", "dst.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestWebDAVClient_ResolveURL(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost/webdav"})
	resolved := c.resolveURL("test.txt")
	assert.Contains(t, resolved, "test.txt")
	assert.Contains(t, resolved, "http://localhost")
}

func TestWebDAVClient_ResolveURL_PathTraversal(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost/webdav"})
	resolved := c.resolveURL("../../../etc/passwd")
	assert.NotContains(t, resolved, "..")
}

func TestWebDAVClient_ResolveURL_CleanPath(t *testing.T) {
	c := NewWebDAVClient(&Config{URL: "http://localhost/webdav"})
	resolved := c.resolveURL("./subdir/../test.txt")
	assert.NotContains(t, resolved, "..")
}

// httptest server tests

func newTestServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestWebDAVClient_Connect_Success(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PROPFIND" {
			w.WriteHeader(http.StatusMultiStatus)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	err := c.Connect(context.Background())
	assert.NoError(t, err)
	assert.True(t, c.IsConnected())
}

func TestWebDAVClient_Connect_WithAuth(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusMultiStatus)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{
		URL:      ts.URL,
		Username: "admin",
		Password: "secret",
	})
	err := c.Connect(context.Background())
	assert.NoError(t, err)
	assert.True(t, c.IsConnected())
}

func TestWebDAVClient_Connect_ServerError(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	err := c.Connect(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestWebDAVClient_Connect_Unauthorized(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	err := c.Connect(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestWebDAVClient_ReadFile_Success(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "file content")
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	reader, err := c.ReadFile(context.Background(), "test.txt")
	require.NoError(t, err)
	require.NotNil(t, reader)
	defer reader.Close()

	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "file content", string(data))
}

func TestWebDAVClient_ReadFile_NotFound(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	reader, err := c.ReadFile(context.Background(), "missing.txt")
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "404")
}

func TestWebDAVClient_WriteFile_Success(t *testing.T) {
	var receivedBody string
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	err := c.WriteFile(context.Background(), "upload.txt", strings.NewReader("upload data"))
	assert.NoError(t, err)
	assert.Equal(t, "upload data", receivedBody)
}

func TestWebDAVClient_WriteFile_ServerError(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	err := c.WriteFile(context.Background(), "upload.txt", strings.NewReader("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestWebDAVClient_GetFileInfo_Success(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "1024")
			w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	info, err := c.GetFileInfo(context.Background(), "test.txt")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "test.txt", info.Name)
	assert.Equal(t, int64(1024), info.Size)
	assert.False(t, info.IsDir)
}

func TestWebDAVClient_GetFileInfo_Directory(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Type", "httpd/unix-directory")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	info, err := c.GetFileInfo(context.Background(), "subdir")
	require.NoError(t, err)
	assert.True(t, info.IsDir)
}

func TestWebDAVClient_GetFileInfo_DirectoryTrailingSlash(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	info, err := c.GetFileInfo(context.Background(), "subdir/")
	require.NoError(t, err)
	assert.True(t, info.IsDir)
}

func TestWebDAVClient_ListDirectory_Success(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PROPFIND" {
			assert.Equal(t, "1", r.Header.Get("Depth"))
			w.WriteHeader(http.StatusMultiStatus)
			fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>/webdav/</D:href>
<D:propstat><D:prop><D:displayname>webdav</D:displayname><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
</D:response>
<D:response>
<D:href>/webdav/file1.txt</D:href>
<D:propstat><D:prop><D:displayname>file1.txt</D:displayname><D:getcontentlength>512</D:getcontentlength><D:getlastmodified>Mon, 02 Jan 2006 15:04:05 GMT</D:getlastmodified><D:resourcetype/></D:prop></D:propstat>
</D:response>
<D:response>
<D:href>/webdav/subdir/</D:href>
<D:propstat><D:prop><D:displayname>subdir</D:displayname><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
</D:response>
</D:multistatus>`)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL + "/webdav"})
	c.connected = true

	files, err := c.ListDirectory(context.Background(), "/")
	require.NoError(t, err)
	assert.Len(t, files, 2) // parent directory should be filtered out

	// Verify file entry
	var fileEntry, dirEntry *client.FileInfo
	for _, f := range files {
		if f.Name == "file1.txt" {
			fileEntry = f
		}
		if f.Name == "subdir" {
			dirEntry = f
		}
	}

	if fileEntry != nil {
		assert.Equal(t, int64(512), fileEntry.Size)
		assert.False(t, fileEntry.IsDir)
	}
	if dirEntry != nil {
		assert.True(t, dirEntry.IsDir)
	}
}

func TestWebDAVClient_ListDirectory_ServerError(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	files, err := c.ListDirectory(context.Background(), "/")
	assert.Error(t, err)
	assert.Nil(t, files)
}

func TestWebDAVClient_FileExists_True(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	exists, err := c.FileExists(context.Background(), "test.txt")
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestWebDAVClient_FileExists_False(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	exists, err := c.FileExists(context.Background(), "missing.txt")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestWebDAVClient_CreateDirectory_Success(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "MKCOL" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	err := c.CreateDirectory(context.Background(), "newdir")
	assert.NoError(t, err)
}

func TestWebDAVClient_CreateDirectory_ServerError(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	err := c.CreateDirectory(context.Background(), "newdir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestWebDAVClient_DeleteFile_Success(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	err := c.DeleteFile(context.Background(), "file.txt")
	assert.NoError(t, err)
}

func TestWebDAVClient_DeleteDirectory_Success(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	err := c.DeleteDirectory(context.Background(), "olddir")
	assert.NoError(t, err)
}

func TestWebDAVClient_CopyFile_Success(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "COPY" {
			dest := r.Header.Get("Destination")
			assert.NotEmpty(t, dest)
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	err := c.CopyFile(context.Background(), "src.txt", "dst.txt")
	assert.NoError(t, err)
}

func TestWebDAVClient_CopyFile_ServerError(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{URL: ts.URL})
	c.connected = true

	err := c.CopyFile(context.Background(), "src.txt", "dst.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestWebDAVClient_ReadFile_WithAuth(t *testing.T) {
	ts := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, "authenticated content")
	})
	defer ts.Close()

	c := NewWebDAVClient(&Config{
		URL:      ts.URL,
		Username: "admin",
		Password: "secret",
	})
	c.connected = true

	reader, err := c.ReadFile(context.Background(), "secure.txt")
	require.NoError(t, err)
	defer reader.Close()

	data, _ := io.ReadAll(reader)
	assert.Equal(t, "authenticated content", string(data))
}

func TestWebDAVConfig_Fields(t *testing.T) {
	config := Config{
		URL:      "https://dav.example.com/files",
		Username: "admin",
		Password: "s3cret",
		Path:     "/media",
	}
	assert.Equal(t, "https://dav.example.com/files", config.URL)
	assert.Equal(t, "admin", config.Username)
	assert.Equal(t, "s3cret", config.Password)
	assert.Equal(t, "/media", config.Path)
}
