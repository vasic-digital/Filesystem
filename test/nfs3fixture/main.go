// Command nfs3fixture is a TEST FIXTURE ONLY: a read-only, user-space NFSv3
// server (willscott/go-nfs v0.0.4, Apache-2.0, an independent implementation of
// RFC 1813) exporting a deterministic in-memory corpus. It exists so the
// pkg/nfs3 client can be tested against a server it shares no code with.
// It is never a runtime dependency of the product.
//
// go-nfs serves MOUNT and NFS on ONE port and has no portmapper, so the client
// is configured with MountPort == NFSPort == the -listen port.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"
)

// roFS refuses every mutation, so a client bug cannot change the corpus.
type roFS struct{ billy.Filesystem }

var errRO = os.ErrPermission

func (roFS) Create(string) (billy.File, error) { return nil, errRO }
func (r roFS) OpenFile(name string, flag int, perm os.FileMode) (billy.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_APPEND|os.O_TRUNC) != 0 {
		return nil, errRO
	}
	return r.Filesystem.OpenFile(name, flag, perm)
}
func (roFS) Remove(string) error                         { return errRO }
func (roFS) Rename(string, string) error                 { return errRO }
func (roFS) MkdirAll(string, os.FileMode) error          { return errRO }
func (roFS) Symlink(string, string) error                { return errRO }
func (roFS) TempFile(string, string) (billy.File, error) { return nil, errRO }

func put(fs billy.Filesystem, name string, data []byte) {
	f, err := fs.Create(name)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		log.Fatal(err)
	}
	_ = f.Close()
}

func build() billy.Filesystem {
	fs := memfs.New()
	put(fs, "docs/a.txt", []byte("alpha\n"))
	put(fs, "docs/b.txt", []byte("bravo bravo\n"))
	put(fs, "empty.txt", nil)
	put(fs, "ünï.txt", []byte("unicode name"))
	big := make([]byte, 3<<20+13)
	for i := range big {
		big[i] = byte(i*7 + i>>8)
	}
	put(fs, "big.bin", big)
	for i := 0; i < 250; i++ {
		put(fs, fmt.Sprintf("many/f%04d", i), []byte(fmt.Sprintf("file %d", i)))
	}
	put(fs, "deep/a/b/c/leaf.txt", []byte("leaf"))
	if err := fs.Symlink("docs/a.txt", "link"); err != nil {
		log.Fatal(err)
	}
	return fs
}

type entry struct {
	Path   string `json:"path"`
	Dir    bool   `json:"dir"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
	Link   bool   `json:"symlink,omitempty"`
}

func walk(fs billy.Filesystem, dir string, out *[]entry) {
	infos, err := fs.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	for _, fi := range infos {
		p := strings.TrimPrefix(dir+"/"+fi.Name(), "/")
		if fi.Mode()&os.ModeSymlink != 0 {
			*out = append(*out, entry{Path: "/" + p, Link: true})
			continue
		}
		if fi.IsDir() {
			*out = append(*out, entry{Path: "/" + p, Dir: true})
			walk(fs, p, out)
			continue
		}
		f, err := fs.Open(p)
		if err != nil {
			log.Fatal(err)
		}
		h := sha256.New()
		buf := make([]byte, 1<<16)
		var n int64
		for {
			m, err := f.Read(buf)
			h.Write(buf[:m])
			n += int64(m)
			if err != nil {
				break
			}
		}
		_ = f.Close()
		*out = append(*out, entry{Path: "/" + p, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
}

func main() {
	listen := flag.String("listen", "0.0.0.0:2049", "listen address (MOUNT and NFS share this port)")
	manifest := flag.String("manifest", "", "write the expected tree (path, type, size, sha256) as JSON to this file and exit")
	authsys := flag.Bool("authsys", false, "advertise AUTH_SYS and verify every call's credential with an independent XDR decoder (see authsys.go)")
	authlog := flag.String("authlog", "", "with -authsys: append one OK/VIOLATION line per checked call to this file")
	authuid := flag.Uint("authuid", 1000, "with -authsys: the uid the client must send")
	authgid := flag.Uint("authgid", 1000, "with -authsys: the gid the client must send")
	authmachine := flag.String("authmachine", "catalogizer", "with -authsys: the machine name the client must send")
	flag.Parse()
	fs := build()
	if *manifest != "" {
		var out []entry
		walk(fs, "", &out)
		sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
		b, _ := json.MarshalIndent(out, "", " ")
		if err := os.WriteFile(*manifest, b, 0o644); err != nil {
			log.Fatal(err)
		}
		return
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("nfs3fixture listening on %s\n", ln.Addr())
	h := nfshelper.NewCachingHandler(nfshelper.NewNullAuthHandler(roFS{fs}), 4096)
	if *authsys {
		if *authlog == "" {
			log.Fatal("-authsys needs -authlog")
		}
		lf, err := os.OpenFile(*authlog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatal(err)
		}
		chk := &authCheck{uid: uint32(*authuid), gid: uint32(*authgid), machine: *authmachine, log: lf}
		log.Fatal(nfs.Serve(tapListener{Listener: ln, chk: chk}, sysHandler{h}))
	}
	log.Fatal(nfs.Serve(ln, h))
}
