// Package nfs3 is a minimal, read-only, pure-Go, user-space NFSv3 client.
//
// It needs no kernel mount, no root and no cgo. It speaks ONC RPC over TCP
// (RFC 5531, record marking per section 11, AUTH_SYS per appendix A), XDR
// (RFC 4506), the port mapper GETPORT call (RFC 1833 section 3, version 2),
// the MOUNT version 3 protocol (RFC 1813 appendix I: NULL, MNT, UMNT, EXPORT)
// and the NFS version 3 procedures NULL, GETATTR, LOOKUP, ACCESS, READ,
// READDIRPLUS and FSINFO (RFC 1813 section 3).
//
// # Read-only by construction
//
// No write procedure (SETATTR, WRITE, CREATE, MKDIR, SYMLINK, MKNOD, REMOVE,
// RMDIR, RENAME, LINK, COMMIT) has a procedure number, an encoder or a public
// entry point in this package. The methods of client.Client that would mutate
// (WriteFile, DeleteFile, CopyFile, CreateDirectory, DeleteDirectory) return
// ErrReadOnly without sending anything. Three independent guards enforce this:
// a run-time allow-list of (program, procedure) pairs at the single place where a request
// is written (rpcConn.call refuses anything else with ErrReadOnly before a byte is sent),
// TestNoWriteProcedureCompiledIn and the call-site allow-list test (which parse the source),
// and the server-side procedure counters of the tests.
//
// The guarantee covers the NFS data and metadata procedures. It does not mean the server
// sees nothing: MNT and UMNT add and remove the server's mount record (rmtab), and READ
// updates access times on exports that do not mount with noatime.
//
// # Reserved source ports
//
// Many NAS products export with the "secure" option (the client's TCP source port must be
// below 1024; Linux knfsd answers a request from another port with NFS3ERR_PERM, other
// servers with NFS3ERR_ACCES or an RPC AUTH_ERROR). The client first connects
// from an ordinary ephemeral port, as an unprivileged process must. When the
// server then refuses (MNT3ERR_ACCES, NFS3ERR_ACCES, or RPC AUTH_ERROR) the
// error is an *AccessError that states the source port used and that a
// privileged port may be required. With Config.TryPrivilegedPort the client
// retries once from a reserved port; when the process may not bind one, the
// error wraps ErrPrivilegedPortUnavailable (needs root, CAP_NET_BIND_SERVICE,
// or a lowered net.ipv4.ip_unprivileged_port_start).
//
// # Authentication flavors
//
// The MOUNT reply lists the flavors the export accepts (RFC 1813 appendix I).
// AUTH_SYS is used when it is listed or when the list is empty; an export that
// lists only AUTH_NULL (user-space servers such as go-nfs) is served with
// AUTH_NONE credentials; any other list is refused with ErrAuthFlavor.
//
// # Security note
//
// AUTH_SYS carries uid/gid in the clear and is trusted by the server on
// the strength of the source address only (RFC 5531 section 14, Security
// Considerations: AUTH_SYS is known to be insecure and SHOULD NOT be used for
// services that permit clients to modify data; the format is appendix A).
// This client never modifies data, which is the reason AUTH_SYS is acceptable
// here. Use it only on trusted networks.
//
// A zero UID or GID in Config is NOT sent as root: it becomes 65534 (nobody)
// unless Config.AsRoot is set, because on a no_root_squash export an unset
// identity would otherwise read the tree as root.
//
// # Sources
//
//	RFC 1813  NFS Version 3 Protocol Specification
//	RFC 1833  Binding Protocols for ONC RPC Version 2 (portmapper v2, GETPORT)
//	RFC 4506  XDR: External Data Representation Standard
//	RFC 5531  RPC: Remote Procedure Call Protocol Specification Version 2
package nfs3
