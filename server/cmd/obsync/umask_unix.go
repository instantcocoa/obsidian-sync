//go:build !windows

package main

import "syscall"

// Everything the server creates (database, WAL, blobs, the ACME cache, the
// admin token) is private to its user: no other local account needs any of it.
func init() {
	syscall.Umask(0o077)
}
