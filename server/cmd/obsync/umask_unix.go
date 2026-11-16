//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Everything the server creates (database, WAL, blobs, the ACME cache) is
// private to its user: no other local account needs any of it.
func init() {
	syscall.Umask(0o077)
}

// becomeOwner lets a CLI run as root (`sudo obsync vault create …`) leave the
// data directory the way the service user needs it. The service runs as a
// DynamicUser whose files sit under /var/lib/private, which only root may
// traverse, so the CLI cannot simply switch to that user; instead it stays
// root and, when it is done, hands any file it created (a WAL, a fresh
// database) to the directory's owner. Returns the function to run at exit.
func becomeOwner(data string) (func(), error) {
	if os.Geteuid() != 0 {
		return func() {}, nil
	}
	fi, err := os.Stat(data)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return func() {}, nil
	}
	uid, gid := int(st.Uid), int(st.Gid)
	return func() {
		for _, dir := range []string{data, filepath.Join(data, "blobs")} {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				p := filepath.Join(dir, e.Name())
				if fi, err := os.Lstat(p); err == nil {
					if s, ok := fi.Sys().(*syscall.Stat_t); ok && s.Uid == 0 {
						if err := os.Lchown(p, uid, gid); err != nil {
							fmt.Fprintf(os.Stderr, "warning: could not hand %s to the service user: %v\n", p, err)
						}
					}
				}
			}
		}
	}, nil
}
