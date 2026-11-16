//go:build windows

package main

// Windows has no umask and no root; the data directory's ACL is the operator's concern.
func becomeOwner(string) (func(), error) { return func() {}, nil }
