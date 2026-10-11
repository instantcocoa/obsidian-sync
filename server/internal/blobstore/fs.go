// Package blobstore stores ciphertext blobs on the filesystem, sharded by the
// first two hex characters of the blob ID, written atomically via a temp
// file and rename.
package blobstore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

type FS struct{ root string }

func New(root string) (*FS, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, err
	}
	return &FS{root: root}, nil
}

func (f *FS) path(vault, id string) string {
	return filepath.Join(f.root, vault, id[:2], id)
}

// Put streams r into the blob file. Returns bytes written.
func (f *FS) Put(vault, id string, r io.Reader) (int64, error) {
	p := f.path(vault, id)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-"+id+"-*")
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(tmp, r)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp.Name())
		return n, err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		os.Remove(tmp.Name())
		return n, err
	}
	return n, nil
}

func (f *FS) Open(vault, id string) (*os.File, error) {
	fh, err := os.Open(f.path(vault, id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	return fh, err
}

func (f *FS) Delete(vault, id string) error {
	err := os.Remove(f.path(vault, id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Promote atomically renames a staged blob into its final name.
func (f *FS) Promote(vault, stage, id string) error {
	return os.Rename(f.path(vault, stage), f.path(vault, id))
}
