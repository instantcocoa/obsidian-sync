// Package blobstore stores ciphertext blobs on the filesystem, sharded by the
// first two hex characters of the blob ID, written atomically via a temp
// file and rename.
package blobstore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
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
	return n, syncDir(filepath.Dir(p))
}

// syncDir makes a rename durable: the file's bytes were fsynced, the
// directory entry that names them was not until this.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		// Directory fsync is unsupported on Windows and on some mounts; the
		// rename is then as durable as the platform allows.
		var errno syscall.Errno
		if runtime.GOOS == "windows" || (errors.As(err, &errno) && (errno == syscall.EINVAL || errno == syscall.ENOTSUP || errno == syscall.ENOTTY)) {
			return nil
		}
		return err
	}
	return nil
}

// Exists reports whether the blob's file is present.
func (f *FS) Exists(vault, id string) bool {
	st, err := os.Stat(f.path(vault, id))
	return err == nil && st.Mode().IsRegular()
}

// SweepStale removes staging and temp files of interrupted uploads older
// than `age` (names "<id>-stage-<nonce>" from putBlob and ".tmp-<id>-*" from
// Put). Nothing else matches those names, so a live upload younger than
// `age` is the only thing spared.
func (f *FS) SweepStale(vault string, age time.Duration) (int, error) {
	root := filepath.Join(f.root, vault)
	cutoff := time.Now().Add(-age)
	n := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.Contains(name, "-stage-") && !strings.HasPrefix(name, ".tmp-") {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.ModTime().After(cutoff) {
			return nil
		}
		if os.Remove(p) == nil {
			n++
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return n, err
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
	if err := os.Rename(f.path(vault, stage), f.path(vault, id)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(f.path(vault, id)))
}
