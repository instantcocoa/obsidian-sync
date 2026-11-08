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
	"strconv"
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

// Orphan is a final blob file found on disk: its id and where it actually is
// (a misplaced file in another shard directory is deleted by path, not by id,
// so the correctly placed namesake is never touched).
type Orphan struct {
	ID   string
	Path string
}

// DeletePath removes one file listed by Orphans.
func (f *FS) DeletePath(p string) error {
	if rel, err := filepath.Rel(f.root, p); err != nil || strings.HasPrefix(rel, "..") {
		return errors.New("path outside the blob store")
	}
	err := os.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Orphans lists final blob files (64 hex characters) older than `age`; the
// caller checks each against the index and removes those with no row.
func (f *FS) Orphans(vault string, age time.Duration) ([]Orphan, error) {
	root := filepath.Join(f.root, vault)
	cutoff := time.Now().Add(-age)
	var out []Orphan
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || !isHexID(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.ModTime().After(cutoff) {
			return nil
		}
		out = append(out, Orphan{ID: d.Name(), Path: p})
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return out, err
}

func isHexID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// SweepStale removes staging, aside and temp files of interrupted uploads
// older than `age`. "<id>-stage-<nonce>" and "<id>-prev-<nonce>" carry their
// creation time in the nonce (base-36 UnixNano, minted by putBlob), which is
// what is aged: an aside copy is a hard link and shares the old blob's mtime,
// and a touch would need file ownership. ".tmp-<id>-*" from Put is aged by
// mtime. Nothing else matches those names, so a live upload younger than
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
		if !strings.HasPrefix(name, ".tmp-") && !strings.Contains(name, "-stage-") && !strings.Contains(name, "-prev-") {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		born := info.ModTime()
		// An aside ("-prev-") copy is a hard link that shares the old blob's
		// mtime, so it is aged by the nonce putBlob put in its name. A stage
		// file is still being written for as long as the upload lasts (which
		// can exceed the hour: idleReader extends the deadline while bytes
		// arrive), so it is aged by its mtime, which that write keeps fresh;
		// so are the ".tmp-" files Put makes. A nonce that does not decode to
		// a plausible time falls back to mtime too.
		if strings.Contains(name, "-prev-") {
			if ns, perr := strconv.ParseInt(name[strings.LastIndex(name, "-")+1:], 36, 64); perr == nil {
				if t := time.Unix(0, ns); t.After(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) && t.Before(time.Now().Add(24*time.Hour)) {
					born = t
				}
			}
		}
		if born.After(cutoff) {
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

// Swap keeps the current blob file (if any) aside under `prev` and promotes
// `stage` into its place, so a caller whose index write then fails can put
// the previous bytes back with Restore. Returns whether a previous file was
// set aside.
//
// The aside copy is a hard link, not a rename: the rename of `stage` over
// `id` then replaces the file atomically and the name is never empty, so a
// reader fetching the blob at that instant never sees "no such file" (which
// the plugin would take for a permanent 404 and skip the op). The link's
// timestamp is set to now, so GC's hour-of-grace sweep for abandoned files
// counts from this request, not from the old blob's write. On a file system
// without hard links the rename pair is used instead.
func (f *FS) Swap(vault, stage, id, prev string) (bool, error) {
	had := false
	cur, prevPath := f.path(vault, id), f.path(vault, prev)
	// The aside copy's age is read from the nonce in its name by SweepStale,
	// never from its mtime (a hard link shares the old inode's timestamp, and
	// a touch needs file ownership that link and rename do not).
	switch err := os.Link(cur, prevPath); {
	case err == nil:
		had = true
	case errors.Is(err, os.ErrNotExist):
	default:
		// No hard links here (FAT, exFAT, some network mounts; Windows reports
		// these with codes Go does not map to a portable errno): fall back to
		// the rename pair. The link is only what closes the brief window in
		// which the name would otherwise be empty.
		if rerr := os.Rename(cur, prevPath); rerr == nil {
			had = true
		} else if !errors.Is(rerr, os.ErrNotExist) {
			return false, rerr
		}
	}
	if err := f.Promote(vault, stage, id); err != nil {
		if had {
			os.Rename(prevPath, cur)
		}
		return had, err
	}
	return had, nil
}

// Restore undoes Swap: the bytes under `prev` become the blob again (or, when
// there were none, the promoted file is removed).
func (f *FS) Restore(vault, prev, id string, had bool) error {
	if !had {
		return f.Delete(vault, id)
	}
	if err := os.Rename(f.path(vault, prev), f.path(vault, id)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(f.path(vault, id)))
}
