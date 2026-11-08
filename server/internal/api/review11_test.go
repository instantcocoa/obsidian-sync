package api_test

// Eleventh review: the tenth round's server fix (9ee3147..a4f34a0: Swap
// touches the current inode before linking it, and any os.Link failure but
// "no such file" falls back to the rename pair), read with the assumption
// that a hurried fix has an edge, plus the whole putBlob path once more as a
// state machine. Each TestR11* is the proof for one candidate finding or a
// confirmation; see plugin/.cache/agent-review11-server/REPORT.md.
//
//	cd server && go test ./internal/api -run 'TestR11' -v

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"obsync/internal/store"
)

// denyWriteAttr makes `path` a file the server can read, link and rename but
// not utimes: the shape of a blob file owned by another uid (Linux utimensat
// with explicit times needs ownership; link and rename need only the
// directory), of a mount that refuses utimensat, or of a Windows sharing
// violation. The only injector available without root is a macOS ACL, so the
// test skips elsewhere.
func denyWriteAttr(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("needs the macOS ACL injector (chmod +a 'user deny writeattr'); on Linux the equivalent is a readable blob file owned by another uid, which needs root to set up")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if out, err := exec.Command("chmod", "+a", u.Username+" deny writeattr", path).CombinedOutput(); err != nil {
		t.Skipf("chmod +a: %v %s", err, out)
	}
	now := time.Now()
	if err := os.Chtimes(path, now, now); !errors.Is(err, os.ErrPermission) {
		t.Skipf("injector premise: Chtimes should fail with EPERM, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// FINDING (low): the tenth round moved the touch ahead of the link and made
// its error fatal (fs.go:227: any Chtimes error but ENOENT returns from Swap,
// and putBlob answers 500). The touch is a GC-grace optimisation, like the
// link whose failure the same commit made non-fatal. Where the server can
// read, link and rename a blob file but not set its times, 0.1.7 (no touch)
// and 0.1.10 (touch error ignored) completed a replacing upload and 0.1.11
// refuses it. New blobs are unaffected (ENOENT is ignored), so what breaks is
// exactly the path a rotation takes for every blob of the vault: the first
// 500 aborts reencrypt() (HttpError is a transport error there) and the
// vault stays on the old keys until an operator fixes ownership.
func TestR11ChtimesRefusalFailsAReplacementTheRenamePairAccepted(t *testing.T) {
	t.Run("blobstore", func(t *testing.T) {
		id := hexID("r11-foreign-owned")
		bs, vault, cur := r10store(t, id)
		r10put(t, bs, vault, id, "old bytes")
		denyWriteAttr(t, cur)
		r10put(t, bs, vault, id+"-stage-a", "new bytes")
		had, err := bs.Swap(vault, id+"-stage-a", id, id+"-prev-a")
		if err == nil {
			if !had || r10read(t, bs, vault, id) != "new bytes" {
				t.Fatalf("Swap: had=%v content %q", had, r10read(t, bs, vault, id))
			}
			t.Logf("Swap tolerated the refused touch (had=%v)", had)
			return
		}
		// What the previous two shapes of Swap would have done on this inode.
		probe := filepath.Join(filepath.Dir(cur), id+"-probe-link")
		lerr := os.Link(cur, probe)
		os.Remove(probe)
		rerr := os.Rename(cur, cur+"-probe-moved")
		os.Rename(cur+"-probe-moved", cur)
		if lerr != nil || rerr != nil {
			t.Fatalf("premise: link (%v) and rename (%v) of the file must work for this to be a Chtimes-only refusal", lerr, rerr)
		}
		if got := r10read(t, bs, vault, id); got != "old bytes" {
			t.Fatalf("the blob must be intact after the refused swap, got %q", got)
		}
		t.Fatalf("FINDING: Swap refused a replacement with %v although os.Link and os.Rename of the same inode succeed, so 0.1.10 (touch error ignored) and 0.1.7 (rename pair, no touch) completed this upload. The touch only buys the aside copy a fresh mtime for the sweep; its failure should fall through (and the stale-file sweep should read the age from the nonce in the name so no touch is needed at all).", err)
	})

	t.Run("http", func(t *testing.T) {
		e, _, dir := r7env(t)
		vault, a, b := e.setup()
		ctx := context.Background()
		x := hexID("r11-http-foreign")
		e.upload(vault, a, x, blob(1, "x at epoch 1")).expect(t, 201)
		denyWriteAttr(t, blobPath(dir, vault, x))
		e.rotateKeep(vault, 2, a, a, b)
		// A new blob at the new epoch: fine (Chtimes ENOENT is ignored).
		e.upload(vault, a, hexID("r11-http-new"), blob(2, "a new blob is unaffected")).expect(t, 201)
		// The re-encryption of the existing one, as reencrypt() sends it.
		res := e.do("PUT", "/v1/vaults/"+vault+"/blobs/"+x, a.token, blob(2, "x re-encrypted at epoch 2"), map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault], "X-Blob-Replace": "1"})
		row, err := e.st.GetBlob(ctx, vault, x)
		if err != nil {
			t.Fatal(err)
		}
		onDisk, _ := os.ReadFile(blobPath(dir, vault, x))
		lo := leftovers(t, dir, vault)
		t.Logf("re-encrypting PUT: %d %s; row epoch %d; file header epoch %d; stage leftovers %d", res.code, res.body, row.Epoch, onDisk[1], len(lo))
		if len(lo) > 0 {
			t.Fatalf("stage files left behind: %v", lo)
		}
		if res.code != 201 {
			below := e.do("GET", "/v1/vaults/"+vault+"/blobs?epoch_lt=2", a.token, nil, nil).expect(t, 200)
			t.Fatalf("FINDING: the replacing upload of a blob the server can read and rename but not utimes answers %d %s (a new blob answered 201; the row is still at epoch %d, the file still holds epoch-%d bytes, no damage). Every blob of the vault takes this path during a rotation (the listing still names it: %s), and reencrypt() aborts on the first HttpError, so the vault cannot leave its old keys until the operator fixes file ownership. Make the touch advisory.", res.code, res.body, row.Epoch, onDisk[1], below.body)
		}
		if row.Epoch != 2 {
			t.Fatalf("row after a 201 must be at epoch 2, got %d", row.Epoch)
		}
	})
}

// ---------------------------------------------------------------------------
// NOTE (premise confirmed, trigger implausible): with the widened fallback a
// link that fails for a reason other than "no such file" uses the rename
// pair, which reopens the empty-name window for that request. EEXIST is the
// one such failure a leftover can cause (a "-prev-" file with the same
// nonce), and the rename then replaces the leftover and succeeds. The nonce
// is base-36 UnixNano chosen under the per-blob lock, so a collision needs a
// crash-leftover from the same nanosecond; not reachable from putBlob. The
// stat loop here measures the window the fallback reopens.
func TestR11LinkEExistFallsBackToTheRenamePairAndReopensTheWindow(t *testing.T) {
	id := hexID("r11-eexist")
	bs, vault, cur := r10store(t, id)
	r10put(t, bs, vault, id, "current")
	prev := id + "-prev-leftover"
	var stop atomic.Bool
	var absent, probes atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() {
		for !stop.Load() {
			probes.Add(1)
			if _, err := os.Stat(cur); errors.Is(err, os.ErrNotExist) {
				absent.Add(1)
			}
		}
	})
	swaps := 0
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); swaps++ {
		r10put(t, bs, vault, prev, "leftover from a crash")
		stage := fmt.Sprintf("%s-stage-%d", id, swaps)
		r10put(t, bs, vault, stage, fmt.Sprintf("new %d", swaps))
		had, err := bs.Swap(vault, stage, id, prev)
		if err != nil || !had {
			t.Fatalf("EEXIST fallback: had=%v err=%v", had, err)
		}
		if got := r10read(t, bs, vault, id); got != fmt.Sprintf("new %d", swaps) {
			t.Fatalf("after the swap the blob must hold the new bytes, got %q", got)
		}
		if got := r10read(t, bs, vault, prev); got != fmt.Sprintf("new %d", swaps-1) && !(swaps == 0 && got == "current") {
			t.Fatalf("the leftover must have been replaced by the previous bytes, got %q", got)
		}
		bs.Delete(vault, prev)
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("%d swaps through the EEXIST fallback: the blob's name was absent in %d of %d stat probes (the rename pair's window, reopened for this failure class only)", swaps, absent.Load(), probes.Load())
}

// ---------------------------------------------------------------------------
// CONFIRMATION: the putBlob state machine after ten rounds. For a crash at
// each step (and the one in-request failure not already pinned by review 8
// to 10) the disk and the row are set to what the crash leaves, then the
// real GC runs with the files aged past its hour of grace and the client's
// recovery path is exercised over HTTP: GET, the missing check, the
// re-encryption listing and the re-upload. Every state must end with one
// file under the blob's name, a row that describes it, and no leftovers.
func TestR11EveryCrashStateOfPutBlobIsRecoverable(t *testing.T) {
	e, bs, dir := r7env(t)
	vault, a, b := e.setup()
	ctx := context.Background()
	base := "/v1/vaults/" + vault
	old := time.Now().Add(-2 * time.Hour)
	gc := func() {
		t.Helper()
		if _, err := e.srv.GC(ctx, 2160*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	age := func(paths ...string) {
		t.Helper()
		for _, p := range paths {
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	get := func(id string) resp { return e.do("GET", base+"/blobs/"+id, b.token, nil, nil) }
	missing := func(id string) []string {
		var out struct {
			Missing []string `json:"missing"`
		}
		e.do("POST", base+"/blobs/missing", b.token, []string{id}, nil).expect(t, 200).json(t, &out)
		return out.Missing
	}
	below := func(epoch int) string {
		return string(e.do("GET", fmt.Sprintf("%s/blobs?epoch_lt=%d", base, epoch), b.token, nil, nil).expect(t, 200).body)
	}
	clean := func(id string) {
		t.Helper()
		if lo := leftovers(t, dir, vault); len(lo) > 0 {
			t.Fatalf("stage/temp leftovers: %v", lo)
		}
		if p := filesMatching(dir, vault, id+"-prev-"); len(p) > 0 {
			t.Fatalf("prev leftovers: %v", p)
		}
	}
	shard := func(id string) string { return filepath.Dir(blobPath(dir, vault, id)) }
	// The epoch-1 seeds go in before the rotation (an empty vault's min_epoch
	// follows the rotation, R10); with them stored, epochs 1 and 2 are legal.
	seed := map[string][]byte{}
	for _, k := range []string{"A", "B", "C", "G"} {
		id := hexID("r11-" + k)
		seed[id] = blob(1, k+" v1")
		e.upload(vault, a, id, seed[id]).expect(t, 201)
	}
	e.rotateKeep(vault, 2, a, a, b)

	// A. Crash after Put, before Swap: the stage file is the only trace.
	t.Run("A stage leftover", func(t *testing.T) {
		id := hexID("r11-A")
		v1 := seed[id]
		stage := filepath.Join(shard(id), id+"-stage-crash")
		os.WriteFile(stage, blob(2, "A v2 never promoted"), 0o600)
		age(stage)
		gc()
		if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the aged stage file must be swept: %v", err)
		}
		if r := get(id); r.code != 200 || string(r.body) != string(v1) {
			t.Fatalf("GET after the sweep: %d", r.code)
		}
		clean(id)
	})

	// B. Crash after Link, before Promote: cur and prev name the old inode.
	t.Run("B link made, nothing promoted", func(t *testing.T) {
		id := hexID("r11-B")
		v1 := seed[id]
		cur := blobPath(dir, vault, id)
		prev := filepath.Join(shard(id), id+"-prev-crash")
		if err := os.Link(cur, prev); err != nil {
			t.Fatal(err)
		}
		age(cur) // one inode: both names look two hours old, as if the touch had not happened
		gc()
		if _, err := os.Stat(prev); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the aged prev link must be swept: %v", err)
		}
		if r := get(id); r.code != 200 || string(r.body) != string(v1) {
			t.Fatalf("the rowed file must survive the sweep even with an old mtime: %d", r.code)
		}
		clean(id)
	})

	// C. Crash after Promote, before the row: new bytes under the old row.
	// This is the one inconsistent state a crash can leave, by design ("a
	// file ahead of its row is merely re-encrypted again"). Check that claim.
	t.Run("C promoted, row not written", func(t *testing.T) {
		id := hexID("r11-C")
		v2 := blob(2, "C v2")
		row1, _ := e.st.GetBlob(ctx, vault, id)
		cur := blobPath(dir, vault, id)
		prev := filepath.Join(shard(id), id+"-prev-crash")
		if err := os.Rename(cur, prev); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(cur, v2, 0o600)
		// What a client sees: the bytes are the new version and self-describe
		// their epoch (the plugin reads it from the header, crypto.ts:295);
		// the response header and Last-Modified still describe the old row.
		r := get(id)
		if r.code != 200 || string(r.body) != string(v2) {
			t.Fatalf("GET: %d", r.code)
		}
		if r.hdr.Get("X-Blob-Epoch") != "1" {
			t.Fatalf("X-Blob-Epoch %q: expected the stale row's 1", r.hdr.Get("X-Blob-Epoch"))
		}
		lm, _ := http.ParseTime(r.hdr.Get("Last-Modified"))
		if !lm.Equal(time.UnixMilli(row1.CreatedAt).Truncate(time.Second)) {
			t.Fatalf("Last-Modified %s must be the row's created_at, not the new file's mtime", lm)
		}
		if m := missing(id); len(m) != 0 {
			t.Fatalf("the blob is present (row and bytes): %v", m)
		}
		if !strings.Contains(below(2), id) {
			t.Fatalf("the stale row must keep the blob in the re-encryption listing: %s", below(2))
		}
		// reencrypt() downloads it, decrypts with the key its header names (a
		// key every device at epoch 2 holds), and re-uploads at the target
		// epoch with X-Blob-Replace. The decision check sees row epoch 1 < 2.
		e.do("PUT", base+"/blobs/"+id, a.token, blob(2, "C v2 re-encrypted"), map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault], "X-Blob-Replace": "1"}).expect(t, 201)
		row2, _ := e.st.GetBlob(ctx, vault, id)
		if row2.Epoch != 2 || strings.Contains(below(2), id) {
			t.Fatalf("after the repair the row must be at epoch 2 and the listing empty of it: %+v %s", row2, below(2))
		}
		age(prev)
		gc()
		clean(id)
		if r := get(id); r.code != 200 || r.hdr.Get("X-Blob-Epoch") != "2" {
			t.Fatalf("final GET: %d epoch %s", r.code, r.hdr.Get("X-Blob-Epoch"))
		}
	})

	// D. Crash after the row commit, before Delete(prev): a lingering link.
	t.Run("D committed, prev not deleted", func(t *testing.T) {
		id := hexID("r11-D")
		v2 := blob(2, "D v2")
		e.upload(vault, a, id, v2).expect(t, 201)
		prev := filepath.Join(shard(id), id+"-prev-crash")
		os.WriteFile(prev, blob(1, "D v1 kept aside"), 0o600)
		age(prev)
		gc()
		if _, err := os.Stat(prev); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the aged prev file must be swept: %v", err)
		}
		if r := get(id); r.code != 200 || string(r.body) != string(v2) || r.hdr.Get("X-Blob-Epoch") != "2" {
			t.Fatalf("GET: %d", r.code)
		}
		if strings.Contains(below(2), id) {
			t.Fatalf("a committed epoch-2 row must not be listed: %s", below(2))
		}
		clean(id)
	})

	// E. Row without a file (GC's own crash between row and file, or the
	// pre-0.1.5 unlocked delete): the index says present, the bytes are gone.
	t.Run("E orphan row", func(t *testing.T) {
		id := hexID("r11-E")
		e.upload(vault, a, id, blob(2, "E v2")).expect(t, 201)
		os.Remove(blobPath(dir, vault, id))
		r := get(id)
		if r.code != 404 || !strings.Contains(string(r.body), "blob data missing") {
			t.Fatalf("GET of an orphan row: %d %s", r.code, r.body)
		}
		if _, err := e.st.GetBlob(ctx, vault, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the orphan row must be dropped by the GET: %v", err)
		}
		if m := missing(id); len(m) != 1 {
			t.Fatalf("the missing check must now ask for the bytes: %v", m)
		}
		v2b := blob(2, "E v2 re-uploaded")
		e.upload(vault, a, id, v2b).expect(t, 201)
		if r := get(id); r.code != 200 || string(r.body) != string(v2b) {
			t.Fatalf("GET after re-upload: %d", r.code)
		}
		clean(id)
		// The other order: the missing check finds the orphan row first.
		id2 := hexID("r11-E2")
		e.upload(vault, a, id2, blob(2, "E2")).expect(t, 201)
		os.Remove(blobPath(dir, vault, id2))
		if m := missing(id2); len(m) != 1 {
			t.Fatalf("missing check must drop the orphan row and report the id: %v", m)
		}
		if _, err := e.st.GetBlob(ctx, vault, id2); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("row must be gone: %v", err)
		}
	})

	// F. File without a row (crash after Promote of a NEW blob): invisible to
	// clients; GC takes it after an hour; a re-upload before that adopts it as
	// the aside copy and lands normally.
	t.Run("F orphan file", func(t *testing.T) {
		id := hexID("r11-F")
		if _, err := bs.Put(vault, id, strings.NewReader(string(blob(2, "F promoted, no row")))); err != nil {
			t.Fatal(err)
		}
		if m := missing(id); len(m) != 1 {
			t.Fatalf("a row-less file is missing to clients: %v", m)
		}
		if r := get(id); r.code != 404 {
			t.Fatalf("GET of a row-less file: %d %s", r.code, r.body)
		}
		// Young: a re-upload adopts it.
		v2 := blob(2, "F re-uploaded")
		e.upload(vault, a, id, v2).expect(t, 201)
		if r := get(id); r.code != 200 || string(r.body) != string(v2) {
			t.Fatalf("GET: %d", r.code)
		}
		clean(id)
		// Old: GC removes it, and the missing check keeps saying so.
		id2 := hexID("r11-F2")
		if _, err := bs.Put(vault, id2, strings.NewReader(string(blob(2, "F2 orphan")))); err != nil {
			t.Fatal(err)
		}
		age(blobPath(dir, vault, id2))
		gc()
		if _, err := os.Stat(blobPath(dir, vault, id2)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the aged orphan file must be collected: %v", err)
		}
		if m := missing(id2); len(m) != 1 {
			t.Fatalf("missing: %v", m)
		}
	})

	// G. In-request failure of the row write with a previous file (pinned by
	// TestR10RestoreAfterFailedRowWriteWithSweepDuringRequest) and without
	// one (TestR10FloorRefusedAtCommitRestoresCleanlyAndMessagesAreStable):
	// re-run the former's essence here so the whole machine is in one place,
	// with the touch of the live inode in the picture.
	t.Run("G row write fails, previous restored", func(t *testing.T) {
		id := hexID("r11-G")
		v1 := seed[id]
		cur := blobPath(dir, vault, id)
		age(cur)
		before, _ := e.st.GetBlob(ctx, vault, id)
		release := holdWriteLock(t, dir)
		done := make(chan resp, 1)
		go func() {
			done <- e.do("PUT", base+"/blobs/"+id, a.token, blob(2, "G v2 will not commit"), map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]})
		}()
		var prev []string
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if prev = filesMatching(dir, vault, id+"-prev-"); len(prev) == 1 {
				break
			}
		}
		if len(prev) != 1 {
			t.Fatalf("premise: one prev file while the row write waits: %v", prev)
		}
		// The aside copy shares the old inode's mtime; the sweep ages it by the nonce in its name.
		if n, err := bs.SweepStale(vault, time.Hour); err != nil || n != 0 {
			t.Fatalf("a sweep during the request must spare it: n=%d err=%v", n, err)
		}
		res := <-done
		release()
		if res.code == 201 {
			t.Fatalf("premise: the row write was expected to fail")
		}
		after, _ := e.st.GetBlob(ctx, vault, id)
		onDisk, _ := os.ReadFile(cur)
		if string(onDisk) != string(v1) || after.Epoch != before.Epoch || after.CreatedAt != before.CreatedAt {
			t.Fatalf("restore: %d bytes on disk, row %+v (was %+v)", len(onDisk), after, before)
		}
		clean(id)
		t.Logf("row write failed as arranged (%d), previous bytes and row intact, no leftovers", res.code)
	})
}
