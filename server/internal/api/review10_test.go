package api_test

// Tenth review: the ninth round's own server fixes (5a88779..9ee3147), read
// with the assumption that a hurried fix has an edge. Each TestR10* is the
// proof for one candidate finding or a confirmation; see
// plugin/.cache/agent-review10-server/REPORT.md for the ranked list.
//
//	cd server && go test ./internal/api -run 'TestR10' -v

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"obsync/internal/blobstore"
	"obsync/internal/store"
)

// r10store is a bare blobstore in a temp dir plus the path of one blob's
// final file, for the tests that exercise Swap/Restore/SweepStale directly.
func r10store(t *testing.T, id string) (*blobstore.FS, string, string) {
	t.Helper()
	dir := t.TempDir()
	bs, err := blobstore.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	vault := hexID("r10-vault")[:32]
	return bs, vault, filepath.Join(dir, vault, id[:2], id)
}

func r10put(t *testing.T, bs *blobstore.FS, vault, name, content string) {
	t.Helper()
	if _, err := bs.Put(vault, name, strings.NewReader(content)); err != nil {
		t.Fatal(err)
	}
}

func r10read(t *testing.T, bs *blobstore.FS, vault, name string) string {
	t.Helper()
	fh, err := bs.Open(vault, name)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	defer fh.Close()
	b, _ := io.ReadAll(fh)
	return string(b)
}

// ---------------------------------------------------------------------------
// FINDING (low, racy): the ninth round's answer to "the prev file inherits
// the old blob's mtime, so GC's sweep can take it mid-request" was a Chtimes
// on the aside link right after it is made. Between os.Link returning and
// os.Chtimes taking effect the link exists under its "-prev-" name with the
// OLD inode's mtime, which for any blob written more than an hour ago is
// already past SweepStale's cutoff. A sweep whose lstat lands in that gap
// removes it; Chtimes then fails ENOENT (ignored), Promote succeeds, Swap
// returns had=true, and if the row write then fails, Restore has nothing to
// put back: the exact state the eighth and ninth rounds set out to prevent.
// The gap is two syscalls wide, so this hammers it; if it does not hit on
// this machine the finding stays unproven.
func TestR10SweepCanStillTakeThePrevFileBetweenLinkAndChtimes(t *testing.T) {
	id := hexID("r10-sweep-window")
	bs, vault, cur := r10store(t, id)
	old := time.Now().Add(-2 * time.Hour)
	r10put(t, bs, vault, id, "old bytes")
	if err := os.Chtimes(cur, old, old); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var sweeps, removed atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() {
		for !stop.Load() {
			n, _ := bs.SweepStale(vault, time.Hour)
			sweeps.Add(1)
			removed.Add(int64(n))
		}
	})
	hits, swaps := 0, 0
	var firstHit string
	for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); swaps++ {
		// Nonces as putBlob mints them (base-36 UnixNano): the sweep ages these files by that nonce.
		nonce := strconv.FormatInt(time.Now().UnixNano()+int64(swaps), 36)
		stage := fmt.Sprintf("%s-stage-%s", id, nonce)
		prev := fmt.Sprintf("%s-prev-%s", id, nonce)
		r10put(t, bs, vault, stage, fmt.Sprintf("new bytes %d", swaps))
		had, err := bs.Swap(vault, stage, id, prev)
		if err != nil || !had {
			t.Fatalf("premise: Swap of an existing blob: had=%v err=%v", had, err)
		}
		prevPath := filepath.Join(filepath.Dir(cur), prev)
		if _, serr := os.Stat(prevPath); errors.Is(serr, os.ErrNotExist) {
			hits++
			// This is what putBlob would do on a failed row write.
			rerr := bs.Restore(vault, prev, id, had)
			if hits == 1 {
				firstHit = fmt.Sprintf("swap #%d: Swap returned had=true, the -prev- file is already gone, Restore says %q, the file under the blob's name now holds %q", swaps, rerr, r10read(t, bs, vault, id))
			}
		} else if rerr := bs.Restore(vault, prev, id, had); rerr != nil {
			t.Fatalf("Restore: %v", rerr)
		}
		// Next round: the blob under its name must look two hours old again.
		if err := os.Chtimes(cur, old, old); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("%d swaps of a 2 h-old blob against %d concurrent SweepStale(1h) passes: the sweep removed %d file(s), %d swap(s) lost their -prev- file", swaps, sweeps.Load(), removed.Load(), hits)
	if hits > 0 {
		t.Fatalf("FINDING: %d of %d swaps lost the aside copy to a concurrent sweep (%s). The Chtimes that the ninth round added lands after os.Link, so for two syscalls the -prev- link carries the old blob's mtime and is sweep-eligible; a row write that then fails leaves the new bytes under the old row with nothing to restore. Fix: touch the CURRENT file before linking it (os.Chtimes(cur, now, now); os.Link(cur, prev)), so the link is born fresh; or make SweepStale read a file's age from the base-36 UnixNano nonce in its name.", hits, swaps, firstHit)
	}
	t.Logf("UNPROVEN here: the link-to-Chtimes gap was not hit in this run")
}

// ---------------------------------------------------------------------------
// CONFIRMATION: with the hard link, a reader that opened the blob before the
// swap reads the previous version to its end (one inode, never mixed), a
// reader that opens after it reads the new version, Restore brings the old
// bytes back atomically under the name, and a successful Delete(prev) leaves
// a single name. The mtime of the live inode is touched by Swap (the link
// shares it) but nothing that serves or collects blobs reads a rowed file's
// mtime: GET's Last-Modified comes from the row's created_at.
func TestR10HardLinkSwapIsConsistentForReadersAndMtimeIsNotServed(t *testing.T) {
	id := hexID("r10-reader-across-swap")
	bs, vault, cur := r10store(t, id)
	r10put(t, bs, vault, id, "version 1")
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(cur, old, old)
	early, err := bs.Open(vault, id)
	if err != nil {
		t.Fatal(err)
	}
	defer early.Close()

	nonce := strconv.FormatInt(time.Now().UnixNano(), 36) // as putBlob mints it; the sweep ages the aside copy by it
	r10put(t, bs, vault, id+"-stage-"+nonce, "version 2 is longer")
	had, err := bs.Swap(vault, id+"-stage-"+nonce, id, id+"-prev-"+nonce)
	if err != nil || !had {
		t.Fatalf("Swap: had=%v err=%v", had, err)
	}
	prevPath := filepath.Join(filepath.Dir(cur), id+"-prev-"+nonce)
	if _, err := os.Stat(prevPath); err != nil {
		t.Fatal(err)
	}
	// The aside copy is aged by the nonce in its name, not by the inode's
	// mtime it shares with the old blob: a sweep now must spare it.
	if n, err := bs.SweepStale(vault, time.Hour); err != nil || n != 0 {
		t.Fatalf("a sweep right after the swap must spare the aside copy: removed %d, err %v", n, err)
	}
	if _, err := os.Stat(prevPath); err != nil {
		t.Fatalf("the -prev- file was swept although its nonce is fresh: %v", err)
	}
	if got, _ := io.ReadAll(early); string(got) != "version 1" {
		t.Fatalf("a reader opened before the swap must read the old version whole, got %q", got)
	}
	if got := r10read(t, bs, vault, id); got != "version 2 is longer" {
		t.Fatalf("a reader opened after the swap must read the new version, got %q", got)
	}
	if err := bs.Restore(vault, id+"-prev-"+nonce, id, had); err != nil {
		t.Fatal(err)
	}
	if got := r10read(t, bs, vault, id); got != "version 1" {
		t.Fatalf("after Restore the old bytes must be back, got %q", got)
	}
	if _, err := os.Stat(prevPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Restore must consume the -prev- name, stat: %v", err)
	}
	// The success path: swap, then Delete(prev).
	r10put(t, bs, vault, id+"-stage-b", "version 3")
	if had, err := bs.Swap(vault, id+"-stage-b", id, id+"-prev-b"); err != nil || !had {
		t.Fatalf("Swap: had=%v err=%v", had, err)
	}
	if err := bs.Delete(vault, id+"-prev-b"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(cur))
	if len(entries) != 1 || entries[0].Name() != id {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("after a successful swap only the blob's own name may remain, got %v", names)
	}
	if got := r10read(t, bs, vault, id); got != "version 3" {
		t.Fatalf("got %q", got)
	}

	// Over HTTP: Last-Modified is the row's created_at, not the file's mtime.
	e, _, dir := r7env(t)
	v, a, b := e.setup()
	hid := hexID("r10-last-modified")
	e.upload(v, a, hid, blob(1, "served")).expect(t, 201)
	os.Chtimes(blobPath(dir, v, hid), old, old)
	row, err := e.st.GetBlob(context.Background(), v, hid)
	if err != nil {
		t.Fatal(err)
	}
	res := e.do("GET", "/v1/vaults/"+v+"/blobs/"+hid, b.token, nil, nil).expect(t, 200)
	lm, err := http.ParseTime(res.hdr.Get("Last-Modified"))
	if err != nil {
		t.Fatalf("Last-Modified %q: %v", res.hdr.Get("Last-Modified"), err)
	}
	if want := time.UnixMilli(row.CreatedAt).Truncate(time.Second); !lm.Equal(want) {
		t.Fatalf("Last-Modified %s is not the row's created_at %s (file mtime is %s)", lm.UTC(), want.UTC(), old.UTC().Truncate(time.Second))
	}
	t.Logf("Last-Modified %s = created_at; the file's 2 h-old mtime is not served", lm.UTC().Format(time.RFC3339))
}

// ---------------------------------------------------------------------------
// NOTE (no fix needed): Swap's own undo when Promote fails after the link
// was made is `rename(prev, cur)`. With the link both names are the same
// inode, and POSIX makes that rename a successful no-op, so the -prev- link
// stays until SweepStale takes it an hour later. The blob itself is intact
// under its name throughout (an improvement on the rename-pair, whose undo
// was a real rename that could itself fail). putBlob then deletes the stage
// and answers 500, which is right.
func TestR10PromoteFailureLeavesThePrevLinkNextToAnIntactBlob(t *testing.T) {
	id := hexID("r10-promote-fails")
	bs, vault, cur := r10store(t, id)
	r10put(t, bs, vault, id, "intact")
	// No stage file was written: Promote's rename fails with ENOENT.
	had, err := bs.Swap(vault, id+"-stage-missing", id, id+"-prev-x")
	if err == nil || !had {
		t.Fatalf("premise: Swap with a missing stage: had=%v err=%v", had, err)
	}
	if got := r10read(t, bs, vault, id); got != "intact" {
		t.Fatalf("the blob must be intact under its name, got %q", got)
	}
	prevPath := filepath.Join(filepath.Dir(cur), id+"-prev-x")
	pst, perr := os.Stat(prevPath)
	cst, _ := os.Stat(cur)
	switch {
	case errors.Is(perr, os.ErrNotExist):
		t.Logf("this platform's rename(prev, cur) over the same inode removed the -prev- name")
	case perr == nil && os.SameFile(pst, cst):
		t.Logf("NOTE: rename(prev, cur) over the same inode was a no-op, the -prev- link lingers next to the intact blob until the sweep")
		if n, err := bs.SweepStale(vault, 0); err != nil || n != 1 {
			t.Fatalf("SweepStale should take exactly the lingering link: n=%d err=%v", n, err)
		}
		if got := r10read(t, bs, vault, id); got != "intact" {
			t.Fatalf("sweeping the link must not touch the blob, got %q", got)
		}
	default:
		t.Fatalf("unexpected state after a failed Promote: prev stat %v, same file %v", perr, perr == nil && os.SameFile(pst, cst))
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: the in-transaction floor. An upload of a NEW blob at the
// retired epoch that was legal when its header arrived is refused at commit
// with 400 once re-encryption finished meanwhile; the refusal goes through
// Restore(had=false): no file, no row, no stage or prev file, min_epoch
// untouched. Afterwards a same-epoch X-Blob-Replace repair still lands, the
// pre-body check on a vault with no blobs and no ops agrees with the
// in-transaction one (min_epoch == epoch), and the ops floor's message is the
// fixed string the plugin's settle() matches ("min_epoch").
func TestR10FloorRefusedAtCommitRestoresCleanlyAndMessagesAreStable(t *testing.T) {
	e, _, dir := r7env(t)
	vault, a, b := e.setup()
	ctx := context.Background()
	base := "/v1/vaults/" + vault
	x := hexID("r10-floor-x")
	e.upload(vault, a, x, blob(1, "x at epoch 1")).expect(t, 201)
	e.rotateKeep(vault, 2, a, a, b)

	y := hexID("r10-floor-y")
	body := blob(1, "y under the retired epoch-1 key")
	res := e.inflightAt("PUT", base+"/blobs/"+y, b.token, map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]}, body, r9HeaderLen+4, func() {
		e.upload(vault, a, x, blob(2, "x re-encrypted at epoch 2")).expect(t, 201)
		if v := e.vault(vault, a); v.MinEpoch != 2 {
			t.Fatalf("premise: min_epoch should be 2, got %+v", v)
		}
	})
	t.Logf("epoch-1 upload of a new blob finished after the floor moved: %d %s", res.code, res.body)
	if res.code != 400 || !strings.Contains(res.body, "blob epoch 1 outside [2,2]") {
		t.Fatalf("expected the in-transaction 400, got %d %s", res.code, res.body)
	}
	if _, err := os.Stat(blobPath(dir, vault, y)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused blob's file must be gone (Restore had=false): %v", err)
	}
	if _, err := e.st.GetBlob(ctx, vault, y); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the refused blob must have no row: %v", err)
	}
	if lo := leftovers(t, dir, vault); len(lo) > 0 {
		t.Fatalf("stage/temp files left: %v", lo)
	}
	if p := filesMatching(dir, vault, "-prev-"); len(p) > 0 {
		t.Fatalf("prev files left: %v", p)
	}
	if v := e.vault(vault, a); v.MinEpoch != 2 || v.Epoch != 2 {
		t.Fatalf("vault after the refusal: %+v", v)
	}
	// A repair at the same epoch is unaffected by the floor.
	e.do("PUT", base+"/blobs/"+x, a.token, blob(2, "x repaired at epoch 2"), map[string]string{"X-Obsync-Vault-Auth": authTok[vault], "X-Blob-Replace": "1"}).expect(t, 201)
	// The ops floor's message is a fixed string containing "min_epoch".
	var out opsOut
	e.do("POST", base+"/ops", a.token, []opIn{put("note.md", str(x), 0)}, authHdr(vault)).expect(t, 200).json(t, &out)
	if len(out.Results) != 1 || out.Results[0].Error != "meta_epoch 1 below the vault's min_epoch 2" {
		t.Fatalf("ops floor message: %+v", out.Results)
	}
	if !regexp.MustCompile(`blob not uploaded|min_epoch`).MatchString(out.Results[0].Error) {
		t.Fatalf("the plugin's settle() rule would not match %q", out.Results[0].Error)
	}

	// A vault with no blobs and no ops: min_epoch == epoch on both checks.
	e2 := newEnv(t)
	v2, a2, b2 := e2.setup()
	e2.rotateKeep(v2, 2, a2, a2, b2)
	if v := e2.vault(v2, a2); v.MinEpoch != 2 {
		t.Fatalf("empty vault after rotation: %+v", v)
	}
	r := e2.upload(v2, a2, hexID("r10-empty-vault"), blob(1, "stale key on an empty vault"))
	if r.code != 400 || !strings.Contains(string(r.body), "blob epoch 1 outside [2,2]") {
		t.Fatalf("empty vault: %d %s", r.code, r.body)
	}
	e2.upload(v2, a2, hexID("r10-empty-vault"), blob(2, "current key")).expect(t, 201)
}

// ---------------------------------------------------------------------------
// CONFIRMATION: Restore with had=true after a failed row write (the
// database write lock held past busy_timeout) puts the previous bytes back
// under the name with no moment of absence, and the -prev- file, timestamped
// by Swap, survives a SweepStale(1h) that runs during the request.
func TestR10RestoreAfterFailedRowWriteWithSweepDuringRequest(t *testing.T) {
	e, bs, dir := r7env(t)
	vault, a, _ := e.setup()
	ctx := context.Background()
	base := "/v1/vaults/" + vault
	id := hexID("r10-restore-had")
	honest := blob(1, "honest ciphertext")
	e.upload(vault, a, id, honest).expect(t, 201)
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(blobPath(dir, vault, id), old, old)
	before, _ := e.st.GetBlob(ctx, vault, id)

	release := holdWriteLock(t, dir)
	done := make(chan r7res, 1)
	go func() {
		res := e.do("PUT", base+"/blobs/"+id, a.token, blob(1, "replacement that will not commit"), map[string]string{"X-Obsync-Vault-Auth": authTok[vault], "X-Blob-Replace": "1"})
		done <- r7res{res.code, string(res.body)}
	}()
	var prev []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if prev = filesMatching(dir, vault, "-prev-"); len(prev) == 1 {
			break
		}
	}
	if len(prev) != 1 {
		t.Fatalf("premise: one -prev- file while the row write waits, got %v", prev)
	}
	// Readers during the window always find a file, and it is one version.
	var absent atomic.Int64
	var stopReaders atomic.Bool
	var wg sync.WaitGroup
	wg.Go(func() {
		for !stopReaders.Load() {
			if _, err := os.Stat(blobPath(dir, vault, id)); errors.Is(err, os.ErrNotExist) {
				absent.Add(1)
			}
		}
	})
	n, err := bs.SweepStale(vault, time.Hour)
	if err != nil || n != 0 {
		t.Fatalf("a sweep during the request must spare the fresh -prev- file: n=%d err=%v", n, err)
	}
	res := <-done
	release()
	stopReaders.Store(true)
	wg.Wait()
	t.Logf("row write failed as arranged: %d %s", res.code, res.body)
	if res.code == 201 {
		t.Fatalf("premise: the row write was expected to fail")
	}
	onDisk, _ := os.ReadFile(blobPath(dir, vault, id))
	after, _ := e.st.GetBlob(ctx, vault, id)
	if string(onDisk) != string(honest) || after.CtSize != before.CtSize || after.CreatedAt != before.CreatedAt {
		t.Fatalf("restore failed: on disk %d bytes, row ct_size %d (was %d)", len(onDisk), after.CtSize, before.CtSize)
	}
	if lo := leftovers(t, dir, vault); len(lo) > 0 {
		t.Fatalf("leftovers: %v", lo)
	}
	if p := filesMatching(dir, vault, "-prev-"); len(p) > 0 {
		t.Fatalf("prev files left after Restore: %v", p)
	}
	if absent.Load() > 0 {
		t.Fatalf("the blob's name was empty %d time(s) during swap/restore", absent.Load())
	}
	t.Logf("previous bytes restored, name never empty, sweep spared the timestamped -prev- file")
}
