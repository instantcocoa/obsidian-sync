package api_test

// Ninth review: the eighth round's own server fixes (93275e9..5a88779), read
// with the assumption that a hurried fix has an edge. Each TestR9* is the
// proof for one candidate finding or a confirmation; see
// plugin/.cache/agent-review9-server/REPORT.md for the ranked list.
//
//	cd server && go test ./internal/api -run 'TestR9' -v

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"obsync/internal/store"
)

const r9HeaderLen = 1 + 4 + 16 + 12 // blobHeaderLen in server.go

// holdWriteLock opens a second connection to the server's database and takes
// the write lock (BEGIN IMMEDIATE) until the returned func is called. The
// server's own write transactions wait out their 10 s busy_timeout and fail.
func holdWriteLock(t *testing.T, dir string) func() {
	t.Helper()
	ctx := context.Background()
	lock, err := sql.Open("sqlite", "file:"+dir+"/db.sqlite?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := lock.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			conn.ExecContext(ctx, "ROLLBACK")
			conn.Close()
			lock.Close()
		})
	}
	t.Cleanup(release)
	return release
}

// filesMatching lists files under a vault's blob directory whose name
// contains `needle`.
func filesMatching(dir, vault, needle string) []string {
	var out []string
	filepath.WalkDir(filepath.Join(dir, "blobs", vault), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(d.Name(), needle) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// inflightAt is inflight with a chosen split: body[:split] is sent, the
// handler is given time to consume it, `during` runs, then the rest follows.
func (e *env) inflightAt(method, path, token string, hdr map[string]string, body []byte, split int, during func()) r7res {
	pr, pw := io.Pipe()
	done := make(chan r7res, 1)
	go func() {
		req, _ := http.NewRequest(method, e.ts.URL+path, pr)
		req.Header.Set("Authorization", "Bearer "+token)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- r7res{0, err.Error()}
			return
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		done <- r7res{res.StatusCode, string(b)}
	}()
	pw.Write(body[:split])
	time.Sleep(300 * time.Millisecond)
	during()
	pw.Write(body[split:])
	pw.Close()
	return <-done
}

func (e *env) vault(vault string, d device) store.Vault {
	var v store.Vault
	e.do("GET", "/v1/vaults/"+vault, d.token, nil, nil).expect(e.t, 200).json(e.t, &v)
	return v
}

// ---------------------------------------------------------------------------
// FINDING (low): the eighth round keeps the previous blob file aside as
// "<id>-prev-<nonce>" until the row commits, and taught SweepStale to remove
// "-prev-" files older than an hour. The aside copy is made by rename, which
// keeps the OLD file's mtime, so the hour of grace that protects a live
// request's stage and temp files does not exist for the prev file of any
// blob uploaded more than an hour ago: a sweep that runs while the row write
// is still pending (GC runs in-process every --gc-interval and from the
// `obsync gc` CLI, and the sweep takes no blob lock) deletes it. If the row
// write then fails, Restore has nothing to put back, logs an error, and the
// state is exactly the one the eighth round set out to prevent: new bytes
// under the old row.
func TestR9PrevFileKeepsTheOldMtimeSoASweepMidRequestDefeatsRestore(t *testing.T) {
	e, bs, dir := r7env(t)
	vault, a, b := e.setup()
	ctx := context.Background()
	base := "/v1/vaults/" + vault
	id := hexID("r9-replace-target")
	honest := blob(1, "honest ciphertext")
	e.upload(vault, a, id, honest).expect(t, 201)
	// The honest blob was uploaded two hours ago.
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(blobPath(dir, vault, id), old, old); err != nil {
		t.Fatal(err)
	}
	before, err := e.st.GetBlob(ctx, vault, id)
	if err != nil {
		t.Fatal(err)
	}

	release := holdWriteLock(t, dir)
	garbage := blob(1, "garbage: a different, longer ciphertext under the same id")
	type out struct {
		code int
		body string
		took time.Duration
	}
	done := make(chan out, 1)
	start := time.Now()
	go func() {
		res := e.do("PUT", base+"/blobs/"+id, a.token, garbage, map[string]string{"X-Obsync-Vault-Auth": authTok[vault], "X-Blob-Replace": "1"})
		done <- out{res.code, string(res.body), time.Since(start)}
	}()
	// Wait until the request has swapped the files and is parked in
	// UpsertBlob behind the write lock.
	var prev []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if prev = filesMatching(dir, vault, "-prev-"); len(prev) == 1 {
			break
		}
	}
	if len(prev) != 1 {
		t.Fatalf("premise: expected one -prev- file while the row write waits, got %v", prev)
	}
	st, err := os.Stat(prev[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("prev file %s has mtime %s, the old blob's (uploaded %s ago)", filepath.Base(prev[0]), st.ModTime().Format(time.RFC3339), time.Since(st.ModTime()).Round(time.Minute))
	// GC's sweep, with GC's argument, while the request is in flight.
	n, err := bs.SweepStale(vault, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SweepStale(1h) during the request removed %d file(s)", n)
	res := <-done
	release()
	t.Logf("replace while the row write cannot commit: %d %s after %s", res.code, res.body, res.took.Round(time.Second))
	if res.code == 201 {
		t.Fatalf("premise: the row write was expected to fail, got 201")
	}

	onDisk, err := os.ReadFile(blobPath(dir, vault, id))
	if err != nil {
		t.Fatal(err)
	}
	after, err := e.st.GetBlob(ctx, vault, id)
	if err != nil {
		t.Fatal(err)
	}
	got := e.do("GET", base+"/blobs/"+id, b.token, nil, nil).expect(t, 200)
	if lo := leftovers(t, dir, vault); len(lo) > 0 {
		t.Errorf("stage files left behind: %v", lo)
	}
	if n == 1 && bytes.Equal(onDisk, garbage) && after.CtSize == before.CtSize && after.CreatedAt == before.CreatedAt {
		t.Fatalf("FINDING: the prev file inherited the blob's %s-old mtime and SweepStale(1h) removed it while the request was between Swap and UpsertBlob; the row write then failed (%d), Restore had nothing to restore, and the new bytes (%d) sit under the old row (ct_size %d, created_at unchanged): GET serves %d bytes under X-Blob-Epoch %s. The eighth round's fix holds only when no GC sweep overlaps the request.",
			time.Since(old).Round(time.Hour), res.code, len(onDisk), after.CtSize, len(got.body), got.hdr.Get("X-Blob-Epoch"))
	}
	if bytes.Equal(onDisk, honest) {
		t.Logf("restored: the previous bytes are back under the row (the prev file survived the sweep)")
	}
}

// ---------------------------------------------------------------------------
// FINDING (low): the blob epoch floor is checked against a vault snapshot
// taken before the body is read, and UpsertBlob does not re-check it in the
// transaction. A member who kept a retired epoch key (the only party the
// floor is aimed at) starts an upload at epoch == min_epoch while that is
// still legal, keeps the body open (progress keeps idleReader alive), and
// finishes after re-encryption has raised min_epoch and GC has pruned the
// keybox rows of the retired epoch. The row lands at the retired epoch:
// min_epoch falls back, the keybox no longer carries a key that reads the
// blob, and the device that re-encrypts next finds a blob it has no key for
// (a placeholder on the plugin side since the eighth round). Honest devices
// never take this path: rotation changes the authority token, so a device
// behind by an epoch is answered 401 before any epoch check.
func TestR9BlobEpochFloorIsReadBeforeTheBodyAndNeverAtCommit(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	ctx := context.Background()
	base := "/v1/vaults/" + vault
	x := hexID("r9-floor-x")
	e.upload(vault, a, x, blob(1, "x at epoch 1")).expect(t, 201)
	e.rotateKeep(vault, 2, a, a, b)
	if v := e.vault(vault, a); v.Epoch != 2 || v.MinEpoch != 1 {
		t.Fatalf("after rotate: %+v", v)
	}

	y := hexID("r9-floor-y")
	body := blob(1, "ciphertext under the retired epoch-1 key")
	// The header (and so the floor check) is consumed before `during`.
	res := e.inflightAt("PUT", base+"/blobs/"+y, b.token, map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]}, body, r9HeaderLen+4, func() {
		// Re-encryption finishes meanwhile: X is re-uploaded at epoch 2 ...
		e.upload(vault, a, x, blob(2, "x re-encrypted at epoch 2")).expect(t, 201)
		v := e.vault(vault, a)
		if v.MinEpoch != 2 {
			t.Fatalf("premise: min_epoch should be 2 once nothing below it remains, got %+v", v)
		}
		// ... and GC prunes the keybox rows below min_epoch, as designed.
		if _, err := e.srv.GC(ctx, 90*24*time.Hour); err != nil {
			t.Fatal(err)
		}
		var kb struct{ Keybox []store.KeyboxRow }
		e.do("GET", base+"/keybox", a.token, nil, nil).expect(t, 200).json(t, &kb)
		for _, r := range kb.Keybox {
			if r.Epoch < 2 {
				t.Fatalf("premise: keybox still carries epoch %d after GC", r.Epoch)
			}
		}
		t.Logf("during the upload: min_epoch rose to 2 and GC pruned every epoch-1 keybox row")
	})
	v := e.vault(vault, a)
	t.Logf("epoch-1 upload finished after the floor moved: %d %s; vault epoch %d, min_epoch now %d", res.code, res.body, v.Epoch, v.MinEpoch)
	if res.code == 201 || v.MinEpoch < 2 {
		ids, _ := e.st.BlobsBelowEpoch(ctx, vault, 2, 10)
		t.Fatalf("FINDING: an epoch-1 blob landed (%d) after min_epoch had risen to 2 and the epoch-1 keybox rows were pruned; min_epoch is back to %d and %d blob(s) below epoch 2 now wait for a re-encryption nobody holds the key for. The floor is checked against the pre-body vault snapshot only; UpsertBlob does not re-check it.", res.code, v.MinEpoch, len(ids))
	}
}

// ---------------------------------------------------------------------------
// FINDING (low, racy): Swap renames the current file aside and then renames
// the stage file into place. Between the two renames the blob has no file
// under its name. 0.1.6's Promote was one rename over the existing file, so
// no such moment existed. A GET that lands in the window answers 404 "blob
// data missing" (dropOrphan then waits for the blob lock, finds the new file
// and keeps the row, so the row is safe); the plugin treats a 404 as a
// non-transient failure of that op and skips it, so the reader's copy of the
// file stays stale until the author changes it again. This test hammers the
// window; if it does not hit on this machine the finding stays unproven.
func TestR9SwapLeavesTheBlobAbsentBetweenTwoRenames(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	id := hexID("r9-swap-window")
	e.upload(vault, a, id, blob(1, "version 0")).expect(t, 201)

	var stop atomic.Bool
	var total, notOK atomic.Int64
	var sample atomic.Value
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			for !stop.Load() {
				req, _ := http.NewRequest("GET", e.ts.URL+base+"/blobs/"+id, nil)
				req.Header.Set("Authorization", "Bearer "+b.token)
				res, err := http.DefaultClient.Do(req)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(res.Body)
				res.Body.Close()
				total.Add(1)
				if res.StatusCode != 200 {
					notOK.Add(1)
					sample.Store(fmt.Sprintf("%d %s", res.StatusCode, body))
				}
			}
		})
	}
	writes := 0
	for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); writes++ {
		e.do("PUT", base+"/blobs/"+id, a.token, blob(1, fmt.Sprintf("version %d", writes+1)), map[string]string{"X-Obsync-Vault-Auth": authTok[vault], "X-Blob-Replace": "1"}).expect(t, 201)
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("%d replacing uploads against %d concurrent GETs: %d non-200 answers", writes, total.Load(), notOK.Load())
	if n := notOK.Load(); n > 0 {
		t.Fatalf("FINDING: %d of %d GETs during %d same-epoch replacements found no file under the blob's name (sample: %s). Swap's rename-aside opens a window 0.1.6's rename-over did not have; a plugin reading the blob at that moment skips the op and keeps a stale file.", n, total.Load(), writes, sample.Load())
	}
	t.Logf("UNPROVEN here: the two-rename window was not hit in this run")
}

// ---------------------------------------------------------------------------
// CONFIRMATION: the pre-check 401 split. A device revoked while its upload
// is in flight reads "device revoked" (the plugin pins the removed message);
// an honest device whose upload crosses a rotation that keeps it reads
// "vault authority changed" (the plugin re-syncs). Neither promotes a file
// or leaves a stage file.
func TestR9PreCheck401OrderAndBodies(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		e, _, dir := r7env(t)
		vault, a, b := e.setup()
		base := "/v1/vaults/" + vault
		id := hexID("r9-revoked-upload")
		res := e.inflight("PUT", base+"/blobs/"+id, b.token, map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]}, blob(1, "from the device being removed"), func() {
			e.revokeB(vault, a, b)
		})
		t.Logf("revoked mid-upload: %d %s", res.code, res.body)
		if res.code != 401 || !strings.Contains(res.body, "device revoked") || strings.Contains(res.body, "vault authority") {
			t.Fatalf("a revoked device must read 'device revoked' and nothing about the authority: %d %s", res.code, res.body)
		}
		if _, err := os.Stat(blobPath(dir, vault, id)); err == nil {
			t.Fatalf("file promoted for a revoked writer")
		}
		if lo := leftovers(t, dir, vault); len(lo) > 0 {
			t.Fatalf("stage files left: %v", lo)
		}
	})
	t.Run("authority changed", func(t *testing.T) {
		e, _, dir := r7env(t)
		vault, a, b := e.setup()
		base := "/v1/vaults/" + vault
		id := hexID("r9-honest-upload")
		res := e.inflight("PUT", base+"/blobs/"+id, a.token, map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]}, blob(1, "honest, crossing a rotation"), func() {
			e.rotateKeep(vault, 2, b, a, b)
		})
		t.Logf("kept device crossing a rotation: %d %s", res.code, res.body)
		if res.code != 401 || !strings.Contains(res.body, "vault authority") || strings.Contains(res.body, "device revoked") {
			t.Fatalf("a kept device must read 'vault authority' and nothing about revocation: %d %s", res.code, res.body)
		}
		if _, err := os.Stat(blobPath(dir, vault, id)); err == nil {
			t.Fatalf("file promoted under a stale authority")
		}
		if lo := leftovers(t, dir, vault); len(lo) > 0 {
			t.Fatalf("stage files left: %v", lo)
		}
		e.upload(vault, a, id, blob(2, "retry under the new token")).expect(t, 201)
	})
}

// ---------------------------------------------------------------------------
// CONFIRMATION: DeletePath refuses anything outside the blob store root, a
// symlink planted in a shard directory is removed as a link (its target is
// untouched), Orphans never lists -prev-/-stage-/.tmp- names, and SweepStale
// takes an old -prev- file while sparing a young one.
func TestR9DeletePathContainmentSymlinksAndSweepNames(t *testing.T) {
	e, bs, dir := r7env(t)
	vault, a, _ := e.setup()
	ctx := context.Background()
	id := hexID("r9-real")
	e.upload(vault, a, id, blob(1, "real")).expect(t, 201)

	db := dir + "/db.sqlite"
	for _, p := range []string{db, filepath.Join(dir, "blobs", vault, "..", "..", "db.sqlite"), filepath.Join(dir, "blobs", ".."), "/etc/hosts"} {
		if err := bs.DeletePath(p); err == nil {
			t.Fatalf("DeletePath(%s) accepted a path outside the store", p)
		}
	}
	if _, err := os.Stat(db); err != nil {
		t.Fatalf("database gone: %v", err)
	}

	// A symlink named like a blob (operator mistake) pointing at the database.
	linkID := hexID("r9-link")
	link := filepath.Join(dir, "blobs", vault, linkID[:2], linkID)
	os.MkdirAll(filepath.Dir(link), 0o750)
	if err := os.Symlink(db, link); err != nil {
		t.Fatal(err)
	}
	// Also the names the request path leaves behind.
	for _, name := range []string{id + "-prev-abc", id + "-stage-abc", ".tmp-" + id + "-abc"} {
		p := filepath.Join(dir, "blobs", vault, id[:2], name)
		os.WriteFile(p, []byte("x"), 0o600)
	}
	time.Sleep(10 * time.Millisecond)
	orphans, err := bs.Orphans(vault, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, o := range orphans {
		names[o.ID] = o.Path
	}
	if _, ok := names[linkID]; !ok {
		t.Fatalf("the symlink named as a blob was not listed: %v", names)
	}
	if _, ok := names[id]; !ok {
		t.Fatalf("the real blob was not listed (age 0): %v", names)
	}
	for n := range names {
		if strings.Contains(n, "-prev-") || strings.Contains(n, "-stage-") || strings.HasPrefix(n, ".tmp-") {
			t.Fatalf("Orphans listed a non-final name %s", n)
		}
	}
	// GC's loop over the listing: the rowed blob stays, the rowless link goes.
	for _, o := range orphans {
		if _, err := e.st.GetBlob(ctx, vault, o.ID); err == nil {
			continue
		}
		if err := bs.DeletePath(o.Path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Lstat(link); err == nil {
		t.Fatalf("symlink survived")
	}
	if _, err := os.Stat(db); err != nil {
		t.Fatalf("symlink target removed: %v", err)
	}
	if !bs.Exists(vault, id) {
		t.Fatalf("real blob removed")
	}

	// SweepStale: the young -prev- is spared, an old one is taken.
	oldPrev := filepath.Join(dir, "blobs", vault, id[:2], id+"-prev-old")
	os.WriteFile(oldPrev, []byte("x"), 0o600)
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(oldPrev, old, old)
	n, err := bs.SweepStale(vault, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("SweepStale removed %d, want 1 (the old -prev-)", n)
	}
	if _, err := os.Stat(oldPrev); err == nil {
		t.Fatalf("old -prev- survived")
	}
	if got := filesMatching(dir, vault, "-prev-"); len(got) != 1 {
		t.Fatalf("young -prev- should survive: %v", got)
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: the meta_epoch floor in AppendOps, and that neither PatchMeta
// nor Restore can take a vault below min_epoch. A device behind by one epoch
// never reaches the floor: its authority token is the old one and the batch
// is refused 401 "vault authority" first. While epoch-1 content remains
// (min_epoch 1), meta_epoch 1 is still accepted under epoch 2; once
// re-encryption has moved everything to 2 it is refused per op with the
// min_epoch body. Restore copies a patched op's meta_epoch (2), so min_epoch
// stays 2; PatchMeta refuses anything at or below the op's current epoch.
func TestR9OpsFloorRestoreAndPatchMetaRespectMinEpoch(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault

	bid1 := hexID("r9-doc-v1")
	e.upload(vault, a, bid1, blob(1, "doc v1")).expect(t, 201)
	r1 := e.ops(vault, a, put("doc.md", new(bid1), 0))
	seq1, t1 := r1.Results[0].Seq, r1.Results[0].CreatedAt
	time.Sleep(5 * time.Millisecond)
	bid2 := hexID("r9-doc-v2")
	e.upload(vault, a, bid2, blob(1, "doc v2")).expect(t, 201)
	r2 := e.ops(vault, a, put("doc.md", new(bid2), seq1))
	seq2 := r2.Results[0].Seq
	if seq2 <= seq1 {
		t.Fatalf("second op not accepted: %+v", r2.Results[0])
	}

	oldAuth := authTok[vault]
	e.rotateKeep(vault, 2, a, a, b)

	// A device behind by one epoch (old authority token, meta_epoch 1): 401
	// before any per-op check, as before this round.
	bid3 := hexID("r9-doc-v3")
	e.upload(vault, b, bid3, blob(2, "v3 at epoch 2")).expect(t, 201)
	behind := put("doc.md", new(bid3), seq2)
	res := e.do("POST", base+"/ops", b.token, []opIn{behind}, map[string]string{"Content-Type": "application/json", "X-Obsync-Vault-Auth": oldAuth})
	if res.code != 401 || !strings.Contains(string(res.body), "vault authority") {
		t.Fatalf("stale authority should be 401 'vault authority': %d %s", res.code, res.body)
	}
	// Same op with the current authority but meta_epoch 1 while min_epoch is
	// still 1: accepted (not a regression for a device whose keyring lags).
	if v := e.vault(vault, a); v.MinEpoch != 1 {
		t.Fatalf("min_epoch should still be 1: %+v", v)
	}
	r3 := e.ops(vault, b, behind)
	if r3.Results[0].Seq == 0 || r3.Results[0].Error != "" {
		t.Fatalf("meta_epoch 1 under epoch 2 with min_epoch 1 should land: %+v", r3.Results[0])
	}
	seq3 := r3.Results[0].Seq

	// Re-encryption: blobs to epoch 2, every op's metadata to epoch 2.
	e.upload(vault, a, bid1, blob(2, "doc v1 re")).expect(t, 201)
	e.upload(vault, a, bid2, blob(2, "doc v2 re")).expect(t, 201)
	for _, seq := range []int64{seq1, seq2, seq3} {
		e.do("PATCH", fmt.Sprintf("%s/ops/%d/meta", base, seq), a.token, map[string]any{"meta_enc": randBytes(40), "meta_epoch": 2}, authHdr(vault)).expect(t, 204)
	}
	if v := e.vault(vault, a); v.MinEpoch != 2 {
		t.Fatalf("min_epoch should be 2 after re-encryption: %+v", v)
	}

	// The floor: meta_epoch 1 is now refused per op, meta_epoch 2 lands.
	bid4 := hexID("r9-doc-v4")
	e.upload(vault, b, bid4, blob(2, "v4")).expect(t, 201)
	low := put("doc.md", new(bid4), seq3)
	r4 := e.ops(vault, b, low)
	if r4.Results[0].Seq != 0 || !strings.Contains(r4.Results[0].Error, "below the vault's min_epoch 2") {
		t.Fatalf("meta_epoch 1 below min_epoch 2 should be refused per op: %+v", r4.Results[0])
	}
	t.Logf("per-op refusal body: %q", r4.Results[0].Error)
	low.MetaEpoch = 2
	low.OpID = "op-" + hexID("r9-low-retry")[:16]
	r5 := e.ops(vault, b, low)
	if r5.Results[0].Seq == 0 || r5.Results[0].Error != "" {
		t.Fatalf("meta_epoch 2 should land: %+v", r5.Results[0])
	}
	// An epoch-1 blob is refused at the floor too (no race here).
	e.upload(vault, b, hexID("r9-late-blob"), blob(1, "late")).expect(t, 400)

	// PatchMeta cannot lower or hold an op's epoch.
	e.do("PATCH", fmt.Sprintf("%s/ops/%d/meta", base, seq1), a.token, map[string]any{"meta_enc": randBytes(40), "meta_epoch": 1}, authHdr(vault)).expect(t, 409)
	e.do("PATCH", fmt.Sprintf("%s/ops/%d/meta", base, seq1), a.token, map[string]any{"meta_enc": randBytes(40), "meta_epoch": 2}, authHdr(vault)).expect(t, 409)

	// Restore to just after v1: the emitted op copies the (patched) epoch-2
	// metadata; min_epoch stays 2.
	var rs struct {
		Emitted int `json:"emitted"`
	}
	e.do("POST", base+"/restore", a.token, map[string]any{"at": t1}, authHdr(vault)).expect(t, 200).json(t, &rs)
	if rs.Emitted != 1 {
		t.Fatalf("restore emitted %d, want 1", rs.Emitted)
	}
	var hist struct{ Ops []store.Op }
	e.do("GET", base+"/history?path_id="+hexID("doc.md"), a.token, nil, nil).expect(t, 200).json(t, &hist)
	var newest store.Op
	for _, o := range hist.Ops {
		if o.Seq > newest.Seq {
			newest = o
		}
	}
	if newest.MetaEpoch != 2 || !strings.HasPrefix(newest.OpID, "restore-") {
		t.Fatalf("restored head: %+v", newest)
	}
	if v := e.vault(vault, a); v.MinEpoch != 2 {
		t.Fatalf("restore pulled min_epoch down: %+v", v)
	}
}
