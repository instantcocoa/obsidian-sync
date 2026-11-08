package api_test

// Twelfth review: the eleventh round's server fix (a4f34a0..1256db0: the
// pre-link Chtimes is gone and SweepStale ages "-stage-"/"-prev-" files by
// the base-36 UnixNano nonce after the last "-" when it decodes to a time
// between 2020 and now+24h, else by mtime; ".tmp-" files by mtime), read
// with the assumption that a hurried fix has an edge. Each TestR12* is the
// proof for one candidate finding or a confirmation; see
// plugin/.cache/agent-review12-server/REPORT.md.
//
//	cd server && go test ./internal/api -run 'TestR12' -v

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// r12nonce is the nonce putBlob mints (server.go:1029, 1077) for a given
// instant.
func r12nonce(at time.Time) string { return strconv.FormatInt(at.UnixNano(), 36) }

// r12decodeNonce reads a nonce back the way SweepStale does (fs.go:181).
func r12decodeNonce(name string) (time.Time, bool) {
	ns, err := strconv.ParseInt(name[strings.LastIndex(name, "-")+1:], 36, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, ns), true
}

// r12fileEpoch reads the epoch from a wire-format blob file's header.
func r12fileEpoch(t *testing.T, path string) uint32 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 5 || b[0] != 0x01 {
		t.Fatalf("not a blob file: %q", path)
	}
	return binary.LittleEndian.Uint32(b[1:5])
}

// ---------------------------------------------------------------------------
// FINDING (medium): the stage file is now aged from the START of its upload.
// putBlob mints the stage nonce before the body is read (server.go:1029),
// Put streams the body into ".tmp-<id>-stage-<nonce>-<rand>" (aged by mtime,
// which the ongoing write keeps fresh) and renames it to "<id>-stage-<nonce>"
// when the body is complete. From that rename until Promote the file is aged
// by its nonce, i.e. by the upload's start time. idleReader exists so that a
// large blob on a slow link may take longer than the 15-minute request
// deadline as long as it makes progress (server.go:1310-1323; the default
// MaxBlobSize is 1 GiB, which is over an hour below ~300 KB/s). An upload
// that took more than an hour therefore presents, in the window between
// Put's rename and Swap's Promote (a GetBlob, the blob lock, two liveness
// reads, the link), a stage file that SweepStale(time.Hour) counts as
// abandoned and removes. Promote then fails ENOENT, Swap puts the aside link
// back, and the request answers 500 after an hour of transfer. Before this
// round the same file was aged by mtime, which the write had just refreshed,
// so a sweep in that window spared it. No corruption (the old blob is
// intact, no leftovers), but the slowest uploads are the ones that fail, and
// they fail only when GC happens to run in the window, which makes the
// failure look random.
func TestR12SweepTakesAStageFileWhoseUploadOutlivedTheHour(t *testing.T) {
	id := hexID("r12-slow-upload")
	stageOf := func(start time.Time) string { return id + "-stage-" + r12nonce(start) }

	t.Run("blobstore", func(t *testing.T) {
		bs, vault, cur := r10store(t, id)
		r10put(t, bs, vault, id, "version 1")
		// The upload began 61 minutes ago; its last byte landed just now.
		stage := stageOf(time.Now().Add(-61 * time.Minute))
		r10put(t, bs, vault, stage, "version 2, an hour in transfer")
		stagePath := filepath.Join(filepath.Dir(cur), stage)
		st, err := os.Stat(stagePath)
		if err != nil {
			t.Fatal(err)
		}
		if age := time.Since(st.ModTime()); age > time.Minute {
			t.Fatalf("premise: the stage file was just written, mtime age %s", age)
		}
		n, err := bs.SweepStale(vault, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(stagePath); err != nil || n != 0 {
			t.Fatalf("a stage file whose bytes landed seconds ago was swept (n=%d, stat: %v): it is aged by the nonce minted when the upload began, not by the write that just finished", n, err)
		}
	})

	t.Run("consequence", func(t *testing.T) {
		// What putBlob sees when the sweep won the window: Swap fails, the old
		// blob is intact, the uploader gets a 500. The aside link lingers
		// (rename of one hard link over another of the same inode is a POSIX
		// no-op), which R10 pinned as the Promote-failure state; the sweep
		// takes it an hour after its nonce.
		bs, vault, cur := r10store(t, id)
		r10put(t, bs, vault, id, "version 1")
		stage := stageOf(time.Now().Add(-61 * time.Minute))
		r10put(t, bs, vault, stage, "version 2, an hour in transfer")
		if n, _ := bs.SweepStale(vault, time.Hour); n != 1 {
			t.Skipf("the sweep did not take the stage file (n=%d): the finding is fixed, nothing to show here", n)
		}
		prev := id + "-prev-" + r12nonce(time.Now())
		had, err := bs.Swap(vault, stage, id, prev)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Swap after the sweep: had=%v err=%v (expected ENOENT from Promote)", had, err)
		}
		if got := r10read(t, bs, vault, id); got != "version 1" {
			t.Fatalf("the old blob must be intact, got %q", got)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(cur), prev)); err != nil {
			t.Fatalf("expected the lingering aside link R10 pinned for a failed Promote, stat: %v", err)
		}
		t.Logf("blast radius confirmed: Swap=%v, blob intact, one -prev- link left for the sweep; putBlob answers 500 after the whole transfer", err)
	})

	t.Run("http: the nonce is the upload's start time", func(t *testing.T) {
		// Over HTTP the clock cannot be moved, so this pins the premise the
		// blobstore proof rests on: the nonce in the stage name is minted
		// before the body is read, and the file is renamed to that name only
		// when the body is complete.
		e, bs, dir := r7env(t)
		vault, a, _ := e.setup()
		data := blob(1, "slow body")
		shard := filepath.Dir(blobPath(dir, vault, id))
		t0 := time.Now()
		var tmpName string
		var minted time.Time
		res := e.inflightAt("PUT", "/v1/vaults/"+vault+"/blobs/"+id, a.token,
			map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]},
			data, 33+1, func() {
				tmps := filesMatching(dir, vault, ".tmp-")
				if len(tmps) != 1 {
					t.Fatalf("expected one .tmp- file while the body is in flight, got %v", tmps)
				}
				tmpName = filepath.Base(tmps[0])
				// ".tmp-<id>-stage-<nonce>-<rand>": the nonce is the segment before the random suffix.
				segs := strings.Split(tmpName, "-")
				ns, err := strconv.ParseInt(segs[len(segs)-2], 36, 64)
				if err != nil {
					t.Fatalf("cannot decode the stage nonce from %q: %v", tmpName, err)
				}
				minted = time.Unix(0, ns)
				// A sweep now must spare the live write: the ".tmp-" prefix is
				// checked first and the file is aged by mtime.
				if n, err := bs.SweepStale(vault, time.Hour); err != nil || n != 0 {
					t.Fatalf("a sweep during the body read removed %d file(s), err %v", n, err)
				}
				time.Sleep(1200 * time.Millisecond) // the "long upload", in miniature
			})
		if res.code != 201 {
			t.Fatalf("upload: %d %s", res.code, res.body)
		}
		if minted.Before(t0) || minted.After(t0.Add(2*time.Second)) {
			t.Fatalf("nonce decodes to %s, request began %s: not the upload's start", minted, t0)
		}
		if !strings.Contains(tmpName, "-stage-") {
			t.Fatalf("the temp name %q does not embed the stage name", tmpName)
		}
		if lo := leftovers(t, dir, vault); len(lo) > 0 {
			t.Fatalf("leftovers: %v", lo)
		}
		if _, err := os.Stat(filepath.Join(shard, id)); err != nil {
			t.Fatal(err)
		}
		t.Logf("stage nonce minted at +%s of a request whose body completed at +%s: the sweep's clock for the stage file starts before the first body byte", minted.Sub(t0).Round(time.Millisecond), time.Since(t0).Round(time.Millisecond))
	})
}

// ---------------------------------------------------------------------------
// FINDING (low, platform-dependent trigger): the stage nonce is minted
// OUTSIDE the per-blob lock (server.go:1029 vs lk.Lock() at :1045; the prev
// nonce at :1077 is inside it), so two concurrent uploads of the same id that
// read time.Now() in the same clock tick name the same stage file. Put's
// final rename then replaces the first uploader's stage file with the
// second's bytes; the lock winner promotes whatever the stage file holds and
// writes ITS row (its epoch, its size); the other finds the stage gone,
// Promote fails ENOENT, 500. When the two uploads carry different epochs the
// row and the bytes disagree, in either direction, including the one the
// eighth round named as the bad state (row epoch 2 over epoch-1 bytes: the
// blob leaves the re-encryption listing while every device prunes key 1).
// time.Now() on darwin has 1 µs granularity (measured: 95 % of back-to-back
// calls repeat), on Linux with the TSC clocksource it is ~1 ns, so the
// trigger is realistic for the macOS servers the plugin's e2e harness runs
// and implausible on the documented Linux deployment. Pre-existing (the
// nonce was minted there before this round), but this round's comment now
// states that the nonce is unique per file and the sweep's design rests on
// the name, so it belongs on the record.
func TestR12StageNonceMintedOutsideTheLockCollidesUnderConcurrentUploads(t *testing.T) {
	e, _, dir := r7env(t)
	vault, a, b := e.setup()
	// One epoch-1 blob keeps min_epoch at 1 after the rotation, so both epoch
	// 1 and epoch 2 uploads are legal (R10/R11 shape).
	e.upload(vault, a, hexID("r12-seed"), blob(1, "seed")).expect(t, 201)
	e.rotateKeep(vault, 2, a, a, b)

	// Each round fires `fan` uploads of one fresh id at once, epochs 2 and 1
	// alternating; absent a stage-name collision the lock serialises them and
	// the row always describes the promoted bytes.
	const pairs, fan = 300, 6
	// Probabilistic: on this host (darwin, 1 µs clock) one run in about ten
	// hits; the hit recorded in the report was two collisions in 300 rounds,
	// one of them silent and in the bad direction (statuses
	// [201 201 200 200 200 200], row epoch 2, file header epoch 1), while
	// another test process loaded the machine. Busy-loop load did not
	// reproduce it; see TestR12TwoPutsToOneStageNameClobber for the
	// deterministic mechanism.
	collisions, mismatches, bad := 0, 0, 0
	var firstBad string
	for i := 0; i < pairs; i++ {
		id := hexID(fmt.Sprintf("r12-pair-%d", i))
		start := make(chan struct{})
		var wg sync.WaitGroup
		codes := make([]int, fan)
		for k := 0; k < fan; k++ {
			d, data := a, blob(2, "A at epoch 2")
			if k%2 == 1 {
				d, data = b, blob(1, "B at epoch 1")
			}
			wg.Add(1)
			go func(k int, d device, data []byte) {
				defer wg.Done()
				<-start
				codes[k] = e.upload(vault, d, id, data).code
			}(k, d, data)
		}
		close(start)
		wg.Wait()
		for _, c := range codes {
			if c == 500 {
				collisions++
			} else if c != 201 && c != 200 {
				t.Fatalf("round %d: unexpected status %v", i, codes)
			}
		}
		res := e.do("GET", "/v1/vaults/"+vault+"/blobs/"+id, b.token, nil, nil).expect(t, 200)
		rowEpoch, _ := strconv.Atoi(res.hdr.Get("X-Blob-Epoch"))
		fileEpoch := int(r12fileEpoch(t, blobPath(dir, vault, id)))
		if rowEpoch != fileEpoch {
			mismatches++
			if rowEpoch > fileEpoch {
				bad++
				if firstBad == "" {
					firstBad = fmt.Sprintf("pair %d: statuses %v, row epoch %d, file header epoch %d", i, codes, rowEpoch, fileEpoch)
				}
			}
		}
		if lo := leftovers(t, dir, vault); len(lo) > 0 {
			t.Fatalf("pair %d: leftovers %v", i, lo)
		}
	}
	t.Logf("%d rounds of %d concurrent uploads: %d answered 500 (stage name collision), %d row/file epoch mismatches, %d in the bad direction (row ahead of bytes)", pairs, fan, collisions, mismatches, bad)
	if mismatches > 0 {
		t.Fatalf("a row that does not describe the bytes under it: %d of %d pairs; first bad-direction case: %s", mismatches, pairs, firstBad)
	}
	if collisions == 0 {
		t.Logf("no collision observed on this host in %d rounds: the finding stays unproven over HTTP here (see TestR12TwoPutsToOneStageNameClobber for the mechanism)", pairs)
	}
}

// Mechanism of the above, deterministic: two Puts to one stage name are a
// last-writer-wins rename, and the first caller's Swap then promotes the
// second caller's bytes.
func TestR12TwoPutsToOneStageNameClobber(t *testing.T) {
	id := hexID("r12-clobber")
	bs, vault, cur := r10store(t, id)
	stage := id + "-stage-" + r12nonce(time.Now())
	r10put(t, bs, vault, stage, "first uploader, epoch 2")
	r10put(t, bs, vault, stage, "second uploader, epoch 1")
	had, err := bs.Swap(vault, stage, id, id+"-prev-"+r12nonce(time.Now()))
	if err != nil || had {
		t.Fatalf("first uploader's Swap: had=%v err=%v", had, err)
	}
	if got := r10read(t, bs, vault, id); got != "second uploader, epoch 1" {
		t.Fatalf("the first uploader promoted %q", got)
	}
	if _, err := bs.Swap(vault, stage, id, id+"-prev-"+r12nonce(time.Now())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second uploader's Swap: %v (expected ENOENT)", err)
	}
	if _, err := os.Stat(cur); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: ".tmp-" names are matched by prefix before the "-stage-"
// substring (fs.go:168, :180), so Put's temp file, whose name embeds the
// stage name, is aged by mtime: an hour-old one is removed, a young one and a
// live write with an old nonce are kept.
func TestR12TmpFilesAreAgedByMtimePrefixFirst(t *testing.T) {
	id := hexID("r12-tmp")
	bs, vault, cur := r10store(t, id)
	shard := filepath.Dir(cur)
	if err := os.MkdirAll(shard, 0o750); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	oldNonce, freshNonce := r12nonce(old), r12nonce(time.Now())
	mk := func(name string, mtime time.Time) string {
		p := filepath.Join(shard, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}
	liveOldNonce := mk(".tmp-"+id+"-stage-"+oldNonce+"-123456", time.Now()) // a long upload still streaming
	youngFresh := mk(".tmp-"+id+"-stage-"+freshNonce+"-234567", time.Now())
	abandoned := mk(".tmp-"+id+"-stage-"+freshNonce+"-345678", old) // fresh nonce, no write for two hours: mtime wins
	abandonedOld := mk(".tmp-"+id+"-stage-"+oldNonce+"-456789", old)
	n, err := bs.SweepStale(vault, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("removed %d, expected the two abandoned temp files", n)
	}
	for _, p := range []string{liveOldNonce, youngFresh} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("a live temp file was swept: %s (%v)", filepath.Base(p), err)
		}
	}
	for _, p := range []string{abandoned, abandonedOld} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("an abandoned temp file survived: %s", filepath.Base(p))
		}
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION (and a design note): a nonce outside 2020..now+24h, or one
// that does not parse, falls back to mtime. For a "-prev-" link that is the
// round-9/10 behaviour (it shares the old inode's mtime and is swept at
// once), so a server whose clock is wrong at mint or sweep time loses the
// hour of grace for the aside copy. Also pins that the fresh case is spared
// and that the sweep decodes the segment after the LAST "-" (a hex id has no
// "-", so that is always the nonce).
func TestR12ImplausibleNonceFallsBackToMtime(t *testing.T) {
	id := hexID("r12-skew")
	bs, vault, cur := r10store(t, id)
	r10put(t, bs, vault, id, "old blob")
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(cur, old, old); err != nil {
		t.Fatal(err)
	}
	link := func(nonce string) string {
		p := filepath.Join(filepath.Dir(cur), id+"-prev-"+nonce)
		if err := os.Link(cur, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]string{
		"clock in 2019":    r12nonce(time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC)),
		"clock 2 days off": r12nonce(time.Now().Add(48 * time.Hour)),
		"not a nonce":      "crash",
		"empty":            "",
	}
	paths := map[string]string{}
	for k, nonce := range cases {
		paths[k] = link(nonce)
	}
	kept := link(r12nonce(time.Now()))
	n, err := bs.SweepStale(vault, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(cases) {
		t.Fatalf("removed %d, expected %d", n, len(cases))
	}
	for k, p := range paths {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: the aside link survived although its nonce is implausible and its mtime is two hours old", k)
		}
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("the aside link with a fresh nonce was swept: %v", err)
	}
	if got := r10read(t, bs, vault, id); got != "old blob" {
		t.Fatalf("the blob itself: %q", got)
	}
	if _, ok := r12decodeNonce(id + "-prev-" + r12nonce(time.Now())); !ok {
		t.Fatal("the nonce after the last '-' must decode")
	}
}
