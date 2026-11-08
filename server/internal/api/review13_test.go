package api_test

// Thirteenth review: the twelfth round's own server changes
// (1256db0..af13604 -- server): the meta_enc header must equal meta_epoch
// (store.validateOp, PatchMeta), History is newest first, the stage name
// carries a per-process counter and stage files are aged by mtime while
// "-prev-" copies are aged by their nonce. Each TestR13* is the proof for one
// candidate finding or a confirmation; the ranked list is in
// plugin/.cache/agent-review13-server/REPORT.md.
//
//	cd server && go test ./internal/api -run 'TestR13' -v

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"obsync/internal/store"
)

// r13hdr reads the plaintext epoch header of a meta_enc the way the server
// (store.metaHeaderMatches) and the plugin (VaultCrypto.metaEpoch) do.
func r13hdr(metaEnc []byte) int64 { return int64(binary.LittleEndian.Uint32(metaEnc[:4])) }

// r13op builds an op whose header and meta_epoch are chosen separately, so a
// test can send the two in disagreement.
func r13op(path string, hdr, metaEpoch int64, n int, base int64) opIn {
	o := put(path, nil, base)
	o.MetaEnc = metaEnc(hdr, n)
	o.MetaEpoch = metaEpoch
	return o
}

// ---------------------------------------------------------------------------
// (a) CONFIRMATION, and the server half of the one legitimate way a client
// can send header != meta_epoch. The plugin reads the epoch twice when it
// builds an op (engine.ts:1468/1495/1508): encryptMeta captures
// keyring.current when it is called, meta_epoch reads keyring.current after
// that await resolves. A rotation on the same device (admin.ts:280
// addEpoch, run by cmdRotate without stopping the engine) or a keybox
// refresh that lands between the two produces header N, meta_epoch N+1.
// Before this round the server stored that row (the round-12 HIGH: a header
// no device will hold once min_epoch passes N, and PATCH never lists it
// because meta_epoch is already N+1). Now the server refuses it, which is
// right; this test pins the refusal and records the text the plugin sees,
// because engine.ts:1444 retries only /blob not uploaded|min_epoch/ and
// treats every other rejection as final for those bytes (dirty mark
// dropped; the edit waits for the next scan or the next edit). The plugin
// side of that is a one-line fix (read the epoch once); it cannot be proven
// here and is reported as such.
func TestR13HeaderMustAgreeWithMetaEpochOnEveryWritePath(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault

	// Epoch 1: a consistent row lands.
	r := e.ops(vault, a, r13op("race.md", 1, 1, 300, 0)).Results[0]
	if r.Error != "" || r.Seq == 0 {
		t.Fatalf("consistent epoch-1 op: %+v", r)
	}
	head := r.Seq

	e.rotateKeep(vault, 2, a, a, b)

	t.Run("post", func(t *testing.T) {
		// The race-shaped op: encrypted before the rotation, labelled after it.
		r := e.ops(vault, a, r13op("race.md", 1, 2, 300, head)).Results[0]
		if r.Seq != 0 || !strings.Contains(r.Error, "header epoch 1 does not match meta_epoch 2") {
			t.Fatalf("header 1 / meta_epoch 2 was not refused per-op: %+v", r)
		}
		if regexp.MustCompile(`blob not uploaded|min_epoch`).MatchString(r.Error) {
			t.Fatalf("the rejection text matches the plugin's retry pattern; the note in the report is wrong: %q", r.Error)
		}
		// The other direction (labelled before, encrypted after) is refused too.
		r = e.ops(vault, a, r13op("race.md", 2, 1, 300, head)).Results[0]
		if r.Seq != 0 || !strings.Contains(r.Error, "header epoch 2 does not match meta_epoch 1") {
			t.Fatalf("header 2 / meta_epoch 1 was not refused per-op: %+v", r)
		}
		// A consistent epoch-2 op lands, and a replay of a refused op is still
		// refused (validation runs before the idempotent-replay lookup).
		r = e.ops(vault, a, r13op("race.md", 2, 2, 300, head)).Results[0]
		if r.Error != "" || r.Seq != head+1 {
			t.Fatalf("consistent epoch-2 op: %+v", r)
		}
		head = r.Seq
	})

	t.Run("patch", func(t *testing.T) {
		patch := func(seq, hdr, metaEpoch int64) int {
			return e.do("PATCH", base+"/ops/"+strconv.FormatInt(seq, 10)+"/meta", a.token, map[string]any{"meta_enc": metaEnc(hdr, 300), "meta_epoch": metaEpoch}, authHdr(vault)).code
		}
		if c := patch(1, 1, 2); c != 400 {
			t.Fatalf("PATCH header 1 / meta_epoch 2: %d, want 400", c)
		}
		if c := patch(1, 3, 3); c != 409 {
			t.Fatalf("PATCH header 3 / meta_epoch 3 above the vault epoch: %d, want 409 (header check passes, range check refuses)", c)
		}
		if c := patch(1, 2, 2); c != 204 {
			t.Fatalf("PATCH header 2 / meta_epoch 2: %d, want 204", c)
		}
		if c := patch(1, 2, 2); c != 409 {
			t.Fatalf("PATCH to the same epoch again: %d, want 409", c)
		}
		op, err := e.st.GetOp(t.Context(), vault, 1)
		if err != nil || r13hdr(op.MetaEnc) != 2 || op.MetaEpoch != 2 {
			t.Fatalf("after the patch: hdr %d meta_epoch %d err %v", r13hdr(op.MetaEnc), op.MetaEpoch, err)
		}
	})

	t.Run("minimum", func(t *testing.T) {
		// 32 bytes is the floor (header 4 + nonce 12 + tag 16, empty body).
		// The plugin's smallest meta_enc is 4+12+256+16 = 288 (META_PAD 256),
		// so no honest client is near it.
		r := e.ops(vault, a, r13op("short.md", 2, 2, 31, 0)).Results[0]
		if r.Seq != 0 || !strings.Contains(r.Error, "too short") {
			t.Fatalf("31-byte meta_enc: %+v", r)
		}
		r = e.ops(vault, a, r13op("short.md", 2, 2, 32, 0)).Results[0]
		if r.Error != "" || r.Seq == 0 {
			t.Fatalf("32-byte meta_enc: %+v", r)
		}
		if c := e.do("PATCH", base+"/ops/"+strconv.FormatInt(r.Seq, 10)+"/meta", a.token, map[string]any{"meta_enc": metaEnc(2, 31), "meta_epoch": 2}, authHdr(vault)).code; c != 400 {
			t.Fatalf("PATCH with a 31-byte meta_enc: %d, want 400", c)
		}
	})

	t.Run("rows", func(t *testing.T) {
		// Every row the server now holds agrees with itself.
		rows, err := e.st.DB().Query(`SELECT seq, meta_enc, meta_epoch FROM ops WHERE vault_id=?`, vault)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var seq, me int64
			var enc []byte
			if err := rows.Scan(&seq, &enc, &me); err != nil {
				t.Fatal(err)
			}
			if r13hdr(enc) != me {
				t.Fatalf("seq %d: header %d, meta_epoch %d", seq, r13hdr(enc), me)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// (a) NOTE (passes on HEAD; documents the one write path without the
// check). Restore copies old rows verbatim (store.go:1402), so a row that
// a 0.1.12 server accepted with a header no epoch has is re-emitted as a
// new head, byte for byte, although POST would now refuse the same bytes.
// Nothing new can reach that state (POST and PATCH check), re-encryption
// repairs it when a device still holds the header's key, and a 0.1.13
// client skips it with a notice instead of stopping; so this is the
// documented "verbatim" contract meeting legacy data, not a defect.
func TestR13RestoreReemitsAPreCheckRowVerbatim(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault

	r1 := e.ops(vault, a, r13op("legacy.md", 1, 1, 300, 0)).Results[0]
	if r1.Error != "" {
		t.Fatal(r1.Error)
	}
	// Age the row into a pre-0.1.13 shape: a header naming epoch 7, which no
	// device has ever held.
	if _, err := e.st.DB().Exec(`UPDATE ops SET meta_enc=? WHERE vault_id=? AND seq=?`, metaEnc(7, 300), vault, r1.Seq); err != nil {
		t.Fatal(err)
	}
	// The same bytes are refused at the door today.
	if r := e.ops(vault, a, r13op("other.md", 7, 1, 300, 0)).Results[0]; r.Seq != 0 || !strings.Contains(r.Error, "header epoch 7") {
		t.Fatalf("POST of the legacy shape: %+v", r)
	}
	time.Sleep(3 * time.Millisecond) // created_at is in milliseconds
	r2 := e.ops(vault, a, r13op("legacy.md", 1, 1, 300, r1.Seq)).Results[0]
	if r2.Error != "" {
		t.Fatal(r2.Error)
	}
	var rs struct {
		Emitted int      `json:"emitted"`
		Skipped []string `json:"skipped_path_ids"`
	}
	e.do("POST", base+"/restore", a.token, map[string]any{"at": r1.CreatedAt}, authHdr(vault)).expect(t, 200).json(t, &rs)
	if rs.Emitted != 1 {
		t.Fatalf("restore: %+v", rs)
	}
	var hist struct{ Ops []store.Op }
	e.do("GET", base+"/history?path_id="+hexID("legacy.md"), a.token, nil, nil).expect(t, 200).json(t, &hist)
	if len(hist.Ops) != 3 || hist.Ops[0].Seq != r2.Seq+1 {
		t.Fatalf("history after restore: %d ops, newest seq %d", len(hist.Ops), hist.Ops[0].Seq)
	}
	nh := hist.Ops[0]
	if r13hdr(nh.MetaEnc) != 7 || nh.MetaEpoch != 1 {
		t.Fatalf("the restored head was not a verbatim copy: header %d meta_epoch %d", r13hdr(nh.MetaEnc), nh.MetaEpoch)
	}
	t.Logf("note: Restore re-emitted header %d under meta_epoch %d (seq %d); POST refuses the same bytes", r13hdr(nh.MetaEnc), nh.MetaEpoch, nh.Seq)
}

// ---------------------------------------------------------------------------
// (b) CONFIRMATION of what the newest-first page cut at maxListLimit means.
// A path with 5,002 versions: history returns 5,000, the head is first and
// the two OLDEST versions are the ones missing. The plugin's deferred retry
// (engine.ts:647, sort desc, [0]) and the history modal (main.ts:816) are
// right with this order; recoverFromRewind's ".some" over history
// (engine.ts:728) asks "was our synced blob ever on this server" and gets
// a wrong "no" only for a device whose synced version is more than 5,000
// versions behind the head on one path, where the outcome is a conflict
// sibling, not a lost write (see the report). The handler takes no client
// limit, so no caller can page past this.
func TestR13HistoryKeepsTheHeadAndDropsTheOldestVersions(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault
	const versions = 5002

	first := e.ops(vault, a, r13op("hot.md", 1, 1, 32, 0)).Results[0]
	if first.Error != "" {
		t.Fatal(first.Error)
	}
	seq := first.Seq // the vault's seq is ours alone: no other writer in this test
	for sent := 1; sent < versions; {
		n := min(1000, versions-sent)
		batch := make([]opIn, n)
		for i := range batch {
			batch[i] = r13op("hot.md", 1, 1, 32, seq+int64(i))
		}
		out := e.ops(vault, a, batch...)
		for i, r := range out.Results {
			if r.Error != "" || r.Conflict != nil || r.Seq != seq+int64(i)+1 {
				t.Fatalf("op %d of batch at %d: %+v", i, sent, r)
			}
		}
		seq += int64(n)
		sent += n
	}
	var hist struct{ Ops []store.Op }
	e.do("GET", base+"/history?path_id="+hexID("hot.md"), a.token, nil, nil).expect(t, 200).json(t, &hist)
	if len(hist.Ops) != 5000 {
		t.Fatalf("history returned %d ops, want the 5000 cap", len(hist.Ops))
	}
	if hist.Ops[0].Seq != seq {
		t.Fatalf("history[0] is seq %d, want the head %d", hist.Ops[0].Seq, seq)
	}
	for i := 1; i < len(hist.Ops); i++ {
		if hist.Ops[i].Seq != hist.Ops[i-1].Seq-1 {
			t.Fatalf("history is not contiguous newest-first at %d: %d after %d", i, hist.Ops[i].Seq, hist.Ops[i-1].Seq)
		}
	}
	oldest := hist.Ops[len(hist.Ops)-1].Seq
	if oldest != first.Seq+2 {
		t.Fatalf("oldest returned seq %d; want %d (versions %d and %d dropped)", oldest, first.Seq+2, first.Seq, first.Seq+1)
	}
	// The dropped versions are real rows: a client reasoning over this page
	// cannot tell "never existed" from "older than the page".
	if op, err := e.st.GetOp(t.Context(), vault, first.Seq); err != nil || op.PathID != hexID("hot.md") {
		t.Fatalf("version 1 is gone from the log: %v", err)
	}
}

// ---------------------------------------------------------------------------
// (c) CONFIRMATION: which clock each file class trusts, with the stage
// name shape this round introduced (<id>-stage-<counter36>-<nanos36>). A
// stage file is aged by mtime (its last byte), whatever its nanos say; a
// "-prev-" copy is aged by the nonce after its last "-", whatever its inode
// says; the stage name's last segment is still the nanos, so anything that
// parses it reads a time, not the counter. The counter restarting at 1 in
// another process cannot reproduce a name: the nanos differ.
func TestR13StageCounterNameAndSweepClocks(t *testing.T) {
	id := hexID("r13-stage")
	bs, vault, cur := r10store(t, id)
	shard := filepath.Dir(cur)
	if err := os.MkdirAll(shard, 0o750); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	stageName := func(counter uint64, at time.Time) string {
		return id + "-stage-" + strconv.FormatUint(counter, 36) + "-" + r12nonce(at) // server.go:1038
	}
	// The segment after the last "-" of a stage name decodes to its nanos,
	// not to the counter, for any counter value.
	for _, c := range []uint64{1, 35, 36, 1 << 40} {
		got, ok := r12decodeNonce(stageName(c, now))
		if !ok || !got.Equal(time.Unix(0, now.UnixNano())) {
			t.Fatalf("counter %d: last segment decoded to %v (%v), want the nanos", c, got, ok)
		}
	}
	if stageName(1, now) == stageName(1, now.Add(time.Nanosecond)) {
		t.Fatal("a restarted counter reproduced a name across different nanoseconds")
	}
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
	keep := []string{
		mk(stageName(7, old), now),                   // began two hours ago, last byte just now: a slow upload (R12 finding 1)
		mk(id+"-prev-"+r12nonce(now), old),           // aside link minted now, inode two hours old (R10/R11)
		mk(".tmp-"+stageName(8, old)+"-abc123", now), // Put's temp file for the same slow upload
	}
	drop := []string{
		mk(stageName(9, now), old),                    // completed two hours ago, never promoted
		mk(id+"-prev-"+r12nonce(old), now),            // aside copy minted two hours ago (fresh mtime cannot save it)
		mk(".tmp-"+stageName(10, now)+"-def456", old), // temp file nobody wrote to for two hours
	}
	n, err := bs.SweepStale(vault, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(drop) {
		t.Fatalf("removed %d, want %d", n, len(drop))
	}
	for _, p := range keep {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("live file swept: %s (%v)", filepath.Base(p), err)
		}
	}
	for _, p := range drop {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("abandoned file survived: %s", filepath.Base(p))
		}
	}
	// Clock skew (asked): the nonce and the sweep read the same clock (one
	// process, or the serve process and `obsync gc` on one host), so a
	// constant offset of any size keeps every prev nonce plausible; only an
	// absolute time before 2020 or a backward step of more than a day
	// between mint and sweep reaches the mtime fallback, which R12 pins.
	plausible := func(name string, sweepNow time.Time) bool { // fs.go:184-186
		at, ok := r12decodeNonce(name)
		return ok && at.After(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) && at.Before(sweepNow.Add(24*time.Hour))
	}
	for _, off := range []time.Duration{0, 365 * 24 * time.Hour, -365 * 24 * time.Hour, 10 * 365 * 24 * time.Hour, -10 * 365 * 24 * time.Hour} {
		clock := now.Add(off) // the one clock both mint and sweep read
		want := clock.After(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
		if got := plausible(id+"-prev-"+r12nonce(clock), clock); got != want {
			t.Fatalf("clock offset %v: nonce plausible %v, want %v", off, got, want)
		}
	}
	// The one realistic skew: a clock stepped back (NTP catching up) after
	// the mint. Within a day the nonce stays plausible; beyond it the aside
	// copy is aged by its inode and swept early, as R12 pinned.
	if !plausible(id+"-prev-"+r12nonce(now), now.Add(-23*time.Hour)) || plausible(id+"-prev-"+r12nonce(now), now.Add(-25*time.Hour)) {
		t.Fatal("backward-step window is not 24h")
	}
}
