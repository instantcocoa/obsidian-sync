package api_test

// Eighth review: the seventh round's own server fixes (9ad72ec), read with the
// assumption that a hurried fix has an edge. Each TestR8* is the proof for one
// candidate finding or a confirmation; see
// plugin/.cache/agent-review8-server/REPORT.md for the ranked list.
//
//	cd server && go test ./internal/api -run 'TestR8' -v

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"obsync/internal/api"
	"obsync/internal/blobstore"
	"obsync/internal/store"
)

func blobPath(dir, vault, id string) string {
	return filepath.Join(dir, "blobs", vault, id[:2], id)
}

// leftovers lists stage and temp files under a vault's blob directory: after
// a request has answered, there must be none.
func leftovers(t *testing.T, dir, vault string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(filepath.Join(dir, "blobs", vault), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (strings.Contains(d.Name(), "-stage-") || strings.HasPrefix(d.Name(), ".tmp-")) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// rotateKeep is a rotation by `by` that keeps every listed device: a new
// epoch and a new authority token, nobody revoked.
func (e *env) rotateKeep(vault string, epoch int64, by device, keep ...device) {
	next := newAuthTok()
	rows := []store.KeyboxRow{}
	for _, d := range keep {
		rows = append(rows, store.KeyboxRow{Epoch: epoch, RecipientID: d.id, Wrapped: randBytes(100)})
	}
	e.do("POST", "/v1/vaults/"+vault+"/rotate", by.token, map[string]any{"epoch": epoch, "keybox": rows, "auth_next": next}, authHdr(vault)).expect(e.t, 200)
	authTok[vault] = next
}

// ---------------------------------------------------------------------------
// FINDING (low): putBlob now promotes the file BEFORE the index row is
// written, and the writer's liveness is checked by a plain read before the
// rename while the authoritative re-check (actorLiveTx) runs inside
// UpsertBlob, after the rename. If UpsertBlob fails for any reason after
// Promote succeeded, the new bytes sit under the OLD row: GET serves them
// with the old X-Blob-Epoch and ct_size, the blob is not listed for
// re-encryption any differently, and the uploader is told the write failed.
// The sixth round's promise ("a write whose device was revoked while its
// request was in flight is never committed") therefore holds for the row but
// not for the bytes: a device whose revocation lands between the pre-check
// and the rename replaces an honest blob's ciphertext with same-epoch
// garbage via X-Blob-Replace and is answered 401. That window is a few
// microseconds and this test cannot hit it deterministically; what it does
// prove is the state the code leaves whenever the row write fails after the
// rename, using the one failure any deployment can produce: another writer
// holding the SQLite write lock past busy_timeout (an `obsync gc` CLI run
// beside the server does exactly that).
func TestR8RowWriteFailureAfterPromoteLeavesNewBytesUnderTheOldRow(t *testing.T) {
	e, bs, dir := r7env(t)
	vault, a, b := e.setup()
	ctx := context.Background()
	base := "/v1/vaults/" + vault
	id := hexID("r8-replace-target")
	honest := blob(1, "honest ciphertext")
	e.do("PUT", base+"/blobs/"+id, a.token, honest, authHdr(vault)).expect(t, 201)
	before, err := e.st.GetBlob(ctx, vault, id)
	if err != nil {
		t.Fatal(err)
	}

	// Another writer holds the database's write lock for the duration of the
	// request: the server's UpsertBlob transaction (BEGIN IMMEDIATE) gives up
	// after its 10 s busy_timeout.
	lock, err := sql.Open("sqlite", "file:"+dir+"/db.sqlite?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	conn, err := lock.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	garbage := blob(1, "garbage: a different, longer ciphertext under the same id")
	start := time.Now()
	res := e.do("PUT", base+"/blobs/"+id, a.token, garbage, map[string]string{"X-Obsync-Vault-Auth": authTok[vault], "X-Blob-Replace": "1"})
	conn.ExecContext(ctx, "ROLLBACK")
	conn.Close()
	t.Logf("replace while the row write cannot commit: %d %s after %s", res.code, res.body, time.Since(start).Round(time.Second))
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
	if bytes.Equal(onDisk, garbage) && after.CtSize == before.CtSize && after.CreatedAt == before.CreatedAt {
		t.Fatalf("FINDING: the uploader was answered %d, yet its bytes replaced the file (file %d bytes) while the index row still describes the previous upload (ct_size %d, created_at unchanged); GET now serves %d bytes under X-Blob-Epoch %s. The same path is taken when actorLiveTx refuses a device revoked between putBlob's pre-check and Promote: the bytes land, the row does not, the answer is 401.",
			res.code, len(onDisk), after.CtSize, len(got.body), got.hdr.Get("X-Blob-Epoch"))
	}
	_ = bs
}

// ---------------------------------------------------------------------------
// CONFIRMATION: an honest device whose upload crosses another device's
// rotation (nobody revoked) is told "vault authority" so the plugin re-syncs;
// its stage file is removed and no file is promoted; the retry under the new
// token lands. Also: a device revoked by that rotation gets the same
// combined text from the pre-check, re-syncs once, and learns from the next
// request that it was removed (a note, not a finding).
func TestR8HonestUploadCrossingARotationIsToldToResync(t *testing.T) {
	e, bs, dir := r7env(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	id := hexID("r8-crossing")
	body := blob(1, strings.Repeat("x", 4096))
	res := e.inflight("PUT", base+"/blobs/"+id, a.token, authHdr(vault), body, func() {
		e.rotateKeep(vault, 2, b, a, b)
	})
	e.do("GET", base, a.token, nil, nil).expect(t, 200) // A is still a member
	if res.code != 401 || !regexp.MustCompile(`(?i)vault authority`).MatchString(res.body) {
		t.Fatalf("honest device crossing a rotation got %d %s; the plugin treats a 401 without 'vault authority' as removal", res.code, res.body)
	}
	if bs.Exists(vault, id) {
		t.Fatalf("a refused upload was promoted into place")
	}
	if lo := leftovers(t, dir, vault); len(lo) > 0 {
		t.Fatalf("stage files left behind after the 401: %v", lo)
	}
	e.do("PUT", base+"/blobs/"+id, a.token, blob(2, strings.Repeat("x", 4096)), authHdr(vault)).expect(t, 201)

	// The revoked flavour: B's upload crosses the rotation that revokes B.
	id2 := hexID("r8-crossing-revoked")
	res = e.inflight("PUT", base+"/blobs/"+id2, b.token, authHdr(vault), blob(2, strings.Repeat("y", 4096)), func() {
		next := newAuthTok()
		e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 3, "revoke": []string{b.id}, "keybox": []store.KeyboxRow{{Epoch: 3, RecipientID: a.id, Wrapped: randBytes(100)}}, "auth_next": next}, authHdr(vault)).expect(t, 200)
		authTok[vault] = next
	})
	t.Logf("revoked device's crossing upload: %d %s (then its next request: %s)", res.code, res.body, e.do("GET", base, b.token, nil, nil).body)
	if res.code != 401 || bs.Exists(vault, id2) {
		t.Fatalf("revoked device's upload: %d, promoted=%v", res.code, bs.Exists(vault, id2))
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: the new orphan sweep removes only final files that have no
// index row AND are older than an hour. A rowed blob whose file mtime is
// ancient (restored backup, clock skew) survives; a rowless file younger than
// an hour (a row write that failed a moment ago; the client is retrying)
// survives; a rowless file older than an hour goes. Stage-named files are
// not confused with blob ids.
func TestR8OrphanSweepRemovesOnlyRowlessFilesOlderThanAnHour(t *testing.T) {
	e, bs, dir := r7env(t)
	vault, a, _ := e.setup()
	ctx := context.Background()
	base := "/v1/vaults/" + vault
	old := time.Now().Add(-3 * time.Hour)

	rowed := hexID("r8-rowed-old-mtime")
	e.do("PUT", base+"/blobs/"+rowed, a.token, blob(1, "kept"), authHdr(vault)).expect(t, 201)
	e.do("POST", base+"/ops", a.token, []opIn{put("r8.md", str(rowed), 0)}, jsonHdr(vault)).expect(t, 200)
	if err := os.Chtimes(blobPath(dir, vault, rowed), old, old); err != nil {
		t.Fatal(err)
	}
	// A rowed blob nothing references, older than retention: GC's dead-blob
	// pass owns it (row and file go together); not the orphan pass.
	write := func(id string, mtime time.Time) {
		p := blobPath(dir, vault, id)
		os.MkdirAll(filepath.Dir(p), 0o750)
		if err := os.WriteFile(p, blob(1, id[:8]), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	orphanOld, orphanNew := hexID("r8-orphan-old"), hexID("r8-orphan-new")
	write(orphanOld, old)
	write(orphanNew, time.Now())
	// A 64-hex name in the wrong shard directory is not a blob id this
	// server wrote; the sweep must not delete the correctly placed file of
	// the same name on its account.
	misplaced := hexID("r8-misplaced")
	mp := filepath.Join(dir, "blobs", vault, "zz", misplaced)
	os.MkdirAll(filepath.Dir(mp), 0o750)
	os.WriteFile(mp, blob(1, "misplaced"), 0o640)
	os.Chtimes(mp, old, old)
	e.do("PUT", base+"/blobs/"+misplaced, a.token, blob(1, "placed"), authHdr(vault)).expect(t, 201)
	e.do("POST", base+"/ops", a.token, []opIn{put("r8b.md", str(misplaced), 0)}, jsonHdr(vault)).expect(t, 200)

	n, err := e.srv.GC(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("gc removed %d", n)
	if !bs.Exists(vault, rowed) {
		t.Fatalf("FINDING: a rowed blob with an old mtime was removed by the orphan sweep")
	}
	if _, err := e.st.GetBlob(ctx, vault, rowed); err != nil {
		t.Fatalf("rowed blob lost its row: %v", err)
	}
	if bs.Exists(vault, orphanOld) {
		t.Errorf("rowless file older than an hour survived")
	}
	if !bs.Exists(vault, orphanNew) {
		t.Errorf("FINDING: rowless file younger than an hour was removed (undercuts the client's retry after a failed row write)")
	}
	if !bs.Exists(vault, misplaced) {
		t.Errorf("FINDING: the correctly placed, rowed file was deleted on account of a misplaced namesake")
	}
	if _, err := os.Stat(mp); err != nil {
		t.Logf("note: misplaced file was removed too (%v)", err)
	} else {
		t.Logf("note: a misplaced 64-hex file is listed by Orphans but never deleted (Delete targets the proper shard); it leaks")
	}
	e.do("GET", base+"/blobs/"+rowed, a.token, nil, nil).expect(t, 200)
}

// ---------------------------------------------------------------------------
// CONFIRMATION: CreateInvite's empty-Actor path is reachable only with the
// admin bearer (never a device token), the device path is re-checked and
// needs authority, and created_by records the device id or "admin".
func TestR8CreateInviteActorAndCreatedBy(t *testing.T) {
	e, _, dir := r7env(t)
	vault, a, _ := e.setup()
	ctx := context.Background()
	base := "/v1/vaults/" + vault
	kb := map[string]any{"keybox_enc": randBytes(64)}

	r := e.do("POST", base+"/invites", a.token, kb, nil).expect(t, 401)
	if !strings.Contains(string(r.body), "vault authority") {
		t.Fatalf("device without authority: %s", r.body)
	}
	e.do("POST", base+"/invites", a.token, kb, authHdr(vault)).expect(t, 201)
	e.do("POST", base+"/invites", adminTok, kb, nil).expect(t, 403)
	// A device token presented where the admin token goes is just a bad admin token.
	e.do("POST", base+"/invites", a.token, kb, map[string]string{"Authorization": "Bearer " + a.token}).expect(t, 401)

	var fresh store.Vault
	e.do("POST", "/v1/vaults", adminTok, nil, nil).expect(t, 201).json(t, &fresh)
	e.do("POST", "/v1/vaults/"+fresh.ID+"/invites", adminTok, kb, nil).expect(t, 201)

	db, err := sql.Open("sqlite", "file:"+dir+"/db.sqlite?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT vault_id, created_by FROM invites ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]int{}
	for rows.Next() {
		var v, by string
		rows.Scan(&v, &by)
		seen[v+":"+by]++
		t.Logf("invite vault=%s created_by=%s", v[:6], by)
	}
	if seen[vault+":"+a.id] == 0 || seen[fresh.ID+":admin"] == 0 {
		t.Fatalf("created_by not recorded as expected: %v", seen)
	}
	for k := range seen {
		if strings.HasSuffix(k, ":") {
			t.Fatalf("an invite with an empty created_by: %v", seen)
		}
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: fail() now echoes err.Error() for ErrForbidden. Every body a
// live device (or an unauthenticated caller) can receive is a fixed string:
// no token, no other device's id, no path, no SQL. And every 401 to a live
// device either says "vault authority" (re-sync) or is a genuine revocation.
func TestR8ForbiddenBodiesLeakNothingAndTheContractHolds(t *testing.T) {
	e, _, dir := r7env(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	bodies := map[string]resp{}

	var inv store.Invite
	e.do("POST", base+"/invites", a.token, map[string]any{"keybox_enc": randBytes(64)}, authHdr(vault)).expect(t, 201).json(t, &inv)
	var red store.Redeemed
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": testPubKex(), "name_enc": randBytes(8)}, nil).expect(t, 201).json(t, &red)
	c := device{red.DeviceID, red.DeviceToken} // a third member every rotation must cover
	bodies["redeem used invite (unauthenticated)"] = e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": testPubKex()}, nil)
	bodies["recovery join wrong passphrase (unauthenticated)"] = e.do("POST", base+"/recovery/join", "rc_"+strings.Repeat("0", 43), map[string]any{"pub_kex": testPubKex()}, nil)
	bodies["middleware: wrong authority"] = e.do("POST", base+"/ops", a.token, []opIn{put("x.md", nil, 0)}, map[string]string{"Content-Type": "application/json", "X-Obsync-Vault-Auth": newAuthTok()})
	bodies["keybox row for another device"] = e.do("POST", base+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: b.id, Wrapped: randBytes(10)}}}, nil)

	opsBody, _ := json.Marshal([]opIn{put("cross.md", nil, 0)})
	r := e.inflight("POST", base+"/ops", a.token, jsonHdr(vault), opsBody, func() { e.rotateKeep(vault, 2, b, a, b, c) })
	bodies["in-tx: authority changed, device kept"] = resp{code: r.code, body: []byte(r.body)}
	r = e.inflight("PUT", base+"/blobs/"+hexID("r8-leak-blob"), a.token, authHdr(vault), blob(2, strings.Repeat("z", 2048)), func() { e.rotateKeep(vault, 3, b, a, b, c) })
	bodies["putBlob pre-check: authority changed, device kept"] = resp{code: r.code, body: []byte(r.body)}
	opsBody, _ = json.Marshal([]opIn{put("cross2.md", nil, 0)})
	r = e.inflight("POST", base+"/ops", b.token, jsonHdr(vault), opsBody, func() {
		next := newAuthTok()
		e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 4, "revoke": []string{b.id}, "keybox": []store.KeyboxRow{{Epoch: 4, RecipientID: a.id, Wrapped: randBytes(100)}, {Epoch: 4, RecipientID: c.id, Wrapped: randBytes(100)}}, "auth_next": next}, authHdr(vault)).expect(t, 200)
		authTok[vault] = next
	})
	bodies["in-tx: device revoked"] = resp{code: r.code, body: []byte(r.body)}
	bodies["middleware: revoked token"] = e.do("GET", base, b.token, nil, nil)

	secret := regexp.MustCompile(`(dv_|in_|va_|rc_|ad_)[A-Za-z0-9]|sqlite|SQL|/`)
	genuine := func(msg string) bool {
		return strings.Contains(msg, "device revoked") || strings.Contains(msg, "invalid or revoked device token")
	}
	for name, rs := range bodies {
		var m map[string]string
		if err := json.Unmarshal(rs.body, &m); err != nil {
			t.Fatalf("%s: non-JSON body %d %s", name, rs.code, rs.body)
		}
		msg := m["error"]
		t.Logf("%-52s %d %q", name, rs.code, msg)
		if rs.code != 401 {
			t.Errorf("%s: expected 401, got %d", name, rs.code)
		}
		if secret.MatchString(msg) || strings.Contains(msg, a.id) || strings.Contains(msg, b.id) || strings.Contains(msg, dir) || strings.Contains(msg, vault) {
			t.Errorf("FINDING: %s leaks: %q", name, msg)
		}
		if strings.Contains(name, "unauthenticated") || strings.Contains(name, "another device") {
			continue // not a sync-loop 401; the plugin maps these elsewhere
		}
		if !regexp.MustCompile(`(?i)vault authority`).MatchString(msg) && !genuine(msg) {
			t.Errorf("FINDING: %s: a live device would read %q as removal", name, msg)
		}
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: ecdh.P256().NewPublicKey rejects the encodings a length check
// let through: all zeros, the (0,0) non-point under an 0x04 prefix, a
// non-canonical x >= p, a compressed prefix padded to 65 bytes, a point from
// another curve. A real point enrols. The check costs microseconds.
func TestR8ValidPubKexRejectsInfinityAndNonCanonicalPoints(t *testing.T) {
	e, _, _ := r7env(t)
	vault, a, _ := e.setup()
	var inv store.Invite
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": randBytes(64)}, authHdr(vault)).expect(t, 201).json(t, &inv)
	try := func(name string, pk []byte) resp {
		r := e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": pk, "name_enc": randBytes(8)}, nil)
		t.Logf("%-34s %d %s", name, r.code, strings.TrimSpace(string(r.body)))
		return r
	}
	p := elliptic.P256().Params().P
	good := testPubKex()
	xP := append([]byte{0x04}, p.FillBytes(make([]byte, 32))...)
	xP = append(xP, good[33:]...)
	compressed := append([]byte{0x02}, good[1:]...)
	p384, _ := ecdh.P384().GenerateKey(rand.Reader)
	other := p384.PublicKey().Bytes()[:65]
	bad := map[string][]byte{
		"65 zero bytes":               make([]byte, 65),
		"0x04 || 0 || 0":              append([]byte{0x04}, make([]byte, 64)...),
		"x = p (non-canonical)":       xP,
		"compressed prefix, 65 bytes": compressed,
		"P-384 prefix bytes":          other,
		"infinity (1 byte)":           {0x00},
		"compressed (33 bytes)":       append([]byte{0x02}, good[1:33]...),
	}
	for name, pk := range bad {
		if r := try(name, pk); r.code != 400 {
			t.Errorf("FINDING: %s enrolled or was not a 400: %d %s", name, r.code, r.body)
		}
	}
	// The negated point (x, p-y) is a different valid point; it enrols.
	neg := append([]byte{0x04}, good[1:33]...)
	y := new(big.Int).SetBytes(good[33:])
	neg = append(neg, new(big.Int).Sub(p, y).FillBytes(make([]byte, 32))...)
	if r := try("valid point (x, p-y)", neg); r.code != 201 {
		t.Errorf("a valid point was refused: %d %s", r.code, r.body)
	}
	start := time.Now()
	const n = 5000
	for i := 0; i < n; i++ {
		ecdh.P256().NewPublicKey(good)
	}
	t.Logf("NewPublicKey: %s per call", (time.Since(start) / n).Round(100*time.Nanosecond))
}

// ---------------------------------------------------------------------------
// CONFIRMATION: --trust-proxy as CIDRs. main.go hands New strings.Split("",
// ",") == [""] by default: trusts nothing. Whitespace, bare addresses,
// IPv4-mapped entries and peers behave; an unparsable entry refuses to
// start. "0.0.0.0/0" restores the old "trust everyone" (an operator's
// choice, and it does not reach IPv6 peers).
func TestR8TrustProxyCIDRs(t *testing.T) {
	newSrv := func(t *testing.T, trusted []string) *api.Server {
		dir := t.TempDir()
		st, err := store.Open(dir + "/db.sqlite")
		if err != nil {
			t.Fatal(err)
		}
		bs, err := blobstore.New(dir + "/blobs")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return api.New(api.Config{AdminToken: adminTok, InviteTTL: time.Hour, AuthRatePerMinute: 60, AuthBurst: 3, TrustedProxies: trusted}, st, bs)
	}
	// hit sends the unauthenticated, limited redeem route straight to the
	// handler with a chosen TCP peer and X-Forwarded-For; reports the codes.
	hit := func(srv *api.Server, peer string, xffs ...string) []int {
		var codes []int
		for _, xff := range xffs {
			req := httptest.NewRequest("POST", "/v1/invites/in_bogus", strings.NewReader(`{"pub_kex":"AA=="}`))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = peer
			if xff != "" {
				req.Header.Set("X-Forwarded-For", xff)
			}
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			codes = append(codes, rec.Code)
		}
		return codes
	}
	distinct := []string{"10.1.1.1", "10.1.1.2", "10.1.1.3", "10.1.1.4", "10.1.1.5"}
	limited := func(codes []int) bool { return codes[len(codes)-1] == 429 }

	t.Run("default from main.go trusts nothing", func(t *testing.T) {
		srv := newSrv(t, strings.Split("", ","))
		if c := hit(srv, "127.0.0.1:1", distinct...); !limited(c) {
			t.Fatalf("FINDING: XFF honoured with the empty default: %v", c)
		}
	})
	t.Run("nil trusts nothing", func(t *testing.T) {
		if c := hit(newSrv(t, nil), "127.0.0.1:1", distinct...); !limited(c) {
			t.Fatalf("%v", c)
		}
	})
	t.Run("whitespace and bare addresses", func(t *testing.T) {
		srv := newSrv(t, []string{" 127.0.0.1 ,, ::1 ", ""})
		if c := hit(srv, "127.0.0.1:1", distinct...); limited(c) {
			t.Fatalf("trusted peer's XFF ignored: %v", c)
		}
		if c := hit(srv, "127.0.0.2:1", distinct...); !limited(c) {
			t.Fatalf("FINDING: a bare address trusted more than that host: %v", c)
		}
	})
	t.Run("IPv4-mapped entry and IPv4-mapped peer", func(t *testing.T) {
		srv := newSrv(t, []string{"::ffff:127.0.0.1"})
		if c := hit(srv, "127.0.0.1:1", distinct...); limited(c) {
			t.Fatalf("mapped entry does not match its IPv4 peer: %v", c)
		}
		srv = newSrv(t, []string{"127.0.0.0/8"})
		if c := hit(srv, "[::ffff:127.0.0.1]:1", distinct...); limited(c) {
			t.Fatalf("IPv4-mapped peer not recognised as the proxy: %v", c)
		}
		// Without XFF, the mapped and the plain spelling of one peer share a bucket.
		srv = newSrv(t, nil)
		c := append(hit(srv, "127.0.0.1:1", "", ""), hit(srv, "[::ffff:127.0.0.1]:2", "", "", "")...)
		if !limited(c) {
			t.Fatalf("FINDING: IPv4-mapped spelling buys a fresh bucket: %v", c)
		}
	})
	t.Run("an IPv4-mapped prefix is the IPv4 network it maps", func(t *testing.T) {
		srv := newSrv(t, []string{"::ffff:127.0.0.0/104"}) // Go reads this as 127.0.0.0/8
		if c := hit(srv, "127.0.0.1:1", distinct...); limited(c) {
			t.Fatalf("%v", c)
		}
		if c := hit(srv, "128.0.0.1:1", distinct...); !limited(c) {
			t.Fatalf("FINDING: outside the mapped network yet trusted: %v", c)
		}
	})
	t.Run("host bits in a CIDR mean the network", func(t *testing.T) {
		srv := newSrv(t, []string{"10.0.0.1/8"})
		if c := hit(srv, "10.9.9.9:1", distinct...); limited(c) {
			t.Fatalf("%v", c)
		}
		if c := hit(srv, "11.0.0.1:1", distinct...); !limited(c) {
			t.Fatalf("FINDING: outside the network yet trusted: %v", c)
		}
	})
	t.Run("0.0.0.0/0 trusts every IPv4 peer and no IPv6 peer", func(t *testing.T) {
		srv := newSrv(t, []string{"0.0.0.0/0"})
		if c := hit(srv, "203.0.113.9:1", distinct...); limited(c) {
			t.Fatalf("%v", c)
		}
		if c := hit(srv, "[2001:db8::9]:1", distinct...); !limited(c) {
			t.Fatalf("::/0 semantics leaked into 0.0.0.0/0: %v", c)
		}
	})
	t.Run("unparsable entries refuse to start", func(t *testing.T) {
		for _, bad := range []string{"fe80::1%en0", "127.0.0.1:8080", "proxy.internal", "10.0.0.0/33", "127.0.0.1/", "1.2.3"} {
			func() {
				defer func() {
					if recover() == nil {
						t.Errorf("FINDING: %q accepted", bad)
					}
				}()
				newSrv(t, []string{bad})
			}()
		}
	})
	t.Run("a non-address XFF from the proxy falls back to the proxy's bucket", func(t *testing.T) {
		srv := newSrv(t, []string{"127.0.0.1"})
		if c := hit(srv, "127.0.0.1:1", "unknown", "unknown", "unknown", "unknown"); !limited(c) {
			t.Fatalf("%v", c)
		}
	})
}

// ---------------------------------------------------------------------------
// CONFIRMATION: no stage or temp file outlives a putBlob that answered 200
// (equal epoch, both short-circuits), 400 (short, epoch out of range) or 201.
func TestR8StageFilesNeverOutliveTheRequest(t *testing.T) {
	e, _, dir := r7env(t)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault
	id := hexID("r8-stage")
	e.do("PUT", base+"/blobs/"+id, a.token, blob(1, "first"), authHdr(vault)).expect(t, 201)
	e.do("PUT", base+"/blobs/"+id, a.token, blob(1, "again"), authHdr(vault)).expect(t, 200)
	e.do("PUT", base+"/blobs/"+hexID("r8-short"), a.token, []byte{0x01, 1, 0, 0, 0}, authHdr(vault)).expect(t, 400)
	e.do("PUT", base+"/blobs/"+hexID("r8-epoch"), a.token, blob(9, "future"), authHdr(vault)).expect(t, 400)
	if lo := leftovers(t, dir, vault); len(lo) > 0 {
		t.Fatalf("leftover upload files: %v", lo)
	}
}
