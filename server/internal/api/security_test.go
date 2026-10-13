package api_test

// Adversarial tests: every route is probed with the wrong token, the wrong
// vault, a revoked device, malformed ids, oversized bodies, and brute-force
// patterns. These encode the access-control rules in DESIGN.md §4.4–4.6.

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"obsync/internal/api"
	"obsync/internal/blobstore"
	"obsync/internal/store"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func TestCrossVaultIsolation(t *testing.T) {
	e := newEnv(t)
	v1, a1, _ := e.setup()
	v2, a2, _ := e.setup()
	bid := hexID("iso")
	e.upload(v1, a1, bid, blob(1, "v1 data")).expect(t, 201)
	e.ops(v1, a1, put("f.md", str(bid), 0))

	// Every device route on vault 1 rejects a vault-2 device, before touching data.
	routes := []struct{ method, path string }{
		{"GET", "/snapshot"}, {"GET", "/changes?since=0"}, {"GET", "/devices"}, {"GET", "/keybox"},
		{"POST", "/keybox"}, {"POST", "/rotate"}, {"PUT", "/recovery"}, {"POST", "/blobs/missing"},
		{"GET", "/blobs?epoch_lt=9"}, {"PUT", "/blobs/" + bid}, {"GET", "/blobs/" + bid}, {"POST", "/ops"},
		{"GET", "/ops?from=0"}, {"PATCH", "/ops/1/meta"}, {"GET", "/history?path_id=" + hexID("f.md")},
		{"POST", "/restore"}, {"POST", "/invites"}, {"PATCH", "/devices/me"}, {"GET", ""},
	}
	for _, rt := range routes {
		r := e.do(rt.method, "/v1/vaults/"+v1+rt.path, a2.token, []byte("{}"), nil)
		if r.code != 403 {
			t.Errorf("%s %s with other vault's token: got %d want 403", rt.method, rt.path, r.code)
		}
	}
	// Blob ids are content-addressed per vault; vault 2 cannot read vault 1's blob even by id.
	e.do("GET", "/v1/vaults/"+v2+"/blobs/"+bid, a2.token, nil, nil).expect(t, 404)
	// Admin token is not a data token.
	for _, p := range []string{"/snapshot", "/changes?since=0", "/blobs/" + bid, "/keybox", "/devices"} {
		e.do("GET", "/v1/vaults/"+v1+p, adminTok, nil, nil).expect(t, 401)
	}
	e.do("POST", "/v1/vaults/"+v1+"/ops", adminTok, []opIn{put("x", nil, 0)}, nil).expect(t, 401)
}

func TestRevokedAndBogusTokens(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	// Revoke B via rotation.
	rows := []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}}
	next := newAuthTok()
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": []string{b.id}, "keybox": rows, "auth_next": next}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next
	for _, p := range []string{"", "/snapshot", "/keybox"} {
		e.do("GET", base+p, b.token, nil, nil).expect(t, 401)
	}
	e.do("POST", base+"/ops", b.token, []opIn{put("x", nil, 0)}, nil).expect(t, 401)
	e.do("POST", base+"/keybox", b.token, map[string]any{"keybox": rows}, nil).expect(t, 401)
	// A revoked device cannot be a keybox recipient any more.
	e.do("POST", base+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)}}}, authHdr(vault)).expect(t, 400)
	// Garbage and empty tokens.
	for _, tok := range []string{"", "Bearer", "dv_", "dv_" + strings.Repeat("A", 43), adminTok + "x", "in_whatever", "rc_whatever"} {
		e.do("GET", base, tok, nil, nil).expect(t, 401)
	}
	// Tokens in the query string are never honoured.
	e.do("GET", base+"?token="+a.token, "", nil, nil).expect(t, 401)
}

// A stolen device token without the vault keys (proxy log, copied
// data.json with sealed keys) must not be able to destroy data, lock the
// owner out, add devices, or hand itself keys at the next rotation.
func TestTokenOnlyAttackerCannotDestroyOrEscalate(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	bid := hexID("victim")
	e.upload(vault, a, bid, blob(1, "victim-bytes")).expect(t, 201)
	e.ops(vault, a, put("victim.md", str(bid), 0))
	recAuth := "rc_" + hex.EncodeToString(randBytes(16))
	var rec struct {
		DeviceID string `json:"device_id"`
	}
	e.do("PUT", base+"/recovery", a.token, map[string]any{"pub_kex": randBytes(65), "recovery_enc": randBytes(80), "salt": randBytes(16), "auth": recAuth}, authHdr(vault)).expect(t, 201).json(t, &rec)

	// b's token is the attacker's. Everything destructive is refused.
	rows := []store.KeyboxRow{{Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)}}
	e.do("POST", base+"/rotate", b.token, map[string]any{"epoch": 2, "revoke": []string{a.id}, "keybox": rows, "auth_next": newAuthTok()}, nil).expect(t, 401)
	e.do("POST", base+"/rotate", b.token, map[string]any{"epoch": 2, "revoke": []string{a.id}, "keybox": rows, "auth_next": newAuthTok()}, map[string]string{"X-Obsync-Vault-Auth": newAuthTok()}).expect(t, 401)
	e.do("PUT", base+"/recovery", b.token, map[string]any{"pub_kex": randBytes(65), "recovery_enc": randBytes(80), "salt": randBytes(16), "auth": "rc_mine"}, nil).expect(t, 401)
	e.do("PATCH", base+"/ops/1/meta", b.token, map[string]any{"meta_enc": randBytes(40), "meta_epoch": 1}, nil).expect(t, 401)
	e.do("POST", base+"/invites", b.token, map[string]any{"keybox_enc": randBytes(8)}, nil).expect(t, 401)
	e.do("POST", base+"/auth", b.token, map[string]any{"auth": newAuthTok()}, nil).expect(t, 409)
	// Ciphertext cannot be replaced in place without the keys, even with a higher epoch header.
	// (First rotate legitimately so epoch 2 exists.)
	next := newAuthTok()
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": nil, "keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}, {Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)}, {Epoch: 2, RecipientID: rec.DeviceID, Wrapped: randBytes(100)}}, "auth_next": next}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next
	noAuth := map[string]string{"Content-Type": "application/octet-stream"}
	e.do("PUT", base+"/blobs/"+bid, b.token, blob(2, "garbage"), noAuth).expect(t, 401)
	r := e.do("GET", base+"/blobs/"+bid, a.token, nil, nil).expect(t, 200)
	if !bytes.Contains(r.body, []byte("victim-bytes")) || r.hdr.Get("X-Blob-Epoch") != "1" {
		t.Fatalf("blob was replaced by a token-only caller: epoch=%s", r.hdr.Get("X-Blob-Epoch"))
	}
	// A device token alone is read-only: no new blobs, no ops, no restore
	// (so no blob-id poisoning and no mass deletes without the keys).
	e.do("PUT", base+"/blobs/"+hexID("fresh"), b.token, blob(2, "fresh"), noAuth).expect(t, 401)
	e.do("POST", base+"/ops", b.token, []opIn{put("x.md", nil, 0)}, nil).expect(t, 401)
	e.do("POST", base+"/restore", b.token, map[string]any{"at": 1}, nil).expect(t, 401)
	// Reading still works.
	e.do("GET", base+"/blobs/"+bid, b.token, nil, nil).expect(t, 200)
	e.do("GET", base+"/changes?since=0", b.token, nil, nil).expect(t, 200)
	// Keybox rows for the recovery identity need authority too (no pre-emption window).
	e.do("POST", base+"/keybox", b.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: rec.DeviceID, Wrapped: randBytes(100)}}}, nil).expect(t, 401)
	e.do("POST", base+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: rec.DeviceID, Wrapped: randBytes(100)}}}, authHdr(vault)).expect(t, 409) // rotation already wrote it; insert-only
	// A key holder can repair a blob in place at the same epoch; a plain re-upload is a no-op.
	e.do("PUT", base+"/blobs/"+bid, a.token, blob(2, "repaired"), map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]}).expect(t, 201)
	e.do("PUT", base+"/blobs/"+bid, a.token, blob(2, "ignored"), map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]}).expect(t, 200)
	e.do("PUT", base+"/blobs/"+bid, a.token, blob(2, "repaired-again"), map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault], "X-Blob-Replace": "1"}).expect(t, 201)
	r = e.do("GET", base+"/blobs/"+bid, a.token, nil, nil).expect(t, 200)
	if !bytes.Contains(r.body, []byte("repaired-again")) {
		t.Fatalf("same-epoch replace by a key holder failed")
	}
	// Everyone is still enrolled and recovery is intact.
	e.do("GET", base, a.token, nil, nil).expect(t, 200)
	e.do("GET", base+"/recovery", "", nil, nil).expect(t, 200)
	// Keybox: a member may not touch another device's rows.
	e.do("POST", base+"/keybox", b.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}}}, nil).expect(t, 401)
	var kb struct{ Keybox []store.KeyboxRow }
	e.do("GET", base+"/keybox", a.token, nil, nil).expect(t, 200).json(t, &kb)
	if len(kb.Keybox) != 2 {
		t.Fatalf("A's keybox altered: %+v", kb.Keybox)
	}
}

// Vault authority can be claimed only by the first device. A multi-device
// vault without one (created before §5.8) gets it from the admin, never
// from a member that merely holds a token.
func TestAuthorityClaimRules(t *testing.T) {
	e := newEnv(t)
	var v store.Vault
	e.do("POST", "/v1/vaults", adminTok, nil, nil).expect(t, 201).json(t, &v)
	enrol := func() device {
		var inv store.Invite
		e.do("POST", "/v1/vaults/"+v.ID+"/invites", adminTok, map[string]any{"keybox_enc": randBytes(64)}, nil).expect(t, 201).json(t, &inv)
		var red store.Redeemed
		e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 201).json(t, &red)
		return device{red.DeviceID, red.DeviceToken}
	}
	a := enrol()
	b := enrol()
	base := "/v1/vaults/" + v.ID
	var info store.Vault
	e.do("GET", base, a.token, nil, nil).expect(t, 200).json(t, &info)
	if info.HasAuth {
		t.Fatal("fresh vault should report has_auth=false")
	}
	// Two live devices and no authority: neither device may claim it.
	e.do("POST", base+"/auth", b.token, map[string]any{"auth": newAuthTok()}, nil).expect(t, 401)
	e.do("POST", base+"/auth", a.token, map[string]any{"auth": newAuthTok()}, nil).expect(t, 401)
	// And nothing can be written meanwhile (no authority exists to present).
	e.do("POST", base+"/ops", a.token, []opIn{put("x.md", nil, 0)}, map[string]string{"X-Obsync-Vault-Auth": newAuthTok()}).expect(t, 401)
	// The admin installs it (token obtained from a key-holding device's settings).
	tok := newAuthTok()
	e.do("POST", base+"/auth", adminTok, map[string]any{"auth": tok}, nil).expect(t, 204)
	e.do("GET", base, a.token, nil, nil).expect(t, 200).json(t, &info)
	if !info.HasAuth {
		t.Fatal("has_auth should be true after admin install")
	}
	e.do("POST", base+"/ops", a.token, []opIn{put("x.md", nil, 0)}, map[string]string{"X-Obsync-Vault-Auth": tok}).expect(t, 200)
	// A member cannot replace it; the admin can.
	e.do("POST", base+"/auth", b.token, map[string]any{"auth": newAuthTok()}, nil).expect(t, 409)
	e.do("POST", base+"/auth", adminTok, map[string]any{"auth": newAuthTok()}, nil).expect(t, 204)
	e.do("POST", base+"/ops", a.token, []opIn{put("y.md", nil, 0)}, map[string]string{"X-Obsync-Vault-Auth": tok}).expect(t, 401)
	// A single-device vault: the first device claims it itself.
	var v2 store.Vault
	e.do("POST", "/v1/vaults", adminTok, nil, nil).expect(t, 201).json(t, &v2)
	var inv store.Invite
	e.do("POST", "/v1/vaults/"+v2.ID+"/invites", adminTok, map[string]any{"keybox_enc": randBytes(64)}, nil).expect(t, 201).json(t, &inv)
	var red store.Redeemed
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 201).json(t, &red)
	e.do("POST", "/v1/vaults/"+v2.ID+"/auth", red.DeviceToken, map[string]any{"auth": newAuthTok()}, nil).expect(t, 204)
	// A legacy single-device vault that already holds data is not claimable by its token either.
	var v3 store.Vault
	e.do("POST", "/v1/vaults", adminTok, nil, nil).expect(t, 201).json(t, &v3)
	e.do("POST", "/v1/vaults/"+v3.ID+"/invites", adminTok, map[string]any{"keybox_enc": randBytes(64)}, nil).expect(t, 201).json(t, &inv)
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 201).json(t, &red)
	legacyTok := newAuthTok()
	e.do("POST", "/v1/vaults/"+v3.ID+"/auth", adminTok, map[string]any{"auth": legacyTok}, nil).expect(t, 204) // simulate: data was written under an admin-installed token…
	e.do("POST", "/v1/vaults/"+v3.ID+"/ops", red.DeviceToken, []opIn{put("old.md", nil, 0)}, map[string]string{"X-Obsync-Vault-Auth": legacyTok}).expect(t, 200)
	// …then imagine the hash were absent (pre-§5.8 DB): clear it the way a migration would leave it.
	if _, err := e.st.DB().Exec(`UPDATE vaults SET auth_hash=NULL WHERE id=?`, v3.ID); err != nil {
		t.Fatal(err)
	}
	e.do("POST", "/v1/vaults/"+v3.ID+"/auth", red.DeviceToken, map[string]any{"auth": newAuthTok()}, nil).expect(t, 401)
	e.do("POST", "/v1/vaults/"+v3.ID+"/auth", adminTok, map[string]any{"auth": newAuthTok()}, nil).expect(t, 204)
}

// A device revoked while its long-poll is open gets nothing from it, and an
// open WebSocket is closed.
func TestRevocationCutsOpenStreams(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(e.ts.URL, "http") + base + "/live"
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{"obsync-bearer", b.token}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	var h api.Hint
	if err := wsjson.Read(ctx, c, &h); err != nil {
		t.Fatal(err)
	}
	type pollRes struct {
		code int
		body string
	}
	polled := make(chan pollRes, 1)
	go func() {
		r := e.do("GET", base+"/changes?since=0&wait=5", b.token, nil, nil)
		polled <- pollRes{r.code, string(r.body)}
	}()
	time.Sleep(200 * time.Millisecond)
	next := newAuthTok()
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": []string{b.id}, "keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}}, "auth_next": next}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next
	bid := hexID("after")
	e.upload(vault, a, bid, blob(2, "after")).expect(t, 201)
	e.ops(vault, a, put("after.md", str(bid), 0))
	res := <-polled
	if res.code != 401 || strings.Contains(res.body, bid) {
		t.Fatalf("revoked long-poll delivered data: %d %s", res.code, res.body)
	}
	if err := wsjson.Read(ctx, c, &h); err == nil {
		t.Fatal("revoked websocket still streaming")
	}
}

// List routes are bounded whatever the caller asks for.
func TestListLimitsAreClamped(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault
	for _, q := range []string{"?limit=-1", "?limit=0", "?limit=999999999", "?meta_epoch_lt=9&limit=-1", "?epoch_lt=9&limit=-1"} {
		for _, p := range []string{"/ops", "/blobs"} {
			if r := e.do("GET", base+p+q, a.token, nil, nil); r.code != 200 && r.code != 400 {
				t.Fatalf("%s%s: %d %s", p, q, r.code, r.body)
			}
		}
	}
	big := make([]string, 5001)
	for i := range big {
		big[i] = hexID(fmt.Sprint(i))
	}
	e.do("POST", base+"/blobs/missing", a.token, big, nil).expect(t, 400)
	e.do("POST", base+"/blobs/missing", a.token, big[:5000], nil).expect(t, 200)
}

func TestInviteLifecycle(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	var inv store.Invite
	// TTL is capped by the server's InviteTTL and a short one is honoured.
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": randBytes(8), "ttl_seconds": 1}, authHdr(vault)).expect(t, 201).json(t, &inv)
	time.Sleep(1100 * time.Millisecond)
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 401)
	// Unknown token, missing pub_kex, empty keybox.
	e.do("POST", "/v1/invites/in_nope", "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 401)
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": randBytes(8)}, authHdr(vault)).expect(t, 201).json(t, &inv)
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": []byte{}}, nil).expect(t, 400)
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": []byte{}}, authHdr(vault)).expect(t, 400)
	// A device cannot mint an invite for a vault it is not in (403 via device()).
	v2, _, _ := e.setup()
	e.do("POST", "/v1/vaults/"+v2+"/invites", a.token, map[string]any{"keybox_enc": randBytes(8)}, authHdr(v2)).expect(t, 403)
	// The invite keybox is wiped after redemption even if the row lingers.
	var red store.Redeemed
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 201).json(t, &red)
	if len(red.KeyboxEnc) == 0 {
		t.Fatal("redeem should return the keybox")
	}
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 401)
}

func TestInputValidation(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault
	// Path traversal / odd ids never reach the filesystem.
	// Path-like ids are stopped either by the router (404/301) or by id validation (400); never served.
	for _, id := range []string{"../../etc/passwd", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64), "%2e%2e", "%2e%2e%2f%2e%2e"} {
		for _, m := range []string{"PUT", "GET"} {
			r := e.do(m, base+"/blobs/"+id, a.token, blob(1, "x"), map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]})
			if r.code != 400 && r.code != 404 && r.code != 301 {
				t.Errorf("%s blob id %q: got %d", m, id, r.code)
			}
		}
	}
	// Ops with bad fields are rejected individually without aborting the batch.
	good := hexID("ok")
	e.upload(vault, a, good, blob(1, "ok")).expect(t, 201)
	out := e.ops(vault, a,
		opIn{OpID: "", PathID: hexID("p"), MetaEnc: []byte{1}, MetaEpoch: 1},
		opIn{OpID: "a", PathID: "nope", MetaEnc: []byte{1}, MetaEpoch: 1},
		opIn{OpID: "b", PathID: hexID("p"), BlobID: str("zz"), MetaEnc: []byte{1}, MetaEpoch: 1},
		opIn{OpID: "c", PathID: hexID("p"), MetaEnc: nil, MetaEpoch: 1},
		opIn{OpID: "d", PathID: hexID("p"), MetaEnc: []byte{1}, MetaEpoch: 0},
		opIn{OpID: "e", PathID: hexID("p"), MetaEnc: []byte{1}, MetaEpoch: 1, BaseSeq: -1},
		opIn{OpID: strings.Repeat("x", 65), PathID: hexID("p"), MetaEnc: []byte{1}, MetaEpoch: 1},
		put("fine.md", str(good), 0),
	)
	for i := 0; i < 7; i++ {
		if out.Results[i].Error == "" {
			t.Errorf("op %d should be rejected: %+v", i, out.Results[i])
		}
	}
	if out.Results[7].Seq != 1 {
		t.Fatalf("valid op in a batch with bad ones should commit: %+v", out.Results[7])
	}
	// Unknown JSON fields and non-array bodies are rejected.
	e.do("POST", base+"/ops", a.token, []byte(`[{"op_id":"z","evil":1}]`), map[string]string{"Content-Type": "application/json", "X-Obsync-Vault-Auth": authTok[vault]}).expect(t, 400)
	e.do("POST", base+"/ops", a.token, []byte(`{"op_id":"z"}`), map[string]string{"Content-Type": "application/json", "X-Obsync-Vault-Auth": authTok[vault]}).expect(t, 400)
	e.do("POST", base+"/ops", a.token, []opIn{}, authHdr(vault)).expect(t, 400)
	// Keybox rows for a future epoch or an unknown recipient.
	e.do("POST", base+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 5, RecipientID: a.id, Wrapped: randBytes(9)}}}, nil).expect(t, 400)
	e.do("POST", base+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: "nobody", Wrapped: randBytes(9)}}}, authHdr(vault)).expect(t, 400)
	// Restore needs a positive time; patch needs a real seq.
	e.do("POST", base+"/restore", a.token, map[string]any{"at": 0}, authHdr(vault)).expect(t, 400)
	e.do("PATCH", base+"/ops/999/meta", a.token, map[string]any{"meta_enc": randBytes(4), "meta_epoch": 1}, authHdr(vault)).expect(t, 404)
	e.do("PATCH", base+"/ops/abc/meta", a.token, map[string]any{"meta_enc": randBytes(4), "meta_epoch": 1}, authHdr(vault)).expect(t, 400)
}

func TestBlobSizeLimit(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir + "/db.sqlite")
	bs, _ := blobstore.New(dir + "/blobs")
	srv := api.New(api.Config{AdminToken: adminTok, MaxBlobSize: 100, InviteTTL: time.Hour, AuthRatePerMinute: -1}, st, bs)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	e := &env{t: t, ts: ts, srv: srv, st: st}
	vault, a, _ := e.setup()
	e.upload(vault, a, hexID("big"), blob(1, strings.Repeat("x", 200))).expect(t, 413)
	e.upload(vault, a, hexID("small"), blob(1, "x")).expect(t, 201)
	// The index must not contain the rejected blob.
	var miss struct{ Missing []string }
	e.do("POST", "/v1/vaults/"+vault+"/blobs/missing", a.token, []string{hexID("big")}, nil).expect(t, 200).json(t, &miss)
	if len(miss.Missing) != 1 {
		t.Fatal("rejected blob must not be indexed")
	}
}

func TestRateLimiting(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir + "/db.sqlite")
	bs, _ := blobstore.New(dir + "/blobs")
	// 60/min with burst 5: the 6th rapid attempt from one IP is throttled.
	srv := api.New(api.Config{AdminToken: adminTok, InviteTTL: time.Hour, AuthRatePerMinute: 60, AuthBurst: 5}, st, bs)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	e := &env{t: t, ts: ts, srv: srv, st: st}
	vault, a, _ := e.setup() // uses a few unauth requests itself (2 redemptions)

	// Invite guessing.
	codes := []int{}
	for i := 0; i < 8; i++ {
		codes = append(codes, e.do("POST", "/v1/invites/in_guess"+fmt.Sprint(i), "", map[string]any{"pub_kex": randBytes(65)}, nil).code)
	}
	if codes[len(codes)-1] != 429 {
		t.Fatalf("invite guessing not throttled: %v", codes)
	}
	// The recovery salt lookup is deliberately not throttled (a throttled
	// joiner must be able to retry without spending the refilled token on
	// the salt), but the join that releases the wrapped key is.
	if c := e.do("GET", "/v1/vaults/"+vault+"/recovery", "", nil, nil).code; c == 429 {
		t.Fatal("recovery salt lookup should not share the throttle bucket")
	}
	if e.do("POST", "/v1/vaults/"+vault+"/recovery/join", "rc_guess", map[string]any{"pub_kex": randBytes(65)}, nil).code != 429 {
		t.Fatal("recovery join should be throttled with the same bucket")
	}
	// Failed device-token guessing is throttled; a valid token still works
	// (the failure bucket is only charged on failure).
	fails := []int{}
	for i := 0; i < 8; i++ {
		fails = append(fails, e.do("GET", "/v1/vaults/"+vault, "dv_guess"+fmt.Sprint(i), nil, nil).code)
	}
	if fails[0] != 401 || fails[len(fails)-1] != 429 {
		t.Fatalf("token guessing not throttled: %v", fails)
	}
	e.do("GET", "/v1/vaults/"+vault, a.token, nil, nil).expect(t, 200)
	// Admin token guessing too.
	for i := 0; i < 3; i++ {
		e.do("POST", "/v1/vaults", "ad_guess", nil, nil)
	}
	if e.do("POST", "/v1/vaults", "ad_guess", nil, nil).code != 429 {
		t.Fatal("admin guessing not throttled")
	}
	// Retry-After is advertised.
	if r := e.do("POST", "/v1/invites/in_x", "", map[string]any{"pub_kex": randBytes(65)}, nil); r.hdr.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
}

func TestWebSocketAuthAndIsolation(t *testing.T) {
	e := newEnv(t)
	v1, _, _ := e.setup()
	_, a2, _ := e.setup()
	// A vault-2 device cannot subscribe to vault 1's live feed.
	r := e.do("GET", "/v1/vaults/"+v1+"/live", "", nil, map[string]string{"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol": "obsync-bearer, " + a2.token})
	if r.code != 403 {
		t.Fatalf("live feed cross-vault: %d", r.code)
	}
}

func TestBlobContentIsOpaque(t *testing.T) {
	// The server stores exactly the bytes it was given and never inspects
	// them beyond the 33-byte header; it cannot "validate" ciphertext.
	e := newEnv(t)
	vault, a, _ := e.setup()
	payload := blob(1, "\x00\xff binary \n\r\x1b[31m")
	id := hexID("opaque")
	e.upload(vault, a, id, payload).expect(t, 201)
	r := e.do("GET", "/v1/vaults/"+vault+"/blobs/"+id, a.token, nil, nil).expect(t, 200)
	if !bytes.Equal(r.body, payload) {
		t.Fatalf("blob altered: %s vs %s", hex.EncodeToString(r.body[:8]), hex.EncodeToString(payload[:8]))
	}
	if ct := r.hdr.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content-type %q", ct)
	}
	_ = http.StatusOK
}
