package api_test

// Adversarial tests: every route is probed with the wrong token, the wrong
// vault, a revoked device, malformed ids, oversized bodies, and brute-force
// patterns. These encode the access-control rules in DESIGN.md §4.4–4.6.

import (
	"bytes"
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
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": []string{b.id}, "keybox": rows}, nil).expect(t, 200)
	for _, p := range []string{"", "/snapshot", "/keybox"} {
		e.do("GET", base+p, b.token, nil, nil).expect(t, 401)
	}
	e.do("POST", base+"/ops", b.token, []opIn{put("x", nil, 0)}, nil).expect(t, 401)
	e.do("POST", base+"/keybox", b.token, map[string]any{"keybox": rows}, nil).expect(t, 401)
	// A revoked device cannot be a keybox recipient any more.
	e.do("POST", base+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)}}}, nil).expect(t, 400)
	// Garbage and empty tokens.
	for _, tok := range []string{"", "Bearer", "dv_", "dv_" + strings.Repeat("A", 43), adminTok + "x", "in_whatever", "rc_whatever"} {
		e.do("GET", base, tok, nil, nil).expect(t, 401)
	}
	// Token in query is only honoured for the WebSocket route; here it is just absent.
	e.do("GET", base+"?token="+a.token, "", nil, nil).expect(t, 401)
}

func TestInviteLifecycle(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	var inv store.Invite
	// TTL is capped by the server's InviteTTL and a short one is honoured.
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": randBytes(8), "ttl_seconds": 1}, nil).expect(t, 201).json(t, &inv)
	time.Sleep(1100 * time.Millisecond)
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 401)
	// Unknown token, missing pub_kex, empty keybox.
	e.do("POST", "/v1/invites/in_nope", "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 401)
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": randBytes(8)}, nil).expect(t, 201).json(t, &inv)
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": []byte{}}, nil).expect(t, 400)
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": []byte{}}, nil).expect(t, 400)
	// A device cannot mint an invite for a vault it is not in (403 via device()).
	v2, _, _ := e.setup()
	e.do("POST", "/v1/vaults/"+v2+"/invites", a.token, map[string]any{"keybox_enc": randBytes(8)}, nil).expect(t, 403)
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
			r := e.do(m, base+"/blobs/"+id, a.token, blob(1, "x"), map[string]string{"Content-Type": "application/octet-stream"})
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
	e.do("POST", base+"/ops", a.token, []byte(`[{"op_id":"z","evil":1}]`), map[string]string{"Content-Type": "application/json"}).expect(t, 400)
	e.do("POST", base+"/ops", a.token, []byte(`{"op_id":"z"}`), map[string]string{"Content-Type": "application/json"}).expect(t, 400)
	e.do("POST", base+"/ops", a.token, []opIn{}, nil).expect(t, 400)
	// Keybox rows for a future epoch or an unknown recipient.
	e.do("POST", base+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 5, RecipientID: a.id, Wrapped: randBytes(9)}}}, nil).expect(t, 400)
	e.do("POST", base+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: "nobody", Wrapped: randBytes(9)}}}, nil).expect(t, 400)
	// Restore needs a positive time; patch needs a real seq.
	e.do("POST", base+"/restore", a.token, map[string]any{"at": 0}, nil).expect(t, 400)
	e.do("PATCH", base+"/ops/999/meta", a.token, map[string]any{"meta_enc": randBytes(4), "meta_epoch": 1}, nil).expect(t, 404)
	e.do("PATCH", base+"/ops/abc/meta", a.token, map[string]any{"meta_enc": randBytes(4), "meta_epoch": 1}, nil).expect(t, 400)
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
	// Recovery lookups share the unauthenticated bucket.
	if e.do("GET", "/v1/vaults/"+vault+"/recovery", "", nil, nil).code != 429 {
		t.Fatal("recovery lookup should be throttled with the same bucket")
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
	r := e.do("GET", "/v1/vaults/"+v1+"/live?token="+a2.token, "", nil, map[string]string{"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="})
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
