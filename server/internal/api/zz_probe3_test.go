package api_test

// Throwaway round-two verification probes. Delete after the review.

import (
	"bytes"
	"testing"

	"obsync/internal/store"
)

func enrolViaAdmin(e *env, vault string) device {
	var inv store.Invite
	var red store.Redeemed
	e.do("POST", "/v1/vaults/"+vault+"/invites", adminTok, map[string]any{"keybox_enc": randBytes(64)}, nil).expect(e.t, 201).json(e.t, &inv)
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65), "name_enc": randBytes(20)}, nil).expect(e.t, 201).json(e.t, &red)
	d := device{red.DeviceID, red.DeviceToken}
	e.do("POST", "/v1/vaults/"+vault+"/keybox", d.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: d.id, Wrapped: randBytes(100)}}}, nil).expect(e.t, 204)
	return d
}

// (1) Token-only caller: every write route.
func TestProbe3TokenOnlyIsReadOnly(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	var rec struct {
		DeviceID string `json:"device_id"`
	}
	e.do("PUT", base+"/recovery", a.token, map[string]any{"pub_kex": randBytes(65), "recovery_enc": randBytes(80), "salt": randBytes(16), "auth": "rc_x"}, authHdr(vault)).expect(t, 201).json(t, &rec)
	bogus := map[string]string{"X-Obsync-Vault-Auth": newAuthTok()}
	for _, hdr := range []map[string]string{nil, bogus} {
		t.Logf("--- headers=%v", hdr)
		t.Logf("PUT blob never-seen id: %d", e.do("PUT", base+"/blobs/"+hexID("never"), b.token, blob(1, "x"), merge(hdr, "Content-Type", "application/octet-stream")).code)
		t.Logf("PUT blob never-seen id + X-Blob-Replace: %d", e.do("PUT", base+"/blobs/"+hexID("never2"), b.token, blob(1, "x"), merge(merge(hdr, "Content-Type", "application/octet-stream"), "X-Blob-Replace", "1")).code)
		t.Logf("POST ops: %d", e.do("POST", base+"/ops", b.token, []opIn{put("x", nil, 0)}, hdr).code)
		t.Logf("POST restore: %d", e.do("POST", base+"/restore", b.token, map[string]any{"at": 1}, hdr).code)
		t.Logf("POST keybox rows for recovery id: %d", e.do("POST", base+"/keybox", b.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: rec.DeviceID, Wrapped: randBytes(100)}}}, hdr).code)
		t.Logf("POST keybox rows for A: %d", e.do("POST", base+"/keybox", b.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: a.id, Wrapped: randBytes(100)}}}, hdr).code)
		t.Logf("POST keybox self row (harmless): %d", e.do("POST", base+"/keybox", b.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: b.id, Wrapped: randBytes(100)}}}, hdr).code)
		t.Logf("PATCH meta: %d", e.do("PATCH", base+"/ops/1/meta", b.token, map[string]any{"meta_enc": randBytes(4), "meta_epoch": 1}, hdr).code)
		t.Logf("POST rotate: %d", e.do("POST", base+"/rotate", b.token, map[string]any{"epoch": 2, "revoke": []string{a.id}, "keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)}}, "auth_next": newAuthTok()}, hdr).code)
		t.Logf("PUT recovery: %d", e.do("PUT", base+"/recovery", b.token, map[string]any{"pub_kex": randBytes(65), "recovery_enc": randBytes(80), "salt": randBytes(16), "auth": "rc_y"}, hdr).code)
		t.Logf("POST invites: %d", e.do("POST", base+"/invites", b.token, map[string]any{"keybox_enc": randBytes(8)}, hdr).code)
		t.Logf("POST auth (replace): %d", e.do("POST", base+"/auth", b.token, map[string]any{"auth": newAuthTok()}, hdr).code)
		t.Logf("PATCH devices/me: %d", e.do("PATCH", base+"/devices/me", b.token, map[string]any{"name_enc": randBytes(20)}, hdr).code)
	}
}

func merge(m map[string]string, k, v string) map[string]string {
	out := map[string]string{}
	for kk, vv := range m {
		out[kk] = vv
	}
	out[k] = v
	return out
}

// (2) Authority claim rules.
func TestProbe3AuthorityClaim(t *testing.T) {
	e := newEnv(t)
	// Two-device vault, no auth_hash (legacy).
	var v store.Vault
	e.do("POST", "/v1/vaults", adminTok, nil, nil).expect(t, 201).json(t, &v)
	a := enrolViaAdmin(e, v.ID)
	b := enrolViaAdmin(e, v.ID)
	base := "/v1/vaults/" + v.ID
	t.Logf("legacy 2-device: A claim %d, B claim %d", e.do("POST", base+"/auth", a.token, map[string]any{"auth": newAuthTok()}, nil).code, e.do("POST", base+"/auth", b.token, map[string]any{"auth": newAuthTok()}, nil).code)
	adminTokn := newAuthTok()
	t.Logf("legacy 2-device: admin sets %d", e.do("POST", base+"/auth", adminTok, map[string]any{"auth": adminTokn}, nil).code)
	t.Logf("A invite with admin-set authority: %d", e.do("POST", base+"/invites", a.token, map[string]any{"keybox_enc": randBytes(8)}, map[string]string{"X-Obsync-Vault-Auth": adminTokn}).code)
	t.Logf("admin REPLACES existing authority: %d", e.do("POST", base+"/auth", adminTok, map[string]any{"auth": newAuthTok()}, nil).code)
	t.Logf("A invite with old authority after admin replace: %d", e.do("POST", base+"/invites", a.token, map[string]any{"keybox_enc": randBytes(8)}, map[string]string{"X-Obsync-Vault-Auth": adminTokn}).code)
	var info store.Vault
	e.do("GET", base, a.token, nil, nil).expect(t, 200).json(t, &info)
	t.Logf("GET vault has_auth=%v", info.HasAuth)

	// Single-device vault: first device claims.
	e.do("POST", "/v1/vaults", adminTok, nil, nil).expect(t, 201).json(t, &v)
	c := enrolViaAdmin(e, v.ID)
	base = "/v1/vaults/" + v.ID
	t.Logf("single-device first claim: %d", e.do("POST", base+"/auth", c.token, map[string]any{"auth": newAuthTok()}, nil).code)

	// Race: second device enrolled (admin invite) between first enrolment and its claim.
	e.do("POST", "/v1/vaults", adminTok, nil, nil).expect(t, 201).json(t, &v)
	d1 := enrolViaAdmin(e, v.ID)
	d2 := enrolViaAdmin(e, v.ID)
	base = "/v1/vaults/" + v.ID
	t.Logf("race: d1 claim %d, d2 claim %d, admin %d", e.do("POST", base+"/auth", d1.token, map[string]any{"auth": newAuthTok()}, nil).code, e.do("POST", base+"/auth", d2.token, map[string]any{"auth": newAuthTok()}, nil).code, e.do("POST", base+"/auth", adminTok, map[string]any{"auth": newAuthTok()}, nil).code)

	// Legacy single-device vault WITH data: token-only thief of the lone device claims.
	e.do("POST", "/v1/vaults", adminTok, nil, nil).expect(t, 201).json(t, &v)
	l := enrolViaAdmin(e, v.ID)
	base = "/v1/vaults/" + v.ID
	// simulate pre-authority data: set auth, write, then clear auth via admin? There is no clear; instead just note the claim rule ignores data.
	t.Logf("legacy single-device thief claim: %d (rule checks live==1 only, not whether the vault already has ops)", e.do("POST", base+"/auth", l.token, map[string]any{"auth": newAuthTok()}, nil).code)
	// Does revoked/recovery count toward live? recovery=0 filter present; fine.
}

// (3) Blob poisoning needs keys; key-holder replace semantics.
func TestProbe3BlobReplace(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	id := hexID("doc")
	real := blob(1, "real")
	ah := map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]}
	t.Logf("B (no keys) creates never-seen id: %d", e.upload(vault, b, id, blob(1, "GARBAGE")).code)
	t.Logf("A upload: %d", e.do("PUT", base+"/blobs/"+id, a.token, real, ah).code)
	t.Logf("A plain re-upload (different bytes): %d", e.do("PUT", base+"/blobs/"+id, a.token, blob(1, "other"), ah).code)
	g := e.do("GET", base+"/blobs/"+id, a.token, nil, nil)
	t.Logf("  stored still 'real': %v", bytes.Contains(g.body, []byte("real")))
	repl := merge(ah, "X-Blob-Replace", "1")
	t.Logf("A replace same epoch: %d", e.do("PUT", base+"/blobs/"+id, a.token, blob(1, "repaired"), repl).code)
	g = e.do("GET", base+"/blobs/"+id, a.token, nil, nil)
	t.Logf("  stored now 'repaired': %v", bytes.Contains(g.body, []byte("repaired")))
	t.Logf("B replace with bogus authority: %d", e.do("PUT", base+"/blobs/"+id, b.token, blob(1, "GARBAGE"), merge(merge(map[string]string{"Content-Type": "application/octet-stream"}, "X-Obsync-Vault-Auth", newAuthTok()), "X-Blob-Replace", "1")).code)
	// Rotate; replace with a lower-epoch body must be a no-op.
	next := newAuthTok()
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": nil, "keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}, {Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)}}, "auth_next": next}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next
	ah2 := merge(ah, "X-Obsync-Vault-Auth", next)
	t.Logf("A re-encrypt at epoch 2 (no replace header): %d", e.do("PUT", base+"/blobs/"+id, a.token, blob(2, "e2"), ah2).code)
	t.Logf("A replace with epoch-1 body after rotation: %d", e.do("PUT", base+"/blobs/"+id, a.token, blob(1, "stale"), merge(ah2, "X-Blob-Replace", "1")).code)
	g = e.do("GET", base+"/blobs/"+id, a.token, nil, nil)
	t.Logf("  stored 'e2': %v hdr=%s", bytes.Contains(g.body, []byte("e2")), g.hdr.Get("X-Blob-Epoch"))
}
