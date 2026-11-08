package api_test

// Twelfth review, whole-system pass (2026-11-08). DESIGN §5.7 row 2 says a
// token-only caller (a stolen device token, no keys) can write no keybox
// rows, "its own included, once written". PutKeybox (store.go) refuses to
// REPLACE a self row that exists, but inserts a self row for any epoch in
// [1, vault.epoch] the device has none for, with no vault authority. The
// gap matters only as a statement: nothing a token thief inserts can be
// unwrapped by anyone (the row is addressed to the device's own public key
// and the engine ignores rows it cannot open), rows below min_epoch are
// never served and are pruned by GC, and future epochs arrive through
// /rotate, which the thief cannot call. So: a wording correction for §5.7,
// pinned here so the sentence and the code agree.
//
//	cd server && go test ./internal/api -run 'TestR12W' -v

import (
	"testing"

	"obsync/internal/store"
)

func TestR12WTokenOnlyCallerInsertsButCannotReplaceSelfKeyboxRows(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	// Epoch 1 has data, so min_epoch stays 1 after the rotation below.
	bid := hexID("r12w-epoch1")
	e.upload(vault, a, bid, blob(1, "epoch-1 bytes")).expect(t, 201)
	e.ops(vault, a, put("r12w.md", str(bid), 0))

	// Rotate to epoch 2, wrapping to a and b (b is honest here).
	next := newAuthTok()
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": nil, "keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}, {Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)}}, "auth_next": next}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next

	// A third device enrols at epoch 2 and, as finishEnrol does, writes only
	// the rows for the epochs its inviter handed it: epoch 2 here.
	var inv store.Invite
	e.do("POST", base+"/invites", a.token, map[string]any{"keybox_enc": randBytes(64)}, authHdr(vault)).expect(t, 201).json(t, &inv)
	var red store.Redeemed
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": testPubKex(), "name_enc": randBytes(20)}, nil).expect(t, 201).json(t, &red)
	c := device{red.DeviceID, red.DeviceToken}
	own2 := randBytes(100)
	e.do("POST", base+"/keybox", c.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: c.id, Wrapped: own2}}}, nil).expect(t, 204)

	// c's token leaks. The thief, with no X-Obsync-Vault-Auth:
	noAuth := map[string]string(nil)
	// ... cannot replace the row c wrote (confirmed, §5.7 as written);
	e.do("POST", base+"/keybox", c.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: c.id, Wrapped: randBytes(100)}}}, noAuth).expect(t, 409)
	// ... cannot write rows for another device or for a future epoch;
	e.do("POST", base+"/keybox", c.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}}}, noAuth).expect(t, 401)
	e.do("POST", base+"/keybox", c.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 3, RecipientID: c.id, Wrapped: randBytes(100)}}}, noAuth).expect(t, 400)
	// ... but CAN insert a self row for an epoch c never had one for.
	planted := randBytes(100)
	e.do("POST", base+"/keybox", c.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: c.id, Wrapped: planted}}}, noAuth).expect(t, 204)

	var kb struct {
		Keybox []store.KeyboxRow `json:"keybox"`
	}
	e.do("GET", base+"/keybox", c.token, nil, nil).expect(t, 200).json(t, &kb)
	got := map[int64]bool{}
	for _, r := range kb.Keybox {
		got[r.Epoch] = true
		if r.Epoch == 2 && string(r.Wrapped) != string(own2) {
			t.Fatalf("the device's own epoch-2 row was altered by a token-only caller")
		}
	}
	if !got[1] || !got[2] {
		t.Fatalf("expected the planted epoch-1 row to be served beside the real epoch-2 row, got epochs %v", got)
	}
	t.Logf("§5.7 wording: a token-only caller cannot replace its rows, but can add self rows for epochs ≤ %d it lacks (harmless: unopenable by anyone, pruned below min_epoch, never a future epoch)", 2)
}
