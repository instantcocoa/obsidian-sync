package api_test

// Regression tests from the third adversarial review (2026-11-07; areas A,
// B, E, F of docs/SECURITY-REVIEW-GUIDE.md). Each was written as a proof
// that failed against the code of the day; each now pins the fix: names
// authenticate under their device id and need vault authority, the admin
// token cannot invite into a populated vault, a device's own keybox rows
// are write-once.

import (
	"bytes"
	"testing"

	"obsync/internal/store"
)

// A device token alone is supposed to be read-only (DESIGN §5.7, §5.8). But
// POST /keybox lets the token holder *overwrite* the device's own existing
// rows (ON CONFLICT DO UPDATE) with no vault authority. After a rotation the
// thief replaces the victim device's row for the new epoch with garbage and
// the legitimate device can never learn K_{e+1}: "no key for vault epoch 2;
// this device may have been removed". Expected: an existing row cannot be
// replaced without authority (or at all: own rows are written exactly once,
// at enrolment; rotation rows come from POST /rotate).
func TestZzTokenOnlyCannotOverwriteOwnKeyboxRow(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault

	// Owner rotates; the server stores the real epoch-2 row for b.
	realRow := randBytes(100)
	next := newAuthTok()
	e.do("POST", base+"/rotate", a.token, map[string]any{
		"epoch": 2, "revoke": nil,
		"keybox":    []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}, {Epoch: 2, RecipientID: b.id, Wrapped: realRow}},
		"auth_next": next,
	}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next

	// Attacker holds b's token only: tries to replace b's epoch-2 row.
	r := e.do("POST", base+"/keybox", b.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)}}}, nil)
	if r.code == 204 {
		t.Errorf("token-only caller replaced its own keybox row (got 204; want 401/409)")
	}
	var kb struct {
		Keybox []store.KeyboxRow `json:"keybox"`
	}
	e.do("GET", base+"/keybox", b.token, nil, nil).expect(t, 200).json(t, &kb)
	for _, row := range kb.Keybox {
		if row.Epoch == 2 && !bytes.Equal(row.Wrapped, realRow) {
			t.Fatalf("epoch-2 row for device b was overwritten by a token-only caller; the legitimate device is now locked out of epoch 2")
		}
	}
}

// PATCH /devices/me needs only a device token, and name_enc is AES-GCM with
// aad = "name" and no device id. A token-only caller can therefore copy any
// other live device's name_enc onto its own row and the roster shows two
// devices with the same decrypted name. The roster is the trust boundary
// (§5.7: "unexpected or unnamed device is flagged"), so a planted device
// should not be able to wear a legitimate device's name. Expected here: the
// write is refused without vault authority (the companion client-side fix is
// to bind the device id into the name AAD; see the vitest proof).
func TestZzTokenOnlyCannotReplayAnotherDevicesName(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	laptop := randBytes(48)
	e.do("PATCH", base+"/devices/me", a.token, map[string]any{"name_enc": laptop}, authHdr(vault)).expect(t, 204)

	var ds struct {
		Devices []store.Device `json:"devices"`
	}
	e.do("GET", base+"/devices", b.token, nil, nil).expect(t, 200).json(t, &ds)
	var stolen []byte
	for _, d := range ds.Devices {
		if d.ID == a.id {
			stolen = d.NameEnc
		}
	}
	if !bytes.Equal(stolen, laptop) {
		t.Fatalf("setup: could not read a's name_enc from the roster")
	}
	r := e.do("PATCH", base+"/devices/me", b.token, map[string]any{"name_enc": stolen}, nil)
	if r.code == 204 {
		t.Errorf("token-only caller set its own name without vault authority (got 204; want 401)")
	}
	e.do("GET", base+"/devices", a.token, nil, nil).expect(t, 200).json(t, &ds)
	for _, d := range ds.Devices {
		if d.ID == b.id && bytes.Equal(d.NameEnc, laptop) {
			t.Fatalf("device b now carries device a's name_enc: the roster shows two devices named like a")
		}
	}
}

// The admin bearer may mint invites on any vault (authorityOrAdmin). An
// admin-minted invite with an arbitrary keybox_enc enrols a device that
// holds a token and a pub_kex but no keys. At the next rotation the owner's
// client wraps K_{e+1} || K_id to every live device with a pub_kex, including
// the planted one (admin.ts rotate()). The admin is supposed to be able to
// do nothing to content beyond deletion (guide §C). Expected: the admin may
// mint an invite only while the vault has no device (the first-enrolment
// case the route exists for).
func TestZzAdminCannotMintInviteOnPopulatedVault(t *testing.T) {
	e := newEnv(t)
	vault, _, _ := e.setup()
	r := e.do("POST", "/v1/vaults/"+vault+"/invites", adminTok, map[string]any{"keybox_enc": randBytes(64)}, nil)
	if r.code == 201 {
		t.Fatalf("admin minted an invite on a vault that already has devices (201); a planted device will be wrapped K_e||K_id at the owner's next rotation")
	}
}
