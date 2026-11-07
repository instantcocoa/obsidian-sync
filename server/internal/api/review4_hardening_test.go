package api_test

// Regression tests from the fourth (hardening) review, 2026-11-07. Each was
// written as a proof that failed against the code of the day and now pins
// the fix: database files private to the server's user, IPv6 clients
// limited by /64, unused invites ended by a rotation.
//
//   go test ./internal/api/ -run Zz -count=1

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"obsync/internal/api"
	"obsync/internal/blobstore"
	"obsync/internal/store"
)

// store.Open creates obsync.db (and SQLite its -wal/-shm siblings) with the
// process umask, 0644 on every default Debian/macOS install (confirmed on the
// live deployment: -rw-r--r-- obsync.db, obsync.db-wal). Blob files are 0600
// (CreateTemp) and admin-token is 0600, so the database is the only
// world-readable artefact, and it is the one that holds recovery_enc + salt
// (an offline PBKDF2 attack on the recovery passphrase), every token hash,
// the keybox and the whole ciphertext index. Any local user, or any process
// in a shared container, reads it.
func TestZzDatabaseFilesNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "obsync.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateVault(context.Background()); err != nil { // forces the WAL and shm files into existence
		t.Fatal(err)
	}
	for _, f := range []string{"obsync.db", "obsync.db-wal", "obsync.db-shm"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			if f == "obsync.db" {
				t.Fatal(err)
			}
			continue
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %v: readable by other local users (it holds recovery_enc, token hashes and the ciphertext index); open it 0600 or set umask 077 in main", f, fi.Mode().Perm())
		}
	}
}

// The failed-auth limiter keys on the full client address. IPv6 hosts own at
// least a /64, so one machine can present 2^64 distinct keys: each request
// from a fresh interface id gets a fresh bucket (and a fresh ~100-byte map
// entry that lives ten minutes), so the limiter neither throttles nor bounds
// its own memory. Ordinary practice is to key IPv6 on the /64 (and cap the
// map). Twenty failed logins from one /64 with burst 2 should be limited.
func TestZzLimiterIPv6AddressesInOneSubnetShareABucket(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir + "/db.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bs, _ := blobstore.New(dir + "/blobs")
	srv := api.New(api.Config{AdminToken: adminTok, AuthRatePerMinute: 1, AuthBurst: 2}, st, bs)
	limited := 0
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "/v1/vaults/"+hexID("v")[:32], nil)
		req.RemoteAddr = fmt.Sprintf("[2001:db8:1:2::%x]:4242", i+1) // one /64, twenty interface ids
		req.Header.Set("Authorization", "Bearer dv_"+hex.EncodeToString(randBytes(32)))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code == 429 {
			limited++
		}
	}
	if limited == 0 {
		t.Fatalf("20 failed logins from one IPv6 /64 were never rate limited: the limiter keys on the full /128, so a single host has 2^64 free buckets (and the server allocates one per address)")
	}
}

// An invite link is "as sensitive as the vault for 24 hours" (DESIGN §5.3)
// and the documented reaction to a leak is to rotate. Rotation does not touch
// the invites table, so a link minted before the rotation still enrols a
// device afterwards: it receives a device token, a roster slot with its own
// pub_kex, K_id for ever, and every epoch key the inviter held, which opens
// all old-epoch ciphertext still on the server until re-encryption finishes.
// Rotating (or removing the inviting device) should kill outstanding invites.
func TestZzRotationLeavesOutstandingInvitesRedeemable(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	var inv store.Invite
	e.do("POST", base+"/invites", a.token, map[string]any{"keybox_enc": randBytes(64)}, authHdr(vault)).expect(t, 201).json(t, &inv)

	// The owner learns the link leaked and rotates (nothing removed).
	next := newAuthTok()
	rows := []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}, {Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)}}
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": []string{}, "keybox": rows, "auth_next": next}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next

	r := e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": testPubKex(), "name_enc": randBytes(20)}, nil)
	if r.code == 201 {
		t.Fatalf("an invite minted before the rotation still enrols a device after it (201): rotation should expire every unused invite of the vault")
	}
}
