package api_test

// Regression tests from the third adversarial review (2026-11-07; areas C
// and D of docs/SECURITY-REVIEW-GUIDE.md). Each was written as a proof that
// failed against the code of the day; each now pins the fix: the limiter
// keys on the proxy-appended address, the recovery token is not a device
// bearer, snapshots are paged and metadata is capped, and GC leaves fresh
// blobs alone.

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"obsync/internal/api"
	"obsync/internal/blobstore"
	"obsync/internal/store"
)

// With --trust-proxy the limiter keys on the FIRST X-Forwarded-For entry.
// A proxy appends the real client address, so the first entry is whatever
// the client wrote: a fresh fake address per request gives a fresh bucket
// and the limiter never fires. The real client (203.0.113.5, appended by
// the proxy) should be throttled after `burst` failures.
func TestZzXFFFirstHopSpoofBypassesLimiter(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir + "/db.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	bs, _ := blobstore.New(dir + "/blobs")
	srv := api.New(api.Config{AdminToken: adminTok, TrustedProxies: []string{"127.0.0.0/8", "::1/128"}, AuthRatePerMinute: 1, AuthBurst: 2}, st, bs)
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close(); st.Close() })

	limited := 0
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", ts.URL+"/v1/vaults/"+hexID("v")[:32], nil)
		req.Header.Set("Authorization", "Bearer dv_"+hex.EncodeToString(randBytes(32)))
		// client-supplied spoof, then the hop the trusted proxy appended
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.9.%d.%d, 203.0.113.5", i/256, i%256))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode == 429 {
			limited++
		}
	}
	if limited == 0 {
		t.Fatalf("20 failed logins from one real client behind a trusted proxy were never rate limited: the limiter keys on the client-controlled first X-Forwarded-For entry")
	}
}

// The recovery identity is a pseudo-device whose token_hash is the hash of
// the passphrase-derived rc_ token. AuthDevice does not exclude recovery
// rows, so the rc_ token works as an ordinary device bearer on every read
// route: a passphrase holder reads the vault without enrolling (no roster
// entry), and passphrase guesses get a second, independent rate bucket.
func TestZzRecoveryTokenActsAsDeviceToken(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault
	bid := hexID("secret")
	e.upload(vault, a, bid, blob(1, "ciphertext")).expect(t, 201)
	e.ops(vault, a, put("secret.md", str(bid), 0))
	rc := "rc_" + hex.EncodeToString(randBytes(32))
	e.do("PUT", base+"/recovery", a.token, map[string]any{"pub_kex": testPubKex(), "recovery_enc": randBytes(80), "salt": randBytes(16), "auth": rc}, authHdr(vault)).expect(t, 201)

	var devs struct{ Devices []store.Device }
	e.do("GET", base+"/devices", a.token, nil, nil).expect(t, 200).json(t, &devs)
	before := len(devs.Devices)

	for _, p := range []string{"", "/snapshot", "/changes?since=0", "/blobs/" + bid, "/keybox", "/devices"} {
		if r := e.do("GET", base+p, rc, nil, nil); r.code != 401 {
			t.Errorf("GET %s with the recovery rc_ token as bearer: got %d, want 401 (the rc_ token is only for POST /recovery/join)", p, r.code)
		}
	}
	// No enrolment happened, so nothing in the roster shows the read.
	e.do("GET", base+"/devices", a.token, nil, nil).expect(t, 200).json(t, &devs)
	if len(devs.Devices) != before {
		t.Fatalf("roster changed: %d -> %d", before, len(devs.Devices))
	}
}

// DESIGN §4.3: "List routes clamp limit to 5000 ... so no member can make
// the server materialise an unbounded result." Snapshot has no LIMIT: it
// returns one op per head, and a member creates heads for free (a tombstone
// needs no blob).
func TestZzSnapshotHasNoLimit(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	const n = 5001
	for i := 0; i < n; i += 1000 {
		var batch []opIn
		for j := i; j < i+1000 && j < n; j++ {
			batch = append(batch, put(fmt.Sprintf("p/%d.md", j), nil, 0))
		}
		out := e.ops(vault, a, batch...)
		for _, r := range out.Results {
			if r.Seq == 0 || r.Error != "" {
				t.Fatalf("tombstone rejected: %+v", r)
			}
		}
	}
	var snap feed
	e.do("GET", "/v1/vaults/"+vault+"/snapshot", a.token, nil, nil).expect(t, 200).json(t, &snap)
	if len(snap.Ops) > 5000 && !snap.More {
		t.Fatalf("snapshot returned %d ops in one response with more=false: no clamp, no pagination", len(snap.Ops))
	}
}

// Nothing bounds a single op's meta_enc except the 16 MiB batch body. Real
// metadata is a few hundred bytes; a member can store 16 MiB per op and make
// every changes/snapshot/history page cost up to limit × 16 MiB.
func TestZzMetaEncHasNoSizeCap(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	big := put("huge.md", nil, 0)
	big.MetaEnc = randBytes(8 << 20)
	out := e.ops(vault, a, big)
	if out.Results[0].Error == "" && out.Results[0].Seq > 0 {
		t.Fatalf("an op with an 8 MiB meta_enc was accepted (seq %d); expected a 400/400-style rejection", out.Results[0].Seq)
	}
}

// GC (DESIGN §4.5): "A blob is live if any op within the retention window
// or any current head references it." A blob that was just uploaded and
// not yet referenced by an op (the normal upload→post window) matches
// neither clause, so a sweep that overlaps a push deletes it; the op posted
// a moment later is rejected with "blob not uploaded". Expected: blobs
// younger than the retention cutoff are never collected.
func TestZzGCCollectsFreshUnreferencedBlob(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	bid := hexID("fresh")
	e.upload(vault, a, bid, blob(1, "just uploaded")).expect(t, 201)
	n, err := e.srv.GC(context.Background(), 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("GC with 90-day retention removed %d blob(s) uploaded milliseconds ago", n)
	}
	out := e.ops(vault, a, put("fresh.md", str(bid), 0))
	if out.Results[0].Error != "" {
		t.Fatalf("op after GC: %s", out.Results[0].Error)
	}
}
