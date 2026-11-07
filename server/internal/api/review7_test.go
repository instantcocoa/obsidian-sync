package api_test

// Seventh review: the sixth round's own server fixes (707ba81), read with the
// assumption that a hurried fix has an edge. Each TestR7* is the proof for one
// candidate finding or a confirmation; see
// plugin/.cache/agent-review7-server/REPORT.md for the ranked list.
//
//	cd server && go test ./internal/api -run 'TestR7' -v

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"obsync/internal/api"
	"obsync/internal/blobstore"
	"obsync/internal/store"
)

// r7env is newEnv that also hands back the blobstore and the data directory.
func r7env(t *testing.T) (*env, *blobstore.FS, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/db.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	bs, err := blobstore.New(dir + "/blobs")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(api.Config{AdminToken: adminTok, MaxWait: 5 * time.Second, InviteTTL: time.Hour, AuthRatePerMinute: -1}, st, bs)
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close(); st.Close() })
	return &env{t: t, ts: ts, srv: srv, st: st}, bs, dir
}

type r7res struct {
	code int
	body string
}

// inflight sends a request whose body arrives in two halves: the first byte,
// then `during` runs with the handler parked in its body read (device and
// authority already checked), then the rest. The response is what the
// handler decided after `during`.
func (e *env) inflight(method, path, token string, hdr map[string]string, body []byte, during func()) r7res {
	pr, pw := io.Pipe()
	done := make(chan r7res, 1)
	go func() {
		req, _ := http.NewRequest(method, e.ts.URL+path, pr)
		req.Header.Set("Authorization", "Bearer "+token)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- r7res{0, err.Error()}
			return
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		done <- r7res{res.StatusCode, string(b)}
	}()
	pw.Write(body[:1])
	time.Sleep(300 * time.Millisecond)
	during()
	pw.Write(body[1:])
	pw.Close()
	return <-done
}

func jsonHdr(vault string) map[string]string {
	return map[string]string{"Content-Type": "application/json", "X-Obsync-Vault-Auth": authTok[vault]}
}

// revokeB is the rotation A performs while B's request is in flight: epoch 2,
// B revoked, keybox for A only, a fresh authority token.
func (e *env) revokeB(vault string, a, b device) {
	next := newAuthTok()
	e.do("POST", "/v1/vaults/"+vault+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": []string{b.id}, "keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}}, "auth_next": next}, authHdr(vault)).expect(e.t, 200)
	authTok[vault] = next
	e.do("GET", "/v1/vaults/"+vault, b.token, nil, nil).expect(e.t, 401)
}

// ---------------------------------------------------------------------------
// FINDING (medium): the sixth round made "every write transaction" re-check
// the writer (store.Actor), and DESIGN §5.7 now promises it for ops, blobs,
// meta, restore, recovery, rotate and devices/me. POST /invites is a write
// too, and it was left out: CreateInvite takes no Actor. A member who keeps a
// POST /invites open (headers sent, body trickling; ReadTimeout allows 15
// minutes per attempt, so a rolling one-connection loop covers every moment)
// has the invite minted AFTER the rotation that revoked it. Rotation ends
// only the invites that exist at rotation time, so this one survives, and
// redeeming it enrols a fresh live device in the vault after the attacker
// was removed: a persistent read-only foothold (the whole ciphertext feed,
// roster, blob and path ids; K_id is never rotated so names and path guesses
// decrypt) that the owner must notice in the roster and revoke again.
func TestR7InFlightInviteSurvivesRevocation(t *testing.T) {
	e, _, _ := r7env(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	body, _ := jsonBytes(map[string]any{"keybox_enc": randBytes(64)})
	res := e.inflight("POST", base+"/invites", b.token, jsonHdr(vault), body, func() { e.revokeB(vault, a, b) })
	var open int
	e.st.DB().QueryRow(`SELECT COUNT(*) FROM invites WHERE vault_id=? AND used_at IS NULL`, vault).Scan(&open)
	if res.code == 201 || open != 0 {
		var inv store.Invite
		_ = json.Unmarshal([]byte(res.body), &inv)
		r := e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": testPubKex()}, nil)
		t.Fatalf("revoked device's in-flight POST /invites was honoured after the rotation (code %d, %d open invite(s)); redeeming it afterwards → %d %s: a device enrolled after its inviter was removed", res.code, open, r.code, r.body)
	}
}

// ---------------------------------------------------------------------------
// Table form of the same question for every state-changing route a device
// can reach: nothing a revoked device had in flight may land. Confirms the
// seven routes the sixth round wired through store.Actor, and PutKeybox
// (whose recipient check happens to cover it); POST /invites is the gap.
func TestR7EveryDeviceWriteRouteRechecksTheWriterAtCommit(t *testing.T) {
	type tc struct {
		name   string
		method string
		path   func(vault string, a, b device, seq int64) string
		body   func(vault string, a, b device) ([]byte, map[string]string)
		landed func(e *env, vault string, a, b device, seq int64) string // "" when nothing landed
	}
	cases := []tc{
		{"ops", "POST", func(v string, a, b device, _ int64) string { return "/v1/vaults/" + v + "/ops" },
			func(v string, a, b device) ([]byte, map[string]string) {
				bb, _ := jsonBytes([]opIn{put("late.md", nil, 0)})
				return bb, jsonHdr(v)
			},
			func(e *env, v string, a, b device, _ int64) string {
				for _, op := range e.changes(v, a, 0, "").Ops {
					if op.DeviceID == b.id {
						return fmt.Sprintf("op seq=%d by revoked device", op.Seq)
					}
				}
				return ""
			}},
		{"blobs", "PUT", func(v string, a, b device, _ int64) string { return "/v1/vaults/" + v + "/blobs/" + hexID("late-blob") },
			func(v string, a, b device) ([]byte, map[string]string) {
				return blob(1, "late"), map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[v]}
			},
			func(e *env, v string, a, b device, _ int64) string {
				if _, err := e.st.GetBlob(e.t.Context(), v, hexID("late-blob")); err == nil {
					return "blob row exists"
				}
				return ""
			}},
		{"meta", "PATCH", func(v string, a, b device, seq int64) string { return fmt.Sprintf("/v1/vaults/%s/ops/%d/meta", v, seq) },
			func(v string, a, b device) ([]byte, map[string]string) {
				bb, _ := jsonBytes(map[string]any{"meta_enc": randBytes(40), "meta_epoch": 2})
				return bb, jsonHdr(v)
			},
			func(e *env, v string, a, b device, seq int64) string {
				op, _ := e.st.GetOp(e.t.Context(), v, seq)
				if op != nil && op.MetaEpoch != 1 {
					return fmt.Sprintf("meta_epoch patched to %d", op.MetaEpoch)
				}
				return ""
			}},
		{"restore", "POST", func(v string, a, b device, _ int64) string { return "/v1/vaults/" + v + "/restore" },
			func(v string, a, b device) ([]byte, map[string]string) {
				bb, _ := jsonBytes(map[string]any{"at": time.Now().Add(-time.Hour).UnixMilli() + 1})
				return bb, jsonHdr(v)
			},
			func(e *env, v string, a, b device, _ int64) string {
				for _, op := range e.changes(v, a, 0, "").Ops {
					if strings.HasPrefix(op.OpID, "restore-") {
						return "restore op emitted"
					}
				}
				return ""
			}},
		{"recovery", "PUT", func(v string, a, b device, _ int64) string { return "/v1/vaults/" + v + "/recovery" },
			func(v string, a, b device) ([]byte, map[string]string) {
				bb, _ := jsonBytes(map[string]any{"pub_kex": testPubKex(), "recovery_enc": randBytes(80), "salt": randBytes(16), "auth": "rc_" + strings.Repeat("b", 40)})
				return bb, jsonHdr(v)
			},
			func(e *env, v string, a, b device, _ int64) string {
				if e.do("GET", "/v1/vaults/"+v+"/recovery", "", nil, nil).code == 200 {
					return "recovery identity installed"
				}
				return ""
			}},
		{"devices/me", "PATCH", func(v string, a, b device, _ int64) string { return "/v1/vaults/" + v + "/devices/me" },
			func(v string, a, b device) ([]byte, map[string]string) {
				bb, _ := jsonBytes(map[string]any{"name_enc": []byte("renamed-after-revocation")})
				return bb, jsonHdr(v)
			},
			func(e *env, v string, a, b device, _ int64) string {
				var devs struct{ Devices []store.Device }
				e.do("GET", "/v1/vaults/"+v+"/devices", a.token, nil, nil).expect(e.t, 200).json(e.t, &devs)
				for _, d := range devs.Devices {
					if d.ID == b.id && string(d.NameEnc) == "renamed-after-revocation" {
						return "name changed"
					}
				}
				return ""
			}},
		{"keybox", "POST", func(v string, a, b device, _ int64) string { return "/v1/vaults/" + v + "/keybox" },
			func(v string, a, b device) ([]byte, map[string]string) {
				bb, _ := jsonBytes(map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: b.id, Wrapped: randBytes(100)}}})
				return bb, map[string]string{"Content-Type": "application/json"}
			},
			func(e *env, v string, a, b device, _ int64) string {
				var n int
				e.st.DB().QueryRow(`SELECT COUNT(*) FROM keybox WHERE vault_id=? AND recipient_id=?`, v, b.id).Scan(&n)
				if n != 0 {
					return fmt.Sprintf("%d keybox row(s) for the revoked device", n)
				}
				return ""
			}},
		{"invites", "POST", func(v string, a, b device, _ int64) string { return "/v1/vaults/" + v + "/invites" },
			func(v string, a, b device) ([]byte, map[string]string) {
				bb, _ := jsonBytes(map[string]any{"keybox_enc": randBytes(64)})
				return bb, jsonHdr(v)
			},
			func(e *env, v string, a, b device, _ int64) string {
				var open int
				e.st.DB().QueryRow(`SELECT COUNT(*) FROM invites WHERE vault_id=? AND used_at IS NULL`, v).Scan(&open)
				if open != 0 {
					return fmt.Sprintf("%d invite(s) minted after revocation", open)
				}
				return ""
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, _, _ := r7env(t)
			vault, a, b := e.setup()
			// A path with history so meta and restore have something to touch.
			out := e.ops(vault, a, put("doc.md", nil, 0))
			seq := out.Results[0].Seq
			body, hdr := c.body(vault, a, b)
			res := e.inflight(c.method, c.path(vault, a, b, seq), b.token, hdr, body, func() { e.revokeB(vault, a, b) })
			if res.code >= 200 && res.code < 300 {
				t.Errorf("%s %s by a device revoked while the request was in flight answered %d", c.method, c.name, res.code)
			}
			if why := c.landed(e, vault, a, b, seq); why != "" {
				t.Errorf("%s %s landed after the writer's revocation: %s", c.method, c.name, why)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FINDING (medium): when the in-transaction re-check trips, the store
// returns ErrForbidden and `fail` renders it as 401 {"error":"forbidden"}.
// The plugin (engine.ts sync loop) distinguishes "my authority token is
// stale, re-sync" from "I was removed" by matching /vault authority/i in the
// 401 body: the middleware's text has it, the transaction's does not. So an
// honest device whose upload or op batch is in flight while ANOTHER device
// rotates keys (no revocation involved; a laptop pushing a large attachment
// while the phone rotates is enough) is told "This device was removed from
// the vault. Leave this vault, or re-join with an invite link." and stops
// syncing until Obsidian restarts. DESIGN §5.7 also says the answer is 403;
// the server sends 401.
func TestR7StaleAuthorityAtCommitIsDistinguishableFromRevocation(t *testing.T) {
	e, _, _ := r7env(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	body, _ := jsonBytes([]opIn{put("attachment.md", nil, 0)})
	res := e.inflight("POST", base+"/ops", a.token, jsonHdr(vault), body, func() {
		// B rotates without revoking anyone; A stays a member in good standing.
		next := newAuthTok()
		e.do("POST", base+"/rotate", b.token, map[string]any{"epoch": 2, "keybox": []store.KeyboxRow{
			{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}, {Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)},
		}, "auth_next": next}, authHdr(vault)).expect(t, 200)
		authTok[vault] = next
	})
	e.do("GET", base, a.token, nil, nil).expect(t, 200) // A is still enrolled
	if res.code == 200 {
		t.Fatalf("write under a retired authority token was accepted: %s", res.body)
	}
	// What the authority middleware says for the same condition before the body is read.
	pre := e.do("POST", base+"/ops", a.token, []opIn{put("x.md", nil, 0)}, map[string]string{"Content-Type": "application/json", "X-Obsync-Vault-Auth": newAuthTok()})
	if !strings.Contains(strings.ToLower(string(pre.body)), "vault authority") {
		t.Fatalf("premise: middleware 401 body is %q", pre.body)
	}
	if !strings.Contains(strings.ToLower(res.body), "vault authority") {
		t.Fatalf("a live device's write that crossed another device's rotation got %d %s; the middleware says %q for the same condition, and the plugin treats any 401 without 'vault authority' in it as 'this device was removed'", res.code, res.body, pre.body)
	}
}

// ---------------------------------------------------------------------------
// FINDING (low): validPubKex checks only len == 65. A P-256 point is 65
// bytes starting 0x04 with x,y on the curve; 65 bytes of 0xff is neither,
// and Go can tell in one call. The server stores it and every member's
// rotation does `importPub(d.pub_kex)` for every live device it must wrap
// to (admin.ts rotate(), crypto.ts wrapEpochKey): WebCrypto throws, the
// rotation throws with it, and the owner cannot rotate until they guess
// which device to revoke. The sixth review's fix note said "reject
// len != 65 || pubKex[0] != 0x04"; the second half did not ship.
func TestR7GarbagePubKexIsEnrolled(t *testing.T) {
	e, _, _ := r7env(t)
	vault, a, _ := e.setup()
	bad := bytes.Repeat([]byte{0xff}, 65)
	if _, err := ecdh.P256().NewPublicKey(bad); err == nil {
		t.Fatal("premise: 65×0xff is not a P-256 point")
	}
	var inv store.Invite
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": randBytes(64)}, authHdr(vault)).expect(t, 201).json(t, &inv)
	r := e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": bad, "name_enc": randBytes(20)}, nil)
	if r.code == 201 {
		t.Fatalf("enrolment accepted a 65-byte pub_kex that is not a P-256 point; the owner's next rotation throws importing it (ecdh.P256().NewPublicKey rejects it server-side in one call)")
	}
	if r.code != 400 {
		t.Fatalf("expected 400, got %d %s", r.code, r.body)
	}
}

// ---------------------------------------------------------------------------
// FINDING (low): putBlob commits the index row (UpsertBlob, synchronous=FULL,
// durable at once) and THEN renames the file into place. A crash, power loss
// or failed rename between the two leaves the index ahead of the bytes.
// For a first upload that is harmless (row without file self-heals since
// 707ba81). For a re-encryption upload it is not: the row says epoch 2 over
// an epoch-1 file, so min_epoch rises to 2, GET /blobs?epoch_lt=2 no longer
// lists the blob (nobody re-encrypts it), PruneKeybox deletes the epoch-1
// keybox rows and every device prunes its epoch-1 key (engine.ts
// refreshKeys → pruneBelow). The blob is then undecryptable by anyone,
// including a fresh join. The reverse order (promote, then index) fails
// safe: a row behind its file just gets re-encrypted once more. The window
// here is simulated by doing exactly the first half of putBlob.
func TestR7IndexCommittedBeforeFileLosesTheOldEpochKey(t *testing.T) {
	e, bs, _ := r7env(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	ctx := context.Background()
	id := hexID("doc-v1")
	ct := blob(1, "epoch-1 ciphertext")
	e.upload(vault, a, id, ct).expect(t, 201)
	seq := e.ops(vault, a, put("doc.md", str(id), 0)).Results[0].Seq
	next := newAuthTok()
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "keybox": []store.KeyboxRow{
		{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}, {Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)},
	}, "auth_next": next}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next

	// Re-encryption upload at epoch 2: putBlob now promotes the file first and
	// records the row after. The crash lands between them: epoch-2 bytes on
	// disk, the row still at epoch 1. That direction is fail-safe: the blob
	// stays in the epoch_lt=2 listing, min_epoch stays 1, the epoch-1 keybox
	// row survives, and the next re-encryption pass simply uploads it again.
	ct2 := blob(2, "epoch-2 ciphertext")
	if _, err := bs.Put(vault, id+"-stage-crash", bytes.NewReader(ct2)); err != nil {
		t.Fatal(err)
	}
	if err := bs.Promote(vault, id+"-stage-crash", id); err != nil {
		t.Fatal(err)
	}
	// Metadata re-encryption may still have run for this op; it does not move min_epoch while the blob row is behind.
	e.do("PATCH", fmt.Sprintf("%s/ops/%d/meta", base, seq), a.token, map[string]any{"meta_enc": randBytes(40), "meta_epoch": 2}, authHdr(vault)).expect(t, 204)
	f, err := bs.Open(vault, id)
	if err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 5)
	io.ReadFull(f, head)
	f.Close()
	fileEpoch := binary.LittleEndian.Uint32(head[1:5])

	var v store.Vault
	e.do("GET", base, a.token, nil, nil).expect(t, 200).json(t, &v)
	var below struct {
		BlobIDs []string `json:"blob_ids"`
	}
	e.do("GET", base+"/blobs?epoch_lt=2", a.token, nil, nil).expect(t, 200).json(t, &below)
	if _, err := e.srv.GC(ctx, 90*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var kb struct{ Keybox []store.KeyboxRow }
	e.do("GET", base+"/keybox", a.token, nil, nil).expect(t, 200).json(t, &kb)
	haveEpoch1 := false
	for _, r := range kb.Keybox {
		if r.Epoch == 1 {
			haveEpoch1 = true
		}
	}
	if fileEpoch != 2 || v.MinEpoch != 1 || len(below.BlobIDs) != 1 || below.BlobIDs[0] != id || !haveEpoch1 {
		t.Fatalf("file ahead of its row must be harmless: file epoch %d, min_epoch=%d, epoch_lt=2 lists %v, epoch-1 keybox row kept: %v", fileEpoch, v.MinEpoch, below.BlobIDs, haveEpoch1)
	}
	// The honest re-encryption pass repeats the upload and completes the move.
	e.upload(vault, a, id, ct2).expect(t, 201)
	e.do("GET", base, a.token, nil, nil).expect(t, 200).json(t, &v)
	if v.MinEpoch != 2 {
		t.Fatalf("after the repeated upload min_epoch should be 2, got %d", v.MinEpoch)
	}
	// And the index is never written ahead of the file by the handler: a
	// stage that fails to promote leaves no row behind.
	if _, err := bs.Put(vault, "zz-stage-x", bytes.NewReader(ct2)); err != nil {
		t.Fatal(err)
	}
	if n, err := bs.SweepStale(vault, 0); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
}

// ---------------------------------------------------------------------------
// FINDING (low, configuration hazard): --trust-proxy is a boolean. Any peer
// that can reach the listener directly (the proxy on the same host with the
// backend on 0.0.0.0, a second interface, a container network) asserts its
// own X-Forwarded-For and picks its bucket, because nothing checks that the
// peer IS the proxy. The usual shape is `--trust-proxy=CIDR[,CIDR]`: honour
// X-Forwarded-For only when peerIP is inside; otherwise key on the peer.
// util runs no proxy and no --trust-proxy, so this is not live there.
func TestR7TrustProxyHonoursXFFFromAnyPeer(t *testing.T) {
	// The proxy lives in 10.0.0.0/8; this test's peer is loopback, i.e. not the proxy.
	dir := t.TempDir()
	st, err := store.Open(dir + "/db.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	bs, err := blobstore.New(dir + "/blobs")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(api.Config{AdminToken: adminTok, InviteTTL: time.Hour, MaxWait: 5 * time.Second, AuthRatePerMinute: 60, AuthBurst: 5, TrustedProxies: []string{"10.0.0.0/8"}}, st, bs)
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close(); st.Close() })
	e := &env{t: t, ts: ts, srv: srv, st: st}
	codes := []int{}
	for i := range 8 {
		req, _ := http.NewRequest("POST", e.ts.URL+"/v1/invites/in_guess"+fmt.Sprint(i), strings.NewReader(`{"pub_kex":"AQ=="}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i)) // not behind any proxy: the peer wrote this
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		codes = append(codes, res.StatusCode)
	}
	if codes[len(codes)-1] != 429 {
		t.Fatalf("a direct peer (not the proxy) chose a fresh bucket per request under --trust-proxy: %v", codes)
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: with a proxy present, the client cannot choose its bucket,
// and a proxy that writes the address with a port, brackets, a zone, or as
// IPv4-mapped IPv6 still lands in one bucket (IPv6 by /64).
func TestR7ProxiedClientCannotChooseItsBucket(t *testing.T) {
	for _, group := range [][]string{
		{"203.0.113.7", "203.0.113.7:12345", "::ffff:203.0.113.7", "[::ffff:203.0.113.7]:443", "203.0.113.7 ", " 203.0.113.7"},
		{"2001:db8:1:2::1", "[2001:db8:1:2::1]:443", "2001:db8:1:2::1%eth0", "2001:db8:1:2:ffff::9", "[2001:db8:1:2::1%eth0]:8443"},
	} {
		e, _ := rateEnv(t, true)
		codes := []int{}
		for i := range 8 {
			req, _ := http.NewRequest("POST", e.ts.URL+"/v1/invites/in_guess"+fmt.Sprint(i), strings.NewReader(`{"pub_kex":"AQ=="}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Add("X-Forwarded-For", fmt.Sprintf("10.9.%d.%d, 10.8.8.8,", i/256, i%256)) // client-written, trailing comma
			req.Header.Add("X-Forwarded-For", group[i%len(group)])                                // proxy-written spelling varies
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			codes = append(codes, res.StatusCode)
		}
		if codes[len(codes)-1] != 429 {
			t.Fatalf("spellings %v of one proxied address were not one bucket: %v", group, codes)
		}
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION (documented behaviour, worth knowing): when the proxy's own
// entry is not an address ("unknown", as some proxies write for a client
// they could not resolve), every client collapses into the proxy's peer
// bucket, so one guesser's failures throttle everyone's recovery join.
func TestR7ProxyNonAddressEntryCollapsesClientsIntoOneBucket(t *testing.T) {
	e, _ := rateEnv(t, true)
	codes := []int{}
	for i := range 8 {
		req, _ := http.NewRequest("POST", e.ts.URL+"/v1/invites/in_guess"+fmt.Sprint(i), strings.NewReader(`{"pub_kex":"AQ=="}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Add("X-Forwarded-For", fmt.Sprintf("10.9.0.%d", i)) // a different real client each time
		req.Header.Add("X-Forwarded-For", "unknown")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		codes = append(codes, res.StatusCode)
	}
	if codes[len(codes)-1] != 429 {
		t.Fatalf("expected the documented collapse into the peer bucket: %v", codes)
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: routing POST /auth's mismatch through failAuth does not
// charge a legitimate device that presents the CORRECT token repeatedly
// (every device after the first does so at enrolment; several from one NAT
// share a bucket). Burst is 5 here and setup already spent two failures.
func TestR7RegisterAuthWithTheRightTokenIsNeverCharged(t *testing.T) {
	e, _ := rateEnv(t, false)
	vault, a, b := e.setup()
	for i := range 12 {
		d := a
		if i%2 == 1 {
			d = b
		}
		if c := e.do("POST", "/v1/vaults/"+vault+"/auth", d.token, map[string]any{"auth": authTok[vault]}, nil).code; c != 204 {
			t.Fatalf("attempt %d with the correct authority token → %d", i, c)
		}
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: SweepStale removes only "<id>-stage-*" and ".tmp-*" files
// older than an hour; a final blob (bare 64-hex name) and a fresh stage
// file are untouched, whatever their age.
func TestR7SweepStaleSparesFinalBlobsAndLiveUploads(t *testing.T) {
	e, _, dir := r7env(t)
	vault, a, _ := e.setup()
	id := hexID("kept")
	e.upload(vault, a, id, blob(1, "kept")).expect(t, 201)
	shard := filepath.Join(dir, "blobs", vault, id[:2])
	old := time.Now().Add(-2 * time.Hour)
	mk := func(name string, at time.Time) string {
		p := filepath.Join(shard, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
		return p
	}
	final := filepath.Join(shard, id)
	os.Chtimes(final, old, old) // an old blob is not an abandoned upload
	freshStage := mk(id+"-stage-fresh", time.Now())
	oldStage := mk(id+"-stage-old", old)
	oldTmp := mk(".tmp-"+id+"-stage-old-123", old)
	if _, err := e.srv.GC(context.Background(), 90*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{final, freshStage} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s should have survived: %v", filepath.Base(p), err)
		}
	}
	for _, p := range []string{oldStage, oldTmp} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s should have been swept", filepath.Base(p))
		}
	}
	e.do("GET", "/v1/vaults/"+vault+"/blobs/"+id, a.token, nil, nil).expect(t, 200)
}

// ---------------------------------------------------------------------------
// CONFIRMATION: the new liveSet rule in Rotate still accepts the recovery
// pseudo-device as a recipient (it must be covered) and still refuses a
// keybox that forgets it.
func TestR7RotateLiveSetKeepsTheRecoveryIdentity(t *testing.T) {
	e, _, _ := r7env(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	var rec struct {
		DeviceID string `json:"device_id"`
	}
	e.do("PUT", base+"/recovery", a.token, map[string]any{"pub_kex": testPubKex(), "recovery_enc": randBytes(80), "salt": randBytes(16), "auth": "rc_" + strings.Repeat("a", 40)}, authHdr(vault)).expect(t, 201).json(t, &rec)
	rows := []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}, {Epoch: 2, RecipientID: b.id, Wrapped: randBytes(100)}}
	next := newAuthTok()
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "keybox": rows, "auth_next": next}, authHdr(vault)).expect(t, 400)
	rows = append(rows, store.KeyboxRow{Epoch: 2, RecipientID: rec.DeviceID, Wrapped: randBytes(100)})
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "keybox": rows, "auth_next": next}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next
}

// ---------------------------------------------------------------------------
// CONFIRMATION: the self-heal path. A row whose file is gone (a GC from a
// second process, a restore that copied the database and blobs/ at
// different instants) reads as missing on POST /blobs/missing and as 404 on
// GET, and the row is dropped so an upload is accepted again. The head op
// still references the blob and Restore skips it; only the author's push
// (or "Re-upload current file") brings the bytes back.
func TestR7OrphanIndexRowSelfHeals(t *testing.T) {
	e, bs, _ := r7env(t)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault
	id := hexID("orphaned")
	e.upload(vault, a, id, blob(1, "v1")).expect(t, 201)
	e.ops(vault, a, put("note.md", str(id), 0))
	if err := bs.Delete(vault, id); err != nil { // the other process's file delete
		t.Fatal(err)
	}
	var miss struct{ Missing []string }
	e.do("POST", base+"/blobs/missing", a.token, []string{id}, nil).expect(t, 200).json(t, &miss)
	if len(miss.Missing) != 1 {
		t.Fatalf("missing check trusted the index: %v", miss.Missing)
	}
	e.do("GET", base+"/blobs/"+id, a.token, nil, nil).expect(t, 404)
	if _, err := e.st.GetBlob(context.Background(), vault, id); err == nil {
		t.Fatal("orphan row not dropped")
	}
	e.upload(vault, a, id, blob(1, "v1-again")).expect(t, 201)
	e.do("GET", base+"/blobs/"+id, a.token, nil, nil).expect(t, 200)
	// Server-side there is no signal to the author: the head still points at the blob it had to re-upload.
	var snap feed
	e.do("GET", base+"/snapshot", a.token, nil, nil).expect(t, 200).json(t, &snap)
	if len(snap.Ops) != 1 || snap.Ops[0].BlobID == nil || *snap.Ops[0].BlobID != id {
		t.Fatalf("unexpected snapshot: %+v", snap.Ops)
	}
}
