package api_test

// End-to-end tests over the real HTTP API with an in-process server, a
// temp SQLite database and blob directory. Two simulated devices (A and B)
// enrol, exchange ops, race on compare-and-swap, rotate keys, re-encrypt,
// recover, restore and garbage-collect. The "crypto" here is fake: the
// server never sees plaintext, so opaque bytes with the right shape are
// enough to exercise every server-side rule.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"obsync/internal/api"
	"obsync/internal/blobstore"
	"obsync/internal/store"
)

const adminTok = "ad_test-admin-token"

// vault authority tokens per vault (what key holders derive from K_e).
var authTok = map[string]string{}

func authHdr(vault string) map[string]string {
	return map[string]string{"X-Obsync-Vault-Auth": authTok[vault]}
}

func newAuthTok() string { return "va_" + hex.EncodeToString(randBytes(16)) }

type env struct {
	t   *testing.T
	ts  *httptest.Server
	srv *api.Server
	st  *store.Store
}

func newEnv(t *testing.T) *env {
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
	return &env{t: t, ts: ts, srv: srv, st: st}
}

// ---- tiny HTTP client ----

type resp struct {
	code int
	body []byte
	hdr  http.Header
}

func (e *env) do(method, path, token string, body any, hdr map[string]string) resp {
	e.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		r = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if _, ok := body.([]byte); !ok && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, b, res.Header}
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("bad json (%d): %s", r.code, r.body)
	}
}

func (r resp) expect(t *testing.T, code int) resp {
	t.Helper()
	if r.code != code {
		t.Fatalf("expected %d got %d: %s", code, r.code, r.body)
	}
	return r
}

// ---- fake crypto helpers ----

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func hexID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(h[:])
}

// blob builds a wire-format blob: 0x01 || epoch || salt || nonce || "ciphertext"
func blob(epoch uint32, payload string) []byte {
	b := []byte{0x01}
	b = binary.LittleEndian.AppendUint32(b, epoch)
	b = append(b, randBytes(16)...)
	b = append(b, randBytes(12)...)
	b = append(b, []byte(payload)...)
	b = append(b, randBytes(16)...) // tag
	return b
}

type device struct {
	id, token string
}

type opIn struct {
	OpID      string  `json:"op_id"`
	PathID    string  `json:"path_id"`
	BlobID    *string `json:"blob_id"`
	MetaEnc   []byte  `json:"meta_enc"`
	MetaEpoch int64   `json:"meta_epoch"`
	BaseSeq   int64   `json:"base_seq"`
}

type opsOut struct {
	Epoch   int64            `json:"epoch"`
	Cursor  int64            `json:"cursor"`
	Results []store.OpResult `json:"results"`
}

type feed struct {
	Epoch      int64      `json:"epoch"`
	MinEpoch   int64      `json:"min_epoch"`
	Cursor     int64      `json:"cursor"`
	Seq        int64      `json:"seq"`
	CursorOpID string     `json:"cursor_op_id"`
	Rewound    bool       `json:"rewound"`
	Ops        []store.Op `json:"ops"`
	More       bool       `json:"more"`
}

func put(path string, blobID *string, base int64) opIn {
	return opIn{OpID: "op-" + hex.EncodeToString(randBytes(8)), PathID: hexID(path), BlobID: blobID, MetaEnc: randBytes(40), MetaEpoch: 1, BaseSeq: base}
}

func str(s string) *string { return &s }

// ---- setup: vault + two devices ----

func (e *env) setup() (vault string, a, b device) {
	t := e.t
	var v store.Vault
	e.do("POST", "/v1/vaults", adminTok, nil, nil).expect(t, 201).json(t, &v)
	vault = v.ID

	// Admin mints the first invite; the first device "wraps" keys itself.
	var inv store.Invite
	e.do("POST", "/v1/vaults/"+vault+"/invites", adminTok, map[string]any{"keybox_enc": randBytes(64)}, nil).expect(t, 201).json(t, &inv)
	var red store.Redeemed
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65), "name_enc": randBytes(20)}, nil).expect(t, 201).json(t, &red)
	a = device{red.DeviceID, red.DeviceToken}
	// Self-enrol keybox row for epoch 1, and register the vault authority
	// token (derived from the epoch key; a token-only attacker cannot).
	e.do("POST", "/v1/vaults/"+vault+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: a.id, Wrapped: randBytes(100)}}}, nil).expect(t, 204)
	authTok[vault] = newAuthTok()
	e.do("POST", "/v1/vaults/"+vault+"/auth", a.token, map[string]any{"auth": authTok[vault]}, nil).expect(t, 204)
	e.do("POST", "/v1/vaults/"+vault+"/auth", a.token, map[string]any{"auth": authTok[vault]}, nil).expect(t, 204) // idempotent
	e.do("POST", "/v1/vaults/"+vault+"/auth", a.token, map[string]any{"auth": newAuthTok()}, nil).expect(t, 409)   // cannot be replaced

	// Device A invites B (needs authority: a stolen token alone cannot add devices).
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": randBytes(64)}, nil).expect(t, 401)
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": randBytes(64)}, authHdr(vault)).expect(t, 201).json(t, &inv)
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65), "name_enc": randBytes(20)}, nil).expect(t, 201).json(t, &red)
	b = device{red.DeviceID, red.DeviceToken}
	e.do("POST", "/v1/vaults/"+vault+"/keybox", b.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: b.id, Wrapped: randBytes(100)}}}, nil).expect(t, 204)

	// Invite is one-time.
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 401)
	return
}

func (e *env) upload(vault string, d device, id string, data []byte) resp {
	return e.do("PUT", "/v1/vaults/"+vault+"/blobs/"+id, d.token, data, map[string]string{"Content-Type": "application/octet-stream", "X-Obsync-Vault-Auth": authTok[vault]})
}

func (e *env) ops(vault string, d device, ops ...opIn) opsOut {
	var out opsOut
	e.do("POST", "/v1/vaults/"+vault+"/ops", d.token, ops, authHdr(vault)).expect(e.t, 200).json(e.t, &out)
	return out
}

func (e *env) changes(vault string, d device, since int64, extra string) feed {
	var f feed
	e.do("GET", fmt.Sprintf("/v1/vaults/%s/changes?since=%d%s", vault, since, extra), d.token, nil, nil).expect(e.t, 200).json(e.t, &f)
	return f
}

// ================= tests =================

func TestEnrolmentAndAuth(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()

	// Wrong token, wrong vault, admin on device route.
	e.do("GET", "/v1/vaults/"+vault, "dv_bogus", nil, nil).expect(t, 401)
	e.do("GET", "/v1/vaults/"+vault, adminTok, nil, nil).expect(t, 401)
	e.do("GET", "/v1/vaults/deadbeef", a.token, nil, nil).expect(t, 403)
	e.do("POST", "/v1/vaults", a.token, nil, nil).expect(t, 401)

	// A device can rename itself.
	e.do("PATCH", "/v1/vaults/"+vault+"/devices/me", b.token, map[string]any{"name_enc": []byte("new-name-ct")}, nil).expect(t, 204)
	e.do("PATCH", "/v1/vaults/"+vault+"/devices/me", b.token, map[string]any{"name_enc": []byte{}}, nil).expect(t, 400)
	var devs struct{ Devices []store.Device }
	e.do("GET", "/v1/vaults/"+vault+"/devices", b.token, nil, nil).expect(t, 200).json(t, &devs)
	if len(devs.Devices) != 2 {
		t.Fatalf("want 2 devices, got %d", len(devs.Devices))
	}
	for _, d := range devs.Devices {
		if d.ID != a.id && d.ID != b.id {
			t.Fatalf("unexpected device %s", d.ID)
		}
		if len(d.NameEnc) == 0 || len(d.PubKex) == 0 {
			t.Fatal("device missing name_enc/pub_kex")
		}
	}
	// CORS preflight.
	r := e.do("OPTIONS", "/v1/vaults/"+vault+"/ops", "", nil, map[string]string{"Origin": "app://obsidian.md"})
	if r.code != 204 || r.hdr.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("preflight: %d %v", r.code, r.hdr)
	}
}

func TestOpsFeedAndCAS(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault

	// Op without blob is rejected (blobs before ops).
	bid := hexID("note1-v1")
	out := e.ops(vault, a, put("note1.md", str(bid), 0))
	if out.Results[0].Error == "" {
		t.Fatalf("expected 'blob not uploaded', got %+v", out.Results[0])
	}
	// Upload, then op succeeds.
	e.upload(vault, a, bid, blob(1, "hello")).expect(t, 201)
	// Re-upload same epoch is an idempotent 200.
	e.upload(vault, a, bid, blob(1, "hello")).expect(t, 200)
	op1 := put("note1.md", str(bid), 0)
	out = e.ops(vault, a, op1)
	if out.Results[0].Seq != 1 {
		t.Fatalf("want seq 1: %+v", out.Results[0])
	}
	// Idempotent replay returns same seq.
	out = e.ops(vault, a, op1)
	if out.Results[0].Seq != 1 {
		t.Fatalf("replay should return seq 1: %+v", out.Results[0])
	}

	// B pulls.
	f := e.changes(vault, b, 0, "")
	if len(f.Ops) != 1 || f.Ops[0].Seq != 1 || *f.Ops[0].BlobID != bid || f.Ops[0].DeviceID != a.id || f.Cursor != 1 {
		t.Fatalf("bad feed: %+v", f)
	}
	// B downloads the blob (with a Range).
	r := e.do("GET", base+"/blobs/"+bid, b.token, nil, map[string]string{"Range": "bytes=0-4"})
	if r.code != 206 || len(r.body) != 5 || r.body[0] != 0x01 {
		t.Fatalf("range get: %d %x", r.code, r.body)
	}

	// CAS: both devices edit note1 based on seq 1.
	bidA, bidB := hexID("note1-A"), hexID("note1-B")
	e.upload(vault, a, bidA, blob(1, "A")).expect(t, 201)
	e.upload(vault, b, bidB, blob(1, "B")).expect(t, 201)
	outA := e.ops(vault, a, put("note1.md", str(bidA), 1))
	outB := e.ops(vault, b, put("note1.md", str(bidB), 1))
	if outA.Results[0].Seq != 2 {
		t.Fatalf("A should win: %+v", outA.Results[0])
	}
	if outB.Results[0].Conflict == nil || outB.Results[0].Conflict.Seq != 2 || *outB.Results[0].Conflict.BlobID != bidA {
		t.Fatalf("B should conflict with head seq 2: %+v", outB.Results[0])
	}
	// B rebases and wins.
	outB = e.ops(vault, b, put("note1.md", str(bidB), 2))
	if outB.Results[0].Seq != 3 {
		t.Fatalf("B rebase: %+v", outB.Results[0])
	}
	// Stale base on a fresh path.
	out = e.ops(vault, a, put("other.md", str(bidA), 7))
	if out.Results[0].Error == "" {
		t.Fatalf("expected error for base on headless path: %+v", out.Results[0])
	}

	// Delete (blob nil) and snapshot includes the tombstone.
	out = e.ops(vault, a, put("note1.md", nil, 3))
	if out.Results[0].Seq != 4 {
		t.Fatalf("delete: %+v", out.Results[0])
	}
	var snap feed
	e.do("GET", base+"/snapshot", b.token, nil, nil).expect(t, 200).json(t, &snap)
	if len(snap.Ops) != 1 || snap.Ops[0].Seq != 4 || snap.Ops[0].BlobID != nil || snap.Cursor != 4 {
		t.Fatalf("snapshot: %+v", snap)
	}
	// History for the path.
	var hist struct{ Ops []store.Op }
	e.do("GET", base+"/history?path_id="+hexID("note1.md"), a.token, nil, nil).expect(t, 200).json(t, &hist)
	if len(hist.Ops) != 4 {
		t.Fatalf("history len %d", len(hist.Ops))
	}
	// Pagination.
	f = e.changes(vault, b, 0, "&limit=2")
	if len(f.Ops) != 2 || !f.More || f.Cursor != 2 {
		t.Fatalf("pagination: %+v", f)
	}
	f = e.changes(vault, b, f.Cursor, "&limit=2")
	if len(f.Ops) != 2 || f.More || f.Cursor != 4 {
		t.Fatalf("pagination page 2: %+v", f)
	}
	// Batch: one ok, one conflict, one bad, all in one request; the ok one commits.
	e.upload(vault, a, hexID("x"), blob(1, "x")).expect(t, 201)
	out = e.ops(vault, a,
		put("new.md", str(hexID("x")), 0),
		put("note1.md", str(hexID("x")), 1), // stale
		opIn{OpID: "bad", PathID: "nothex", MetaEnc: []byte{1}, MetaEpoch: 1},
	)
	if out.Results[0].Seq != 5 || out.Results[1].Conflict == nil || out.Results[2].Error == "" {
		t.Fatalf("batch: %+v", out.Results)
	}
}

func TestLongPollAndWebSocket(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()

	// Long-poll with no changes times out with an empty feed quickly.
	start := time.Now()
	f := e.changes(vault, b, 0, "&wait=1")
	if len(f.Ops) != 0 || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("expected ~1s empty wait, got %v %+v", time.Since(start), f)
	}

	// Long-poll wakes on a push.
	done := make(chan feed, 1)
	go func() { done <- e.changes(vault, b, 0, "&wait=5") }()
	time.Sleep(200 * time.Millisecond)
	bid := hexID("lp")
	e.upload(vault, a, bid, blob(1, "lp")).expect(t, 201)
	e.ops(vault, a, put("lp.md", str(bid), 0))
	select {
	case f := <-done:
		if len(f.Ops) != 1 {
			t.Fatalf("long-poll feed: %+v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long-poll did not wake")
	}

	// WebSocket hint.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(e.ts.URL, "http") + "/v1/vaults/" + vault + "/live"
	dial := func(tok string) (*websocket.Conn, error) {
		c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{"obsync-bearer", tok}})
		return c, err
	}
	c, err := dial(b.token)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	var h api.Hint
	if err := wsjson.Read(ctx, c, &h); err != nil || h.Seq != 1 {
		t.Fatalf("initial hint: %+v %v", h, err)
	}
	bid2 := hexID("ws")
	e.upload(vault, a, bid2, blob(1, "ws")).expect(t, 201)
	e.ops(vault, a, put("ws.md", str(bid2), 0))
	if err := wsjson.Read(ctx, c, &h); err != nil || h.Seq != 2 {
		t.Fatalf("push hint: %+v %v", h, err)
	}
	// Bad token on WS is rejected before upgrade.
	if _, err := dial("dv_nope"); err == nil {
		t.Fatal("ws with bad token should fail")
	}
	// The token is never accepted in the URL.
	if _, _, err := websocket.Dial(ctx, wsURL+"?token="+b.token, nil); err == nil {
		t.Fatal("ws token in query string should be refused")
	}
}

func TestConcurrentCAS(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	bid := hexID("race")
	e.upload(vault, a, bid, blob(1, "race")).expect(t, 201)

	const n = 32
	var wg sync.WaitGroup
	results := make([]opsOut, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = e.ops(vault, a, put("race.md", str(bid), 0))
		}(i)
	}
	wg.Wait()
	wins, conflicts := 0, 0
	for _, r := range results {
		switch {
		case r.Results[0].Seq == 1:
			wins++
		case r.Results[0].Conflict != nil && r.Results[0].Conflict.Seq == 1:
			conflicts++
		default:
			t.Fatalf("unexpected result %+v", r.Results[0])
		}
	}
	if wins != 1 || conflicts != n-1 {
		t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
	}
	// Now a chain of successful rebases from many goroutines: every accepted
	// op must get a unique, gapless seq and heads must track the last one.
	var mu sync.Mutex
	accepted := map[int64]bool{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			base := int64(1)
			for tries := 0; tries < 200; tries++ {
				r := e.ops(vault, a, put("race.md", str(bid), base))
				if r.Results[0].Seq > 0 && r.Results[0].Conflict == nil {
					mu.Lock()
					accepted[r.Results[0].Seq] = true
					mu.Unlock()
					return
				}
				if r.Results[0].Conflict != nil {
					base = r.Results[0].Conflict.Seq
				}
			}
			t.Error("gave up rebasing")
		}()
	}
	wg.Wait()
	if len(accepted) != n {
		t.Fatalf("accepted %d of %d", len(accepted), n)
	}
	for s := int64(2); s <= int64(n)+1; s++ {
		if !accepted[s] {
			t.Fatalf("gap at seq %d", s)
		}
	}
	var snap feed
	e.do("GET", "/v1/vaults/"+vault+"/snapshot", a.token, nil, nil).expect(t, 200).json(t, &snap)
	if len(snap.Ops) != 1 || snap.Ops[0].Seq != int64(n)+1 {
		t.Fatalf("head should be seq %d: %+v", n+1, snap.Ops)
	}
}

func TestRotateReencryptAndRecovery(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault

	// Some data under epoch 1.
	bid := hexID("doc")
	e.upload(vault, b, bid, blob(1, "doc")).expect(t, 201)
	e.ops(vault, b, put("doc.md", str(bid), 0))

	// Recovery identity, wrapped to epoch 1 by A.
	recAuth := "rc_" + hex.EncodeToString(randBytes(16))
	var rec struct {
		DeviceID string `json:"device_id"`
	}
	recSalt := randBytes(16)
	e.do("PUT", base+"/recovery", a.token, map[string]any{"pub_kex": randBytes(65), "recovery_enc": randBytes(80), "salt": recSalt, "auth": recAuth}, nil).expect(t, 401) // authority required
	e.do("PUT", base+"/recovery", a.token, map[string]any{"pub_kex": randBytes(65), "recovery_enc": randBytes(80), "salt": recSalt, "auth": recAuth}, authHdr(vault)).expect(t, 201).json(t, &rec)
	e.do("POST", base+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: rec.DeviceID, Wrapped: randBytes(100)}}}, nil).expect(t, 401) // rows for another identity need authority
	e.do("POST", base+"/keybox", a.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: rec.DeviceID, Wrapped: randBytes(100)}}}, authHdr(vault)).expect(t, 204)

	// Rotation validation: wrong epoch, self-revoke, missing recipient.
	nextAuth := newAuthTok()
	rot := func(epoch int64, revoke []string, recips ...string) resp {
		var rows []store.KeyboxRow
		for _, r := range recips {
			rows = append(rows, store.KeyboxRow{Epoch: epoch, RecipientID: r, Wrapped: randBytes(100)})
		}
		return e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": epoch, "revoke": revoke, "keybox": rows, "auth_next": nextAuth}, authHdr(vault))
	}
	// Without the authority token nothing rotates, whatever the body.
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": []string{b.id}, "keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}, {Epoch: 2, RecipientID: rec.DeviceID, Wrapped: randBytes(100)}}, "auth_next": nextAuth}, nil).expect(t, 401)
	rot(3, nil, a.id, b.id, rec.DeviceID).expect(t, 409)
	rot(2, []string{a.id}, b.id, rec.DeviceID).expect(t, 400)
	rot(2, []string{b.id}, a.id).expect(t, 400)                     // recovery not covered
	rot(2, []string{b.id}, a.id, b.id, rec.DeviceID).expect(t, 400) // wraps to revoked

	// Remove B.
	rot(2, []string{b.id}, a.id, rec.DeviceID).expect(t, 200)
	e.do("GET", base, b.token, nil, nil).expect(t, 401)
	// The old authority token died with epoch 1; the new one is live.
	e.do("PATCH", base+"/ops/1/meta", a.token, map[string]any{"meta_enc": randBytes(40), "meta_epoch": 2}, authHdr(vault)).expect(t, 401)
	authTok[vault] = nextAuth
	var v store.Vault
	e.do("GET", base, a.token, nil, nil).expect(t, 200).json(t, &v)
	if v.Epoch != 2 || v.MinEpoch != 1 {
		t.Fatalf("after rotate: %+v", v)
	}
	var kb struct{ Keybox []store.KeyboxRow }
	e.do("GET", base+"/keybox", a.token, nil, nil).expect(t, 200).json(t, &kb)
	if len(kb.Keybox) != 2 || kb.Keybox[1].Epoch != 2 {
		t.Fatalf("keybox: %+v", kb.Keybox)
	}
	// Old-epoch blob upload is still allowed (epoch 1 ≤ current) but a
	// too-new epoch is rejected.
	e.upload(vault, a, hexID("future"), blob(3, "x")).expect(t, 400)

	// Re-encryption worklist.
	var work struct {
		BlobIDs []string `json:"blob_ids"`
	}
	e.do("GET", base+"/blobs?epoch_lt=2", a.token, nil, nil).expect(t, 200).json(t, &work)
	if len(work.BlobIDs) != 1 || work.BlobIDs[0] != bid {
		t.Fatalf("worklist: %+v", work)
	}
	// Re-upload under epoch 2 replaces; then lower epoch is a no-op. Without
	// authority nothing is ever uploaded.
	e.do("PUT", base+"/blobs/"+bid, a.token, blob(2, "doc-reenc"), map[string]string{"Content-Type": "application/octet-stream"}).expect(t, 401)
	e.upload(vault, a, bid, blob(2, "doc-reenc")).expect(t, 201)
	e.upload(vault, a, bid, blob(1, "stale")).expect(t, 200)
	r := e.do("GET", base+"/blobs/"+bid, a.token, nil, nil).expect(t, 200)
	if r.hdr.Get("X-Blob-Epoch") != "2" || !bytes.Contains(r.body, []byte("doc-reenc")) {
		t.Fatalf("blob not replaced: epoch=%s", r.hdr.Get("X-Blob-Epoch"))
	}
	e.do("GET", base+"/blobs?epoch_lt=2", a.token, nil, nil).expect(t, 200).json(t, &work)
	if len(work.BlobIDs) != 0 {
		t.Fatalf("worklist should be empty: %+v", work)
	}
	// Ops metadata worklist + patch.
	var seqs struct {
		Seqs []int64 `json:"seqs"`
	}
	e.do("GET", base+"/ops?meta_epoch_lt=2", a.token, nil, nil).expect(t, 200).json(t, &seqs)
	if len(seqs.Seqs) != 1 {
		t.Fatalf("meta worklist: %+v", seqs)
	}
	e.do("PATCH", base+"/ops/1/meta", a.token, map[string]any{"meta_enc": randBytes(40), "meta_epoch": 2}, nil).expect(t, 401)
	e.do("PATCH", base+"/ops/1/meta", a.token, map[string]any{"meta_enc": randBytes(40), "meta_epoch": 1}, authHdr(vault)).expect(t, 409)
	e.do("PATCH", base+"/ops/1/meta", a.token, map[string]any{"meta_enc": randBytes(40), "meta_epoch": 2}, authHdr(vault)).expect(t, 204)
	e.do("PATCH", base+"/ops/1/meta", a.token, map[string]any{"meta_enc": randBytes(40), "meta_epoch": 2}, authHdr(vault)).expect(t, 409)
	e.do("GET", base, a.token, nil, nil).expect(t, 200).json(t, &v)
	if v.MinEpoch != 2 {
		t.Fatalf("min_epoch should advance to 2: %+v", v)
	}
	// After GC prune, epoch-1 keybox rows are gone.
	if _, err := e.srv.GC(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	e.do("GET", base+"/keybox", a.token, nil, nil).expect(t, 200).json(t, &kb)
	if len(kb.Keybox) != 1 || kb.Keybox[0].Epoch != 2 {
		t.Fatalf("keybox after prune: %+v", kb.Keybox)
	}
	// New ops must use the current epoch or lower, never higher.
	o := put("e.md", nil, 0)
	o.MetaEpoch = 3
	if out := e.ops(vault, a, o); out.Results[0].Error == "" {
		t.Fatal("meta_epoch 3 should be rejected")
	}

	// Recovery join: unauthenticated info fetch (salt only, nothing to attack
	// offline), then join with the auth token, which releases the wrapped key.
	var info store.RecoveryInfo
	r = e.do("GET", base+"/recovery", "", nil, nil).expect(t, 200)
	r.json(t, &info)
	if info.DeviceID != rec.DeviceID || !bytes.Equal(info.Salt, recSalt) || bytes.Contains(r.body, []byte("recovery_enc")) {
		t.Fatalf("recovery info: %+v %s", info, r.body)
	}
	e.do("POST", base+"/recovery/join", "rc_wrong", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 401)
	var joined struct {
		DeviceToken string            `json:"device_token"`
		Epoch       int64             `json:"epoch"`
		Keybox      []store.KeyboxRow `json:"keybox"`
		RecoveryEnc []byte            `json:"recovery_enc"`
	}
	e.do("POST", base+"/recovery/join", recAuth, map[string]any{"pub_kex": randBytes(65), "name_enc": randBytes(10)}, nil).expect(t, 201).json(t, &joined)
	if joined.Epoch != 2 || len(joined.Keybox) != 1 || joined.Keybox[0].Epoch != 2 || joined.Keybox[0].RecipientID != rec.DeviceID || len(joined.RecoveryEnc) != 80 {
		t.Fatalf("recovery join: %+v", joined)
	}
	e.do("GET", base, joined.DeviceToken, nil, nil).expect(t, 200)
}

func TestGCAndRestore(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault

	v1, v2, keep := hexID("n-v1"), hexID("n-v2"), hexID("keep")
	e.upload(vault, a, v1, blob(1, "v1")).expect(t, 201)
	e.upload(vault, a, v2, blob(1, "v2")).expect(t, 201)
	e.upload(vault, a, keep, blob(1, "keep")).expect(t, 201)
	e.ops(vault, a, put("n.md", str(v1), 0)) // seq 1
	time.Sleep(5 * time.Millisecond)
	tBetween := time.Now().UnixMilli()
	time.Sleep(5 * time.Millisecond)
	e.ops(vault, a, put("n.md", str(v2), 1))   // seq 2 supersedes v1
	e.ops(vault, a, put("k.md", str(keep), 0)) // seq 3
	// The last check restores to seq 2's own timestamp; the restore op below
	// must land in a later millisecond or it is what that check picks.
	time.Sleep(5 * time.Millisecond)

	// Restore to tBetween: n.md goes back to v1 as a new op; k.md did not exist then so is untouched
	// (restore only rewinds paths that had a version at T).
	var rs struct {
		Emitted int      `json:"emitted"`
		Skipped []string `json:"skipped_path_ids"`
		Cursor  int64    `json:"cursor"`
	}
	e.do("POST", base+"/restore", a.token, map[string]any{"at": tBetween}, authHdr(vault)).expect(t, 200).json(t, &rs)
	if rs.Emitted != 1 || len(rs.Skipped) != 0 || rs.Cursor != 4 {
		t.Fatalf("restore: %+v", rs)
	}
	var snap feed
	e.do("GET", base+"/snapshot", a.token, nil, nil).expect(t, 200).json(t, &snap)
	heads := map[string]string{}
	for _, o := range snap.Ops {
		heads[o.PathID] = *o.BlobID
	}
	if heads[hexID("n.md")] != v1 || heads[hexID("k.md")] != keep {
		t.Fatalf("heads after restore: %+v", heads)
	}

	// GC with zero retention: v2 is superseded and unreferenced by any head → removed.
	// v1 and keep are heads → kept.
	n, err := e.srv.GC(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("gc removed %d, want 1", n)
	}
	e.do("GET", base+"/blobs/"+v2, a.token, nil, nil).expect(t, 404)
	e.do("GET", base+"/blobs/"+v1, a.token, nil, nil).expect(t, 200)
	e.do("GET", base+"/blobs/"+keep, a.token, nil, nil).expect(t, 200)

	// GC with long retention keeps recently superseded blobs.
	e.upload(vault, a, hexID("n-v3"), blob(1, "v3")).expect(t, 201)
	e.ops(vault, a, put("n.md", str(hexID("n-v3")), 4)) // supersedes v1 again
	n, _ = e.srv.GC(context.Background(), time.Hour)
	if n != 0 {
		t.Fatalf("gc with retention removed %d", n)
	}

	// Restore to a time whose blob was collected is reported as skipped.
	// (seq 2 used v2 which is gone; restore to just after seq 2 picks v2.)
	var hist struct{ Ops []store.Op }
	e.do("GET", base+"/history?path_id="+hexID("n.md"), a.token, nil, nil).expect(t, 200).json(t, &hist)
	tAfterSeq2 := hist.Ops[1].CreatedAt
	e.do("POST", base+"/restore", a.token, map[string]any{"at": tAfterSeq2}, authHdr(vault)).expect(t, 200).json(t, &rs)
	if rs.Emitted != 0 || len(rs.Skipped) != 1 || rs.Skipped[0] != hexID("n.md") {
		t.Fatalf("restore with collected blob: %+v", rs)
	}
}

func TestBlobValidation(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	id := hexID("val")
	e.upload(vault, a, id, []byte{0x01, 1, 0, 0, 0}).expect(t, 400)                  // too short
	e.upload(vault, a, id, append([]byte{0x02}, blob(1, "x")[1:]...)).expect(t, 400) // bad version
	e.upload(vault, a, id, blob(0, "x")).expect(t, 400)                              // epoch 0
	e.upload(vault, a, "zz", blob(1, "x")).expect(t, 400)                            // bad id
	e.upload(vault, a, id, blob(1, "ok")).expect(t, 201)
	var miss struct{ Missing []string }
	e.do("POST", "/v1/vaults/"+vault+"/blobs/missing", a.token, []string{id, hexID("nope")}, nil).expect(t, 200).json(t, &miss)
	if len(miss.Missing) != 1 || miss.Missing[0] != hexID("nope") {
		t.Fatalf("missing: %+v", miss)
	}
	e.do("GET", "/v1/vaults/"+vault+"/blobs/"+hexID("nope"), a.token, nil, nil).expect(t, 404)
}

// A client names the op it believes sits at its cursor. After the operator
// restores the server from a backup the log is shorter, or has re-issued the
// same numbers for different ops; either way the feed must say "rewound"
// instead of pretending nothing happened (DESIGN.md §6.8).
func TestRestoredLogIsDetected(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	bid := hexID("blob-r")
	e.upload(vault, a, bid, blob(1, "x")).expect(t, 201)
	r1 := e.ops(vault, a, put("r.md", &bid, 0))
	r2 := e.ops(vault, a, put("s.md", &bid, 0))
	if r1.Results[0].Seq != 1 || r2.Results[0].Seq != 2 || r2.Results[0].CreatedAt == 0 {
		t.Fatalf("unexpected results %+v %+v", r1.Results, r2.Results)
	}
	op2 := r2.Results[0].OpID

	// The feed reports the vault seq and the op id at the cursor.
	f := e.changes(vault, a, 0, "")
	if f.Seq != 2 || f.CursorOpID != op2 || f.Rewound {
		t.Fatalf("feed %+v", f)
	}
	// Right expectation: nothing new, not rewound.
	f = e.changes(vault, a, 2, "&expect="+op2)
	if f.Rewound || len(f.Ops) != 0 || f.Seq != 2 {
		t.Fatalf("feed %+v", f)
	}
	// Wrong expectation (the op at seq 2 is not the one the client saw): rewound.
	f = e.changes(vault, a, 2, "&expect=op-not-this-one")
	if !f.Rewound || len(f.Ops) != 0 || f.Seq != 2 || f.Cursor != 2 {
		t.Fatalf("feed %+v", f)
	}
	// A cursor beyond the log (the backup was older than the client's view) is rewound too.
	f = e.changes(vault, a, 5, "&expect="+op2)
	if !f.Rewound || f.Seq != 2 {
		t.Fatalf("feed %+v", f)
	}
	// Without an expectation the feed still reports seq so an older client can compare.
	f = e.changes(vault, a, 5, "")
	if f.Rewound || f.Seq != 2 {
		t.Fatalf("feed %+v", f)
	}
	// Snapshot carries the cursor's op id so a fresh client can start checking at once.
	var snap feed
	e.do("GET", "/v1/vaults/"+vault+"/snapshot", a.token, nil, nil).expect(t, 200).json(t, &snap)
	if snap.Cursor != 2 || snap.CursorOpID != op2 {
		t.Fatalf("snapshot %+v", snap)
	}
}
