package api_test

// Sixth review (server and deployment as a whole system, fresh eyes). Each
// TestZz* below is the proof for one candidate finding; a test that fails on
// HEAD demonstrates the finding, a test that passes is a confirmation. See
// plugin/.cache/agent-review6-server/REPORT.md for the ranked list.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"obsync/internal/api"
	"obsync/internal/blobstore"
	"obsync/internal/store"
)

// rateEnv is newEnv with a real limiter (60/min, burst 5) and optional
// --trust-proxy, and it keeps the blobstore handle for GC interleavings.
func rateEnv(t *testing.T, trustProxy bool) (*env, *blobstore.FS) {
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
	srv := api.New(api.Config{AdminToken: adminTok, InviteTTL: time.Hour, MaxWait: 5 * time.Second, AuthRatePerMinute: 60, AuthBurst: 5, TrustProxy: trustProxy}, st, bs)
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close(); st.Close() })
	return &env{t: t, ts: ts, srv: srv, st: st}, bs
}

// ---------------------------------------------------------------------------
// FINDING (medium): under --trust-proxy the limiter and the event log read
// X-Forwarded-For with Header.Get, which returns only the FIRST header line.
// A proxy that adds its own X-Forwarded-For line instead of appending to the
// client's (HAProxy `option forwardfor`, and any proxy in front of a second
// hop) leaves the client's line first, so the "last entry" the server keys
// on is whatever the client wrote: a fresh bucket per request, and a forged
// address in every security event. The README's "it assumes exactly one
// trusted hop" does not cover this: there IS exactly one hop here.
func TestZzTrustProxyReadsOnlyTheFirstXFFHeaderLine(t *testing.T) {
	e, _ := rateEnv(t, true)
	codes := []int{}
	for i := range 8 {
		req, _ := http.NewRequest("POST", e.ts.URL+"/v1/invites/in_guess"+fmt.Sprint(i), strings.NewReader(`{"pub_kex":"AQ=="}`))
		req.Header.Set("Content-Type", "application/json")
		// Line 1: written by the attacker, different every time.
		req.Header.Add("X-Forwarded-For", fmt.Sprintf("10.9.%d.%d", i/256, i%256))
		// Line 2: added by the trusted proxy; the real client address, constant.
		req.Header.Add("X-Forwarded-For", "203.0.113.7")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		codes = append(codes, res.StatusCode)
	}
	if codes[len(codes)-1] != 429 {
		t.Fatalf("eight invite guesses from one proxied client (203.0.113.7) were never throttled: %v; the limiter keyed on the client-written first X-Forwarded-For line", codes)
	}
}

// ---------------------------------------------------------------------------
// FINDING (low): MaxOpaque (4 KiB) bounds a device name set via PATCH
// /devices/me and every keybox row, but the two enrolment routes store
// name_enc and pub_kex with no bound beyond the 64 KiB JSON body. An invite
// holder (or passphrase holder) plants ~45 KiB per device that every member
// then downloads on each GET /devices, and pub_kex is never checked for the
// 65-byte P-256 shape the design specifies.
func TestZzEnrolmentBypassesOpaqueCaps(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault
	var inv store.Invite
	e.do("POST", base+"/invites", a.token, map[string]any{"keybox_enc": randBytes(64)}, authHdr(vault)).expect(t, 201).json(t, &inv)
	big := randBytes(40_000) // ten times MaxOpaque; still under the 64 KiB body cap once base64'd
	r := e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(1000), "name_enc": big}, nil)
	if r.code == 201 {
		var devs struct{ Devices []store.Device }
		e.do("GET", base+"/devices", a.token, nil, nil).expect(t, 200).json(t, &devs)
		for _, d := range devs.Devices {
			if len(d.NameEnc) > store.MaxOpaque || len(d.PubKex) > 65 {
				t.Fatalf("invite redemption stored name_enc=%d B pub_kex=%d B (MaxOpaque is %d, a P-256 point is 65); PATCH /devices/me would have refused this", len(d.NameEnc), len(d.PubKex), store.MaxOpaque)
			}
		}
		t.Fatal("redeemed with oversized fields but the roster does not show them")
	}
	if r.code != 400 {
		t.Fatalf("expected 400, got %d: %s", r.code, r.body)
	}
}

// ---------------------------------------------------------------------------
// FINDING (low): authentication and authority are checked once, before the
// body is read; the write transaction never re-checks that the device is
// still live. A device revoked by a rotation while its POST /ops (or PUT
// /blobs, whose idleReader extends the deadline for as long as bytes
// trickle) is in flight has its write committed after its revocation, and
// the op is attributed to a device the roster shows as removed.
func TestZzInFlightWriteSurvivesRevocation(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	ops, _ := jsonBytes([]opIn{put("late.md", nil, 0)})
	pr, pw := io.Pipe()
	type result struct {
		code int
		body string
	}
	done := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest("POST", e.ts.URL+base+"/ops", pr)
		req.Header.Set("Authorization", "Bearer "+b.token)
		req.Header.Set("X-Obsync-Vault-Auth", authTok[vault])
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- result{0, err.Error()}
			return
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		done <- result{res.StatusCode, string(body)}
	}()
	// The handler has passed device+authority and is blocked in readJSON.
	pw.Write(ops[:1])
	time.Sleep(300 * time.Millisecond)
	// A revokes B (and with it B's authority token, since the epoch moves).
	next := newAuthTok()
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": []string{b.id}, "keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}}, "auth_next": next}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next
	e.do("GET", base, b.token, nil, nil).expect(t, 401) // B is gone
	pw.Write(ops[1:])
	pw.Close()
	res := <-done
	f := e.changes(vault, a, 0, "")
	for _, op := range f.Ops {
		if op.DeviceID == b.id {
			t.Fatalf("op seq=%d was committed for device %s after its revocation (response %d %s)", op.Seq, b.id, res.code, res.body)
		}
	}
	if res.code == 200 {
		t.Fatalf("revoked device's in-flight write answered 200: %s", res.body)
	}
}

func jsonBytes(v any) ([]byte, error) { return json.Marshal(v) }

// ---------------------------------------------------------------------------
// FINDING (low): GC deletes the index row inside a transaction (re-checking
// liveness) and then deletes the file outside it, without the per-blob lock
// putBlob holds for index-update + promote. A key holder re-uploading the
// same blob id in that window (the client just saw "blob not uploaded")
// lands its row and file between GC's two steps; GC then removes the fresh
// file. The index says present, /blobs/missing says not missing, every GET
// is 404 "blob data missing", and no client re-uploads because the server
// says it has it.
func TestZzGCFileDeleteRacesReupload(t *testing.T) {
	e, bs := rateEnv(t, false)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault
	id := hexID("recreated-later")
	e.upload(vault, a, id, blob(1, "v1")).expect(t, 201)
	out := e.ops(vault, a, put("note.md", str(id), 0))
	// Superseded by a tombstone, and everything aged past retention.
	e.ops(vault, a, put("note.md", nil, out.Results[0].Seq))
	old := time.Now().Add(-100 * 24 * time.Hour).UnixMilli()
	if _, err := e.st.DB().Exec(`UPDATE blobs SET created_at=? WHERE vault_id=?`, old, vault); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DB().Exec(`UPDATE ops SET created_at=? WHERE vault_id=?`, old, vault); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().Add(-90 * 24 * time.Hour).UnixMilli()
	ctx := t.Context()
	dead, err := e.st.DeadBlobs(ctx, vault, cutoff)
	if err != nil || len(dead) != 1 || dead[0] != id {
		t.Fatalf("expected the superseded blob to be dead: %v %v", dead, err)
	}
	// GC step 1 (Server.GC): the row goes, inside its own transaction.
	gone, err := e.st.DeleteDeadBlob(ctx, vault, id, cutoff)
	if err != nil || !gone {
		t.Fatalf("DeleteDeadBlob: %v %v", gone, err)
	}
	// Interleaved: the user recreates the file; the client re-uploads.
	e.upload(vault, a, id, blob(1, "v1-again")).expect(t, 201)
	// GC step 2 (Server.GC): the file delete, outside the transaction and
	// outside putBlob's per-blob lock.
	if err := bs.Delete(vault, id); err != nil {
		t.Fatal(err)
	}
	var miss struct{ Missing []string }
	e.do("POST", base+"/blobs/missing", a.token, []string{id}, nil).expect(t, 200).json(t, &miss)
	r := e.do("GET", base+"/blobs/"+id, a.token, nil, nil)
	if r.code != 200 && len(miss.Missing) == 0 {
		t.Fatalf("index and file disagree after GC raced a re-upload: /blobs/missing says present, GET says %d %s", r.code, r.body)
	}
}

// ---------------------------------------------------------------------------
// FINDING (note): POST /auth by an enrolled device answers 204 for the
// current authority token and 409 for any other, and a mismatch is not
// charged to the failed-auth limiter (the authority middleware's is). It is
// an unthrottled equality oracle on the vault authority token. Harmless at
// 256 bits of HKDF output; worth closing because the guide asks that the
// limiter not be bypassable for confirming a guess, and the fix is one line.
func TestZzAuthorityOracleOnAuthRouteIsNotThrottled(t *testing.T) {
	e, _ := rateEnv(t, false)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault
	codes := []int{}
	for range 8 {
		codes = append(codes, e.do("POST", base+"/auth", a.token, map[string]any{"auth": newAuthTok()}, nil).code)
	}
	if codes[len(codes)-1] != 429 {
		t.Fatalf("eight wrong authority tokens on POST /auth were all answered (%v); the same guesses on an authority route are throttled after the burst", codes)
	}
}

// ---------------------------------------------------------------------------
// FINDING (note): Rotate validates that the keybox covers every live device
// and addresses none revoked in this call, but, unlike PutKeybox, it never
// checks that each recipient is a device of this vault. A rotation can
// plant rows for ids that do not exist and for devices revoked by an
// earlier rotation; they persist until min_epoch passes them.
func TestZzRotateAcceptsKeyboxRowsForStrangers(t *testing.T) {
	e := newEnv(t)
	vault, a, b := e.setup()
	base := "/v1/vaults/" + vault
	next := newAuthTok()
	e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 2, "revoke": []string{b.id}, "keybox": []store.KeyboxRow{{Epoch: 2, RecipientID: a.id, Wrapped: randBytes(100)}}, "auth_next": next}, authHdr(vault)).expect(t, 200)
	authTok[vault] = next
	stranger := hex.EncodeToString(randBytes(16))
	next = newAuthTok()
	r := e.do("POST", base+"/rotate", a.token, map[string]any{"epoch": 3, "revoke": nil, "keybox": []store.KeyboxRow{
		{Epoch: 3, RecipientID: a.id, Wrapped: randBytes(100)},
		{Epoch: 3, RecipientID: b.id, Wrapped: randBytes(100)},     // revoked one epoch ago
		{Epoch: 3, RecipientID: stranger, Wrapped: randBytes(100)}, // not a device at all
	}, "auth_next": next}, authHdr(vault))
	if r.code == 200 {
		authTok[vault] = next
		var n int
		e.st.DB().QueryRow(`SELECT COUNT(*) FROM keybox WHERE vault_id=? AND epoch=3 AND recipient_id IN (?,?)`, vault, b.id, stranger).Scan(&n)
		t.Fatalf("rotation stored %d keybox rows for a revoked device and a non-device; PutKeybox refuses the same rows", n)
	}
	if r.code != 400 {
		t.Fatalf("expected 400, got %d: %s", r.code, r.body)
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: one invite, 32 concurrent redemptions, exactly one device.
func TestZzInviteRedemptionRaceIsSingleUse(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	var inv store.Invite
	e.do("POST", "/v1/vaults/"+vault+"/invites", a.token, map[string]any{"keybox_enc": randBytes(64)}, authHdr(vault)).expect(t, 201).json(t, &inv)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65)}, nil).code
			mu.Lock()
			codes[c]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	n, _ := e.st.LiveDeviceCount(t.Context(), vault)
	if codes[201] != 1 || n != 3 {
		t.Fatalf("invite redeemed %d times (codes %v), %d live devices", codes[201], codes, n)
	}
}

// ---------------------------------------------------------------------------
// CONFIRMATION: every route refuses every wrong token class. Admin token on
// device and authority routes, invite token and recovery token as bearer,
// device token on admin routes, authority token as bearer, and an admin
// token in X-Obsync-Vault-Auth.
func TestZzRouteTokenClasses(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	base := "/v1/vaults/" + vault
	var inv store.Invite
	e.do("POST", base+"/invites", a.token, map[string]any{"keybox_enc": randBytes(64)}, authHdr(vault)).expect(t, 201).json(t, &inv)
	recAuth := "rc_" + hex.EncodeToString(randBytes(16))
	e.do("PUT", base+"/recovery", a.token, map[string]any{"pub_kex": randBytes(65), "recovery_enc": randBytes(80), "salt": randBytes(16), "auth": recAuth}, authHdr(vault)).expect(t, 201)

	bid := hexID("x")
	deviceRoutes := []struct{ m, p string }{
		{"GET", base}, {"GET", base + "/devices"}, {"GET", base + "/keybox"}, {"GET", base + "/snapshot"},
		{"GET", base + "/changes?since=0"}, {"GET", base + "/blobs?epoch_lt=2"}, {"GET", base + "/blobs/" + bid},
		{"GET", base + "/ops"}, {"GET", base + "/history?path_id=" + bid}, {"POST", base + "/blobs/missing"},
		{"POST", base + "/keybox"},
	}
	authorityRoutes := []struct{ m, p string }{
		{"PATCH", base + "/devices/me"}, {"POST", base + "/rotate"}, {"PUT", base + "/recovery"},
		{"PUT", base + "/blobs/" + bid}, {"POST", base + "/ops"}, {"PATCH", base + "/ops/1/meta"}, {"POST", base + "/restore"},
	}
	wrongBearers := []string{adminTok, inv.Token, recAuth, authTok[vault], "va_" + strings.Repeat("a", 43)}
	for _, rt := range append(deviceRoutes, authorityRoutes...) {
		for _, tok := range wrongBearers {
			if c := e.do(rt.m, rt.p, tok, []byte("{}"), map[string]string{"X-Obsync-Vault-Auth": authTok[vault]}).code; c != 401 {
				t.Errorf("%s %s with bearer %.6s… → %d, want 401", rt.m, rt.p, tok, c)
			}
		}
	}
	// Authority routes with a valid device but the admin (or recovery) token in the authority header.
	for _, rt := range authorityRoutes {
		for _, va := range []string{adminTok, recAuth, inv.Token} {
			if c := e.do(rt.m, rt.p, a.token, []byte("{}"), map[string]string{"X-Obsync-Vault-Auth": va}).code; c != 401 {
				t.Errorf("%s %s with X-Obsync-Vault-Auth=%.6s… → %d, want 401", rt.m, rt.p, va, c)
			}
		}
	}
	// Admin routes with a device token, an authority token, a recovery token.
	for _, tok := range []string{a.token, authTok[vault], recAuth, inv.Token} {
		if c := e.do("POST", "/v1/vaults", tok, nil, nil).code; c != 401 {
			t.Errorf("POST /v1/vaults with %.6s… → %d", tok, c)
		}
		if c := e.do("GET", "/v1/vaults", tok, nil, nil).code; c != 401 {
			t.Errorf("GET /v1/vaults with %.6s… → %d", tok, c)
		}
	}
	// Recovery join with a device token or the admin token as the rc_ bearer.
	for _, tok := range []string{a.token, adminTok, inv.Token} {
		if c := e.do("POST", base+"/recovery/join", tok, map[string]any{"pub_kex": randBytes(65)}, nil).code; c != 401 {
			t.Errorf("recovery/join with %.6s… → %d", tok, c)
		}
	}
	// The invite still redeems afterwards (none of the above consumed it).
	e.do("POST", "/v1/invites/"+inv.Token, "", map[string]any{"pub_kex": randBytes(65)}, nil).expect(t, 201)
}

// ---------------------------------------------------------------------------
// FINDING (low): in live(), the write on a hub wake-up (`case <-ch`) uses the
// request context with no deadline, while the heartbeat write has a 10 s
// one. A subscriber that completes the handshake and then never reads
// (alive, zero window) absorbs hints until the socket buffers fill; the next
// hub wake-up then parks the handler in a write that nothing times out. The
// ticker, the revocation check and ctx are all behind that select, so the
// goroutine and its connection live as long as the peer keeps the TCP
// session up. Proof: fill the buffers with publishes and look for the live
// handler blocked under wsjson.Write in a goroutine dump.
func TestZzLiveSubscriberThatNeverReadsPinsTheHandlerInAnUnboundedWrite(t *testing.T) {
	e := newEnv(t)
	vault, _, b := e.setup()
	addr := strings.TrimPrefix(e.ts.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A small receive window stands in for a peer on a slow link that has
	// stopped reading; the server's send buffer then fills in a few thousand hints.
	conn.(*net.TCPConn).SetReadBuffer(2048)
	fmt.Fprintf(conn, "GET /v1/vaults/%s/live HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: obsync-bearer, %s\r\n\r\n", vault, addr, b.token)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, " 101 ") {
		t.Fatalf("handshake: %q %v", status, err)
	}
	// From here on the client reads nothing. Publish until the handler is
	// parked in a socket write (buffers full), or give up after 10 s.
	deadline := time.Now().Add(10 * time.Second)
	stuck := ""
	for time.Now().Before(deadline) && stuck == "" {
		for i := range 2000 {
			e.srv.Hub().Publish(vault, int64(i), 1)
		}
		time.Sleep(20 * time.Millisecond)
		stuck = liveHandlerBlockedInWrite()
	}
	if stuck == "" {
		// On a loopback with multi-megabyte buffers and hint coalescing (the
		// hub channel has capacity 1) the handler writes ~4 KB/s, so this
		// attempt does not reach the parked state: the finding is UNPROVEN
		// here and rests on the code (server.go live(): the <-ch write has no
		// deadline; the ping write has 10 s).
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := io.Copy(io.Discard, br)
		t.Skipf("could not fill the loopback socket buffers in 10 s (server had written %d bytes); unproven on this machine", n)
	}
	// Still parked 3 s later; no deadline will ever fire for this write.
	time.Sleep(3 * time.Second)
	if again := liveHandlerBlockedInWrite(); again == "" {
		t.Fatal("handler recovered on its own")
	}
	t.Fatalf("live handler for a non-reading subscriber is parked in a write with no deadline:\n%s", stuck)
}

// liveHandlerBlockedInWrite returns the goroutine stack in which
// (*Server).live is blocked under a websocket write, or "".
func liveHandlerBlockedInWrite() string {
	var buf bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&buf, 2)
	for _, g := range strings.Split(buf.String(), "\n\n") {
		if strings.Contains(g, "api.(*Server).live") && strings.Contains(g, "internal/poll.(*FD).Write") {
			lines := strings.Split(g, "\n")
			if len(lines) > 12 {
				lines = lines[:12]
			}
			return strings.Join(lines, "\n")
		}
	}
	return ""
}
