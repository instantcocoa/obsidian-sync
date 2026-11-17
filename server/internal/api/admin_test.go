package api_test

// Create links and the security-key admin page (DESIGN.md §5.9). A software
// authenticator stands in for the YubiKey: it produces the same attestation
// and assertion structures a browser would hand the page, signed with a
// P-256 key it holds, so the full register → sign in → mint flow runs here.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"obsync/internal/api"
	"obsync/internal/blobstore"
	"obsync/internal/store"
)

// ---------- create links ----------

func TestCreateLinkLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	body := func() map[string]any { return map[string]any{"pub_kex": testPubKex(), "name_enc": randBytes(20)} }

	// Unknown, malformed, expired: one and the same 401.
	e.do("POST", "/v1/create/cr_nope", "", body(), nil).expect(t, 401)
	e.do("POST", "/v1/create/in_nope", "", body(), nil).expect(t, 401)
	short, err := e.st.CreateLink(ctx, store.LinkCreate, "test", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	e.do("POST", "/v1/create/"+short.Token, "", body(), nil).expect(t, 401)
	// A register link is not a create link.
	rg, _ := e.st.CreateLink(ctx, store.LinkRegister, "test", time.Hour)
	e.do("POST", "/v1/create/"+rg.Token, "", body(), nil).expect(t, 401)
	// A bad public key is refused without spending the link.
	tok := e.createLink()
	e.do("POST", "/v1/create/"+tok, "", map[string]any{"pub_kex": randBytes(10)}, nil).expect(t, 400)

	var red store.Redeemed
	e.do("POST", "/v1/create/"+tok, "", body(), nil).expect(t, 201).json(t, &red)
	if red.VaultID == "" || red.DeviceID == "" || !strings.HasPrefix(red.DeviceToken, "dv_") || red.Epoch != 1 || len(red.KeyboxEnc) != 0 {
		t.Fatalf("redeemed: %+v", red)
	}
	// One-time.
	e.do("POST", "/v1/create/"+tok, "", body(), nil).expect(t, 401)

	// The first device is a real member: it claims authority and writes.
	v := red.VaultID
	d := device{red.DeviceID, red.DeviceToken}
	var info store.Vault
	e.do("GET", "/v1/vaults/"+v, d.token, nil, nil).expect(t, 200).json(t, &info)
	if info.HasAuth || info.Epoch != 1 {
		t.Fatalf("fresh vault: %+v", info)
	}
	authTok[v] = newAuthTok()
	e.do("POST", "/v1/vaults/"+v+"/keybox", d.token, map[string]any{"keybox": []store.KeyboxRow{{Epoch: 1, RecipientID: d.id, Wrapped: randBytes(100)}}}, nil).expect(t, 204)
	e.do("POST", "/v1/vaults/"+v+"/auth", d.token, map[string]any{"auth": authTok[v]}, nil).expect(t, 204)
	e.ops(v, d, put("hello.md", nil, 0))
	// And it alone can invite.
	e.do("POST", "/v1/vaults/"+v+"/invites", d.token, map[string]any{"keybox_enc": randBytes(64)}, authHdr(v)).expect(t, 201)

	// The operator's listing shows the vault with one device; devices never see that route.
	vs, err := e.st.ListVaults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range vs {
		if x.ID == v {
			found = true
			if x.Devices != 1 || !x.HasAuth {
				t.Fatalf("listing: %+v", x)
			}
		}
	}
	if !found {
		t.Fatal("vault missing from listing")
	}
	if c := e.do("GET", "/v1/vaults", d.token, nil, nil).code; c != 404 && c != 405 {
		t.Fatalf("GET /v1/vaults should not exist, got %d", c)
	}
}

func TestCreateLinkBounds(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for i := 0; i < store.MaxOpenLinks; i++ {
		if _, err := e.st.CreateLink(ctx, store.LinkCreate, "test", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.st.CreateLink(ctx, store.LinkCreate, "test", time.Hour); err == nil {
		t.Fatal("unbounded create links")
	}
	// Register links have their own budget.
	if _, err := e.st.CreateLink(ctx, store.LinkRegister, "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	// TTLs outside 1s..24h are refused.
	if _, err := e.st.CreateLink(ctx, store.LinkRegister, "test", 48*time.Hour); err == nil {
		t.Fatal("48h link accepted")
	}
}

func TestLinkFormats(t *testing.T) {
	link := api.CreateLink("https://sync.example.com", "cr_abc")
	if link != "obsync://create#https%3A%2F%2Fsync.example.com,cr_abc" {
		t.Fatalf("create link: %s", link)
	}
	open := api.OpenURL(link)
	u, err := url.Parse(open)
	if err != nil || u.Scheme != "obsidian" || u.Host != "obsync-join" || u.Query().Get("link") != link {
		t.Fatalf("open url: %s (%v)", open, err)
	}
	if got := api.RegisterURL("https://sync.example.com/", "rg_x"); got != "https://sync.example.com/admin/r/rg_x" {
		t.Fatalf("register url: %s", got)
	}
}

// ---------- the admin page ----------

// adminEnv serves with a PublicURL so the page is on. WebAuthn needs a
// domain for the relying party, so the public URL is the httptest server's
// port on "localhost" while the client still connects to 127.0.0.1.
func adminEnv(t *testing.T) *env {
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
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	srv := api.New(api.Config{PublicURL: adminOrigin(ts.URL), InviteTTL: time.Hour, AuthRatePerMinute: -1}, st, bs)
	ts.Config.Handler = srv
	t.Cleanup(func() { ts.Close(); st.Close() })
	return &env{t: t, ts: ts, srv: srv, st: st}
}

func adminOrigin(tsURL string) string { return strings.Replace(tsURL, "127.0.0.1", "localhost", 1) }

// adminDo is e.do with an Origin header (a browser sends one on every POST)
// and an optional session cookie.
func (e *env) adminDo(method, path string, body any, cookie string, hdr map[string]string) resp {
	e.t.Helper()
	h := map[string]string{"Origin": adminOrigin(e.ts.URL)}
	if cookie != "" {
		h["Cookie"] = "obsync_admin=" + cookie
	}
	for k, v := range hdr {
		h[k] = v
	}
	return e.do(method, path, "", body, h)
}

func cookieOf(r resp) string { return namedCookie(r, "obsync_admin") }

func namedCookie(r resp, name string) string {
	for _, c := range (&http.Response{Header: r.hdr}).Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// jar is the Cookie header a browser would send: session, door and known.
func jar(sess, door, known string) string {
	parts := []string{}
	if sess != "" {
		parts = append(parts, "obsync_admin="+sess)
	}
	if door != "" {
		parts = append(parts, "obsync_admin_door="+door)
	}
	if known != "" {
		parts = append(parts, "obsync_admin_known="+known)
	}
	return strings.Join(parts, "; ")
}

func (e *env) registerLink() string {
	e.t.Helper()
	l, err := e.st.CreateLink(context.Background(), store.LinkRegister, "test", time.Hour)
	if err != nil {
		e.t.Fatal(err)
	}
	return l.Token
}

// openDoor follows a fresh register link the way a browser does and returns
// the door cookie the redirect set.
func (e *env) openDoor() string {
	e.t.Helper()
	e.noFollow = true
	r := e.do("GET", "/admin/r/"+e.registerLink(), "", nil, nil)
	e.noFollow = false
	if r.code != 303 || r.hdr.Get("Location") != "/admin/" {
		e.t.Fatalf("door: %d %v", r.code, r.hdr)
	}
	door := namedCookie(r, "obsync_admin_door")
	if door == "" || !strings.Contains(r.hdr.Get("Set-Cookie"), "SameSite=Lax") {
		e.t.Fatalf("door cookie: %s", r.hdr.Get("Set-Cookie"))
	}
	return door
}

// notFound checks a response is indistinguishable from any unknown path's.
func notFound(t *testing.T, r resp) {
	t.Helper()
	if r.code != 404 || strings.TrimSpace(string(r.body)) != "404 page not found" || r.hdr.Get("Content-Security-Policy") != "" || r.hdr.Get("Set-Cookie") != "" || r.hdr.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("not a plain 404: %d %q %v", r.code, r.body, r.hdr)
	}
}

func TestAdminPageOffWithoutPublicURL(t *testing.T) {
	e := newEnv(t)
	notFound(t, e.do("GET", "/admin/", "", nil, nil))
	notFound(t, e.adminDo("POST", "/admin/api/login/begin", nil, "", nil))
	notFound(t, e.adminDo("GET", "/admin/api/state", nil, "", nil))
}

// A stranger sees nothing under /admin: not the page, not its assets, not
// the API, not a wrong register link, not a wrong method on the right path.
// Every answer is the 404 any unknown path gets, headers included.
func TestAdminHiddenFromStrangers(t *testing.T) {
	e := adminEnv(t)
	for _, p := range []string{"/admin", "/admin/", "/admin/app.js", "/admin/app.css", "/admin/api/state", "/admin/r/rg_nope", "/admin/r/" + e.registerLink()[3:], "/admin/register", "/admin/nothing"} {
		notFound(t, e.do("GET", p, "", nil, nil))
	}
	notFound(t, e.adminDo("POST", "/admin/api/login/begin", nil, "", nil))
	notFound(t, e.adminDo("POST", "/admin/api/register/begin", map[string]any{}, "", nil))
	notFound(t, e.adminDo("POST", "/admin/api/create-link", nil, "", nil))
	notFound(t, e.adminDo("POST", "/admin/api/create-link", nil, "forged-session", nil))
	notFound(t, e.do("POST", "/admin/r/"+e.registerLink(), "", nil, nil))
	notFound(t, e.do("GET", "/admin/", "", nil, map[string]string{"Cookie": jar("", "forged-door", "forged-known")}))
	// The same 404 the device API gives for a path it has never heard of.
	notFound(t, e.do("GET", "/v1/nothing", "", nil, nil))
	// A spent link is a 404 too.
	door := e.openDoor()
	key := newSoftKey(t, adminOrigin(e.ts.URL))
	var begin struct {
		Ceremony string          `json:"ceremony"`
		Options  json.RawMessage `json:"options"`
	}
	e.adminDo("POST", "/admin/api/register/begin", map[string]any{}, "", map[string]string{"Cookie": jar("", door, "")}).expect(t, 200).json(t, &begin)
	e.adminDo("POST", "/admin/api/register/finish", map[string]any{"ceremony": begin.Ceremony, "name": "k", "credential": key.attest(t, begin.Options)}, "", map[string]string{"Cookie": jar("", door, "")}).expect(t, 201)
	notFound(t, e.do("GET", "/admin/", "", nil, map[string]string{"Cookie": jar("", door, "")}))
}

// An IP-address public URL (LAN or test deployment) keeps links working but
// turns the security-key page off with an explanation, instead of refusing to start.
func TestAdminPageOffForIPPublicURL(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir + "/db.sqlite")
	bs, _ := blobstore.New(dir + "/blobs")
	srv := api.New(api.Config{PublicURL: "http://192.168.1.10:8080", AuthRatePerMinute: -1}, st, bs)
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close(); st.Close() })
	e := &env{t: t, ts: ts, srv: srv, st: st}
	notFound(t, e.do("GET", "/admin/", "", nil, nil))
	notFound(t, e.do("GET", "/admin/r/"+e.registerLink(), "", nil, nil))
	e.newVault() // create links still redeem
}

func TestAdminPageHeaders(t *testing.T) {
	e := adminEnv(t)
	door := e.openDoor()
	r := e.do("GET", "/admin/", "", nil, map[string]string{"Origin": "https://evil.example", "Cookie": jar("", door, "")})
	r.expect(t, 200)
	if !strings.Contains(string(r.body), "<title>obsync admin</title>") {
		t.Fatalf("not the page: %.100s", r.body)
	}
	if r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS header on the admin page")
	}
	csp := r.hdr.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP lacks %q: %s", want, csp)
		}
	}
	if r.hdr.Get("Cache-Control") != "no-store" || r.hdr.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", r.hdr)
	}
	for _, p := range []string{"/admin/app.js", "/admin/app.css"} {
		e.do("GET", p, "", nil, map[string]string{"Cookie": jar("", door, "")}).expect(t, 200)
	}
	// Device routes still carry CORS for Obsidian's app:// origin.
	if h := e.do("GET", "/healthz", "", nil, nil); h.hdr.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("CORS missing on device routes")
	}
}

func TestAdminRegisterLoginCreate(t *testing.T) {
	e := adminEnv(t)
	// Through the door: the page shows, the state says so, nothing to sign in with yet.
	door := e.openDoor()
	at := func(door, known string) map[string]string { return map[string]string{"Cookie": jar("", door, known)} }
	var st map[string]any
	e.adminDo("GET", "/admin/api/state", nil, "", at(door, "")).expect(t, 200).json(t, &st)
	if st["registered"] != false || st["logged_in"] != false || st["door"] != true {
		t.Fatalf("state: %v", st)
	}
	e.adminDo("POST", "/admin/api/login/begin", nil, "", at(door, "")).expect(t, 409)

	// Register: begin, authenticator creates, finish.
	key := newSoftKey(t, adminOrigin(e.ts.URL))
	var begin struct {
		Ceremony string          `json:"ceremony"`
		Options  json.RawMessage `json:"options"`
	}
	e.adminDo("POST", "/admin/api/register/begin", map[string]any{}, "", at(door, "")).expect(t, 200).json(t, &begin)
	att := key.attest(t, begin.Options)
	// The wrong ceremony id is a failed authentication; the link survives.
	e.adminDo("POST", "/admin/api/register/finish", map[string]any{"ceremony": "bogus", "name": "k", "credential": att}, "", at(door, "")).expect(t, 401)
	// Begin again (the ceremony above was consumed by the failed finish).
	e.adminDo("POST", "/admin/api/register/begin", map[string]any{}, "", at(door, "")).expect(t, 200).json(t, &begin)
	att = key.attest(t, begin.Options)
	var reg map[string]any
	r := e.adminDo("POST", "/admin/api/register/finish", map[string]any{"ceremony": begin.Ceremony, "name": "yubikey 5", "credential": att}, "", at(door, "")).expect(t, 201)
	r.json(t, &reg)
	if reg["name"] != "yubikey 5" {
		t.Fatalf("register: %v", reg)
	}
	// The browser is now known (a long-lived cookie, hashed on the server) and the door is closed.
	known := namedCookie(r, "obsync_admin_known")
	if known == "" || !strings.Contains(r.hdr.Get("Set-Cookie"), "Max-Age=31536000") {
		t.Fatalf("known cookie: %v", r.hdr.Values("Set-Cookie"))
	}
	// The link and the door are spent.
	e.adminDo("POST", "/admin/api/register/begin", map[string]any{}, "", at(door, known)).expect(t, 401)
	notFound(t, e.do("GET", "/admin/", "", nil, at(door, "")))
	keys, _ := e.st.ListAdminCredentials(context.Background())
	if len(keys) != 1 || keys[0].Name != "yubikey 5" || !bytes.Equal(keys[0].ID, key.id) {
		t.Fatalf("stored keys: %+v", keys)
	}
	// Known: the page shows with a sign-in button; no door, no session.
	e.do("GET", "/admin/", "", nil, at("", known)).expect(t, 200)
	e.adminDo("GET", "/admin/api/state", nil, "", at("", known)).expect(t, 200).json(t, &st)
	if st["registered"] != true || st["logged_in"] != false || st["door"] != false || st["vaults"] != nil {
		t.Fatalf("state: %v", st)
	}

	// Not signed in: no link.
	e.adminDo("POST", "/admin/api/create-link", nil, "", at("", known)).expect(t, 401)
	e.adminDo("POST", "/admin/api/create-link", nil, "not-a-session", at("", known)).expect(t, 401)

	// Sign in with a different key: refused.
	stranger := newSoftKey(t, adminOrigin(e.ts.URL))
	e.adminDo("POST", "/admin/api/login/begin", nil, "", at("", known)).expect(t, 200).json(t, &begin)
	e.adminDo("POST", "/admin/api/login/finish", map[string]any{"ceremony": begin.Ceremony, "credential": stranger.assertWithID(t, begin.Options, key.id)}, "", at("", known)).expect(t, 401)

	// Sign in with the registered key.
	e.adminDo("POST", "/admin/api/login/begin", nil, "", at("", known)).expect(t, 200).json(t, &begin)
	// allowCredentials names the registered key, nothing else.
	var opts struct {
		PublicKey struct {
			Allow []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
			RPID string `json:"rpId"`
		} `json:"publicKey"`
	}
	json.Unmarshal(begin.Options, &opts)
	if len(opts.PublicKey.Allow) != 1 || opts.PublicKey.Allow[0].ID != base64.RawURLEncoding.EncodeToString(key.id) || opts.PublicKey.RPID != "localhost" {
		t.Fatalf("login options: %s", begin.Options)
	}
	// A replayed ceremony id (same options signed twice) is refused after the first use.
	asr := key.assert(t, begin.Options)
	r = e.adminDo("POST", "/admin/api/login/finish", map[string]any{"ceremony": begin.Ceremony, "credential": asr}, "", at("", known)).expect(t, 200)
	sess := cookieOf(r)
	if sess == "" {
		t.Fatal("no session cookie")
	}
	raw := r.hdr.Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "SameSite=Strict", "Path=/admin"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("cookie attributes: %s", raw)
		}
	}
	if namedCookie(r, "obsync_admin_known") != "" {
		t.Fatal("a known browser was given a second known cookie")
	}
	e.adminDo("POST", "/admin/api/login/finish", map[string]any{"ceremony": begin.Ceremony, "credential": asr}, "", at("", known)).expect(t, 401)

	// Signed in: state shows vaults and keys; a link can be minted.
	e.adminDo("GET", "/admin/api/state", nil, sess, nil).expect(t, 200).json(t, &st)
	if st["logged_in"] != true || st["key"] != "yubikey 5" {
		t.Fatalf("state: %v", st)
	}
	var made struct {
		Link      string `json:"link"`
		OpenURL   string `json:"open_url"`
		QR        string `json:"qr_svg"`
		ExpiresAt int64  `json:"expires_at"`
	}
	e.adminDo("POST", "/admin/api/create-link", nil, sess, nil).expect(t, 201).json(t, &made)
	prefix := "obsync://create#" + url.QueryEscape(adminOrigin(e.ts.URL)) + ",cr_"
	if !strings.HasPrefix(made.Link, prefix) || !strings.HasPrefix(made.OpenURL, "obsidian://obsync-join?link=") || !strings.HasPrefix(made.QR, "<svg") || made.ExpiresAt < time.Now().UnixMilli() {
		t.Fatalf("create link: %+v", made)
	}
	// The link works for a device, once.
	tok := made.Link[strings.LastIndex(made.Link, ",")+1:]
	var red store.Redeemed
	e.do("POST", "/v1/create/"+tok, "", map[string]any{"pub_kex": testPubKex()}, nil).expect(t, 201).json(t, &red)
	e.do("POST", "/v1/create/"+tok, "", map[string]any{"pub_kex": testPubKex()}, nil).expect(t, 401)
	e.adminDo("GET", "/admin/api/state", nil, sess, nil).expect(t, 200).json(t, &st)
	vaults, _ := st["vaults"].([]any)
	if len(vaults) != 1 {
		t.Fatalf("state after create: %v", st)
	}

	// Cross-origin: refused even with the cookie (CSRF). No Origin at all: refused.
	e.do("POST", "/admin/api/create-link", "", nil, map[string]string{"Origin": "https://evil.example", "Cookie": "obsync_admin=" + sess}).expect(t, 403)
	e.do("POST", "/admin/api/create-link", "", nil, map[string]string{"Cookie": "obsync_admin=" + sess}).expect(t, 403)

	// The session cannot register a key: that takes a register link from the host.
	e.adminDo("POST", "/admin/api/register/begin", map[string]any{}, sess, nil).expect(t, 401)

	// Sign out ends the session; the browser stays known (sign-in button, no 404).
	e.adminDo("POST", "/admin/api/logout", nil, sess, nil).expect(t, 204)
	// A dead session alone is a stranger (404); with its known cookie, as a
	// real browser sends it, the page is there and the session is gone (401).
	notFound(t, e.adminDo("POST", "/admin/api/create-link", nil, sess, nil))
	e.adminDo("POST", "/admin/api/create-link", nil, "", map[string]string{"Cookie": jar(sess, "", known)}).expect(t, 401)
	e.do("GET", "/admin/", "", nil, at("", known)).expect(t, 200)

	// A cloned key (counter went backwards) is refused on sign-in.
	e.adminDo("POST", "/admin/api/login/begin", nil, "", at("", known)).expect(t, 200).json(t, &begin)
	key.counter = 0
	e.adminDo("POST", "/admin/api/login/finish", map[string]any{"ceremony": begin.Ceremony, "credential": key.assert(t, begin.Options)}, "", at("", known)).expect(t, 401)

	// A second browser (no cookies) comes in through a new link. It may sign
	// in with the existing key instead of adding one; that spends the link
	// and makes it known too.
	door2 := e.openDoor()
	e.adminDo("GET", "/admin/api/state", nil, "", at(door2, "")).expect(t, 200).json(t, &st)
	if st["registered"] != true || st["door"] != true {
		t.Fatalf("second browser state: %v", st)
	}
	key.counter = 10
	e.adminDo("POST", "/admin/api/login/begin", nil, "", at(door2, "")).expect(t, 200).json(t, &begin)
	r = e.adminDo("POST", "/admin/api/login/finish", map[string]any{"ceremony": begin.Ceremony, "credential": key.assert(t, begin.Options)}, "", at(door2, "")).expect(t, 200)
	known2 := namedCookie(r, "obsync_admin_known")
	if known2 == "" || cookieOf(r) == "" {
		t.Fatalf("second browser cookies: %v", r.hdr.Values("Set-Cookie"))
	}
	notFound(t, e.do("GET", "/admin/", "", nil, at(door2, "")))
	e.do("GET", "/admin/", "", nil, at("", known2)).expect(t, 200)

	// Registering the same key again is excluded by the options the page gets.
	// (The first browser follows this link, so it sends its known cookie too.)
	door3 := e.openDoor()
	e.adminDo("POST", "/admin/api/register/begin", map[string]any{}, "", at(door3, known)).expect(t, 200).json(t, &begin)
	var creation struct {
		PublicKey struct {
			Exclude []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
			Attestation string `json:"attestation"`
			Selection   struct {
				ResidentKey string `json:"residentKey"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	json.Unmarshal(begin.Options, &creation)
	if len(creation.PublicKey.Exclude) != 1 || creation.PublicKey.Exclude[0].ID != base64.RawURLEncoding.EncodeToString(key.id) || creation.PublicKey.Attestation != "none" || creation.PublicKey.Selection.ResidentKey != "discouraged" {
		t.Fatalf("creation options: %s", begin.Options)
	}
	// A second key registers fine and the first can be removed by name.
	second := newSoftKey(t, adminOrigin(e.ts.URL))
	r = e.adminDo("POST", "/admin/api/register/finish", map[string]any{"ceremony": begin.Ceremony, "name": "", "credential": second.attest(t, begin.Options)}, "", at(door3, known)).expect(t, 201)
	if namedCookie(r, "obsync_admin_known") != "" {
		t.Fatal("an already known browser got a second known cookie on register")
	}
	keys, _ = e.st.ListAdminCredentials(context.Background())
	if len(keys) != 2 || !strings.HasPrefix(keys[1].Name, "security key ") {
		t.Fatalf("keys: %+v", keys)
	}
	if err := e.st.RemoveAdminCredential(context.Background(), "yubikey 5"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.RemoveAdminCredential(context.Background(), "yubikey 5"); err == nil {
		t.Fatal("removed twice")
	}
	e.adminDo("POST", "/admin/api/login/begin", nil, "", at("", known)).expect(t, 200).json(t, &begin)
	e.adminDo("POST", "/admin/api/login/finish", map[string]any{"ceremony": begin.Ceremony, "credential": second.assert(t, begin.Options)}, "", at("", known)).expect(t, 200)

	// Forgetting browsers on the host makes them all strangers again.
	if n, err := e.st.ForgetAdminBrowsers(context.Background()); err != nil || n != 2 {
		t.Fatalf("forget: %d %v", n, err)
	}
	notFound(t, e.do("GET", "/admin/", "", nil, at("", known)))
	notFound(t, e.do("GET", "/admin/", "", nil, at("", known2)))
}

// The known-browser table is bounded: the oldest entry goes.
func TestAdminBrowserCap(t *testing.T) {
	e := adminEnv(t)
	ctx := context.Background()
	first := bytes.Repeat([]byte{1}, 32)
	if err := e.st.AddAdminBrowser(ctx, first); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < store.MaxAdminBrowsers; i++ {
		h := bytes.Repeat([]byte{byte(i + 2)}, 32)
		if err := e.st.AddAdminBrowser(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := e.st.AdminBrowserKnown(ctx, first); ok {
		t.Fatal("oldest browser survived the cap")
	}
	if ok, _ := e.st.AdminBrowserKnown(ctx, bytes.Repeat([]byte{byte(store.MaxAdminBrowsers + 1)}, 32)); !ok {
		t.Fatal("newest browser missing")
	}
}

// A wrong origin inside the signed client data (a phishing page proxying the
// ceremony) fails verification even though the HTTP Origin header is right.
func TestAdminPhishedOriginFails(t *testing.T) {
	e := adminEnv(t)
	key := newSoftKey(t, "https://sync.owner.example.evil.example")
	door := e.openDoor()
	hdr := map[string]string{"Cookie": jar("", door, "")}
	var begin struct {
		Ceremony string          `json:"ceremony"`
		Options  json.RawMessage `json:"options"`
	}
	e.adminDo("POST", "/admin/api/register/begin", map[string]any{}, "", hdr).expect(t, 200).json(t, &begin)
	e.adminDo("POST", "/admin/api/register/finish", map[string]any{"ceremony": begin.Ceremony, "name": "k", "credential": key.attest(t, begin.Options)}, "", hdr).expect(t, 401)
	// The link is still usable by the real page: the door is open and begin works again.
	e.adminDo("POST", "/admin/api/register/begin", map[string]any{}, "", hdr).expect(t, 200)
}

// ---------- a software security key ----------

type softKey struct {
	priv    *ecdsa.PrivateKey
	id      []byte
	origin  string
	rpID    string
	counter uint32
}

func newSoftKey(t *testing.T, origin string) *softKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(origin)
	return &softKey{priv: priv, id: randBytes(32), origin: origin, rpID: u.Hostname(), counter: 1}
}

func (k *softKey) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": k.origin, "crossOrigin": false})
	return b
}

func (k *softKey) authData(flags byte, withKey bool) []byte {
	h := sha256.Sum256([]byte(k.rpID))
	var b bytes.Buffer
	b.Write(h[:])
	b.WriteByte(flags)
	binary.Write(&b, binary.BigEndian, k.counter)
	if withKey {
		b.Write(make([]byte, 16)) // AAGUID
		binary.Write(&b, binary.BigEndian, uint16(len(k.id)))
		b.Write(k.id)
		pub, err := k.priv.PublicKey.Bytes() // 0x04 || x || y
		if err != nil {
			panic(err)
		}
		x, y := pub[1:33], pub[33:65]
		// COSE_Key: kty EC2, alg ES256, crv P-256, x, y
		b.Write(cbor(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y}))
	}
	return b.Bytes()
}

func challengeOf(t *testing.T, options json.RawMessage) string {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil || o.PublicKey.Challenge == "" {
		t.Fatalf("options without a challenge: %s", options)
	}
	return o.PublicKey.Challenge
}

// attest answers a creation ceremony with attestation format "none".
func (k *softKey) attest(t *testing.T, options json.RawMessage) map[string]any {
	cd := k.clientData("webauthn.create", challengeOf(t, options))
	att := cbor(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(0x45 /* UP|UV|AT */, true)})
	id := base64.RawURLEncoding.EncodeToString(k.id)
	return map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cd),
			"attestationObject": base64.RawURLEncoding.EncodeToString(att),
			"transports":        []string{"usb", "nfc"},
		},
		"clientExtensionResults": map[string]any{},
	}
}

// assert answers a request ceremony, incrementing the counter like a real key.
func (k *softKey) assert(t *testing.T, options json.RawMessage) map[string]any {
	return k.assertWithID(t, options, k.id)
}

// assertWithID lets a stranger's key claim a registered credential id.
func (k *softKey) assertWithID(t *testing.T, options json.RawMessage, id []byte) map[string]any {
	k.counter++
	cd := k.clientData("webauthn.get", challengeOf(t, options))
	ad := k.authData(0x05 /* UP|UV */, false)
	cdh := sha256.Sum256(cd)
	msg := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	eid := base64.RawURLEncoding.EncodeToString(id)
	return map[string]any{
		"id": eid, "rawId": eid, "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cd),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(ad),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
			"userHandle":        nil,
		},
		"clientExtensionResults": map[string]any{},
	}
}

// cbor is the small canonical encoder the authenticator structures need:
// maps with int or text keys, text and byte strings, small ints.
func cbor(v any) []byte {
	var b bytes.Buffer
	cborTo(&b, v)
	return b.Bytes()
}

func cborHead(b *bytes.Buffer, major byte, n uint64) {
	switch {
	case n < 24:
		b.WriteByte(major<<5 | byte(n))
	case n < 1<<8:
		b.WriteByte(major<<5 | 24)
		b.WriteByte(byte(n))
	case n < 1<<16:
		b.WriteByte(major<<5 | 25)
		binary.Write(b, binary.BigEndian, uint16(n))
	default:
		b.WriteByte(major<<5 | 26)
		binary.Write(b, binary.BigEndian, uint32(n))
	}
}

func cborTo(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case int:
		if x >= 0 {
			cborHead(b, 0, uint64(x))
		} else {
			cborHead(b, 1, uint64(-1-x))
		}
	case []byte:
		cborHead(b, 2, uint64(len(x)))
		b.Write(x)
	case string:
		cborHead(b, 3, uint64(len(x)))
		b.WriteString(x)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// Canonical order: shorter keys first, then bytewise.
		sort.Slice(keys, func(i, j int) bool {
			if len(keys[i]) != len(keys[j]) {
				return len(keys[i]) < len(keys[j])
			}
			return keys[i] < keys[j]
		})
		cborHead(b, 5, uint64(len(keys)))
		for _, k := range keys {
			cborTo(b, k)
			cborTo(b, x[k])
		}
	case map[int]any:
		keys := make([]int, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// Canonical order for ints: by encoded form, which for these small
		// values is non-negatives ascending then negatives by magnitude.
		sort.Slice(keys, func(i, j int) bool {
			ei, ej := cbor(keys[i]), cbor(keys[j])
			if len(ei) != len(ej) {
				return len(ei) < len(ej)
			}
			return bytes.Compare(ei, ej) < 0
		})
		cborHead(b, 5, uint64(len(keys)))
		for _, k := range keys {
			cborTo(b, k)
			cborTo(b, x[k])
		}
	default:
		panic("cbor: unsupported type")
	}
}
