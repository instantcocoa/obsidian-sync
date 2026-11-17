package api

// The admin page (DESIGN.md §5.9): a small same-origin browser app served
// from this binary at /admin that lets the operator sign in with a security
// key (WebAuthn: a YubiKey over USB or NFC, or a platform authenticator) and
// mint create links for new vaults. There is no password and no admin bearer
// token: the server stores only the keys' public halves, so nothing on its
// disk lets anyone sign in. A signed-in admin can list vaults (ids and
// device counts, nothing readable) and create new ones; it can never read,
// join or alter an existing vault, because that takes the vault keys, which
// only devices hold.
//
// Registering a key needs a register link minted on the host
// (`obsync admin register`), so a stolen admin session cannot add a key.
//
// To anyone else the page does not exist: every /admin path answers the
// same plain 404 as any unknown path unless the browser is known. A browser
// becomes known by arriving through a register link (GET /admin/r/{t} sets a
// short-lived "door" cookie and redirects to the page) and finishing a
// ceremony there, after which a long-lived cookie, stored hashed, marks it.
// Being known shows the sign-in button and nothing more.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"obsync/internal/qr"
	"obsync/internal/store"
)

//go:embed adminpage/*
var adminPage embed.FS

// errAdminNeedsDomain: a --public-url with an IP address host (a LAN or test
// deployment) gets create links but no security-key page.
var errAdminNeedsDomain = errors.New("the admin page needs --public-url to name a domain, not an IP address")

const (
	adminCookie        = "obsync_admin"
	adminKnownCookie   = "obsync_admin_known" // this browser has finished a ceremony here; shows the page
	adminDoorCookie    = "obsync_admin_door"  // this browser arrived through a live register link
	adminSessionTTL    = 15 * time.Minute
	adminDoorTTL       = 10 * time.Minute
	adminKnownTTL      = 365 * 24 * time.Hour
	maxAdminDoors      = 100
	adminCeremonyTTL   = 5 * time.Minute
	adminRegisterTTL   = time.Hour // how long a register link minted by the CLI lives (the CLI may shorten it)
	maxPendingCeremony = 1000      // begin() calls without a finish(), across all clients
	maxAdminSessions   = 100
)

type adminCeremony struct {
	session webauthn.SessionData
	expires time.Time
}

type adminSession struct {
	key     string // the credential's name, for the log
	expires time.Time
}

// adminDoor is a browser that followed a register link and has not yet
// registered or signed in; it carries the link so the page need not.
type adminDoor struct {
	token   string
	expires time.Time
}

type admin struct {
	wa        *webauthn.WebAuthn
	origin    string // canonical PublicURL, scheme://host[:port]
	secure    bool
	mu        sync.Mutex
	ceremonie map[string]adminCeremony // ceremony id → pending WebAuthn session
	sessions  map[[32]byte]adminSession
	doors     map[[32]byte]adminDoor
}

// adminUser is the single admin account every registered key belongs to.
type adminUser struct{ creds []webauthn.Credential }

func (adminUser) WebAuthnID() []byte                           { return []byte("obsync-admin") }
func (adminUser) WebAuthnName() string                         { return "admin" }
func (adminUser) WebAuthnDisplayName() string                  { return "obsync admin" }
func (u adminUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// newAdmin configures WebAuthn for the public URL, or returns nil (page
// disabled) when there is none.
func newAdmin(publicURL string) (*admin, error) {
	if publicURL == "" {
		return nil, nil
	}
	u, err := url.Parse(publicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("--public-url must be an origin such as https://sync.example.com")
	}
	origin := u.Scheme + "://" + u.Host
	if net.ParseIP(u.Hostname()) != nil {
		// WebAuthn binds credentials to a domain, never an address. Links
		// still work (the CLI prints them); the page says why it is off.
		return nil, errAdminNeedsDomain
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "obsync",
		RPOrigins:     []string{origin},
		// A roaming key (YubiKey) is the expected authenticator; no resident
		// credential is needed, user verification (PIN) is welcome but not
		// demanded, since a touch on a key the person physically holds is the
		// factor this page is built on.
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementDiscouraged, UserVerification: protocol.VerificationPreferred},
		AttestationPreference:  protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: adminCeremonyTTL, TimeoutUVD: adminCeremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: adminCeremonyTTL, TimeoutUVD: adminCeremonyTTL},
		},
	})
	if err != nil {
		return nil, err
	}
	return &admin{wa: wa, origin: origin, secure: u.Scheme == "https", ceremonie: map[string]adminCeremony{}, sessions: map[[32]byte]adminSession{}, doors: map[[32]byte]adminDoor{}}, nil
}

// adminRoutes are reached only through ServeHTTP's gate (adminVisible): a
// request that gets here has a live door, a known-browser cookie or a
// session, or is the door itself.
func (s *Server) adminRoutes() {
	m := s.mux
	m.HandleFunc("GET /admin/{$}", s.adminStatic("adminpage/index.html", "text/html; charset=utf-8"))
	m.HandleFunc("GET /admin/app.js", s.adminStatic("adminpage/app.js", "text/javascript; charset=utf-8"))
	m.HandleFunc("GET /admin/app.css", s.adminStatic("adminpage/app.css", "text/css; charset=utf-8"))
	m.HandleFunc("GET /admin/r/{t}", s.adminOpenDoor) // not rate-limited: a 429 would say the path exists, and the token is 256 bits
	m.HandleFunc("GET /admin/api/state", s.adminState)
	m.HandleFunc("POST /admin/api/register/begin", s.sameOrigin(s.limited(s.adminRegisterBegin)))
	m.HandleFunc("POST /admin/api/register/finish", s.sameOrigin(s.limited(s.adminRegisterFinish)))
	m.HandleFunc("POST /admin/api/login/begin", s.sameOrigin(s.limited(s.adminLoginBegin)))
	m.HandleFunc("POST /admin/api/login/finish", s.sameOrigin(s.limited(s.adminLoginFinish)))
	m.HandleFunc("POST /admin/api/logout", s.sameOrigin(s.adminLogout))
	m.HandleFunc("POST /admin/api/create-link", s.sameOrigin(s.adminSessionRequired(s.adminCreateLink)))
}

func (s *Server) adminStatic(name, ctype string) http.HandlerFunc {
	body, err := adminPage.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ctype)
		w.Write(body)
	}
}

// adminVisible decides whether this request may see that /admin exists at
// all: it needs a cookie the server recognises. The door (GET /admin/r/{t})
// is the one way in without one; ServeHTTP routes it like a device path, so
// a bad token's 404 carries the same headers as any unknown path's.
func (s *Server) adminVisible(r *http.Request) bool {
	if s.admin == nil {
		return false
	}
	if _, ok := s.admin.lookup(r); ok {
		return true
	}
	if _, ok := s.admin.door(r); ok {
		return true
	}
	return s.knownBrowser(r)
}

// knownBrowser checks the long-lived cookie against the stored hashes.
func (s *Server) knownBrowser(r *http.Request) bool {
	c, err := r.Cookie(adminKnownCookie)
	if err != nil || c.Value == "" {
		return false
	}
	h := sessionKey(c.Value)
	ok, err := s.st.AdminBrowserKnown(r.Context(), h[:])
	return err == nil && ok
}

// adminOpenDoor is where a register link lands: GET /admin/r/{t}. A live
// link sets the door cookie and sends the browser to the page, so the token
// leaves the address bar at once; anything else is the same 404 a stranger
// gets everywhere under /admin. The link is not spent here: a link previewer
// fetching the URL must not burn it. Note the handler is reached without the
// admin headers (ServeHTTP) so its 404 is byte-for-byte any other 404.
func (s *Server) adminOpenDoor(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("t")
	if !strings.HasPrefix(tok, "rg_") || s.st.PeekLink(r.Context(), tok, store.LinkRegister) != nil {
		s.event(r, "admin.door.refused")
		http.NotFound(w, r)
		return
	}
	door, ok := s.admin.newDoor(tok)
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many open register links")
		return
	}
	// Lax, not Strict: the browser arrives here from a message or a terminal,
	// which is a cross-site navigation, and the redirect that follows must
	// carry the cookie. It gates nothing but the page shell.
	http.SetCookie(w, &http.Cookie{Name: adminDoorCookie, Value: door, Path: "/admin", HttpOnly: true, Secure: s.admin.secure, SameSite: http.SameSiteLaxMode, MaxAge: int(adminDoorTTL.Seconds())})
	s.event(r, "admin.door.opened")
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// sameOrigin refuses a state-changing request whose Origin is not this
// server's: the browser always sends Origin on POST, so a page elsewhere
// cannot drive the admin API with the admin's cookie, and a request with no
// Origin at all (not a browser) is refused too.
func (s *Server) sameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Origin"), s.admin.origin) {
			writeErr(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
		next(w, r)
	}
}

// ---------- sessions ----------

func sessionKey(tok string) [32]byte { return sha256.Sum256([]byte(tok)) }

// adminOf returns the signed-in admin's key name, or "" (for the security log).
func adminOf(r *http.Request) string {
	a, _ := r.Context().Value(adminKey).(string)
	return a
}

const adminKey ctxKey = 2

func (a *admin) lookup(r *http.Request) (string, bool) {
	c, err := r.Cookie(adminCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweep()
	sess, ok := a.sessions[sessionKey(c.Value)]
	if !ok || time.Now().After(sess.expires) {
		return "", false
	}
	return sess.key, true
}

func (a *admin) sweep() {
	now := time.Now()
	for k, c := range a.ceremonie {
		if now.After(c.expires) {
			delete(a.ceremonie, k)
		}
	}
	for k, sess := range a.sessions {
		if now.After(sess.expires) {
			delete(a.sessions, k)
		}
	}
	for k, d := range a.doors {
		if now.After(d.expires) {
			delete(a.doors, k)
		}
	}
}

// door returns the register token behind this browser's door cookie.
func (a *admin) door(r *http.Request) (string, bool) {
	c, err := r.Cookie(adminDoorCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweep()
	d, ok := a.doors[sessionKey(c.Value)]
	if !ok || time.Now().After(d.expires) {
		return "", false
	}
	return d.token, true
}

func (a *admin) newDoor(token string) (string, bool) {
	tok := randToken()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweep()
	if len(a.doors) >= maxAdminDoors {
		return "", false
	}
	a.doors[sessionKey(tok)] = adminDoor{token: token, expires: time.Now().Add(adminDoorTTL)}
	return tok, true
}

// closeDoor forgets the door behind the request's cookie and clears the cookie.
func (s *Server) closeDoor(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(adminDoorCookie); err == nil {
		s.admin.mu.Lock()
		delete(s.admin.doors, sessionKey(c.Value))
		s.admin.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: adminDoorCookie, Value: "", Path: "/admin", HttpOnly: true, Secure: s.admin.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// markKnown gives the browser its long-lived cookie, unless it has one
// already, and records the hash. Lax like the door, for the same reason: a
// bookmark or a link opened from another app must still find the page.
func (s *Server) markKnown(w http.ResponseWriter, r *http.Request) error {
	if s.knownBrowser(r) {
		return nil
	}
	tok := randToken()
	h := sessionKey(tok)
	if err := s.st.AddAdminBrowser(r.Context(), h[:]); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: adminKnownCookie, Value: tok, Path: "/admin", HttpOnly: true, Secure: s.admin.secure, SameSite: http.SameSiteLaxMode, MaxAge: int(adminKnownTTL.Seconds())})
	return nil
}

func (a *admin) newSession(key string) (string, bool) {
	tok := randToken()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweep()
	if len(a.sessions) >= maxAdminSessions {
		return "", false
	}
	a.sessions[sessionKey(tok)] = adminSession{key: key, expires: time.Now().Add(adminSessionTTL)}
	return tok, true
}

func (a *admin) putCeremony(sd *webauthn.SessionData) (string, bool) {
	id := randToken()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweep()
	if len(a.ceremonie) >= maxPendingCeremony {
		return "", false
	}
	a.ceremonie[id] = adminCeremony{session: *sd, expires: time.Now().Add(adminCeremonyTTL)}
	return id, true
}

// takeCeremony returns and removes the pending ceremony: one begin, one finish.
func (a *admin) takeCeremony(id string) (webauthn.SessionData, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.ceremonie[id]
	delete(a.ceremonie, id)
	if !ok || time.Now().After(c.expires) {
		return webauthn.SessionData{}, false
	}
	return c.session, true
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) setAdminCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: value, Path: "/admin", HttpOnly: true, Secure: s.admin.secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func (s *Server) adminSessionRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, ok := s.admin.lookup(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "sign in with your security key first")
			return
		}
		next(w, r.WithContext(contextWithAdmin(r, key)))
	}
}

// ---------- handlers ----------

// adminUser loads every registered key.
func (s *Server) adminUser(r *http.Request) (adminUser, []store.AdminCredential, error) {
	rows, err := s.st.ListAdminCredentials(r.Context())
	if err != nil {
		return adminUser{}, nil, err
	}
	u := adminUser{}
	for _, row := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal(row.Cred, &c); err != nil {
			return adminUser{}, nil, err
		}
		u.creds = append(u.creds, c)
	}
	return u, rows, nil
}

func (s *Server) adminState(w http.ResponseWriter, r *http.Request) {
	_, rows, err := s.adminUser(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	_, door := s.admin.door(r)
	out := map[string]any{"registered": len(rows) > 0, "logged_in": false, "door": door, "origin": s.admin.origin}
	if key, ok := s.admin.lookup(r); ok {
		out["logged_in"] = true
		out["key"] = key
		vs, err := s.st.ListVaults(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		out["vaults"] = vs
		keys := []map[string]any{}
		for _, row := range rows {
			keys = append(keys, map[string]any{"name": row.Name, "created_at": row.CreatedAt, "last_used": row.LastUsed})
		}
		out["keys"] = keys
	}
	writeJSON(w, http.StatusOK, out)
}

// adminRegisterBegin checks the register link behind the browser's door and
// returns creation options. The link is not consumed until a key has
// actually been verified, so a cancelled browser prompt costs nothing.
func (s *Server) adminRegisterBegin(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.admin.door(r)
	if !ok || s.st.PeekLink(r.Context(), tok, store.LinkRegister) != nil {
		s.event(r, "admin.register.failed", "reason", "bad link")
		s.failAuth(w, r, "this register link is not valid: it was used, expired, or never existed; get a new one from the server")
		return
	}
	user, _, err := s.adminUser(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	// Registering the same key twice is refused by the authenticator through excludeCredentials.
	exclude := []protocol.CredentialDescriptor{}
	for _, c := range user.creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, sd, err := s.admin.wa.BeginRegistration(user, webauthn.WithExclusions(exclude))
	if err != nil {
		s.fail(w, err)
		return
	}
	id, ok := s.admin.putCeremony(sd)
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many pending ceremonies")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": creation})
}

func (s *Server) adminRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ceremony   string          `json:"ceremony"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := readJSON(r, &body, 64<<10); err != nil || body.Ceremony == "" || len(body.Credential) == 0 {
		writeErr(w, http.StatusBadRequest, "ceremony, name and credential required")
		return
	}
	tok, ok := s.admin.door(r)
	if !ok {
		s.failAuth(w, r, "this register link is not valid: it was used, expired, or never existed; get a new one from the server")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "security key " + time.Now().UTC().Format("2006-01-02")
	}
	if len(name) > 64 {
		writeErr(w, http.StatusBadRequest, "name too long")
		return
	}
	sd, ok := s.admin.takeCeremony(body.Ceremony)
	if !ok {
		s.failAuth(w, r, "registration expired; reload the page and try again")
		return
	}
	user, _, err := s.adminUser(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body.Credential))
	if err != nil {
		s.event(r, "admin.register.failed", "reason", "unparseable credential")
		s.failAuth(w, r, "the browser's response could not be read")
		return
	}
	cred, err := s.admin.wa.CreateCredential(user, sd, parsed)
	if err != nil {
		s.event(r, "admin.register.failed", "reason", "verification")
		s.failAuth(w, r, "the security key's response did not verify")
		return
	}
	// Verified: now spend the link, then store the key. The link is checked
	// again here, inside a transaction, so two finishes with the same token
	// cannot both register.
	if err := s.st.ConsumeLink(r.Context(), tok, store.LinkRegister); err != nil {
		s.event(r, "admin.register.failed", "reason", "bad link")
		s.failAuth(w, r, "this register link is not valid: it was used, expired, or never existed")
		return
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.st.AddAdminCredential(r.Context(), cred.ID, name, blob); err != nil {
		s.fail(w, err)
		return
	}
	// The browser that registered a key is one the page may show itself to.
	if err := s.markKnown(w, r); err != nil {
		s.fail(w, err)
		return
	}
	s.closeDoor(w, r)
	s.event(r, "admin.registered", "key", name)
	writeJSON(w, http.StatusCreated, map[string]any{"name": name})
}

func (s *Server) adminLoginBegin(w http.ResponseWriter, r *http.Request) {
	user, rows, err := s.adminUser(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(rows) == 0 {
		writeErr(w, http.StatusConflict, "no security key is registered yet; run `obsync admin register` on the server")
		return
	}
	assertion, sd, err := s.admin.wa.BeginLogin(user)
	if err != nil {
		s.fail(w, err)
		return
	}
	id, ok := s.admin.putCeremony(sd)
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many pending ceremonies")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": assertion})
}

func (s *Server) adminLoginFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := readJSON(r, &body, 64<<10); err != nil || body.Ceremony == "" || len(body.Credential) == 0 {
		writeErr(w, http.StatusBadRequest, "ceremony and credential required")
		return
	}
	sd, ok := s.admin.takeCeremony(body.Ceremony)
	if !ok {
		s.failAuth(w, r, "sign-in expired; try again")
		return
	}
	user, rows, err := s.adminUser(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body.Credential))
	if err != nil {
		s.event(r, "admin.login.failed", "reason", "unparseable credential")
		s.failAuth(w, r, "the browser's response could not be read")
		return
	}
	cred, err := s.admin.wa.ValidateLogin(user, sd, parsed)
	if err != nil {
		s.event(r, "admin.login.failed", "reason", "verification")
		s.failAuth(w, r, "the security key's response did not verify")
		return
	}
	name := ""
	for _, row := range rows {
		if subtle.ConstantTimeCompare(row.ID, cred.ID) == 1 {
			name = row.Name
		}
	}
	if cred.Authenticator.CloneWarning {
		// The counter went backwards: two copies of this key may exist. Refuse
		// and say so; the operator removes and re-registers the key.
		s.event(r, "admin.login.failed", "reason", "clone warning", "key", name)
		s.failAuth(w, r, "this key's counter went backwards, which suggests a cloned key; remove and re-register it")
		return
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.st.TouchAdminCredential(r.Context(), cred.ID, blob); err != nil {
		s.fail(w, err)
		return
	}
	tok, ok := s.admin.newSession(name)
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many admin sessions")
		return
	}
	s.setAdminCookie(w, tok, int(adminSessionTTL.Seconds()))
	if err := s.markKnown(w, r); err != nil {
		s.fail(w, err)
		return
	}
	// A sign-in through a register link spends the link: it has done its job,
	// which was to let this browser in.
	if link, ok := s.admin.door(r); ok {
		if err := s.st.ConsumeLink(r.Context(), link, store.LinkRegister); err != nil && !errors.Is(err, store.ErrForbidden) {
			s.fail(w, err)
			return
		}
		s.closeDoor(w, r)
	}
	s.event(r.WithContext(contextWithAdmin(r, name)), "admin.login", "key", name)
	writeJSON(w, http.StatusOK, map[string]any{"key": name, "expires_in": int(adminSessionTTL.Seconds())})
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(adminCookie); err == nil {
		s.admin.mu.Lock()
		delete(s.admin.sessions, sessionKey(c.Value))
		s.admin.mu.Unlock()
	}
	s.setAdminCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

// adminCreateLink mints a create link and returns it three ways: the
// obsync:// text, the obsidian:// URL a tap opens, and a QR of that URL.
func (s *Server) adminCreateLink(w http.ResponseWriter, r *http.Request) {
	l, err := s.st.CreateLink(r.Context(), store.LinkCreate, "admin:"+adminOf(r), s.cfg.InviteTTL)
	if err != nil {
		s.fail(w, err)
		return
	}
	link := CreateLink(s.admin.origin, l.Token)
	open := OpenURL(link)
	svg, err := qr.SVG(open)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.event(r, "create.link.minted", "ttl_s", int64(s.cfg.InviteTTL.Seconds()))
	writeJSON(w, http.StatusCreated, map[string]any{"link": link, "open_url": open, "qr_svg": svg, "expires_at": l.ExpiresAt})
}

// CreateLink is the text a device pastes: `obsync://create#<server>,<token>`,
// the same shape as an invite link minus the key (the device makes its own).
// Everything after # is a fragment: it never appears in a request line.
func CreateLink(server, token string) string {
	return "obsync://create#" + url.QueryEscape(server) + "," + token
}

// OpenURL wraps a link in the obsidian:// URL the OS hands to Obsidian.
func OpenURL(link string) string {
	return "obsidian://obsync-join?link=" + url.QueryEscape(link)
}

// RegisterURL is where a register link lands: the token is in the path so
// the server can judge it before serving a byte (a bad one is a 404), and
// the handler redirects at once so it does not stay in the address bar.
func RegisterURL(server, token string) string {
	return strings.TrimRight(server, "/") + "/admin/r/" + token
}
