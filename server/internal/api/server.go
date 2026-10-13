// Package api exposes the obsync HTTP API described in DESIGN.md §4.3.
package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"obsync/internal/blobstore"
	"obsync/internal/store"
)

// Blob wire format (DESIGN.md §5.2): 0x01 || epoch(u32 LE) || salt(16) || nonce(12) || ciphertext+tag(≥16)
const (
	blobVersion   = 0x01
	blobHeaderLen = 1 + 4 + 16 + 12
	blobMinLen    = blobHeaderLen + 16
)

type Config struct {
	AdminToken   string
	MaxBlobSize  int64         // bytes
	MaxWait      time.Duration // long-poll cap
	InviteTTL    time.Duration
	ChangesLimit int
	Logger       *slog.Logger
	// Rate limits for unauthenticated routes and failed auth, per client IP.
	// Zero means the default (10/min, burst 20). Negative disables (tests).
	AuthRatePerMinute int
	AuthBurst         int
	// TrustProxy uses X-Forwarded-For for the client IP. Only enable behind a proxy you control.
	TrustProxy bool
}

type Server struct {
	cfg   Config
	st    *store.Store
	blobs *blobstore.FS
	hub   *Hub
	mux   *http.ServeMux
	log   *slog.Logger
	// blobLocks serialises index-update + file-promote per blob so two
	// concurrent uploads at different epochs cannot leave the index and the
	// file disagreeing. Striped to bound memory.
	blobLocks [64]sync.Mutex
	// unauth limits the routes an attacker can hit with no token; authFail
	// limits token guessing (charged only on failure).
	unauth   *limiter
	authFail *limiter
}

func (s *Server) blobLock(id string) *sync.Mutex {
	h := fnv.New32a()
	h.Write([]byte(id))
	return &s.blobLocks[h.Sum32()%uint32(len(s.blobLocks))]
}

func New(cfg Config, st *store.Store, blobs *blobstore.FS) *Server {
	if cfg.MaxBlobSize == 0 {
		cfg.MaxBlobSize = 1 << 30
	}
	if cfg.MaxWait == 0 {
		cfg.MaxWait = 60 * time.Second
	}
	if cfg.InviteTTL == 0 {
		cfg.InviteTTL = 24 * time.Hour
	}
	if cfg.ChangesLimit == 0 {
		cfg.ChangesLimit = 1000
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	rate, burst := cfg.AuthRatePerMinute, cfg.AuthBurst
	if rate == 0 {
		rate = 10
	}
	if burst == 0 {
		burst = 20
	}
	s := &Server{cfg: cfg, st: st, blobs: blobs, hub: NewHub(), mux: http.NewServeMux(), log: cfg.Logger}
	if rate > 0 {
		s.unauth = newLimiter(rate, burst, cfg.TrustProxy)
		s.authFail = newLimiter(rate, burst, cfg.TrustProxy)
	}
	s.routes()
	return s
}

func (s *Server) Hub() *Hub { return s.hub }

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	// A human opening the URL in a browser should learn that it is the right
	// one, not get a bare 404.
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("obsync server is running.\n\nPoint the Obsidian plugin at this URL (Settings → obsync → Create a new vault, or paste an invite link).\n"))
	})

	m.HandleFunc("POST /v1/vaults", s.admin(s.createVault))
	m.HandleFunc("GET /v1/vaults", s.admin(s.listVaults))
	m.HandleFunc("POST /v1/vaults/{v}/invites", s.authorityOrAdmin(s.createInvite))
	m.HandleFunc("POST /v1/invites/{t}", s.limited(s.redeemInvite))

	m.HandleFunc("GET /v1/vaults/{v}", s.device(s.getVault))
	m.HandleFunc("GET /v1/vaults/{v}/devices", s.device(s.listDevices))
	m.HandleFunc("PATCH /v1/vaults/{v}/devices/me", s.device(s.setDeviceName))
	m.HandleFunc("GET /v1/vaults/{v}/keybox", s.device(s.getKeybox))
	m.HandleFunc("POST /v1/vaults/{v}/keybox", s.device(s.putKeybox))
	m.HandleFunc("POST /v1/vaults/{v}/auth", s.device(s.registerAuth))
	m.HandleFunc("POST /v1/vaults/{v}/rotate", s.authority(s.rotate))

	m.HandleFunc("PUT /v1/vaults/{v}/recovery", s.authority(s.setRecovery))
	m.HandleFunc("GET /v1/vaults/{v}/recovery", s.getRecovery) // salt only; unthrottled so a throttled join can retry
	m.HandleFunc("POST /v1/vaults/{v}/recovery/join", s.limited(s.recoveryJoin))

	m.HandleFunc("GET /v1/vaults/{v}/snapshot", s.device(s.snapshot))
	m.HandleFunc("GET /v1/vaults/{v}/changes", s.device(s.changes))
	m.HandleFunc("GET /v1/vaults/{v}/live", s.deviceWith(wsBearer, s.live))

	m.HandleFunc("POST /v1/vaults/{v}/blobs/missing", s.device(s.blobsMissing))
	m.HandleFunc("GET /v1/vaults/{v}/blobs", s.device(s.blobsBelowEpoch))
	m.HandleFunc("PUT /v1/vaults/{v}/blobs/{id}", s.device(s.putBlob))
	m.HandleFunc("GET /v1/vaults/{v}/blobs/{id}", s.device(s.getBlob))

	m.HandleFunc("POST /v1/vaults/{v}/ops", s.device(s.postOps))
	m.HandleFunc("GET /v1/vaults/{v}/ops", s.device(s.opsQuery))
	m.HandleFunc("PATCH /v1/vaults/{v}/ops/{seq}/meta", s.authority(s.patchMeta))
	m.HandleFunc("GET /v1/vaults/{v}/history", s.device(s.history))
	m.HandleFunc("POST /v1/vaults/{v}/restore", s.device(s.restore))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS: Obsidian runs at app://obsidian.md (desktop) and
	// capacitor://localhost (mobile). Auth is a bearer header, never a
	// cookie, so a wildcard origin is safe.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Range, X-Blob-Epoch, X-Obsync-Vault-Auth")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, X-Blob-Epoch")
	w.Header().Set("Access-Control-Max-Age", "86400")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// ---------- auth middleware ----------

type ctxKey int

const deviceKey ctxKey = 1

// bearer reads the Authorization header. Tokens are never accepted in the
// query string: URLs end up in proxy and browser logs.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// wsSubprotocol is the subprotocol name a WebSocket client offers alongside
// its token: `new WebSocket(url, ["obsync-bearer", "dv_…"])`. Browser
// WebSocket clients cannot set headers, and the Sec-WebSocket-Protocol
// header, unlike the URL, is not logged by proxies.
const wsSubprotocol = "obsync-bearer"

func wsBearer(r *http.Request) string {
	if t := bearer(r); t != "" {
		return t
	}
	for _, h := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(h, ",") {
			if p = strings.TrimSpace(p); strings.HasPrefix(p, "dv_") {
				return p
			}
		}
	}
	return ""
}

// vaultAuth reads the vault authority token (DESIGN.md §5.8).
func vaultAuth(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Obsync-Vault-Auth"))
}

func (s *Server) isAdmin(tok string) bool {
	return s.cfg.AdminToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.AdminToken)) == 1
}

// limited applies the unauthenticated-route rate limit.
func (s *Server) limited(next http.HandlerFunc) http.HandlerFunc {
	if s.unauth == nil {
		return next
	}
	return s.unauth.allow(next)
}

// failAuth records a failed credential and rejects, or short-circuits with
// 429 once the client has failed too often.
func (s *Server) failAuth(w http.ResponseWriter, r *http.Request, msg string) {
	if s.authFail != nil && !s.authFail.take(s.authFail.key(r)) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many failed authentication attempts")
		return
	}
	writeErr(w, http.StatusUnauthorized, msg)
}

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAdmin(bearer(r)) {
			s.failAuth(w, r, "admin token required")
			return
		}
		next(w, r)
	}
}

// device authenticates a device token and checks it belongs to {v}.
func (s *Server) device(next http.HandlerFunc) http.HandlerFunc {
	return s.deviceWith(bearer, next)
}

func (s *Server) deviceWith(tok func(*http.Request) string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, err := s.st.AuthDevice(r.Context(), tok(r))
		if err != nil {
			s.failAuth(w, r, "invalid or revoked device token")
			return
		}
		if v := r.PathValue("v"); v != "" && v != d.VaultID {
			writeErr(w, http.StatusForbidden, "device does not belong to this vault")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), deviceKey, d)))
	}
}

// authority requires a device token AND the vault authority token, which
// only key holders can derive. Guards everything that can destroy data or
// hand keys to a new party.
func (s *Server) authority(next http.HandlerFunc) http.HandlerFunc {
	return s.device(func(w http.ResponseWriter, r *http.Request) {
		ok, err := s.st.CheckVaultAuth(r.Context(), r.PathValue("v"), vaultAuth(r))
		if err != nil {
			s.fail(w, err)
			return
		}
		if !ok {
			s.failAuth(w, r, "vault authority token required (X-Obsync-Vault-Auth)")
			return
		}
		next(w, r)
	})
}

func (s *Server) authorityOrAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.isAdmin(bearer(r)) {
			next(w, r)
			return
		}
		s.authority(next)(w, r)
	}
}

func dev(r *http.Request) *store.Device {
	d, _ := r.Context().Value(deviceKey).(*store.Device)
	return d
}

func callerID(r *http.Request) string {
	if d := dev(r); d != nil {
		return d.ID
	}
	return "admin"
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrBadRequest):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, store.ErrForbidden):
		writeErr(w, http.StatusUnauthorized, "forbidden")
	default:
		s.log.Error("internal error", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

func readJSON(r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, limit))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// maxListLimit bounds every list-style response so one member cannot make
// the server materialise an unbounded result (negative LIMIT is unlimited
// in SQLite).
const maxListLimit = 5000

func clampLimit(n int64) int {
	if n <= 0 || n > maxListLimit {
		return maxListLimit
	}
	return int(n)
}

func qInt(r *http.Request, key string, def int64) int64 {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// ---------- vaults & enrolment ----------

func (s *Server) createVault(w http.ResponseWriter, r *http.Request) {
	v, err := s.st.CreateVault(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) listVaults(w http.ResponseWriter, r *http.Request) {
	vs, err := s.st.ListVaults(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vaults": vs})
}

func (s *Server) getVault(w http.ResponseWriter, r *http.Request) {
	v, err := s.st.GetVault(r.Context(), r.PathValue("v"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		KeyboxEnc  []byte `json:"keybox_enc"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := readJSON(r, &body, 1<<20); err != nil || len(body.KeyboxEnc) == 0 {
		writeErr(w, http.StatusBadRequest, "keybox_enc required")
		return
	}
	ttl := s.cfg.InviteTTL
	if body.TTLSeconds > 0 && time.Duration(body.TTLSeconds)*time.Second < ttl {
		ttl = time.Duration(body.TTLSeconds) * time.Second
	}
	if _, err := s.st.GetVault(r.Context(), r.PathValue("v")); err != nil {
		s.fail(w, err)
		return
	}
	inv, err := s.st.CreateInvite(r.Context(), r.PathValue("v"), callerID(r), body.KeyboxEnc, ttl)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}

func (s *Server) redeemInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PubKex  []byte `json:"pub_kex"`
		NameEnc []byte `json:"name_enc"`
	}
	if err := readJSON(r, &body, 1<<16); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	out, err := s.st.RedeemInvite(r.Context(), r.PathValue("t"), body.PubKex, body.NameEnc)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.st.ListDevices(r.Context(), r.PathValue("v"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": ds})
}

func (s *Server) setDeviceName(w http.ResponseWriter, r *http.Request) {
	var body struct {
		NameEnc []byte `json:"name_enc"`
	}
	if err := readJSON(r, &body, 1<<16); err != nil || len(body.NameEnc) == 0 {
		writeErr(w, http.StatusBadRequest, "name_enc required")
		return
	}
	if err := s.st.SetDeviceName(r.Context(), dev(r).ID, body.NameEnc); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- keybox / rotation / recovery ----------

func (s *Server) getKeybox(w http.ResponseWriter, r *http.Request) {
	rows, err := s.st.GetKeybox(r.Context(), r.PathValue("v"), dev(r).ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keybox": rows})
}

func (s *Server) putKeybox(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Keybox []store.KeyboxRow `json:"keybox"`
	}
	if err := readJSON(r, &body, 1<<20); err != nil || len(body.Keybox) == 0 {
		writeErr(w, http.StatusBadRequest, "keybox rows required")
		return
	}
	if err := s.st.PutKeybox(r.Context(), r.PathValue("v"), dev(r).ID, body.Keybox); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// registerAuth installs the vault authority hash on first enrolment (or on a
// vault that predates the field). Idempotent for the matching token.
func (s *Server) registerAuth(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Auth string `json:"auth"`
	}
	if err := readJSON(r, &body, 1<<12); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	if err := s.st.EnsureVaultAuth(r.Context(), r.PathValue("v"), body.Auth); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Epoch    int64             `json:"epoch"`
		Revoke   []string          `json:"revoke"`
		Keybox   []store.KeyboxRow `json:"keybox"`
		AuthNext string            `json:"auth_next"`
	}
	if err := readJSON(r, &body, 4<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	v := r.PathValue("v")
	if err := s.st.Rotate(r.Context(), v, dev(r).ID, body.Epoch, body.Revoke, body.Keybox, body.AuthNext); err != nil {
		s.fail(w, err)
		return
	}
	vault, err := s.st.GetVault(r.Context(), v)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.hub.Publish(v, vault.Seq, vault.Epoch)
	writeJSON(w, http.StatusOK, vault)
}

func (s *Server) setRecovery(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PubKex      []byte `json:"pub_kex"`
		RecoveryEnc []byte `json:"recovery_enc"`
		Salt        []byte `json:"salt"`
		Auth        string `json:"auth"`
	}
	if err := readJSON(r, &body, 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	id, err := s.st.SetRecovery(r.Context(), r.PathValue("v"), body.PubKex, body.RecoveryEnc, body.Salt, body.Auth)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"device_id": id})
}

func (s *Server) getRecovery(w http.ResponseWriter, r *http.Request) {
	// Unauthenticated by design: the joiner has nothing but the URL and the
	// passphrase. Only the KDF salt and the public key are returned; the
	// wrapped private key is released by recovery/join once the derived auth
	// token is presented, so guessing is online and rate-limited there. This
	// read is deliberately not throttled: if it shared the join's bucket, a
	// client retrying after a 429 would spend each refilled token here and
	// never reach the join. The vault id is random 128-bit, so existence is
	// not enumerable.
	info, err := s.st.GetRecovery(r.Context(), r.PathValue("v"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) recoveryJoin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PubKex  []byte `json:"pub_kex"`
		NameEnc []byte `json:"name_enc"`
	}
	if err := readJSON(r, &body, 1<<16); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	out, rows, recoveryEnc, err := s.st.RecoveryJoin(r.Context(), r.PathValue("v"), bearer(r), body.PubKex, body.NameEnc)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"device_id": out.DeviceID, "device_token": out.DeviceToken, "vault_id": out.VaultID, "epoch": out.Epoch, "keybox": rows,
		"recovery_enc": recoveryEnc,
	})
}

// ---------- feed ----------

type feedResponse struct {
	Epoch    int64      `json:"epoch"`
	MinEpoch int64      `json:"min_epoch"`
	Cursor   int64      `json:"cursor"`
	Ops      []store.Op `json:"ops"`
	More     bool       `json:"more"`
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	v := r.PathValue("v")
	vault, err := s.st.GetVault(r.Context(), v)
	if err != nil {
		s.fail(w, err)
		return
	}
	ops, err := s.st.Snapshot(r.Context(), v)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, feedResponse{Epoch: vault.Epoch, MinEpoch: vault.MinEpoch, Cursor: vault.Seq, Ops: ops})
}

func (s *Server) changes(w http.ResponseWriter, r *http.Request) {
	v := r.PathValue("v")
	since := qInt(r, "since", 0)
	limit := int(qInt(r, "limit", int64(s.cfg.ChangesLimit)))
	if limit <= 0 || limit > s.cfg.ChangesLimit {
		limit = s.cfg.ChangesLimit
	}
	wait := time.Duration(qInt(r, "wait", 0)) * time.Second
	if wait > s.cfg.MaxWait {
		wait = s.cfg.MaxWait
	}
	deadline := time.Now().Add(wait)
	waited := false
	for {
		// Subscribe before querying so a publish between query and wait is not lost.
		ch, unsub := s.hub.Subscribe(v)
		ops, err := s.st.Changes(r.Context(), v, since, limit+1)
		if err != nil {
			unsub()
			s.fail(w, err)
			return
		}
		vault, err := s.st.GetVault(r.Context(), v)
		if err != nil {
			unsub()
			s.fail(w, err)
			return
		}
		remaining := time.Until(deadline)
		if len(ops) > 0 || remaining <= 0 {
			unsub()
			if waited && !s.st.DeviceLive(r.Context(), dev(r).ID) {
				// Revoked while this long-poll was open: deliver nothing.
				writeErr(w, http.StatusUnauthorized, "device revoked")
				return
			}
			more := len(ops) > limit
			if more {
				ops = ops[:limit]
			}
			cursor := since
			if len(ops) > 0 {
				cursor = ops[len(ops)-1].Seq
			}
			writeJSON(w, http.StatusOK, feedResponse{Epoch: vault.Epoch, MinEpoch: vault.MinEpoch, Cursor: cursor, Ops: ops, More: more})
			return
		}
		t := time.NewTimer(remaining)
		select {
		case <-ch:
		case <-t.C:
		case <-r.Context().Done():
			t.Stop()
			unsub()
			return
		}
		t.Stop()
		unsub()
		waited = true
	}
}

func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	v := r.PathValue("v")
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}, Subprotocols: []string{wsSubprotocol}})
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := r.Context()
	self := dev(r).ID
	ch, unsub := s.hub.Subscribe(v)
	defer unsub()
	// Initial hint so the client knows where the server is.
	vault, err := s.st.GetVault(ctx, v)
	if err != nil {
		return
	}
	if err := wsjson.Write(ctx, c, Hint{Seq: vault.Seq, Epoch: vault.Epoch}); err != nil {
		return
	}
	// Drain client messages so pings/closes are processed.
	go func() {
		for {
			if _, _, err := c.Read(ctx); err != nil {
				return
			}
		}
	}()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			c.Close(websocket.StatusNormalClosure, "bye")
			return
		case <-ch:
			if !s.st.DeviceLive(ctx, self) {
				// Revoked (a rotation publishes a hint): stop streaming.
				c.Close(websocket.StatusPolicyViolation, "device revoked")
				return
			}
			if err := wsjson.Write(ctx, c, s.hub.Current(v)); err != nil {
				return
			}
		case <-ping.C:
			if !s.st.DeviceLive(ctx, self) {
				c.Close(websocket.StatusPolicyViolation, "device revoked")
				return
			}
			// A JSON heartbeat rather than a bare ping frame: browser WebSocket
			// clients cannot observe pings, so this lets them detect a dead
			// channel and reconnect.
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := wsjson.Write(pctx, c, s.hub.Current(v))
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// ---------- blobs ----------

func (s *Server) blobsMissing(w http.ResponseWriter, r *http.Request) {
	var ids []string
	if err := readJSON(r, &ids, 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "expected JSON array of blob ids")
		return
	}
	if len(ids) > maxListLimit {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("at most %d blob ids per request", maxListLimit))
		return
	}
	for _, id := range ids {
		if !store.ValidHexID(id) {
			writeErr(w, http.StatusBadRequest, "bad blob id "+id)
			return
		}
	}
	missing, err := s.st.MissingBlobs(r.Context(), r.PathValue("v"), ids)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"missing": missing})
}

func (s *Server) blobsBelowEpoch(w http.ResponseWriter, r *http.Request) {
	epoch := qInt(r, "epoch_lt", 0)
	if epoch <= 0 {
		writeErr(w, http.StatusBadRequest, "epoch_lt required")
		return
	}
	limit := clampLimit(qInt(r, "limit", 500))
	ids, err := s.st.BlobsBelowEpoch(r.Context(), r.PathValue("v"), epoch, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"blob_ids": ids})
}

// parseBlobHeader validates the fixed header and returns the epoch.
func parseBlobHeader(h []byte) (int64, error) {
	if len(h) < blobHeaderLen || h[0] != blobVersion {
		return 0, errors.New("bad blob header")
	}
	return int64(binary.LittleEndian.Uint32(h[1:5])), nil
}

func (s *Server) putBlob(w http.ResponseWriter, r *http.Request) {
	v, id := r.PathValue("v"), r.PathValue("id")
	if !store.ValidHexID(id) {
		writeErr(w, http.StatusBadRequest, "bad blob id")
		return
	}
	vault, err := s.st.GetVault(r.Context(), v)
	if err != nil {
		s.fail(w, err)
		return
	}
	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxBlobSize)
	head := make([]byte, blobHeaderLen)
	if _, err := io.ReadFull(body, head); err != nil {
		writeErr(w, http.StatusBadRequest, "blob too short")
		return
	}
	epoch, err := parseBlobHeader(head)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if epoch < 1 || epoch > vault.Epoch {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("blob epoch %d outside [1,%d]", epoch, vault.Epoch))
		return
	}
	// Short-circuit: already have an equal-or-newer epoch. Drain and ack.
	if cur, err := s.st.GetBlob(r.Context(), v, id); err == nil {
		if cur.Epoch >= epoch {
			io.Copy(io.Discard, body)
			w.Header().Set("X-Blob-Epoch", strconv.FormatInt(cur.Epoch, 10))
			w.WriteHeader(http.StatusOK)
			return
		}
		// Replacing stored ciphertext (re-encryption after a rotation) is
		// destructive: a wrong body loses the only copy. Key holders only.
		ok, err := s.st.CheckVaultAuth(r.Context(), v, vaultAuth(r))
		if err != nil {
			s.fail(w, err)
			return
		}
		if !ok {
			s.failAuth(w, r, "vault authority token required to replace a blob")
			return
		}
	}
	// Write to a staging name first; only after the index accepts it do we
	// move it into place, so a concurrent higher-epoch upload can't be
	// clobbered by a lower one.
	stage := id + "-stage-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	n, err := s.blobs.Put(v, stage, io.MultiReader(bytes.NewReader(head), body))
	if err != nil {
		s.blobs.Delete(v, stage)
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "blob exceeds max size")
			return
		}
		s.fail(w, err)
		return
	}
	if n < blobMinLen {
		s.blobs.Delete(v, stage)
		writeErr(w, http.StatusBadRequest, "blob too short")
		return
	}
	lk := s.blobLock(id)
	lk.Lock()
	defer lk.Unlock()
	stored, err := s.st.UpsertBlob(r.Context(), v, id, epoch, n)
	if err != nil {
		s.blobs.Delete(v, stage)
		s.fail(w, err)
		return
	}
	if !stored {
		s.blobs.Delete(v, stage)
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := s.blobs.Promote(v, stage, id); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("X-Blob-Epoch", strconv.FormatInt(epoch, 10))
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) getBlob(w http.ResponseWriter, r *http.Request) {
	v, id := r.PathValue("v"), r.PathValue("id")
	if !store.ValidHexID(id) {
		writeErr(w, http.StatusBadRequest, "bad blob id")
		return
	}
	info, err := s.st.GetBlob(r.Context(), v, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	f, err := s.blobs.Open(v, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "blob data missing")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Blob-Epoch", strconv.FormatInt(info.Epoch, 10))
	w.Header().Set("Cache-Control", "private, max-age=0")
	http.ServeContent(w, r, id, time.UnixMilli(info.CreatedAt), f)
}

// ---------- ops ----------

func (s *Server) postOps(w http.ResponseWriter, r *http.Request) {
	var ops []store.Op
	if err := readJSON(r, &ops, 16<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "expected JSON array of ops: "+err.Error())
		return
	}
	if len(ops) == 0 || len(ops) > 1000 {
		writeErr(w, http.StatusBadRequest, "1..1000 ops per batch")
		return
	}
	v := r.PathValue("v")
	results, seq, err := s.st.AppendOps(r.Context(), v, dev(r).ID, ops)
	if err != nil {
		s.fail(w, err)
		return
	}
	vault, err := s.st.GetVault(r.Context(), v)
	if err != nil {
		s.fail(w, err)
		return
	}
	accepted := 0
	for _, res := range results {
		if res.Seq > 0 && res.Conflict == nil && res.Error == "" {
			accepted++
		}
	}
	if accepted > 0 {
		s.hub.Publish(v, seq, vault.Epoch)
	}
	writeJSON(w, http.StatusOK, map[string]any{"epoch": vault.Epoch, "cursor": seq, "results": results})
}

func (s *Server) opsQuery(w http.ResponseWriter, r *http.Request) {
	v := r.PathValue("v")
	limit := clampLimit(qInt(r, "limit", 1000))
	if e := qInt(r, "meta_epoch_lt", 0); e > 0 {
		seqs, err := s.st.OpsBelowMetaEpoch(r.Context(), v, e, limit)
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"seqs": seqs})
		return
	}
	from := qInt(r, "from", 0)
	to := qInt(r, "to", time.Now().UnixMilli())
	ops, err := s.st.OpsByTime(r.Context(), v, from, to, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ops": ops})
}

func (s *Server) patchMeta(w http.ResponseWriter, r *http.Request) {
	seq, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad seq")
		return
	}
	var body struct {
		MetaEnc   []byte `json:"meta_enc"`
		MetaEpoch int64  `json:"meta_epoch"`
	}
	if err := readJSON(r, &body, 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	if err := s.st.PatchMeta(r.Context(), r.PathValue("v"), seq, body.MetaEnc, body.MetaEpoch); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	pid := r.URL.Query().Get("path_id")
	if !store.ValidHexID(pid) {
		writeErr(w, http.StatusBadRequest, "path_id required")
		return
	}
	ops, err := s.st.History(r.Context(), r.PathValue("v"), pid, maxListLimit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ops": ops})
}

func (s *Server) restore(w http.ResponseWriter, r *http.Request) {
	var body struct {
		At int64 `json:"at"`
	}
	if err := readJSON(r, &body, 1<<10); err != nil || body.At <= 0 {
		writeErr(w, http.StatusBadRequest, "at (unix ms) required")
		return
	}
	v := r.PathValue("v")
	n, skipped, err := s.st.Restore(r.Context(), v, dev(r).ID, body.At)
	if err != nil {
		s.fail(w, err)
		return
	}
	vault, err := s.st.GetVault(r.Context(), v)
	if err != nil {
		s.fail(w, err)
		return
	}
	if n > 0 {
		s.hub.Publish(v, vault.Seq, vault.Epoch)
	}
	if skipped == nil {
		skipped = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"emitted": n, "skipped_path_ids": skipped, "cursor": vault.Seq})
}

// ---------- GC ----------

// GC removes blobs no head references and no op newer than retention
// references, for every vault. Returns the count removed.
func (s *Server) GC(ctx context.Context, retention time.Duration) (int, error) {
	vaults, err := s.st.ListVaults(ctx)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-retention).UnixMilli()
	removed := 0
	for _, v := range vaults {
		dead, err := s.st.DeadBlobs(ctx, v.ID, cutoff)
		if err != nil {
			return removed, err
		}
		for _, id := range dead {
			gone, err := s.st.DeleteDeadBlob(ctx, v.ID, id, cutoff)
			if err != nil {
				return removed, err
			}
			if !gone {
				continue // referenced again since the listing
			}
			if err := s.blobs.Delete(v.ID, id); err != nil {
				s.log.Warn("gc: delete blob file", "vault", v.ID, "blob", id, "err", err)
			}
			removed++
		}
		if err := s.st.PruneKeybox(ctx, v.ID); err != nil {
			return removed, err
		}
	}
	return removed, nil
}
