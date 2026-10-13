// Package store is the SQLite-backed persistence layer: vaults, devices,
// invites, keybox rows, the op log, heads, and the blob index.
//
// All writes go through a single mutex plus BEGIN IMMEDIATE so that the
// compare-and-swap in AppendOps and the epoch bump in Rotate are serialised.
// Reads run concurrently under WAL.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
	ErrBadRequest = errors.New("bad request")
	ErrForbidden  = errors.New("forbidden")
)

type Store struct {
	db *sql.DB
	mu sync.Mutex // serialises write transactions
}

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS vaults (
  id TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL DEFAULT 1,
  seq INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  auth_hash BLOB
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL REFERENCES vaults(id),
  name_enc BLOB,
  pub_kex BLOB,
  token_hash BLOB UNIQUE,
  recovery INTEGER NOT NULL DEFAULT 0,
  recovery_enc BLOB,
  recovery_salt BLOB,
  created_at INTEGER NOT NULL,
  last_seen INTEGER,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS devices_vault ON devices(vault_id);
CREATE TABLE IF NOT EXISTS invites (
  token_hash BLOB PRIMARY KEY,
  vault_id TEXT NOT NULL REFERENCES vaults(id),
  keybox_enc BLOB NOT NULL,
  created_by TEXT,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE TABLE IF NOT EXISTS keybox (
  vault_id TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  recipient_id TEXT NOT NULL,
  wrapped BLOB NOT NULL,
  author_id TEXT,
  PRIMARY KEY (vault_id, epoch, recipient_id)
);
CREATE TABLE IF NOT EXISTS ops (
  vault_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  op_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  path_id TEXT NOT NULL,
  blob_id TEXT,
  meta_enc BLOB NOT NULL,
  meta_epoch INTEGER NOT NULL,
  base_seq INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (vault_id, seq),
  UNIQUE (vault_id, op_id)
);
CREATE INDEX IF NOT EXISTS ops_path ON ops(vault_id, path_id, seq);
CREATE INDEX IF NOT EXISTS ops_blob ON ops(vault_id, blob_id);
CREATE INDEX IF NOT EXISTS ops_created ON ops(vault_id, created_at);
CREATE INDEX IF NOT EXISTS ops_meta_epoch ON ops(vault_id, meta_epoch);
CREATE TABLE IF NOT EXISTS heads (
  vault_id TEXT NOT NULL,
  path_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  PRIMARY KEY (vault_id, path_id)
);
CREATE TABLE IF NOT EXISTS blobs (
  vault_id TEXT NOT NULL,
  blob_id TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  ct_size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (vault_id, blob_id)
);
CREATE INDEX IF NOT EXISTS blobs_epoch ON blobs(vault_id, epoch);
`

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Columns added after the first release. SQLite has no ADD COLUMN IF NOT
	// EXISTS, so probe each one.
	for _, m := range []struct{ table, col, ddl string }{
		{"vaults", "auth_hash", "ALTER TABLE vaults ADD COLUMN auth_hash BLOB"},
		{"devices", "recovery_salt", "ALTER TABLE devices ADD COLUMN recovery_salt BLOB"},
	} {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, m.table, m.col).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := s.db.Exec(m.ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------- helpers ----------

func now() int64 { return time.Now().UnixMilli() }

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewToken returns a bearer token with the given prefix and its hash.
func NewToken(prefix string) (token string, hash []byte) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token = prefix + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	return token, h[:]
}

func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// ValidHexID checks a 64-char lowercase hex identifier (HMAC-SHA-256 output).
func ValidHexID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (s *Store) writeTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---------- vaults ----------

type Vault struct {
	ID        string `json:"vault_id"`
	Epoch     int64  `json:"epoch"`
	MinEpoch  int64  `json:"min_epoch"`
	Seq       int64  `json:"seq"`
	CreatedAt int64  `json:"created_at"`
	// HasAuth is false only for a vault from before vault authority existed
	// (DESIGN.md §5.8); such a vault accepts no writes until an admin runs
	// `obsync vault auth`.
	HasAuth bool `json:"has_auth"`
}

func (s *Store) CreateVault(ctx context.Context) (*Vault, error) {
	v := &Vault{ID: randomHex(16), Epoch: 1, MinEpoch: 1, CreatedAt: now()}
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO vaults(id, epoch, seq, created_at) VALUES(?,1,0,?)`, v.ID, v.CreatedAt)
		return err
	})
	return v, err
}

func (s *Store) GetVault(ctx context.Context, id string) (*Vault, error) {
	v := &Vault{}
	var ah []byte
	err := s.db.QueryRowContext(ctx, `SELECT id, epoch, seq, created_at, auth_hash FROM vaults WHERE id=?`, id).
		Scan(&v.ID, &v.Epoch, &v.Seq, &v.CreatedAt, &ah)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v.HasAuth = len(ah) > 0
	v.MinEpoch, err = s.minEpoch(ctx, s.db, id, v.Epoch)
	return v, err
}

type queryer interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

// ---------- vault authority ----------
//
// The vault authority token is derived by key holders from the current epoch
// key (HKDF, DESIGN.md §5.8) and presented on routes that can destroy or
// hand out data: rotation, ciphertext replacement, metadata replacement,
// recovery (re)installation and invites. The server stores only its hash, so
// a stolen device token alone (proxy logs, a copied data.json without keys)
// cannot lock the owner out or overwrite history. Rotation installs the hash
// for the next epoch at the same time, so a revoked device's old token stops
// working together with its old keys.

// EnsureVaultAuth installs the authority hash on first enrolment: only when
// the vault has none yet AND the caller is its only live device, so a
// token-only member of an older multi-device vault cannot claim it (an
// admin installs it there with SetVaultAuth). A matching token is accepted
// idempotently; a different one is refused.
func (s *Store) EnsureVaultAuth(ctx context.Context, vault, device, token string) error {
	if !validAuthToken(token) {
		return fmt.Errorf("%w: bad vault auth token", ErrBadRequest)
	}
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		var cur []byte
		if err := tx.QueryRowContext(ctx, `SELECT auth_hash FROM vaults WHERE id=?`, vault).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		h := HashToken(token)
		switch {
		case len(cur) == 0:
			var live int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE vault_id=? AND revoked_at IS NULL AND recovery=0`, vault).Scan(&live); err != nil {
				return err
			}
			if live != 1 || !s.deviceLiveTx(ctx, tx, device, vault) {
				return fmt.Errorf("%w: vault authority can only be claimed by the first device; an admin sets it for older vaults", ErrForbidden)
			}
			_, err := tx.ExecContext(ctx, `UPDATE vaults SET auth_hash=? WHERE id=?`, h, vault)
			return err
		case subtle.ConstantTimeCompare(cur, h) == 1:
			return nil
		default:
			return fmt.Errorf("%w: vault authority already set", ErrConflict)
		}
	})
}

func (s *Store) deviceLiveTx(ctx context.Context, tx *sql.Tx, device, vault string) bool {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE id=? AND vault_id=? AND revoked_at IS NULL AND recovery=0`, device, vault).Scan(&n); err != nil {
		return false
	}
	return n == 1
}

// SetVaultAuth installs or replaces the authority hash unconditionally. For
// the administrator: migrating a vault created before §5.8 existed (the
// token is shown in the plugin's settings on any device holding the keys),
// or resetting after a mishap.
func (s *Store) SetVaultAuth(ctx context.Context, vault, token string) error {
	if !validAuthToken(token) {
		return fmt.Errorf("%w: bad vault auth token", ErrBadRequest)
	}
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE vaults SET auth_hash=? WHERE id=?`, HashToken(token), vault)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// CheckVaultAuth reports whether token is the vault's current authority
// token. A vault with no authority yet (legacy) accepts nothing: the first
// device to call EnsureVaultAuth sets it.
func (s *Store) CheckVaultAuth(ctx context.Context, vault, token string) (bool, error) {
	if !validAuthToken(token) {
		return false, nil
	}
	var cur []byte
	err := s.db.QueryRowContext(ctx, `SELECT auth_hash FROM vaults WHERE id=?`, vault).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	return len(cur) > 0 && subtle.ConstantTimeCompare(cur, HashToken(token)) == 1, nil
}

// validAuthToken accepts "va_" plus 32..128 base64url/hex characters.
func validAuthToken(t string) bool {
	if !strings.HasPrefix(t, "va_") || len(t) < 35 || len(t) > 131 {
		return false
	}
	for _, c := range t[3:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// DeviceLive reports whether a device id still has a valid, unrevoked token.
func (s *Store) DeviceLive(ctx context.Context, id string) bool {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at IS NULL AND token_hash IS NOT NULL`, id).Scan(&n); err != nil {
		return false
	}
	return n == 1
}

// minEpoch is the lowest epoch any stored ciphertext still uses. Once it
// equals the current epoch, keys for older epochs may be discarded.
func (s *Store) minEpoch(ctx context.Context, q queryer, vault string, cur int64) (int64, error) {
	var mb, mo sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT MIN(epoch) FROM blobs WHERE vault_id=?`, vault).Scan(&mb); err != nil {
		return 0, err
	}
	if err := q.QueryRowContext(ctx, `SELECT MIN(meta_epoch) FROM ops WHERE vault_id=?`, vault).Scan(&mo); err != nil {
		return 0, err
	}
	m := cur
	if mb.Valid && mb.Int64 < m {
		m = mb.Int64
	}
	if mo.Valid && mo.Int64 < m {
		m = mo.Int64
	}
	return m, nil
}

func (s *Store) ListVaults(ctx context.Context) ([]Vault, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, epoch, seq, created_at FROM vaults ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Vault
	for rows.Next() {
		var v Vault
		if err := rows.Scan(&v.ID, &v.Epoch, &v.Seq, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---------- devices ----------

type Device struct {
	ID        string `json:"id"`
	VaultID   string `json:"vault_id"`
	NameEnc   []byte `json:"name_enc"`
	PubKex    []byte `json:"pub_kex"`
	Recovery  bool   `json:"recovery"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  *int64 `json:"last_seen"`
	RevokedAt *int64 `json:"revoked_at"`
}

// AuthDevice resolves a bearer token to a live device and bumps last_seen.
func (s *Store) AuthDevice(ctx context.Context, token string) (*Device, error) {
	d := &Device{}
	var rec int
	err := s.db.QueryRowContext(ctx,
		`SELECT id, vault_id, name_enc, pub_kex, recovery, created_at, last_seen, revoked_at FROM devices WHERE token_hash=?`,
		HashToken(token)).Scan(&d.ID, &d.VaultID, &d.NameEnc, &d.PubKex, &rec, &d.CreatedAt, &d.LastSeen, &d.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrForbidden
	}
	if err != nil {
		return nil, err
	}
	if d.RevokedAt != nil {
		return nil, ErrForbidden
	}
	d.Recovery = rec == 1
	// last_seen is advisory; throttle to once a minute to avoid write churn.
	if d.LastSeen == nil || now()-*d.LastSeen > 60_000 {
		_ = s.writeTx(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE devices SET last_seen=? WHERE id=?`, now(), d.ID)
			return err
		})
	}
	return d, nil
}

// SetDeviceName lets a device (re)name itself once it holds the vault keys.
func (s *Store) SetDeviceName(ctx context.Context, device string, nameEnc []byte) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE devices SET name_enc=? WHERE id=?`, nameEnc, device)
		return err
	})
}

func (s *Store) ListDevices(ctx context.Context, vault string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, vault_id, name_enc, pub_kex, recovery, created_at, last_seen, revoked_at FROM devices WHERE vault_id=? ORDER BY created_at`, vault)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var rec int
		if err := rows.Scan(&d.ID, &d.VaultID, &d.NameEnc, &d.PubKex, &rec, &d.CreatedAt, &d.LastSeen, &d.RevokedAt); err != nil {
			return nil, err
		}
		d.Recovery = rec == 1
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---------- invites ----------

type Invite struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

func (s *Store) CreateInvite(ctx context.Context, vault, createdBy string, keyboxEnc []byte, ttl time.Duration) (*Invite, error) {
	token, hash := NewToken("in_")
	inv := &Invite{Token: token, ExpiresAt: now() + ttl.Milliseconds()}
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO invites(token_hash, vault_id, keybox_enc, created_by, expires_at) VALUES(?,?,?,?,?)`,
			hash, vault, keyboxEnc, createdBy, inv.ExpiresAt)
		return err
	})
	return inv, err
}

type Redeemed struct {
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	VaultID     string `json:"vault_id"`
	Epoch       int64  `json:"epoch"`
	KeyboxEnc   []byte `json:"keybox_enc"`
}

// RedeemInvite consumes a one-time invite and enrols a device.
func (s *Store) RedeemInvite(ctx context.Context, token string, pubKex, nameEnc []byte) (*Redeemed, error) {
	if len(pubKex) == 0 {
		return nil, fmt.Errorf("%w: pub_kex required", ErrBadRequest)
	}
	hash := HashToken(token)
	out := &Redeemed{}
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		var expires int64
		var used sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT vault_id, keybox_enc, expires_at, used_at FROM invites WHERE token_hash=?`, hash).
			Scan(&out.VaultID, &out.KeyboxEnc, &expires, &used)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (used.Valid || expires < now())) {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT epoch FROM vaults WHERE id=?`, out.VaultID).Scan(&out.Epoch); err != nil {
			return err
		}
		devToken, devHash := NewToken("dv_")
		out.DeviceID = randomHex(16)
		out.DeviceToken = devToken
		if _, err := tx.ExecContext(ctx, `INSERT INTO devices(id, vault_id, name_enc, pub_kex, token_hash, created_at) VALUES(?,?,?,?,?,?)`,
			out.DeviceID, out.VaultID, nameEnc, pubKex, devHash, now()); err != nil {
			return err
		}
		// One-time: mark used and drop the key material.
		_, err = tx.ExecContext(ctx, `UPDATE invites SET used_at=?, keybox_enc=X'' WHERE token_hash=?`, now(), hash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---------- keybox ----------

type KeyboxRow struct {
	Epoch       int64  `json:"epoch"`
	RecipientID string `json:"recipient_id"`
	Wrapped     []byte `json:"wrapped"`
	AuthorID    string `json:"author_id,omitempty"`
}

func (s *Store) GetKeybox(ctx context.Context, vault, recipient string) ([]KeyboxRow, error) {
	v, err := s.GetVault(ctx, vault)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT epoch, recipient_id, wrapped, author_id FROM keybox WHERE vault_id=? AND recipient_id=? AND epoch>=? ORDER BY epoch`,
		vault, recipient, v.MinEpoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KeyboxRow{}
	for rows.Next() {
		var r KeyboxRow
		var author sql.NullString
		if err := rows.Scan(&r.Epoch, &r.RecipientID, &r.Wrapped, &author); err != nil {
			return nil, err
		}
		r.AuthorID = author.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// PutKeybox lets an enrolled device write rows for epochs up to the current
// one, addressed to itself (self-enrolment after an invite) or to a recovery
// identity (wrapping keys to a new passphrase). Rows for any other device
// are refused and rows for a recovery identity are insert-only, so no
// member can blank out another device's or the recovery identity's keys.
func (s *Store) PutKeybox(ctx context.Context, vault, author string, rows []KeyboxRow) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		var cur int64
		if err := tx.QueryRowContext(ctx, `SELECT epoch FROM vaults WHERE id=?`, vault).Scan(&cur); err != nil {
			return err
		}
		for _, r := range rows {
			if r.Epoch < 1 || r.Epoch > cur || len(r.Wrapped) == 0 {
				return fmt.Errorf("%w: bad keybox row", ErrBadRequest)
			}
			var n, rec int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(recovery),0) FROM devices WHERE id=? AND vault_id=? AND revoked_at IS NULL`, r.RecipientID, vault).Scan(&n, &rec); err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("%w: unknown recipient %s", ErrBadRequest, r.RecipientID)
			}
			switch {
			case r.RecipientID == author:
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO keybox(vault_id, epoch, recipient_id, wrapped, author_id) VALUES(?,?,?,?,?)
					 ON CONFLICT(vault_id, epoch, recipient_id) DO UPDATE SET wrapped=excluded.wrapped, author_id=excluded.author_id`,
					vault, r.Epoch, r.RecipientID, r.Wrapped, author); err != nil {
					return err
				}
			case rec == 1:
				res, err := tx.ExecContext(ctx,
					`INSERT INTO keybox(vault_id, epoch, recipient_id, wrapped, author_id) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`,
					vault, r.Epoch, r.RecipientID, r.Wrapped, author)
				if err != nil {
					return err
				}
				if k, _ := res.RowsAffected(); k == 0 {
					return fmt.Errorf("%w: keybox row for recovery identity epoch %d already exists", ErrConflict, r.Epoch)
				}
			default:
				return fmt.Errorf("%w: a device may only write keybox rows for itself or a recovery identity", ErrForbidden)
			}
		}
		return nil
	})
}

// Rotate advances the vault to epoch, revokes the listed devices, and stores
// the new epoch's keybox rows. The keybox must cover every device that will
// remain live (including a recovery identity), so nobody is locked out.
func (s *Store) Rotate(ctx context.Context, vault, author string, epoch int64, revoke []string, rows []KeyboxRow, authNext string) error {
	if !validAuthToken(authNext) {
		return fmt.Errorf("%w: auth_next (vault authority token for the new epoch) required", ErrBadRequest)
	}
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		var cur int64
		if err := tx.QueryRowContext(ctx, `SELECT epoch FROM vaults WHERE id=?`, vault).Scan(&cur); err != nil {
			return err
		}
		if epoch != cur+1 {
			return fmt.Errorf("%w: expected epoch %d", ErrConflict, cur+1)
		}
		revoked := map[string]bool{}
		for _, id := range revoke {
			if id == author {
				return fmt.Errorf("%w: cannot revoke self", ErrBadRequest)
			}
			revoked[id] = true
		}
		covered := map[string]bool{}
		for _, r := range rows {
			if r.Epoch != epoch || len(r.Wrapped) == 0 {
				return fmt.Errorf("%w: keybox rows must be for epoch %d", ErrBadRequest, epoch)
			}
			covered[r.RecipientID] = true
		}
		live, err := tx.QueryContext(ctx, `SELECT id FROM devices WHERE vault_id=? AND revoked_at IS NULL`, vault)
		if err != nil {
			return err
		}
		var liveIDs []string
		for live.Next() {
			var id string
			if err := live.Scan(&id); err != nil {
				live.Close()
				return err
			}
			liveIDs = append(liveIDs, id)
		}
		live.Close()
		for _, id := range liveIDs {
			if revoked[id] {
				continue
			}
			if !covered[id] {
				return fmt.Errorf("%w: keybox missing recipient %s", ErrBadRequest, id)
			}
		}
		for id := range covered {
			if revoked[id] {
				return fmt.Errorf("%w: keybox addresses revoked device %s", ErrBadRequest, id)
			}
		}
		for id := range revoked {
			if _, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at=?, token_hash=NULL WHERE id=? AND vault_id=?`, now(), id, vault); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM keybox WHERE vault_id=? AND recipient_id=?`, vault, id); err != nil {
				return err
			}
		}
		for _, r := range rows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO keybox(vault_id, epoch, recipient_id, wrapped, author_id) VALUES(?,?,?,?,?)`,
				vault, r.Epoch, r.RecipientID, r.Wrapped, author); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE vaults SET epoch=?, auth_hash=? WHERE id=?`, epoch, HashToken(authNext), vault)
		return err
	})
}

// ---------- recovery ----------

// RecoveryInfo is what an unauthenticated joiner may learn: enough to run
// the passphrase KDF, nothing to attack offline. The wrapped private key
// itself is released only on presentation of the derived auth token
// (RecoveryJoin), so every passphrase guess costs an online request.
type RecoveryInfo struct {
	DeviceID string `json:"device_id"`
	PubKex   []byte `json:"pub_kex"`
	Salt     []byte `json:"salt"`
}

// SetRecovery installs (or replaces) the recovery identity: a pseudo-device
// whose private key is stored passphrase-wrapped, plus an auth token derived
// client-side from the same passphrase.
func (s *Store) SetRecovery(ctx context.Context, vault string, pubKex, recoveryEnc, salt []byte, authToken string) (string, error) {
	if len(pubKex) == 0 || len(recoveryEnc) == 0 || len(salt) < 8 || len(salt) > 64 || !strings.HasPrefix(authToken, "rc_") {
		return "", fmt.Errorf("%w: pub_kex, recovery_enc, salt and rc_ auth required", ErrBadRequest)
	}
	id := randomHex(16)
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at=?, token_hash=NULL WHERE vault_id=? AND recovery=1 AND revoked_at IS NULL`, now(), vault); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM keybox WHERE vault_id=? AND recipient_id IN (SELECT id FROM devices WHERE vault_id=? AND recovery=1 AND revoked_at IS NOT NULL)`, vault, vault); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO devices(id, vault_id, pub_kex, token_hash, recovery, recovery_enc, recovery_salt, created_at) VALUES(?,?,?,?,1,?,?,?)`,
			id, vault, pubKex, HashToken(authToken), recoveryEnc, salt, now())
		return err
	})
	return id, err
}

func (s *Store) GetRecovery(ctx context.Context, vault string) (*RecoveryInfo, error) {
	r := &RecoveryInfo{}
	err := s.db.QueryRowContext(ctx, `SELECT id, pub_kex, recovery_salt FROM devices WHERE vault_id=? AND recovery=1 AND revoked_at IS NULL`, vault).
		Scan(&r.DeviceID, &r.PubKex, &r.Salt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// RecoveryJoin enrols a new device after it proved knowledge of the recovery
// passphrase (by presenting the derived auth token). It returns the keybox
// rows addressed to the recovery identity so the joiner can unwrap them.
func (s *Store) RecoveryJoin(ctx context.Context, vault, authToken string, pubKex, nameEnc []byte) (*Redeemed, []KeyboxRow, []byte, error) {
	if len(pubKex) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: pub_kex required", ErrBadRequest)
	}
	out := &Redeemed{VaultID: vault}
	var recID string
	var recoveryEnc []byte
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT id, recovery_enc FROM devices WHERE vault_id=? AND recovery=1 AND revoked_at IS NULL AND token_hash=?`, vault, HashToken(authToken)).Scan(&recID, &recoveryEnc)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT epoch FROM vaults WHERE id=?`, vault).Scan(&out.Epoch); err != nil {
			return err
		}
		devToken, devHash := NewToken("dv_")
		out.DeviceID = randomHex(16)
		out.DeviceToken = devToken
		_, err = tx.ExecContext(ctx, `INSERT INTO devices(id, vault_id, name_enc, pub_kex, token_hash, created_at) VALUES(?,?,?,?,?,?)`,
			out.DeviceID, vault, nameEnc, pubKex, devHash, now())
		return err
	})
	if err != nil {
		return nil, nil, nil, err
	}
	rows, err := s.GetKeybox(ctx, vault, recID)
	return out, rows, recoveryEnc, err
}

// ---------- blobs ----------

type BlobInfo struct {
	BlobID    string `json:"blob_id"`
	Epoch     int64  `json:"epoch"`
	CtSize    int64  `json:"ct_size"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Store) GetBlob(ctx context.Context, vault, id string) (*BlobInfo, error) {
	b := &BlobInfo{}
	err := s.db.QueryRowContext(ctx, `SELECT blob_id, epoch, ct_size, created_at FROM blobs WHERE vault_id=? AND blob_id=?`, vault, id).
		Scan(&b.BlobID, &b.Epoch, &b.CtSize, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

// UpsertBlob records a blob. Returns (stored=true) when the caller's bytes
// should be kept, or (false) when an equal-or-newer epoch already exists and
// the upload is a no-op.
//
// `replace` lets a key holder overwrite an existing record at the same epoch
// (repairing a blob whose stored bytes turned out to be undecryptable).
func (s *Store) UpsertBlob(ctx context.Context, vault, id string, epoch, ctSize int64, replace bool) (stored bool, err error) {
	err = s.writeTx(ctx, func(tx *sql.Tx) error {
		var cur sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT epoch FROM blobs WHERE vault_id=? AND blob_id=?`, vault, id).Scan(&cur); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if cur.Valid && (cur.Int64 > epoch || (cur.Int64 == epoch && !replace)) {
			stored = false
			return nil
		}
		stored = true
		_, err := tx.ExecContext(ctx,
			`INSERT INTO blobs(vault_id, blob_id, epoch, ct_size, created_at) VALUES(?,?,?,?,?)
			 ON CONFLICT(vault_id, blob_id) DO UPDATE SET epoch=excluded.epoch, ct_size=excluded.ct_size`,
			vault, id, epoch, ctSize, now())
		return err
	})
	return stored, err
}

func (s *Store) MissingBlobs(ctx context.Context, vault string, ids []string) ([]string, error) {
	missing := []string{}
	for _, id := range ids {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE vault_id=? AND blob_id=?`, vault, id).Scan(&n); err != nil {
			return nil, err
		}
		if n == 0 {
			missing = append(missing, id)
		}
	}
	return missing, nil
}

func (s *Store) BlobsBelowEpoch(ctx context.Context, vault string, epoch int64, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT blob_id FROM blobs WHERE vault_id=? AND epoch<? ORDER BY created_at LIMIT ?`, vault, epoch, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ---------- ops ----------

type Op struct {
	Seq       int64   `json:"seq"`
	OpID      string  `json:"op_id"`
	DeviceID  string  `json:"device_id"`
	PathID    string  `json:"path_id"`
	BlobID    *string `json:"blob_id"` // nil = deletion
	MetaEnc   []byte  `json:"meta_enc"`
	MetaEpoch int64   `json:"meta_epoch"`
	BaseSeq   int64   `json:"base_seq"`
	CreatedAt int64   `json:"created_at"`
}

type OpResult struct {
	OpID     string `json:"op_id"`
	Seq      int64  `json:"seq,omitempty"`
	Conflict *Op    `json:"conflict,omitempty"`
	Error    string `json:"error,omitempty"`
}

const opCols = `seq, op_id, device_id, path_id, blob_id, meta_enc, meta_epoch, base_seq, created_at`

func scanOp(sc interface{ Scan(...any) error }) (Op, error) {
	var o Op
	var blob sql.NullString
	err := sc.Scan(&o.Seq, &o.OpID, &o.DeviceID, &o.PathID, &blob, &o.MetaEnc, &o.MetaEpoch, &o.BaseSeq, &o.CreatedAt)
	if blob.Valid {
		b := blob.String
		o.BlobID = &b
	}
	return o, err
}

func (s *Store) GetOp(ctx context.Context, vault string, seq int64) (*Op, error) {
	o, err := scanOp(s.db.QueryRowContext(ctx, `SELECT `+opCols+` FROM ops WHERE vault_id=? AND seq=?`, vault, seq))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &o, err
}

func (s *Store) validateOp(o Op) error {
	if o.OpID == "" || len(o.OpID) > 64 {
		return fmt.Errorf("%w: op_id required", ErrBadRequest)
	}
	if !ValidHexID(o.PathID) {
		return fmt.Errorf("%w: path_id must be 64 hex chars", ErrBadRequest)
	}
	if o.BlobID != nil && !ValidHexID(*o.BlobID) {
		return fmt.Errorf("%w: blob_id must be 64 hex chars", ErrBadRequest)
	}
	if len(o.MetaEnc) == 0 {
		return fmt.Errorf("%w: meta_enc required", ErrBadRequest)
	}
	if o.MetaEpoch < 1 || o.BaseSeq < 0 {
		return fmt.Errorf("%w: bad meta_epoch or base_seq", ErrBadRequest)
	}
	return nil
}

// AppendOps applies a batch with per-op compare-and-swap on the path head.
// Accepted ops are committed even if others in the batch conflict. Returns
// the results in input order and the vault seq after the batch.
func (s *Store) AppendOps(ctx context.Context, vault, device string, ops []Op) ([]OpResult, int64, error) {
	results := make([]OpResult, len(ops))
	var finalSeq int64
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		var seq, epoch int64
		if err := tx.QueryRowContext(ctx, `SELECT seq, epoch FROM vaults WHERE id=?`, vault).Scan(&seq, &epoch); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		for i, o := range ops {
			results[i].OpID = o.OpID
			if err := s.validateOp(o); err != nil {
				results[i].Error = err.Error()
				continue
			}
			if o.MetaEpoch > epoch {
				results[i].Error = "meta_epoch ahead of vault epoch"
				continue
			}
			// Idempotent replay.
			var existing int64
			err := tx.QueryRowContext(ctx, `SELECT seq FROM ops WHERE vault_id=? AND op_id=?`, vault, o.OpID).Scan(&existing)
			if err == nil {
				results[i].Seq = existing
				continue
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			// CAS against the head.
			var head sql.NullInt64
			if err := tx.QueryRowContext(ctx, `SELECT seq FROM heads WHERE vault_id=? AND path_id=?`, vault, o.PathID).Scan(&head); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			headSeq := int64(0)
			if head.Valid {
				headSeq = head.Int64
			}
			if headSeq != o.BaseSeq {
				if headSeq == 0 {
					results[i].Error = "base_seq refers to a path with no head"
					continue
				}
				ho, err := scanOp(tx.QueryRowContext(ctx, `SELECT `+opCols+` FROM ops WHERE vault_id=? AND seq=?`, vault, headSeq))
				if err != nil {
					return err
				}
				results[i].Conflict = &ho
				continue
			}
			// Blobs before ops.
			if o.BlobID != nil {
				var n int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE vault_id=? AND blob_id=?`, vault, *o.BlobID).Scan(&n); err != nil {
					return err
				}
				if n == 0 {
					results[i].Error = "blob not uploaded"
					continue
				}
			}
			seq++
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO ops(vault_id, seq, op_id, device_id, path_id, blob_id, meta_enc, meta_epoch, base_seq, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
				vault, seq, o.OpID, device, o.PathID, o.BlobID, o.MetaEnc, o.MetaEpoch, o.BaseSeq, now()); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO heads(vault_id, path_id, seq) VALUES(?,?,?) ON CONFLICT(vault_id, path_id) DO UPDATE SET seq=excluded.seq`,
				vault, o.PathID, seq); err != nil {
				return err
			}
			results[i].Seq = seq
		}
		if _, err := tx.ExecContext(ctx, `UPDATE vaults SET seq=? WHERE id=?`, seq, vault); err != nil {
			return err
		}
		finalSeq = seq
		return nil
	})
	return results, finalSeq, err
}

func (s *Store) queryOps(ctx context.Context, q string, args ...any) ([]Op, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Op{}
	for rows.Next() {
		o, err := scanOp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) Changes(ctx context.Context, vault string, since int64, limit int) ([]Op, error) {
	return s.queryOps(ctx, `SELECT `+opCols+` FROM ops WHERE vault_id=? AND seq>? ORDER BY seq LIMIT ?`, vault, since, limit)
}

// Snapshot returns the head op of every path, including tombstones.
func (s *Store) Snapshot(ctx context.Context, vault string) ([]Op, error) {
	return s.queryOps(ctx, `SELECT `+opCols+` FROM ops WHERE vault_id=? AND seq IN (SELECT seq FROM heads WHERE vault_id=?) ORDER BY seq`, vault, vault)
}

func (s *Store) History(ctx context.Context, vault, pathID string, limit int) ([]Op, error) {
	return s.queryOps(ctx, `SELECT `+opCols+` FROM ops WHERE vault_id=? AND path_id=? ORDER BY seq LIMIT ?`, vault, pathID, limit)
}

func (s *Store) OpsByTime(ctx context.Context, vault string, from, to int64, limit int) ([]Op, error) {
	return s.queryOps(ctx, `SELECT `+opCols+` FROM ops WHERE vault_id=? AND created_at>=? AND created_at<=? ORDER BY seq LIMIT ?`, vault, from, to, limit)
}

func (s *Store) OpsBelowMetaEpoch(ctx context.Context, vault string, epoch int64, limit int) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq FROM ops WHERE vault_id=? AND meta_epoch<? ORDER BY seq LIMIT ?`, vault, epoch, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return nil, err
		}
		out = append(out, seq)
	}
	return out, rows.Err()
}

// PatchMeta replaces an op's encrypted metadata with a higher-epoch version.
func (s *Store) PatchMeta(ctx context.Context, vault string, seq int64, metaEnc []byte, metaEpoch int64) error {
	if len(metaEnc) == 0 {
		return fmt.Errorf("%w: meta_enc required", ErrBadRequest)
	}
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		var cur, vaultEpoch int64
		if err := tx.QueryRowContext(ctx, `SELECT epoch FROM vaults WHERE id=?`, vault).Scan(&vaultEpoch); err != nil {
			return err
		}
		err := tx.QueryRowContext(ctx, `SELECT meta_epoch FROM ops WHERE vault_id=? AND seq=?`, vault, seq).Scan(&cur)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if metaEpoch <= cur || metaEpoch > vaultEpoch {
			return fmt.Errorf("%w: meta_epoch must be in (%d, %d]", ErrConflict, cur, vaultEpoch)
		}
		_, err = tx.ExecContext(ctx, `UPDATE ops SET meta_enc=?, meta_epoch=? WHERE vault_id=? AND seq=?`, metaEnc, metaEpoch, vault, seq)
		return err
	})
}

// ---------- restore ----------

// Restore re-emits, for every path, the latest op at or before `at` whenever
// it differs from the current head and its blob still exists. It needs no
// keys: metadata and blob references are copied verbatim. Returns the number
// of ops emitted and the paths skipped because their blob was collected.
func (s *Store) Restore(ctx context.Context, vault, device string, at int64) (emitted int, skipped []string, err error) {
	err = s.writeTx(ctx, func(tx *sql.Tx) error {
		var seq int64
		if err := tx.QueryRowContext(ctx, `SELECT seq FROM vaults WHERE id=?`, vault).Scan(&seq); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx,
			`SELECT o.`+strings.ReplaceAll(opCols, ", ", ", o.")+`, h.seq
			 FROM heads h
			 JOIN ops o ON o.vault_id=h.vault_id AND o.seq = (
			   SELECT MAX(seq) FROM ops p WHERE p.vault_id=h.vault_id AND p.path_id=h.path_id AND p.created_at<=?)
			 WHERE h.vault_id=? AND o.seq <> h.seq`, at, vault)
		if err != nil {
			return err
		}
		type pair struct {
			old  Op
			head int64
		}
		var todo []pair
		for rows.Next() {
			var o Op
			var blob sql.NullString
			var head int64
			if err := rows.Scan(&o.Seq, &o.OpID, &o.DeviceID, &o.PathID, &blob, &o.MetaEnc, &o.MetaEpoch, &o.BaseSeq, &o.CreatedAt, &head); err != nil {
				rows.Close()
				return err
			}
			if blob.Valid {
				b := blob.String
				o.BlobID = &b
			}
			todo = append(todo, pair{o, head})
		}
		rows.Close()
		for _, p := range todo {
			if p.old.BlobID != nil {
				var n int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE vault_id=? AND blob_id=?`, vault, *p.old.BlobID).Scan(&n); err != nil {
					return err
				}
				if n == 0 {
					skipped = append(skipped, p.old.PathID)
					continue
				}
			}
			seq++
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO ops(vault_id, seq, op_id, device_id, path_id, blob_id, meta_enc, meta_epoch, base_seq, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
				vault, seq, "restore-"+randomHex(8), device, p.old.PathID, p.old.BlobID, p.old.MetaEnc, p.old.MetaEpoch, p.head, now()); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE heads SET seq=? WHERE vault_id=? AND path_id=?`, seq, vault, p.old.PathID); err != nil {
				return err
			}
			emitted++
		}
		_, err = tx.ExecContext(ctx, `UPDATE vaults SET seq=? WHERE id=?`, seq, vault)
		return err
	})
	return emitted, skipped, err
}

// ---------- GC ----------

// DeadBlobs lists blobs referenced neither by any head nor by any op created
// after cutoff. Also prunes keybox rows below min_epoch as a side effect.
func (s *Store) DeadBlobs(ctx context.Context, vault string, cutoff int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT b.blob_id FROM blobs b
		 WHERE b.vault_id=?
		   AND NOT EXISTS (SELECT 1 FROM ops o JOIN heads h ON h.vault_id=o.vault_id AND h.seq=o.seq
		                   WHERE o.vault_id=b.vault_id AND o.blob_id=b.blob_id)
		   AND NOT EXISTS (SELECT 1 FROM ops o WHERE o.vault_id=b.vault_id AND o.blob_id=b.blob_id AND o.created_at>?)`,
		vault, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DeleteDeadBlob removes the blob record only if it is still unreferenced at
// the moment of deletion (the DeadBlobs listing was computed outside this
// transaction, and an op may have referenced the blob since). Returns
// whether the record was removed.
func (s *Store) DeleteDeadBlob(ctx context.Context, vault, id string, cutoff int64) (bool, error) {
	var deleted bool
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM blobs WHERE vault_id=? AND blob_id=?
			   AND NOT EXISTS (SELECT 1 FROM ops o JOIN heads h ON h.vault_id=o.vault_id AND h.seq=o.seq
			                   WHERE o.vault_id=blobs.vault_id AND o.blob_id=blobs.blob_id)
			   AND NOT EXISTS (SELECT 1 FROM ops o WHERE o.vault_id=blobs.vault_id AND o.blob_id=blobs.blob_id AND o.created_at>?)`,
			vault, id, cutoff)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		deleted = n == 1
		return nil
	})
	return deleted, err
}

func (s *Store) PruneKeybox(ctx context.Context, vault string) error {
	v, err := s.GetVault(ctx, vault)
	if err != nil {
		return err
	}
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM keybox WHERE vault_id=? AND epoch<?`, vault, v.MinEpoch)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM invites WHERE vault_id=? AND (used_at IS NOT NULL OR expires_at<?)`, vault, now())
		return err
	})
}
