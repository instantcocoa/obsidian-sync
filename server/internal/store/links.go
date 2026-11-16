package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Operator-minted one-time links (DESIGN.md §5.9). There is no admin bearer
// token any more: the person who runs the server proves it by running the
// CLI on the host, or by signing in to the admin page with a security key,
// and either way the server hands out a short-lived, single-use link.
//
//   - A create link (`cr_`) lets exactly one device create one new vault and
//     become its first member. It cannot touch any existing vault.
//   - A register link (`rg_`) lets one browser register one security key as
//     an admin credential.
//
// Both are stored hashed, like every other token, and bounded in number so
// a forgotten loop cannot fill the table.

type LinkKind string

const (
	LinkCreate   LinkKind = "create"
	LinkRegister LinkKind = "register"
)

// MaxOpenLinks bounds unused, unexpired links per kind.
const MaxOpenLinks = 20

func (k LinkKind) prefix() string {
	switch k {
	case LinkCreate:
		return "cr_"
	case LinkRegister:
		return "rg_"
	}
	panic("unknown link kind " + string(k))
}

type Link struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// CreateLink mints a one-time link of the given kind. `by` names the actor
// for the security log ("cli" or the admin credential's name).
func (s *Store) CreateLink(ctx context.Context, kind LinkKind, by string, ttl time.Duration) (*Link, error) {
	if ttl <= 0 || ttl > 24*time.Hour {
		return nil, fmt.Errorf("%w: link ttl must be between 1s and 24h", ErrBadRequest)
	}
	token, hash := NewToken(kind.prefix())
	l := &Link{Token: token, ExpiresAt: now() + ttl.Milliseconds()}
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		var open int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM links WHERE kind=? AND used_at IS NULL AND expires_at>?`, string(kind), now()).Scan(&open); err != nil {
			return err
		}
		if open >= MaxOpenLinks {
			return fmt.Errorf("%w: %d unused %s links already; wait for them to expire", ErrConflict, open, kind)
		}
		// Expired, unused rows are of no further use to anyone; sweep them here
		// so the table never grows past what is live plus what was redeemed.
		if _, err := tx.ExecContext(ctx, `DELETE FROM links WHERE used_at IS NULL AND expires_at<=?`, now()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO links(token_hash, kind, created_by, expires_at) VALUES(?,?,?,?)`, hash, string(kind), by, l.ExpiresAt)
		return err
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

// linkLiveTx returns nil if the link exists, is of the kind, unused and
// unexpired; ErrForbidden otherwise (one error for every failure, so the
// route is not an oracle for which tokens exist).
func linkLiveTx(ctx context.Context, q queryer, hash []byte, kind LinkKind) error {
	var k string
	var expires int64
	var used sql.NullInt64
	err := q.QueryRowContext(ctx, `SELECT kind, expires_at, used_at FROM links WHERE token_hash=?`, hash).Scan(&k, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (k != string(kind) || used.Valid || expires < now())) {
		return ErrForbidden
	}
	return err
}

// PeekLink reports whether a link is currently redeemable, without using it
// (the register page checks before asking for the key).
func (s *Store) PeekLink(ctx context.Context, token string, kind LinkKind) error {
	return linkLiveTx(ctx, s.db, HashToken(token), kind)
}

// ConsumeLink uses up a register link. The caller stores the credential in
// the same breath; a failure after this point costs one link, never a key.
func (s *Store) ConsumeLink(ctx context.Context, token string, kind LinkKind) error {
	hash := HashToken(token)
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		if err := linkLiveTx(ctx, tx, hash, kind); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE links SET used_at=? WHERE token_hash=?`, now(), hash)
		return err
	})
}

// RedeemCreateLink consumes a create link: in one transaction it creates a
// new vault at epoch 1 and enrols the caller as its first device. The device
// made the vault keys itself, so there is no keybox to hand back; it writes
// its own keybox rows and claims vault authority next, exactly as after an
// invite. The vault id is recorded on the link for the security log.
func (s *Store) RedeemCreateLink(ctx context.Context, token string, pubKex, nameEnc []byte) (*Redeemed, error) {
	if !validPubKex(pubKex) {
		return nil, fmt.Errorf("%w: pub_kex must be a 65-byte P-256 point", ErrBadRequest)
	}
	if len(nameEnc) > MaxOpaque {
		return nil, fmt.Errorf("%w: name_enc too large", ErrBadRequest)
	}
	hash := HashToken(token)
	out := &Redeemed{Epoch: 1}
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		if err := linkLiveTx(ctx, tx, hash, LinkCreate); err != nil {
			return err
		}
		out.VaultID = randomHex(16)
		if _, err := tx.ExecContext(ctx, `INSERT INTO vaults(id, epoch, seq, created_at) VALUES(?,1,0,?)`, out.VaultID, now()); err != nil {
			return err
		}
		devToken, devHash := NewToken("dv_")
		out.DeviceID = randomHex(16)
		out.DeviceToken = devToken
		if _, err := tx.ExecContext(ctx, `INSERT INTO devices(id, vault_id, name_enc, pub_kex, token_hash, created_at) VALUES(?,?,?,?,?,?)`,
			out.DeviceID, out.VaultID, nameEnc, pubKex, devHash, now()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE links SET used_at=?, vault_id=? WHERE token_hash=?`, now(), out.VaultID, hash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---------- settings ----------

// SetSetting stores an operator-level value (the public URL the server was
// started with, so the CLI can print complete links).
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
		return err
	})
}

// GetSetting returns "" for an unset key.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// ---------- admin credentials (security keys) ----------

// AdminCredential is one registered security key. Cred is the WebAuthn
// credential record (public key, sign counter, flags) as JSON; the store
// does not interpret it.
type AdminCredential struct {
	ID        []byte
	Name      string
	Cred      []byte
	CreatedAt int64
	LastUsed  int64
}

// MaxAdminCredentials bounds registered keys: a forgotten register loop must
// not turn into an unbounded table.
const MaxAdminCredentials = 10

func (s *Store) AddAdminCredential(ctx context.Context, id []byte, name string, cred []byte) error {
	if len(id) == 0 || len(id) > 1024 || name == "" || len(name) > 64 || len(cred) == 0 || len(cred) > 64<<10 {
		return fmt.Errorf("%w: bad credential", ErrBadRequest)
	}
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_credentials`).Scan(&n); err != nil {
			return err
		}
		if n >= MaxAdminCredentials {
			return fmt.Errorf("%w: %d security keys already registered; remove one first", ErrConflict, n)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO admin_credentials(id, name, cred, created_at) VALUES(?,?,?,?)`, id, name, cred, now())
		if err != nil && isUnique(err) {
			return fmt.Errorf("%w: a key with that id or name is already registered", ErrConflict)
		}
		return err
	})
}

func (s *Store) ListAdminCredentials(ctx context.Context) ([]AdminCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, cred, created_at, COALESCE(last_used,0) FROM admin_credentials ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminCredential{}
	for rows.Next() {
		var c AdminCredential
		if err := rows.Scan(&c.ID, &c.Name, &c.Cred, &c.CreatedAt, &c.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// TouchAdminCredential stores the updated record (sign counter) after a login.
func (s *Store) TouchAdminCredential(ctx context.Context, id, cred []byte) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE admin_credentials SET cred=?, last_used=? WHERE id=?`, cred, now(), id)
		return err
	})
}

func (s *Store) RemoveAdminCredential(ctx context.Context, name string) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM admin_credentials WHERE name=?`, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// isUnique reports a UNIQUE constraint violation from the SQLite driver.
func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
