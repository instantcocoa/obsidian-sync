# obsync server

Single-binary sync server for the obsync Obsidian plugin. Implements the API in
`../DESIGN.md` §4: an append-only op log with compare-and-swap on each path's
head, a keyed content-addressed blob store, epoch-based key rotation, invites,
recovery, restore-to-time, and garbage collection. SQLite (WAL) plus a blob
directory; no other dependencies.

The server never sees plaintext, paths, names, or keys. It stores and orders
ciphertext.

## Build and run

```sh
cd server
go build -o obsync ./cmd/obsync

# local / behind a reverse proxy
./obsync serve --data /var/lib/obsync --listen :8080
# public, with automatic Let's Encrypt (serves :443 and :80)
./obsync serve --data /var/lib/obsync --acme-domain sync.example.com
```

There is no admin token. A vault comes into being when its first device
redeems a one-time **create link**, which you mint on the host:

```sh
sudo ./obsync vault create --data /var/lib/obsync
# prints  obsync://create#https%3A%2F%2Fsync.example.com,cr_…  and a QR code
```

Paste the link into Settings → obsync on the first device, or scan the QR
with the device's camera. The link lasts an hour and works once; the device
makes the vault keys itself, so the server never holds anything that opens a
vault. Later devices join by invite links minted by a member device.
`--public-url` tells the server the address it is reached at, so the CLI can
print complete links without being told (`--url` overrides). The CLI writes
to the database directly, so run it on the host; under `sudo` it drops to
the data directory's owner before touching anything.

Everything under `DIR` is created private to the
server's user (umask 077; the database, its WAL and the blobs are 0600), and
the server should run as its own user: `obsync.service` in this directory
is a systemd unit that does that (its own transient user, read-only
system, no new privileges, the one capability needed to bind 80 and 443,
data in `/var/lib/obsync`). Mobile Obsidian needs a publicly trusted
certificate, so use `--acme-domain` or put Caddy in front; the
built-in listener offers TLS 1.2 and 1.3 with AEAD suites only and sends
HSTS.

### Behind Caddy

Caddy terminates TLS and proxies to the server on loopback; the server needs
to know its public origin and to trust Caddy's `X-Forwarded-For`:

```sh
./obsync serve --data /var/lib/obsync --listen 127.0.0.1:8080 \
  --public-url https://sync.example.com --trust-proxy 127.0.0.1,::1
```

`Caddyfile.example` in this directory is the whole Caddy side: one site
block with `reverse_proxy 127.0.0.1:8080`. Caddy obtains and renews the
certificate, passes WebSockets through unchanged, and appends the client
address to `X-Forwarded-For`, which `--trust-proxy` lets the rate limiter
and the security log use. `obsync.service` has the matching `ExecStart`
line commented out; with Caddy in front the unit needs no capability to
bind low ports, so drop the two `CAP_NET_BIND_SERVICE` lines too.

### The admin page (security keys)

`https://sync.example.com/admin` mints create links from any browser after a
sign-in with a security key (WebAuthn: a YubiKey over USB or NFC, or the
platform's own authenticator), so you can create a vault from a phone with
no shell at hand. Register a key with a one-time link from the host:

```sh
sudo ./obsync admin register --data /var/lib/obsync
# prints  https://sync.example.com/admin/register#rg_…
sudo ./obsync admin keys   --data /var/lib/obsync      # list
sudo ./obsync admin remove --data /var/lib/obsync NAME # revoke one
```

Open the link, touch the key, give it a name. Register two keys so losing
one does not lock you out of the page (the CLI always works). The server
stores only each key's public key and counter: nothing on its disk signs in.
A session lasts fifteen minutes in an HttpOnly, SameSite=Strict cookie
scoped to `/admin`; the page sends no CORS header and a strict CSP, and
every state-changing call checks `Origin`. A signed-in admin can list vaults
(ids, device and op counts) and create new ones, nothing else: joining,
reading or inviting into a vault takes the vault keys, which only devices
hold. Adding or removing keys is CLI-only. The page needs `--public-url` to
name a domain; with an IP address it stays off and says so, while links
keep working. DESIGN.md §5.9 has the full rationale.

Every security-relevant event is one `security` line on stderr with the
client address, the acting device or admin key, the vault and the outcome:
vault created, create or register link minted or refused, security key
registered, admin signed in (or refused), invite created or redeemed (or
refused), recovery set or joined (or refused), authority installed, keys
rotated, vault restored, and every failed or rate-limited authentication.
Tokens are never logged. A vault can hold at most 20 unused invites; a
rotation ends them all. At most 20 unused create links and 20 unused
register links exist at a time.

Unauthenticated routes (create-link and invite redemption, recovery join,
the admin page's sign-in and registration ceremonies) and
failed token checks are rate-limited per client IP: `--auth-rate N` requests
per minute (default 10, burst 2N; `-1` disables, for tests). Behind a reverse
proxy pass `--trust-proxy CIDR[,CIDR]` (the proxy's own addresses) so the
limiter and the security log key on the last `X-Forwarded-For` entry, the one
your proxy appended, for requests that arrive from those addresses; requests
from any other peer are keyed on the peer itself, so nothing that reaches the
listener directly can pick its own bucket. Give it the proxy's addresses,
never `0.0.0.0/0` (that would trust every IPv4 peer's header again). Without
the flag every client behind a proxy would share the proxy's address.
All `X-Forwarded-For` lines are read as one list, so a proxy that adds its
own line (HAProxy's default) is handled the same as one that appends to the
client's; an entry that is not an IP address is ignored and the peer address
is used. IPv6 clients are keyed by their /64, and the limiter holds at most
100,000 buckets.

## Backup and restore

Everything lives under `--data`: `obsync.db` (op log, heads, devices,
keybox) and `blobs/` (encrypted content, content-addressed). Back up both
together, with the server stopped or with SQLite's online backup
(`sqlite3 obsync.db ".backup /path/obsync.db"`) followed by a copy of
`blobs/`. The server holds no keys, so a backup is ciphertext and can sit
anywhere.

Restoring an older backup is safe for the devices: each one notices that the
op at its cursor is no longer the one it saw (`cursor_op_id` / `expect` on
the changes feed) and reconciles against the restored heads. Versions the
restore forgot are pushed back by whichever device still holds them, blobs
included; a version written by another device after the restore is kept as
a conflict copy rather than overwritten. See `DESIGN.md` §6.8.

```sh
./obsync vault create --data /var/lib/obsync   # a one-time create link for a new vault's first device
./obsync vault list   --data /var/lib/obsync   # ids, device counts, authority state
./obsync gc           --data /var/lib/obsync --retention 2160h   # also runs daily inside `serve`; run the CLI only while `serve` is stopped (the two processes do not share the per-blob locks)
```

## Test

```sh
go test ./...                     # end-to-end over HTTP, in-process
CGO_ENABLED=1 go test -race ./... # with the race detector
```

The suite enrols two devices, exchanges ops, races 32 goroutines on one
path, long-polls, uses the WebSocket, rotates keys and revokes a device,
re-encrypts, joins via recovery, restores to a point in time, and runs GC.
`security_test.go` is adversarial: every route with another vault's token,
revoked and malformed tokens, invite expiry and reuse, traversal-shaped blob
ids, oversized bodies, unknown JSON fields, and brute-force throttling of
invites, recovery, device tokens and create links; `admin_test.go` drives
the security-key page with a software authenticator (register, sign in,
mint, cross-origin and cloned-key refusals).

## API summary

All device routes take `Authorization: Bearer dv_…`; the WebSocket carries
it as the second subprotocol (`Sec-WebSocket-Protocol: obsync-bearer, dv_…`).
Tokens are never accepted in the URL. Routes marked **authority** also need
`X-Obsync-Vault-Auth: va_…`, a token only holders of the current epoch key
can derive (DESIGN.md §5.8). Every write is such a route, so a leaked device
token on its own is read-only: it can fetch ciphertext and nothing else.
There are no admin routes on the device API; the admin page lives under
`/admin` with its own cookie session (above).

A vault created by a server from before this existed has no authority token
and refuses writes until you install one. On any device that holds the
keys, Settings → obsync → Advanced → Write protection → **Copy command**
gives you the exact line:

```sh
./obsync vault auth --data /var/lib/obsync <vault-id> va_…
```

Bodies are JSON unless noted;
binary fields are base64 in JSON. IDs (`path_id`, `blob_id`) are 64 lowercase
hex chars.

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/v1/create/{t}` | no auth; `t` is a create link's `cr_` token. `{pub_kex, name_enc}` → `{vault_id, device_id, device_token, epoch: 1}`. Makes the vault and its first device in one transaction. One-time. |
| `POST` | `/v1/vaults/{v}/invites` | **authority**. `{keybox_enc, ttl_seconds?}` → `{token, expires_at}` |
| `POST` | `/v1/invites/{t}` | no auth. `{pub_kex, name_enc}` → `{device_id, device_token, vault_id, epoch, keybox_enc}`. One-time. |
| `GET` | `/v1/vaults/{v}` | `{epoch, min_epoch, seq, has_auth}` |
| `GET` | `/v1/vaults/{v}/devices` | roster |
| `PATCH` | `/v1/vaults/{v}/devices/me` | `{name_enc}` rename the calling device |
| `GET` | `/v1/vaults/{v}/keybox` | rows addressed to the caller, epochs ≥ `min_epoch` |
| `POST` | `/v1/vaults/{v}/keybox` | `{keybox:[{epoch, recipient_id, wrapped}]}` for epochs ≤ current; recipient must be the caller, or a recovery identity (insert-only, **authority**) |
| `POST` | `/v1/vaults/{v}/auth` | `{auth:"va_…"}`. Installs the hash only on first enrolment (the caller is the vault's sole device); 204 when equal, 401 when different (charged to the failed-authentication limiter like any wrong authority token), 401 otherwise. Replacing it is CLI-only (`vault auth`). |
| `GET` | `/admin/`, `/admin/register` | the admin page (HTML); 503 without `--public-url` |
| `GET` | `/admin/api/state` | `{registered, logged_in, origin}` plus `vaults` and `keys` when signed in |
| `POST` | `/admin/api/register/begin`, `…/finish` | WebAuthn registration against a register link (`{token}` → `{ceremony, options}`; `{token, ceremony, name, credential}` → `{name}`) |
| `POST` | `/admin/api/login/begin`, `…/finish` | WebAuthn assertion (`{}` → `{ceremony, options}`; `{ceremony, credential}` → session cookie) |
| `POST` | `/admin/api/create-link` | session → `{link, open_url, qr_svg, expires_at}` |
| `POST` | `/admin/api/logout` | ends the session |
| `POST` | `/v1/vaults/{v}/rotate` | **authority**. `{epoch: cur+1, revoke:[ids], keybox:[rows], auth_next:"va_…"}`; atomic; must cover every remaining device |
| `PUT` | `/v1/vaults/{v}/recovery` | **authority**. `{pub_kex, recovery_enc, salt, auth:"rc_…"}` |
| `GET` | `/v1/vaults/{v}/recovery` | no auth → `{device_id, pub_kex, salt}` (salt only; nothing to attack offline) |
| `POST` | `/v1/vaults/{v}/recovery/join` | bearer `rc_…` → device token, keybox rows for the recovery identity, and `recovery_enc` |
| `GET` | `/v1/vaults/{v}/snapshot` | head op per path incl. tombstones, `cursor` |
| `GET` | `/v1/vaults/{v}/changes?since=N&wait=S&limit=L` | long-poll up to 60 s; `more` flag; a device revoked while waiting gets 401 |
| `GET` | `/v1/vaults/{v}/live` | WebSocket (token in the subprotocol list), pushes `{seq, epoch}` hints on every change and as a 25 s heartbeat; closed when the device is revoked |
| `POST` | `/v1/vaults/{v}/blobs/missing` | `[ids]` → `{missing:[ids]}` |
| `PUT` | `/v1/vaults/{v}/blobs/{id}` | **authority**. raw body; `0x01‖epoch u32LE‖salt16‖nonce12‖ct`; 201 new or higher epoch, 200 no-op; `X-Blob-Replace: 1` overwrites at the same epoch (repair) |
| `GET` | `/v1/vaults/{v}/blobs/{id}` | raw; supports `Range`; `X-Blob-Epoch` header |
| `GET` | `/v1/vaults/{v}/blobs?epoch_lt=E` | re-encryption worklist |
| `POST` | `/v1/vaults/{v}/ops` | **authority**. `[{op_id, path_id, blob_id|null, meta_enc, meta_epoch, base_seq}]` → per-op `{seq}` / `{conflict: headOp}` / `{error}` |
| `PATCH` | `/v1/vaults/{v}/ops/{seq}/meta` | **authority**. `{meta_enc, meta_epoch}`; higher epoch only |
| `GET` | `/v1/vaults/{v}/ops?meta_epoch_lt=E` | `{seqs}` re-encryption worklist |
| `GET` | `/v1/vaults/{v}/ops?from=ms&to=ms` | op log by time |
| `GET` | `/v1/vaults/{v}/history?path_id=…` | ops for a path (first 5000) |
| `POST` | `/v1/vaults/{v}/restore` | **authority**. `{at: ms}` → re-emits older heads; `{emitted, skipped_path_ids}` |

Invariants enforced server-side: a `put` needs its blob uploaded first;
`base_seq` must equal the path's current head (0 for a new path); ops are
never mutated except `meta_enc` re-encryption; `rotate` rejects a keybox that
would lock any remaining device out; blob GC only removes blobs that no head
references and no op newer than the retention window references; every list
route clamps `limit` to 5000.

## Layout

```
cmd/obsync          CLI: serve, vault create|list|auth, admin register|keys|remove, gc
internal/store      SQLite schema and all queries (CAS lives in AppendOps; links.go: create/register links, security keys)
internal/blobstore  sharded on-disk blobs, atomic temp+rename
internal/api        HTTP handlers, CORS, long-poll hub, WebSocket, GC; admin.go + adminpage/: the security-key page
internal/qr         QR codes as SVG (admin page) and half-block text (terminal)
```
