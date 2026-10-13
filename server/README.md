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

On first start an admin token is generated and saved to `DIR/admin-token`
(or pass `--admin-token` / `OBSYNC_ADMIN_TOKEN`). Mobile Obsidian needs a
publicly trusted certificate, so use `--acme-domain` or put Caddy/Traefik in
front.

Unauthenticated routes (invite redemption and recovery join) and
failed token checks are rate-limited per client IP: `--auth-rate N` requests
per minute (default 10, burst 2N; `-1` disables, for tests). Behind a reverse
proxy pass `--trust-proxy` so the limiter keys on `X-Forwarded-For`; without
it every client would share the proxy's address.

```sh
./obsync vault create --data /var/lib/obsync   # prints the vault id
./obsync vault list   --data /var/lib/obsync
./obsync gc           --data /var/lib/obsync --retention 2160h   # also runs daily inside `serve`
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
invites, recovery, device tokens and the admin token.

## API summary

All device routes take `Authorization: Bearer dv_…`; the WebSocket carries
it as the second subprotocol (`Sec-WebSocket-Protocol: obsync-bearer, dv_…`).
Tokens are never accepted in the URL. Routes marked **authority** also need
`X-Obsync-Vault-Auth: va_…`, a token only holders of the current epoch key
can derive (DESIGN.md §5.8). Every write is such a route, so a leaked device
token on its own is read-only: it can fetch ciphertext and nothing else.
Admin routes take the admin token.

A vault created by a server from before this existed has no authority token
and refuses writes until you install one. On any device that holds the
keys, Settings → obsync → Advanced → Vault authority → **Copy command**
gives you the exact line:

```sh
./obsync vault auth --data /var/lib/obsync <vault-id> va_…
``` Bodies are JSON unless noted;
binary fields are base64 in JSON. IDs (`path_id`, `blob_id`) are 64 lowercase
hex chars.

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/v1/vaults` | admin → `{vault_id, epoch, …}` |
| `GET` | `/v1/vaults` | admin |
| `POST` | `/v1/vaults/{v}/invites` | **authority** or admin. `{keybox_enc, ttl_seconds?}` → `{token, expires_at}` |
| `POST` | `/v1/invites/{t}` | no auth. `{pub_kex, name_enc}` → `{device_id, device_token, vault_id, epoch, keybox_enc}`. One-time. |
| `GET` | `/v1/vaults/{v}` | `{epoch, min_epoch, seq, has_auth}` |
| `GET` | `/v1/vaults/{v}/devices` | roster |
| `PATCH` | `/v1/vaults/{v}/devices/me` | `{name_enc}` rename the calling device |
| `GET` | `/v1/vaults/{v}/keybox` | rows addressed to the caller, epochs ≥ `min_epoch` |
| `POST` | `/v1/vaults/{v}/keybox` | `{keybox:[{epoch, recipient_id, wrapped}]}` for epochs ≤ current; recipient must be the caller, or a recovery identity (insert-only, **authority**) |
| `POST` | `/v1/vaults/{v}/auth` | `{auth:"va_…"}`. Device: installs the hash only on first enrolment (the caller is the vault's sole device); 204 when equal, 409 when different, 401 otherwise. Admin: installs or replaces it unconditionally (migration, reset). |
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
cmd/obsync          CLI: serve, vault create|list, gc
internal/store      SQLite schema and all queries (CAS lives in AppendOps)
internal/blobstore  sharded on-disk blobs, atomic temp+rename
internal/api        HTTP handlers, CORS, long-poll hub, WebSocket, GC
```
