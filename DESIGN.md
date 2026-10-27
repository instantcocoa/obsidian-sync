# obsync — a simple, fast, reliable Obsidian vault sync

Status: 2026-10-13. Server (`server/`) and plugin (`plugin/`) implemented and
tested at three levels: unit, multi-device end to end under Node against the
real server, and the shipped plugin inside real headless Obsidian (two
instances) against the real server, including onboarding through the real
settings dialog with the server's rate limiter on, and per-device key
protection (PIN; OS keychain where available). The server has an
adversarial route test suite. Two independent reviews were run by separate
agents given only the code and the documentation: a security review
(2 high, 3 medium, 5 low findings, all fixed and regression-tested; §5.8 and
the §6.5 path validation came out of it) and a first-time-user walkthrough
that set up two devices from the READMEs alone (24 friction points and one
bug, all addressed). The shipped bundle is checked statically for mobile
safety (`plugin/test/bundle-mobile.test.ts`: no Node modules or globals
outside feature-guarded paths, `isDesktopOnly: false`). Every conflict
shape and recovery path has a scenario test, and seeded random
multi-device histories are checked for convergence and no loss (§8,
`docs/CONFLICT-RECOVERY-MATRIX.md`). Not done: any run on
an actual iOS or Android device, and a security review by a human
specialist. Each component's README has the operational
details and how to run each suite.

One rule was added during real-Obsidian testing: a device that has never
synced a config-folder file adopts the vault's version instead of creating a
conflict copy (§6.6). The cause is reproduced, not inferred: every vault has
its own `app.json` before the plugin runs, Obsidian rewrites it by itself on
any settings change, so a joining device's copy differs from the vault's with
no shared base. `plugin/test/obsidian-config.test.ts` turns the rule off,
joins, and gets the exact conflict copy that was seen; turns it on, joins
again, and gets silent adoption.

This document records what we learned from reading Self-hosted LiveSync
(`../git/obsidian-livesync`, v1.0.35, plus its `@vrtmrz/livesync-commonlib`
0.1.36 package) and the design we are going to build instead.

---

## 1. Why LiveSync is hard: the root causes

LiveSync is not badly written. It is a large, careful codebase (≈93k lines of
plugin TypeScript across ≈490 files, plus a 3.8 MB common library) whose
complexity is almost entirely a consequence of a handful of early decisions.
Every one of those decisions is something we can avoid.

### 1.1 It is built on the CouchDB replication protocol

The vault is modelled as CouchDB documents so that PouchDB can replicate them.
That one choice forces all of the following:

- **Files must be split into chunks stored as separate documents**, because
  CouchDB/Cloudant limit document size. Chunks are content-addressed, shared
  between files, and referenced from a metadata document's `children` array.
- **Chunk and metadata writes are not atomic.** A reader can see metadata
  before its chunks arrive. LiveSync has an entire ADR
  (`docs/adr/2026_07_chunk_arrival_quiescence.md`) and a state machine with
  per-identifier claims, 2/4/6/8/10 s backoff, a five-minute "leak fuse", and
  a "finite replication activity count" just to decide how long to wait for a
  missing chunk.
- **Orphaned chunks accumulate** ("garbage storm" during typing). Garbage
  collection is a manual, beta, multi-step operation that requires every
  device to have synced, and CouchDB compaction needs free space equal to the
  database size. The "Eden" and "tiered chunk pack" designs were attempts to
  fix this and were deprecated.
- **Conflicts are PouchDB revision trees.** PouchDB picks a deterministic
  "winner" that is unrelated to what is on disk, so LiveSync had to layer a
  device-local "provenance" store (path → exact revision reflected to disk) on
  top, with rules for missing provenance, compacted ancestors, generation-one
  roots, and so on. `docs/specs_conflict_resolution.md` is 286 lines of
  invariants.
- **CouchDB server quirks leak into the client:** CORS configuration, reverse
  proxy buffering, `max_http_request_size`, opaque `seq` tokens that differ
  between 3.2 and 3.5, heartbeat vs. timeout semantics, Cloudflare 524s, and
  the need to run a Deno provisioning script before first use.
- **PouchDB over IndexedDB is slow on mobile** and the local database can
  diverge from both disk and remote, which is why "Fetch", "Rebuild", flag
  files (`redflag.md`, `flag_fetch.md`, `flag_rebuild.md`) and "SCRAM switches"
  exist.

### 1.2 Everything is a setting, and settings must agree across devices

`docs/settings.md` has 234 headings. Chunk splitter (3 versions), hash
algorithm, chunk size, E2EE version (2), path obfuscation, case sensitivity,
property encryption, internal-metadata encryption, compression, "read chunks
online", batch sizes, and more are "tweak values" that must match on every
device. A mismatch pauses sync with a dialogue, and some mismatches require a
full rebuild. Setting up a second device means transporting all of this via an
encrypted "Setup URI" with its own separate passphrase.

### 1.3 Three transports × three optional features

CouchDB, S3/MinIO "journal", and P2P WebRTC, each with its own replicator,
lifecycle, fences, and recovery paths. Hidden File Sync and Customisation Sync
are separate opt-in features with their own namespaces (`i:`, `ix:`, `ps:`),
their own Merge/Fetch/Overwrite initialisation direction, and a warning not to
enable both on the same files.

### 1.4 A decade of compatibility

Legacy `notes` document type, V1 encryption with dynamic iteration counts,
`doNotUseFixedRevisionForChunks`, `redflag2.md` aliases, two Setup URI formats,
QR key-index tables, legacy ID derivation. None of it can be removed.

### 1.5 What LiveSync got right (keep these)

- Content-addressed storage with a keyed hash so the server cannot confirm
  guesses about content.
- E2EE V2: AES-256-GCM with HKDF-derived subkeys. Paths are encrypted too.
- "File bytes, not mtime or size, decide whether content is known."
- Floor timestamps to integers before writing (Capacitor casts to Java `Long`;
  a float crashes Android on launch). See
  `src/serviceModules/FileSystemAdapters/sanitizeWriteOptions.ts`.
- Read via `adapter.readBinary`, never `vault.read` (which strips the BOM).
- Store the target of a rename before deleting the source.
- Treat a watcher DELETE as untrusted until the file is confirmed absent.
- Guard against a mass deletion propagating.
- Warn on path components over 255 UTF-8 bytes (Android/Linux limit).
- Persist the pending event queue so a restart mid-sync loses nothing.
- Use `fileManager.trashFile` for remote deletes so they land in `.trash`.
- Tear down and rebuild the live channel on `visibilitychange`, because a
  long-poll can stall without erroring.

### 1.6 Bugs LiveSync shipped that this design prevents by construction

From `docs/releases/*.md` and the code. Each one maps to a design rule below.

| Shipped bug | Root cause | Our rule |
| --- | --- | --- |
| Passphrase brute-forceable from a chunk ID when a zero-byte file existed (pre-0.24.7) | Content IDs derived from the passphrase | IDs are HMACs under a random 256-bit key; passphrases never touch IDs (§5) |
| Some chunks stored unencrypted; migration corrupted documents (0.25.6) | ID bug in the chunk/encryption layer; a permanent "compromised chunks" startup scan remains | One blob format, AEAD with the blob ID as associated data; nothing is ever written in a second format (§5) |
| U+FEFF at a Rabin–Karp chunk boundary silently dropped; repeated size-mismatch conflicts | Text-aware chunking | Blobs are opaque bytes; no chunking in v1 (§9) |
| Binaries corrupted by false Base64 detection | Type sniffing in the storage layer | Storage layer never inspects content; text vs. binary matters only to the merge step and is by extension + UTF-8 validity (§6.6) |
| "Unexpectedly shortened file" size mismatches, never auto-repaired | Metadata size vs. rebuilt-from-chunks size vs. disk size can disagree | Whole-file blobs, AEAD-authenticated, `blob_id` re-verified after decrypt (§5, §6.5) |
| Failed disk writes recorded as successful, then propagated as deletions | State updated before the write was confirmed | Mark intent → write → verify → record (§6.5, §8) |
| Unchanged local files overwrote newer synced content after restart (#994) | PouchDB winner ≠ file on disk | Equality is a hash of the bytes on disk vs. the synced hash; no revision tree (§6.5) |
| Float `mtime` crashed Android on launch (#1087) | Capacitor casts to Java `Long` | All timestamps floored at the write boundary (§6.7) |
| External folder case change silently deleted files from sync (#1168) | Case-folded IDs + watcher delete trusted | Deletes verified against disk; case-insensitive FS handled explicitly (§6.5) |
| Changing filters left excluded files permanently unseen | Replication checkpoint already past them | Remote ops for excluded paths are still recorded in state; un-excluding fetches the head (§6.5) |
| `vault.on('raw')` fires on *reads*, causing phantom hidden-file changes | Event taken as evidence of change | Events only schedule a hash; the hash decides (§6.2) |
| Hidden File Sync keyed by literal `i:.obsidian/…`, so a device with a different `configDir` never lines up | Device-specific name in a shared key | Config paths stored as `$CONFIG/…` and mapped through `app.vault.configDir` (§7.4) |
| Customisation Sync v2 forgot to reload plugins after applying | Early return before the reload code | Post-write hooks are a table, not scattered code (§7.2) |
| Customisation Sync scans only two directory levels under `.obsidian` | Hand-written walker | One recursive walker for everything (§6.3) |

---

## 2. Goals and non-goals

Goals:

1. **Setup in under two minutes.** One binary on the server, one invite link
   pasted into the plugin. No CouchDB, no CORS, no Deno, no second passphrase.
2. **Sync the whole vault**, including `.obsidian/` (settings, themes,
   snippets, plugins and their `data.json`), with a short, editable
   per-device exclusion list for device-specific state.
3. **Fast.** Cold start on a 20k-file vault in well under a second. Edit on
   one device visible on another in about a second. New-device bootstrap
   limited by bandwidth, not by protocol overhead.
4. **Never lose data, never block on a dialogue.** Conflicts become sibling
   files. The server keeps history so anything can be restored.
5. **End-to-end encrypted by default.** The server stores ciphertext and
   opaque identifiers only.
6. **Small.** Target ≈5k lines for the plugin and ≈2k for the server. Fewer
   than ten user-visible settings.

Non-goals (v1):

- Multiple remotes, P2P, S3-only mode, CouchDB compatibility.
- Real-time collaborative editing (CRDT). Single-user, multi-device.
- Selective sync of subfolders (exclusion patterns cover the common cases).

---

## 3. Architecture overview

```
┌──────────────── device A ────────────────┐        ┌──────── server ────────┐
│ Obsidian                                 │        │ obsync (single binary) │
│  ┌─────────┐  events  ┌────────────────┐ │  HTTPS │  ┌──────────────────┐  │
│  │ vault / │─────────▶│ watcher        │ │   +    │  │ op log (SQLite)  │  │
│  │ adapter │◀─────────│ applier        │ │   WS   │  │ seq, path_id,    │  │
│  └─────────┘  writes  └───────┬────────┘ │◀──────▶│  │ blob_id, base    │  │
│                               │          │        │  ├──────────────────┤  │
│                       ┌───────▼────────┐ │        │  │ blobs (files)    │  │
│                       │ state + queue  │ │        │  │ content-addressed│  │
│                       │ (one JSON file)│ │        │  └──────────────────┘  │
│                       └───────┬────────┘ │        └───────────▲────────────┘
│                       ┌───────▼────────┐ │                    │
│                       │ sync engine    │ │                    │ device B, C …
│                       │ pull→merge→push│ │                    │
│                       └────────────────┘ │
└──────────────────────────────────────────┘
```

Three ideas carry the whole design:

1. **The server is an append-only op log plus a content-addressed blob
   store.** No chunk documents, no revision trees. An op is
   `{seq, device, path, kind: put|delete, blob, size, mtime, base}`.
2. **Concurrency control is compare-and-swap on the per-path head.** A client
   says "I am replacing version N of this path." If N is not the current head,
   the server says no and returns the head. The client merges and retries.
3. **Local state is a cache, not a source of truth.** Truth is "bytes on disk"
   versus "head blob on server". If the local state file is lost or stale, a
   scan rebuilds it by hashing. Nothing can be bricked.

---

## 4. Server

### 4.1 Technology

- **Go**, single static binary, pure-Go SQLite (`modernc.org/sqlite`) in WAL
  mode for the op log and blob index, blobs as files on disk under
  `data/blobs/<xx>/<id>`. Cross-compiles for every host. (Rust + rusqlite is an
  equally fine choice; Go is suggested for the smaller build surface.)
- Built-in TLS via ACME (`--acme-domain`) or plain HTTP behind Caddy/Traefik.
  Mobile Obsidian requires a publicly trusted certificate.
- One process serves many vaults. A vault is created with an admin token.

### 4.2 Data model

```sql
vaults   (id, epoch, min_epoch, created_at)
devices  (id, vault_id, name_enc BLOB, pub_kex BLOB,
          token_hash, created_at, last_seen, revoked_at)
invites  (token_hash, vault_id, keybox_enc BLOB, expires_at, used)
keybox   (vault_id, epoch, recipient_id, wrapped BLOB, author_id)
ops      (vault_id, seq INTEGER, op_id TEXT UNIQUE, device_id, path_id,
          blob_id NULL, meta_enc BLOB, meta_epoch, base_seq, created_at)
heads    (vault_id, path_id, seq)          -- latest op per path, incl. tombstones
blobs    (vault_id, blob_id, epoch, ct_size, created_at, last_ref_at)
```

- `seq` is a per-vault monotonically increasing int64, assigned by the server
  inside the same transaction that checks `base_seq`.
- `path_id` = HMAC-SHA-256(path-ID key, NFC-normalised path). The server
  indexes on it but cannot invert it.
- `blob_id` = HMAC-SHA-256(blob-ID key, plaintext). Content-addressed, keyed,
  so identical files dedupe across devices and renames cost zero transfer, but
  the server cannot confirm a guessed plaintext. `NULL` means the op is a
  deletion. That one bit (put vs. delete) is the only per-op fact in the clear.
- `meta_enc` is the AEAD-encrypted `{path, mtime, size, flags}`. The server
  never sees a path, mtime, or plaintext size. `meta_epoch` says which epoch
  key encrypted it, so re-encryption can be tracked.
- `ct_size` is the ciphertext length the server observed on upload. It is used
  only for GC accounting and quota; the plaintext size lives in `meta_enc`.
- `name_enc` is the encrypted device name. The server logs and lists devices
  by `id` only.
- `pub_kex` is the device's ECDH P-256 public key, uploaded at enrolment.
  `keybox` holds epoch keys wrapped to each recipient's `pub_kex` (§5.4).
- `op_id` is a client UUID. Replays of the same op are idempotent.
- Tombstones are kept forever. They are ~150 bytes each.

### 4.3 HTTP API (the whole thing)

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/vaults` | Create a vault (admin token). |
| `POST` | `/v1/vaults/{v}/invites` | Mint a one-time invite. Body carries the invite keybox (§5.3). Needs vault authority (§5.8) or the admin token. |
| `POST` | `/v1/invites/{t}` | Redeem: body has the new device's `pub_kex` and `name_enc` → device token + invite keybox. |
| `GET` | `/v1/vaults/{v}/devices` | Roster: `id, name_enc, pub_kex, revoked_at`. |
| `PATCH` | `/v1/vaults/{v}/devices/me` | Set the calling device's `name_enc` (after enrolment, once it holds the keys). |
| `GET` | `/v1/vaults/{v}/keybox` | All keybox rows addressed to the calling device. |
| `POST` | `/v1/vaults/{v}/keybox` | Rows addressed to the caller itself, or (insert-only) to a recovery identity. Never to another device. |
| `POST` | `/v1/vaults/{v}/auth` | Register the vault authority hash (§5.8) on first enrolment. Idempotent for the same token, 409 for a different one. |
| `POST` | `/v1/vaults/{v}/rotate` | Atomically: store keybox rows for epoch+1, bump `vault.epoch`, revoke listed devices, install `auth_next` (§5.4, §5.8). Vault authority required. |
| `PUT` | `/v1/vaults/{v}/recovery` | Install or replace the recovery identity (§5.5). Vault authority required. |
| `GET` | `/v1/vaults/{v}/recovery` | No auth: `{device_id, pub_kex, salt}`. Only the KDF salt, nothing attackable offline. |
| `POST` | `/v1/vaults/{v}/recovery/join` | Bearer `rc_…` (derived from the passphrase): enrols a device and returns the keybox rows plus `recovery_enc`. Every wrong passphrase is an online, rate-limited request. |
| `GET` | `/v1/vaults/{v}/snapshot` | Current head op for every path + `cursor`. Used for bootstrap or when far behind. |
| `GET` | `/v1/vaults/{v}/changes?since=N&wait=30` | Ops with `seq > N` in order. Long-poll up to `wait` seconds. |
| `GET` | `/v1/vaults/{v}/live` | WebSocket; server pushes `{seq, epoch}` hints, client then calls `changes`. The token travels as the second entry of the `Sec-WebSocket-Protocol` list (`["obsync-bearer", token]`), never in the URL. A revoked device's socket is closed at the next hint. |
| `POST` | `/v1/vaults/{v}/blobs/missing` | Body: `[blob_id…]` → the subset the server does not have. |
| `PUT` | `/v1/vaults/{v}/blobs/{id}` | Upload ciphertext. Idempotent. A re-upload is accepted only if its header epoch is higher than the stored one, and then only with vault authority (it replaces the only copy). |
| `GET` | `/v1/vaults/{v}/blobs/{id}` | Download ciphertext. Supports `Range`. |
| `GET` | `/v1/vaults/{v}/blobs?epoch_lt=E` | Blob IDs still encrypted under an old epoch (re-encryption worklist). |
| `POST` | `/v1/vaults/{v}/ops` | Body: `[op…]`. Each op is CAS-checked and either `{seq}` or `{conflict: headOp}`. Applied atomically per op, not per batch. |
| `PATCH` | `/v1/vaults/{v}/ops/{seq}/meta` | Replace `meta_enc` with a higher `meta_epoch` (re-encryption). Nothing else about an op can change. Vault authority required. |
| `GET` | `/v1/vaults/{v}/history?path_id=…` | All ops for a path (versions UI, restore). |
| `GET` | `/v1/vaults/{v}/ops?from=T` | Op log by time, for "restore vault to T" tooling. |

All requests carry `Authorization: Bearer <device token>`, never a token in
the query string. List routes clamp `limit` to 5000 and `blobs/missing`
accepts at most 5000 ids, so no member can make the server materialise an
unbounded result. A long-poll re-checks that the caller is still enrolled
before answering, so a device revoked while waiting gets nothing. Everything
is JSON except blob bodies. The API is small enough that a second implementation on
Cloudflare Workers + D1 + R2 would be a weekend project if ever wanted.

### 4.4 Invariants the server enforces

- `POST /ops` for `{path_id, base_seq}` succeeds only if `heads[path_id].seq ==
  base_seq` (or `base_seq == 0` and no head exists). Checked and updated in one
  SQLite transaction. This is the only concurrency control in the system.
- A `put` op is rejected unless its `blob_id` exists. Blobs before ops, always
  (the same ordering LiveSync relies on, but enforced server-side so the
  "missing chunk" class of bug cannot occur).
- Ops are never mutated or deleted. Blob GC (below) is the only destructive
  operation.

### 4.5 Garbage collection and history

Server-side, automatic, no device coordination:

- A blob is live if any op within the retention window (default 90 days) or
  any current head references it.
- A daily sweep deletes dead blobs. The op log itself is retained forever.
- "Restore vault to time T" = for every path, take the latest op with
  `created_at ≤ T`; if its blob is still present, emit a new `put` op. This is
  a CLI command on the server and a command in the plugin.

Compare with LiveSync: GC V3 is manual, beta, CouchDB-only, requires "fetch
chunks on demand" off and all devices synced, and then needs CouchDB compaction
with 2× free disk.

### 4.6 Auth and trust

- **Trust assumption: the server is honest but curious.** It is trusted to
  store and order ciphertext faithfully, to serve every device the same
  history, and to enforce which device tokens may call which vault. It is not
  trusted with content, paths, names, times, or keys. A server that actively
  lies (withholds ops, forks history between devices, injects roster entries)
  is out of scope; we assume you run it or trust whoever does.
- Device tokens are random 256-bit, stored hashed. A revoked device's token is
  rejected and its keybox rows are deleted.
- A device token alone proves only "this device is enrolled". Anything that
  can destroy data or hand out keys (rotation, replacing ciphertext or
  metadata, installing recovery, minting invites) additionally needs the
  vault authority token (§5.8), which only a holder of the current epoch key
  can derive. So a token leaked through a proxy log or a copied `data.json`
  with sealed keys can read ciphertext and append ops as that device, and
  nothing more.
- Invite tokens are one-time with a short TTL (default 24 h). The invite link
  the user pastes is `obsync://join#<server>,<invite>,<I>`; `I` is the invite
  key (§5.3). Everything after `#` is a fragment and never reaches the server
  in a request line or log.
- Rate-limit invite redemption and failed auth.
- CORS: `Access-Control-Allow-Origin: *`, safe because auth is a bearer header
  and never a cookie.

---

## 5. Keys, encryption, and rotation

All primitives are WebCrypto (AES-GCM, HMAC, HKDF, PBKDF2, and ECDH on
P-256) so they are native and hardware-accelerated in Electron, Safari and
WKWebView (iOS 15+), and Chrome WebView (Android). P-256 rather than X25519
because X25519 in WebCrypto is still missing on older WebKit. There are no
signatures anywhere: under the honest-server assumption (§4.6) the server's
own authentication of the writing device is sufficient provenance.

### 5.1 Key hierarchy

```
K_id   identity key, 32 random bytes, created with the vault, never rotated
         K_blobid = HKDF(K_id, "obsync/blob-id/v1")
         K_pathid = HKDF(K_id, "obsync/path-id/v1")

K_e    content key for epoch e, 32 random bytes; e starts at 1
         K_meta,e = HKDF(K_e, "obsync/meta/v1")
         K_blob   = HKDF(K_e, salt, "obsync/blob/v1")    per blob

device  pub/priv_kex  ECDH P-256, generated at enrolment, private key never leaves the device
```

Two roots, on purpose. Identifiers must stay stable across rotation or every
blob and path would get a new ID and the whole vault would re-upload. The
identity key is therefore long-lived and is only ever replaced by a full
re-key (§5.6). Content confidentiality is what rotation protects, and that is
what the epoch keys carry.

### 5.2 Formats

```
blob_id  = HMAC-SHA-256(K_blobid, plaintext)
path_id  = HMAC-SHA-256(K_pathid, NFC(path))

blob     = 0x01 || epoch(u32 LE) || salt(16B) || nonce(12B)
           || AES-256-GCM(K_blob, body, aad = "blob" || blob_id || epoch)
         body = flags(1B: bit0 deflate) || plaintext

meta_enc = epoch(u32 LE) || nonce(12B)
           || AES-256-GCM(K_meta,e, JSON{path, mtime, size, flags}, aad = "meta" || path_id || epoch)

name_enc = 0x00000000 || nonce(12B)
           || AES-256-GCM(K_name, name, aad = "name"),  K_name = HKDF(K_id, "obsync/name/v1")
           (set by the device itself after enrolment via PATCH /devices/me,
           because it cannot encrypt anything before it holds the keys. Under
           the identity key rather than an epoch key: a device can only write
           its own name, so names written under epoch e would become
           unreadable to everyone once e is pruned after a rotation. A
           removed device loses roster access with its token, so the
           non-rotating key gives nothing away. A non-zero leading u32 marks
           a row from an older version, encrypted under K_meta,e.)
```

- Per-blob HKDF salt removes the AES-GCM nonce-reuse bound as a concern.
- The AAD binds every ciphertext to its identifier and epoch, so the server
  cannot swap one blob or one op's metadata for another, and cannot replay an
  old-epoch ciphertext as current without it failing to authenticate under the
  epoch the client expects.
- `mtime` and `size` are inside `meta_enc`. The server sees only ciphertext
  lengths and op timing. Ciphertext length is a close proxy for size; the
  `pad` flag rounds bodies up to 4 KiB before encryption for users who want
  that trade.
- Device names are inside `name_enc`. The server and its logs know devices
  only by random ID.

### 5.3 Enrolment (the invite)

A device holds no shared secret in the link any more; it holds a keypair. The
inviter does the wrapping so that the invitee can join without another device
being online:

1. Inviting device generates a random invite key `I` and builds an *invite
   keybox*: `AES-GCM(I, JSON{K_id, {e: K_e for every epoch ≥ min_epoch}})`.
2. `POST /invites` stores the invite keybox with a one-time token `t`.
   The link is `obsync://join#<server>,<t>,<I>`.
3. The new device generates its `kex` keypair and `POST /invites/{t}` with its
   public key.
   The server returns a device token and the invite keybox, then deletes the
   invite row.
4. The new device decrypts the keys with `I`, then writes its own keybox rows
   (each epoch key wrapped to its own `pub_kex`) so that future rotations can
   address it like any other device.
5. It encrypts its device name under `K_name` and sets it with
   `PATCH /devices/me`, registers the vault authority hash (§5.8, a no-op
   unless it is the first device), then stores `K_id`, the epoch keys, its
   private key and token in plugin data.

The link is as sensitive as the vault for 24 hours or until used, whichever
comes first. Send it over a channel you already trust and then discard it.

### 5.4 Keybox and rotation

A keybox row is one epoch key delivered to one recipient:

```
wrapped = ECIES(recipient.pub_kex, K_e || K_id)
        = eph_pub(65B) || nonce(12B) || AES-256-GCM(HKDF(ECDH(eph_priv, pub_kex), "obsync/wrap/v1"), K_e || K_id,
                                                     aad = vault_id || epoch || recipient_id)

Every row carries the identity key as well as the epoch key, so a device that
joins through the recovery identity (which never receives an invite keybox)
still obtains `K_id`.
```

**Rotation** is one command, "Remove device" (also available as "Rotate keys"
with nothing removed). On the device running it:

1. Fetch the roster. Generate `K_{e+1}`.
2. Wrap `K_{e+1}` to every non-revoked device's `pub_kex` except the ones
   being removed, plus the recovery identity if one exists (§5.5).
3. `POST /rotate {epoch: e+1, revoke: [ids], keybox: [rows]}`. The server, in
   one transaction, checks `epoch == vault.epoch + 1`, stores the rows, sets
   `vault.epoch = e+1`, marks the listed devices revoked, and deletes their
   keybox rows. A concurrent rotation loses the CAS and retries after
   re-reading the roster.
4. From now on every new blob and `meta_enc` this device writes uses
   `K_{e+1}`. Other devices learn the new epoch on their next keybox fetch
   (the `changes` response carries the vault's current epoch, so they notice
   within one sync).
5. **Re-encryption** runs as a resumable background job on the rotating device
   (any device can pick it up): `GET /blobs?epoch_lt=e+1` → for each blob,
   download, decrypt with the old epoch key, re-encrypt under `K_{e+1}` with a
   fresh salt, `PUT` it back under the same `blob_id`; the server accepts the
   replacement because the header epoch is higher. Likewise `PATCH` every op's
   `meta_enc` with `meta_epoch < e+1`. Heads first, then history, 8 at a time.
   A removed device that somehow still has a valid token sees only ciphertext
   it cannot open once this finishes; until then, old-epoch ciphertext is
   exactly as exposed as it was before rotation, never more.
6. When nothing remains below epoch `e+1`, the server raises
   `vault.min_epoch`, and devices discard keys for epochs below it. Old keys
   are never written to the server again.

What rotation does and does not achieve:

- A removed device **cannot decrypt anything written after rotation** and,
  after re-encryption completes, cannot decrypt anything the server still
  holds. This is the property that was missing.
- A removed device still **knows `K_id`**. With a valid device token (which it
  no longer has) or a server breach, it could compute identifiers for guessed
  plaintexts and learn whether a file with those exact bytes exists. If that
  matters, run a full re-key (§5.6).
- Rotation does not protect against a device that was malicious *before* it
  was removed; it already had everything.

**Roster trust.** The roster is whatever the server says it is, and the
server records which authenticated device wrote each keybox row. "Remove
device" shows the roster with names decrypted before the user confirms, so a
device that was enrolled with a leaked invite link is visible and removable.
Nothing more is needed under the honest-server assumption.

### 5.5 Recovery passphrase (optional)

A recovery identity is a device that exists only on paper:

1. The user sets a passphrase once. The plugin generates a recovery `kex`
   keypair, derives `K_wrap = PBKDF2-SHA-256(passphrase, salt, 600 000)`, and
   stores `AES-GCM(K_wrap, priv_kex)` plus the public key on the server as a
   roster entry flagged `recovery`.
2. Every rotation wraps the new epoch key to the recovery public key like any
   other recipient, so the recovery entry is never stale and no device needs
   the passphrase at rotation time.
3. Joining with "server URL + passphrase" derives `K_wrap`, unwraps
   `priv_kex`, opens the keybox rows addressed to the recovery identity, and
   then enrols normally (§5.3 step 4 onward). Changing the passphrase re-wraps
   the same private key; rotating the recovery identity is "Remove device" on
   it followed by setting a new passphrase.

The passphrase's strength is the whole security of this path; the UI
enforces a minimum length. Without a passphrase set, losing every device
loses the vault. That is the correct default.

Parameter choices, with the reasoning so they can be reviewed:

- **PBKDF2-HMAC-SHA-256, 600 000 iterations, 16-byte random salt.** This is
  the OWASP Password Storage Cheat Sheet recommendation for PBKDF2 with
  SHA-256 (2023 revision). Argon2id would be preferable but is not in
  WebCrypto, and shipping a WASM implementation would add an unaudited
  dependency to the most sensitive path. PBKDF2 costs about one second per
  attempt on a phone, which is acceptable for a join-time operation.
- **64 bytes derived, split into a wrapping key and an auth token.** The
  server stores only the SHA-256 of the auth token. An attacker with the
  server's database therefore has `recovery_enc` (needs the passphrase) and
  a hash (needs the passphrase); neither helps guess the other.
- **Online guessing** is bounded by the per-IP rate limit on the recovery
  routes (§4.6), not by the KDF.
- **AES-256-GCM with a fresh 12-byte nonce and a per-blob HKDF subkey.**
  Each derived key encrypts exactly one message, so the GCM nonce-reuse
  bound is never approached regardless of vault size. HKDF-SHA-256 and
  AES-GCM are the NIST SP 800-56C / SP 800-38D constructions WebCrypto
  implements natively.
- **ECDH P-256 + HKDF + AES-GCM for keybox rows** is the ECIES shape used
  by, for example, Apple's `SecKeyAlgorithm.eciesEncryptionStandardX963`,
  minus the X9.63 KDF in favour of HKDF.

No external audit has been performed. The wire formats are pinned in
`plugin/test/vectors.json` so that an auditor or a second implementation can
check every byte.

### 5.5a Local key protection (on-device)

Everything above protects data on the server and on the wire. On the device,
the vault keys, device private key and token live in the plugin's
`data.json`, which is only as safe as the OS disk encryption and the user's
login session. This section is the per-device unlock.

Measured in real Obsidian 1.12 (desktop, via the DevTools protocol):

| Mechanism | Available to a plugin? | Finding |
| --- | --- | --- |
| WebAuthn (Touch ID / Hello / FIDO2 key, PRF extension) | **No** | Chromium refuses public-key credentials on `app://obsidian.md`; only HTTPS and localhost origins qualify. |
| Electron `safeStorage` via `require("electron").remote` | **Yes, desktop** | macOS Keychain, Windows DPAPI, Linux libsecret/kwallet. Reports `basic_text` when no keyring exists, which the plugin treats as unavailable. |
| Electron `systemPreferences.promptTouchID` | **Yes, macOS only** | A prompt that resolves on success. It yields no secret; it is a gate our code enforces before unwrapping. |
| Biometrics on mobile | **No** | Capacitor exposes no biometric or keychain bridge to community plugins. |
| PKCS#11 / hardware tokens | **No** | Needs a native module; not possible in a community plugin. |

Design: one sealed key-store format, three ways to obtain the 32-byte
wrapping key.

```
sealed = { v:1, method: "pin"|"safe", salt?, nonce, ct }
ct     = AES-256-GCM(wrapKey, identity JSON, aad = "obsync/keystore/v1")

pin  : wrapKey = PBKDF2-SHA-256(pin, salt, 600 000)                 every platform
safe : wrapKey random; stored as safeStorage.encryptString(wrapKey)  desktop with a keychain
       optionally: systemPreferences.promptTouchID() before unwrap   macOS
none : identity stored in the clear                                  default on mobile
```

Threat model for each: `pin` resists an attacker with the file and no PIN,
bounded by PIN entropy and the KDF. `safe` resists an attacker with the file
and no OS session; an attacker inside the logged-in session can call
`safeStorage.decryptString` themselves, and the Touch ID gate only raises the
bar for someone who does not know to bypass our code. `none` resists nothing
beyond disk encryption. The settings UI says so in those words. Switching
methods re-seals; the server and wire format are untouched.

### 5.6 Full re-key (replaces `K_id`)

Needed only if `K_id` itself is believed compromised. It is a new vault:
create, enrol, upload everything under new identifiers, point every device at
the new vault, delete the old one. The plugin offers it as one command
("Re-key vault") that does those steps with a progress bar; the server does
not need to know it is happening. History does not carry over except through
"restore to T" run before the switch.

### 5.7 Threat model

| Adversary | Gets | Cannot | Mitigation / residual |
| --- | --- | --- | --- |
| Reads server disk or backups | ciphertext, path and blob IDs, op timing, ciphertext sizes, device IDs, roster public keys | content, paths, names, mtimes, which human owns which device | padding flag for sizes; timing is inherent |
| Steals a device token (proxy log, copied `data.json` with sealed keys) | read ciphertext and the op log; see which device is online | write anything: no ops, no blobs, no rotation, revocation, recovery, invites or keybox rows for others | vault authority (§5.8) gates every write; revoke device → rotate |
| Steals an unused invite link, or holds any member's keys | joins as a device with full read/write, **which means code execution on every device**: a synced `.obsidian/plugins/*/main.js` is reloaded, and `community-plugins.json` enables plugins, automatically (§7.3) | write outside the vault, or under a path other than the one an op is keyed by (§6.5 validation) | 24 h TTL, one-time; unexpected or unnamed device is flagged in the roster; remove + rotate; turn "sync config folder" off if vault members are not fully trusted |
| Takes a device (phone with Obsidian) | everything that device has, including `K_id` and current keys | anything after rotation; anything at all after re-encryption, given the token is revoked | OS disk encryption; per-device key protection (§5.5a); remove + rotate from another device |
| Guesses the recovery passphrase | one online attempt per request, rate-limited | an offline attack: the server hands out only the KDF salt; the wrapped key is released only against the derived auth token | PBKDF2-600k plus the limiter; someone with the server's disk can still attack offline, so pick a long passphrase |
| Server operator (honest but curious) | the "reads server disk" row, live, plus which device is online when | content, paths, names, mtimes; cannot substitute one ciphertext for another without AEAD failing | by assumption (§4.6) they do not tamper; curiosity gains nothing beyond metadata |
| Passive network | nothing beyond TLS metadata | | TLS |

Accepted residual exposure:

1. **Op timing** and the put-vs-delete bit per op are visible. Hiding them
   needs cover traffic or batching delays; not worth it for this threat model.
2. **Vault write access is code execution** on every device that syncs the
   config folder (§7.3). That is the point of syncing plugins; the roster is
   the trust boundary, and the plugin announces every plugin it enables.
3. **An actively malicious server is out of scope.** If that ever changes,
   the fix is a per-device running hash over the op log exchanged through
   the keybox channel; the formats here do not preclude it.

### 5.8 Vault authority token

Every device holds the current epoch key `K_e`. From it, each derives

    A_e = "va_" ‖ b64url(HKDF-SHA-256(K_e, salt = "", info = "obsync/auth/v1"))

and the server stores `SHA-256(A_e)` on the vault (`POST /auth` by the first
device at enrolment, accepted only while it is the vault's sole device;
`auth_next` in every rotation installs the hash for the new epoch atomically
with the epoch bump). Every write requires `X-Obsync-Vault-Auth: A_e` in
addition to the device token: blob uploads, ops, restore, rotation,
metadata re-encryption, keybox rows for a recovery identity, installing or
replacing the recovery identity, and minting invites. A device token alone
is read-only.

What this buys: a device *token* and the device *keys* are different
secrets, and only the token ever travels or sits in a log. A token-only
attacker (proxy access log, a copied `data.json` whose keys are sealed under
a PIN or the OS keychain) can fetch ciphertext, which it cannot read, and
nothing else: it cannot post ops, upload a blob under an id the vault will
later use (blob-id poisoning), revoke the owner, replace the recovery
passphrase, enrol a device of its own to be wrapped at the next rotation, or
overwrite any ciphertext. HKDF is one-way, so the server learns nothing
about `K_e` from `A_e`, and a revoked device's old `A_e` dies with its epoch.

Vaults from before this existed have no hash. They accept no writes until
the administrator installs one with `obsync vault auth` using the token
shown in a key-holding device's settings; a member may not claim it, since
on such a vault a token thief would be just as eligible. A device may claim
only while it is the vault's sole device and the vault holds no op and no
blob, which is exactly the first-enrolment moment and nothing else. A key holder can
also overwrite a stored blob at the same epoch (`X-Blob-Replace`), which is
the repair for a blob whose bytes turn out to be undecryptable.

- **No passphrase-derived identifiers, ever.** LiveSync derived chunk IDs
  from the E2EE passphrase; with a zero-byte file present, the ID of the
  empty chunk became a passphrase oracle (fixed in 0.24.7). Our `K_blobid` is
  derived from the random identity key, so an identifier reveals nothing for
  known plaintexts beyond "this vault contains these exact bytes", and only
  to someone who already holds `K_id`.
- **No plaintext at rest beyond the vault itself.** LiveSync's local PouchDB
  holds every chunk in plaintext. Our local state holds paths, hashes, and
  stats; blobs are never cached locally, since the file on disk is the cache.
- Compression: text bodies may be `deflate-raw` compressed before encryption
  (native `CompressionStream`), signalled by the body flag byte. Optional, off
  by default until measured; LiveSync measured only ~9 % savings on mixed
  data at 3× CPU cost.

---

## 6. Client (the Obsidian plugin)

TypeScript, esbuild, no UI framework. Five modules plus a thin settings tab.

### 6.1 Local state

One JSON file at `.obsidian/plugins/obsync/state.json` (excluded from sync),
loaded fully into memory at startup, written debounced and atomically
(write `state.json.tmp`, then `adapter.rename`):

```ts
interface State {
  cursor: number;                       // last applied server seq
  files: Record<string, {               // key: NFC path
    hash: string;                       // blob_id of the bytes we last synced
    size: number; mtime: number;        // disk stat at last sync, cheap change check
    seq: number;                        // server head seq we are based on
  }>;
  pending: Op[];                        // local ops not yet accepted by server
  inflight?: { path: string; hash: string }[]; // writes we were in the middle of
  epoch: number;                        // current vault epoch as last seen (§5.4)
  reencrypt?: { target: number; blobsDone: number; opsDone: number }; // resumable job
}
```

For 20k files this is ~3 MB and loads in tens of milliseconds. If it is lost
or corrupt, a scan rebuilds it (section 6.3). IndexedDB was considered and
rejected: nothing here needs indexing, and a single file is easier to inspect,
back up, and reason about on mobile.

### 6.2 Watcher

- Normal files: `vault.on('create'|'modify'|'delete'|'rename')`.
- `.obsidian/**` and other dot-paths: Obsidian does not index these. On
  desktop the undocumented `vault.on('raw', path)` fires for adapter-level
  changes under `configDir` only, and it also fires on mere *reads*; on mobile
  it does not fire reliably at all. So: subscribe to `raw` where available as
  a hint only, **and** run a cheap stat-walk of all dot-directories every 30 s
  and on app resume. A stat of a few hundred config files is a few
  milliseconds. Dot-files nested inside normal folders (e.g. `notes/.foo`) are
  covered by the same walk; LiveSync never reaches them.
- Debounce per path 1.5 s while typing; flush immediately on `file-open`
  change, on window blur, and on `visibilitychange: hidden` (mobile
  backgrounding).
- **Self-echo suppression by content, not time.** Before the applier writes a
  file it records `(path, blob_id)` in `inflight`. When an event arrives, the
  watcher hashes the file; if the hash equals the inflight/synced hash the
  event is dropped. No timers, no "ignore events for 500 ms" heuristics.

### 6.3 Scanner / reconciler

Runs at startup (after state load, in the background, yielding every few
hundred files), on resume, and on demand.

1. Enumerate: `vault.getFiles()` for indexed files (stats are already in
   memory, zero I/O) plus a recursive `adapter.list` of dot-directories.
2. For each path compare `(size, mtime)` to state. Unchanged → skip. Changed
   or unknown → `adapter.readBinary`, hash, compare `blob_id` to state:
   - equal → update stat in state (touch only, e.g. git checkout);
   - different → enqueue local `put`.
3. Paths in state but not on disk → enqueue local `delete`, subject to the
   mass-deletion guard: if more than max(50, 20 %) of files would be deleted
   in one scan, hold them and show a notice with an "apply deletions" button.
   This is the one place a human is asked anything.
4. Honour `inflight`: a path marked inflight whose disk hash is neither the
   old nor the new hash was interrupted mid-write; re-download instead of
   treating the partial file as a local edit.

### 6.4 Sync engine: pull → merge → push

A single loop, serialised, triggered by: WS hint, local queue non-empty, timer
(60 s), resume, reconnect.

```
pull:   ops = GET changes?since=cursor   (or snapshot if cursor==0 or very far behind)
        if response.epoch != state.epoch: GET keybox, unwrap new epoch keys, state.epoch = response.epoch
        for each op in order: apply (6.5), cursor = op.seq
merge:  for each pending local op whose path got a remote op during pull: resolve (6.6)
push:   blobs = pending puts' blob_ids; missing = POST blobs/missing; upload missing (8-way parallel)
        results = POST ops (pending)      // each carries base = state.files[path].seq
        accepted → state.files[path].seq = seq, remove from pending
        conflict → resolve (6.6), re-queue
```

Bootstrap of a new device = `snapshot` + parallel blob downloads (8 at a
time, largest first for attachments, with `Range` resume). Progress is shown
in the status bar. 10k notes at a few KB each is seconds; attachments are
bandwidth-bound.

### 6.5 Applier (remote → disk)

For a remote `put`:

1. If the path is excluded on this device, record it in state and skip.
2. Acquire the per-path lock. Re-stat and, if changed since state, hash the
   disk file. If disk hash ≠ state hash, the user edited locally while we were
   offline → go to 6.6 instead of overwriting.
3. Download blob (cached if we already have it from another path), decrypt,
   verify `blob_id`.
4. Mark `inflight`, write with `vault.modifyBinary`/`createBinary` for indexed
   files (keeps open editors in sync) or `adapter.writeBinary` for dot-files,
   with `mtime` floored to an integer. For dot-files, call the undocumented
   `adapter.reconcileInternalFile(path)` afterwards so Obsidian notices the
   change (LiveSync does this too). Update state, clear inflight.
5. Post-write hooks (section 7) for `.obsidian` paths.

Excluded paths: a remote op whose path is excluded on this device is still
recorded in `state.files[path].seq` (without writing to disk) so that removing
the exclusion later makes the scanner fetch the current head instead of
silently never seeing it.

**Network from inside Obsidian.** Desktop runs at origin `app://obsidian.md`
and mobile at `capacitor://localhost`, so plain `fetch` is subject to CORS.
The server therefore always answers `Access-Control-Allow-Origin: *` and
`Access-Control-Allow-Headers: Authorization, Content-Type` (safe: auth is a
bearer token, never a cookie). WebSockets are not subject to CORS. Obsidian's
`requestUrl` bypasses CORS but cannot stream or abort, so it is only a
fallback for the small JSON calls, never for blobs. This removes an entire
class of LiveSync support issues (CouchDB CORS config, proxy headers,
Cloudflare 524s stripping CORS headers).

For a remote `delete`: same lock and hash check; if disk hash equals the synced
hash, `fileManager.trashFile` (so it lands in Obsidian's trash, recoverable);
otherwise keep the local file and re-upload it as a new version (the user's
edit wins over a stale delete).

Case-insensitive filesystems: keep a case-folded index; if an incoming path
collides with a different-case existing path, write it as a conflict sibling
rather than clobbering.

### 6.6 Conflict resolution

A conflict means: local pending op for path P with base N, and the server head
for P is now M ≠ N.

1. If local bytes == server head bytes (same `blob_id`): no conflict; accept M
   as our base and drop the pending op. This covers the common "both devices
   synced the same thing" and "echo" cases.
2. If the file is text (by extension allow-list, and the bytes are valid
   UTF-8) and we still have the base blob N available (we do, if we synced it;
   otherwise fetch from server history by `blob_id`): three-way merge with
   `diff3` semantics (non-overlapping hunks merge cleanly; overlapping hunks
   fall to step 3). Line endings and BOM are preserved verbatim; the merge
   works on lines split on `\n` with `\r` left attached. For `.json` under
   `.obsidian`, merge at the JSON key level instead of line level. The base is
   always the exact blob the pending op was based on, never "the nearest
   lower generation" (LiveSync's hidden-file JSON merge does the latter and
   its own spec lists it as unsafe).
3. Otherwise: keep the server head at P, write local bytes to
   `P (conflict <device> 2026-10-08 1432).md` as a new file, and show a
   notice. Both versions are in the op log forever anyway. The stamp has
   minute resolution, so a second conflict on the same file within the same
   minute gets an ordinal (`… 1432 2).md`) instead of overwriting the first
   copy; a copy with identical bytes is reused rather than duplicated.

Exception: a file under `$CONFIG` that this device has never synced (no base
at all, which is the state of a device that just joined) takes the vault's
version silently. Its local copy is Obsidian's defaults, written before the
plugin was installed, not a user edit. Ordinary files with no base and
different bytes still get a sibling, because a hand-copied vault is a common
way to seed a new device and nothing may be discarded.

Why this exception exists (reproduced in `plugin/test/obsidian-config.test.ts`
inside real Obsidian): Obsidian creates `app.json` in every vault and rewrites
it on its own whenever a setting changes, so by the time a second device joins
its `app.json` is already different from the first device's upload, and there
is no base to merge against. Without the exception the generic rule produces
`app (conflict <device> …).json` on every such join. The engine option
`adoptConfig` (default on) exists only so the test can show both behaviours.

Never a modal. A "Show conflicts" command lists files matching the conflict
pattern.

Failure isolation: one op that cannot be applied (its blob does not decrypt
because a key holder uploaded garbage under a real id, its name is refused
by the local file system, its parent vanished) is logged, reported through a
notice, and skipped; the cursor moves on and the next op for that path heals
it. The same holds on the push side: a local edit whose server head cannot
be read is reported and left for the next change rather than failing the
whole push. Only transport failures abort a batch, because those are
retried as a whole. Without this, a single bad op would stall every device
forever. Exclusion patterns match case-insensitively and the config-dir
alias check folds case and combining marks, because on macOS and Windows
volumes `Workspace.json` and `plugins/Obsync/` are the excluded paths.

### 6.8 Restored server

An operator who restores the server from a backup (DB file plus blob
directory, see `server/README.md`) rewinds the op log. Devices that synced
after the backup hold versions the server has forgotten, and the server now
hands out sequence numbers those devices have already consumed. Left alone,
a device would see "nothing new" forever and never re-push, and a device
that was behind would apply old ops under numbers it had already passed.

Detection is by identity, not by number: every feed carries the `op_id` at
the cursor (`cursor_op_id`), the client stores it beside its cursor and
sends it back as `expect`; the server answers `rewound: true` when the op
at that sequence is not the one the client saw (or no longer exists). A
restore that happens to have re-issued exactly the same count of ops is
therefore still caught. Feeds also carry the vault's `seq` for the cheap
case.

Reconciliation (`Engine.recoverFromRewind`) compares every state entry with
the server's current heads and uses the server's own timestamps, which it
stores per entry as `at`:

- the entry matches the head: nothing to do;
- the server's history for the path contains the version the device last
  synced: the server moved on after the restore, so the head is applied
  through the ordinary rules (a later local edit merges or becomes a
  sibling);
- the server has never seen that version and its head is older than the
  device's sync: the device's copy is the newer one, so it is rebased on
  the head and pushed again, which re-uploads any blob the restore lost;
- the server has never seen that version and its head is newer (another
  device wrote the path after the restore): a genuine concurrent edit, so
  the local copy becomes a conflict sibling and the head is applied;
- the path is unknown to the server: pushed as a new file.

If the backup predates a key rotation the server's epoch goes backwards
too. The device re-learns the old epoch key from the restored keybox,
makes it current again (so its authority token and new ciphertext match
what the server expects), and forgets epochs the server no longer has, so
the next invite does not offer them. Then the cursor resets and a snapshot
pull plus the usual push finish the job. Nothing is written to disk by the reconciliation itself; every
outcome goes through §6.5 and §6.6, so the "nothing is lost" guarantee
holds across a restore. `plugin/test/conflict-recovery.test.ts` rows 21 and
22 exercise both the simple case and the concurrent one.

### 6.7 Mobile

- iOS kills background WebSockets; on `visibilitychange: visible` and on
  `online` events, reconnect and run the loop. No wake locks.
- All hashing and crypto is WebCrypto (off the JS thread in practice).
- Never hold more than one blob in memory per concurrent download; stream
  large downloads to disk via `Range` requests of 4 MiB.
- Timestamps floored to integers (Capacitor crash).
- Warn (status bar) on path components over 255 UTF-8 bytes.

---

## 7. Syncing `.obsidian` properly

This is where LiveSync is weakest (two overlapping features, each opt-in with
initialisation directions). For us it is just files, with three additions.

### 7.1 Default exclusions (per device, editable)

```
.obsidian/workspace.json          # window layout; device-specific, churns constantly
.obsidian/workspace-mobile.json
.obsidian/workspaces.json
.obsidian/plugins/obsync/         # ourselves
.obsidian/plugins/*/data.json     # NOT excluded by default; opt-out per plugin
.trash/
.git/ , node_modules/ , .DS_Store , desktop.ini , Thumbs.db
```

Rationale: `workspace*.json` are the only files Obsidian itself treats as
per-device. Plugin `data.json` is usually settings the user wants everywhere;
the few plugins that keep device state (e.g. a local path) are excluded by the
user with one line. The UI makes this a text box of glob patterns plus a
checklist of installed plugins.

### 7.2 Post-write hooks

| Path changed | Action after write |
| --- | --- |
| `.obsidian/plugins/<id>/{main.js,manifest.json,styles.css}` | If plugin enabled: `app.plugins.disablePlugin(id)` then `enablePlugin(id)` (same mechanism BRAT and hot-reload use), debounced 2 s so the three files reload once. |
| `.obsidian/community-plugins.json` | Enable/disable plugins to match. |
| `.obsidian/snippets/*.css`, `appearance.json` | `app.customCss.requestLoadSnippets()` / `app.customCss.loadCss()`. |
| `.obsidian/themes/*` | `app.customCss.setTheme(current)` to reload. |
| `.obsidian/app.json`, `hotkeys.json`, `core-plugins.json` | Obsidian reads these on demand; notify the user "settings changed remotely, reload (Ctrl/Cmd+R) to apply everything" once per session. |
| `.obsidian/plugins/<id>/data.json` | Nothing; most plugins read on load. Covered by the notice above. |

`app.plugins`, `app.customCss` are undocumented but stable for years and used
by the most popular community plugins. Wrap each in a try/catch; failure
degrades to "reload Obsidian" rather than breaking sync.

### 7.4 The config directory name is per device

`app.vault.configDir` is usually `.obsidian` but can be changed per vault copy.
LiveSync keys hidden files by the literal path, so devices with different
names never line up. We store config paths as `$CONFIG/…` in the op log and
map `$CONFIG` ↔ `app.vault.configDir` at the edge. Everything else in the
engine sees ordinary paths.

### 7.5 What LiveSync's two features do that we deliberately do not

Customisation Sync is a per-device publish-and-pick model: each device uploads
its own copy of every plugin/theme/snippet under its device name, and the user
picks, item by item, which device's version to apply. That is a reasonable
answer to "I want different plugins on my phone", but it costs ~3.5k lines
and a second storage format. Our answer to the same need is the per-device
exclusion list: a plugin you do not want on the phone is one line in the
phone's exclusions, and `community-plugins.json` is then also excluded there.
Everything else is a plain mirror.

### 7.3 Atomic plugin updates

A plugin update changes three files. Each is a separate op, but they arrive
in one `changes` page and are applied in sequence under the plugin-reload
debounce, so the reload sees a consistent set. There is no cross-file
transaction and we do not need one: a half-applied plugin directory is
repaired on the next loop and the reload is idempotent.

---

## 8. Reliability checklist (what must be true at all times)

- **Idempotency everywhere.** Blob PUT is content-addressed. Op POST carries
  `op_id`. Applying a remote op twice is a no-op (hash check). Retrying after
  any network error is always safe.
- **Blobs before ops**, enforced by the server.
- **Write-then-record, with intent.** Mark `inflight` → write file → update
  state. Any crash point is recoverable by the scanner.
- **Hash is the only equality.** mtime/size are hints to avoid hashing, never
  evidence of sameness or difference.
- **No local write without the per-path lock and a fresh disk check.**
- **Deletes are conservative:** verified absent before pushed; never applied
  over local edits; mass deletions need a click.
- **Nothing is ever destroyed on the server except dead blobs past the
  retention window.**
- **Degrade, don't halt.** Every optional integration (`raw` events, plugin
  reload, CSS reload, WebSocket) has a fallback (polling, notice, long-poll).
- **One scan rebuilds everything.** Delete `state.json` on any device and the
  next start reconciles correctly by hashing. There is no "rebuild database"
  or flag-file workflow because there is no database to rebuild.
- **A restored server is noticed, not trusted.** The feed names the op at
  the cursor; a mismatch triggers reconciliation (§6.8) instead of silence.
- **Proven, not argued.** `plugin/test/conflict-recovery.test.ts` runs one
  scenario per conflict shape and recovery path (31 of them, listed in
  `docs/CONFLICT-RECOVERY-MATRIX.md`); `plugin/test/convergence.test.ts`
  runs seeded random multi-device histories with restarts, crashes, state
  loss and server outages and checks convergence and that no last write is
  ever lost.

---

## 9. Performance targets and how we hit them

| Scenario | Target | Mechanism |
| --- | --- | --- |
| Cold start, 20k files, nothing changed | < 300 ms to live | Load one JSON, compare in-memory stats from `vault.getFiles()`, no I/O, no hashing. |
| Edit propagation (LAN) | ≈1 s | 1.5 s typing debounce dominates; WS hint + one `changes` call + one blob GET. |
| New device, 10k notes + 1 GB attachments | bandwidth-bound | Snapshot (one request) + 8-way parallel blob GETs, resume via `Range`. |
| Rename a 500 MB file | 0 bytes transferred | Content-addressed; `delete` + `put` reuse the blob. |
| Typing storm (100 saves/min on one note) | no server bloat | Each version is one small blob; GC removes superseded ones after retention. No chunk documents, no compaction. |
| Memory on mobile | < 50 MB over baseline | State file in memory (~3 MB), streaming blob I/O. |

Large-file delta sync (content-defined chunking so a 1-byte change in a 100 MB
file uploads 1 MB) is deliberately deferred. Notes are small and attachments
are rarely edited in place. If needed later: FastCDC inside a blob
(`blob = [chunk_id…]`), a purely client-side change; the server already stores
chunks as blobs.

---

## 10. Settings (all of them)

1. Invite link / server URL + status (connected, last sync, pending).
2. Device name.
3. Exclusion patterns (text area, pre-filled from 7.1).
4. Sync `.obsidian` (on by default) with per-plugin `data.json` checklist.
5. Recovery passphrase (optional, set once).
6. Pad blob sizes (off).
7. Compress text (off until measured).

Commands: Sync now, Show conflicts, Show history for current file, Restore
vault to a point in time, Generate invite link for another device, Devices
(roster with decrypted names; Remove device, which rotates keys), Rotate keys,
Re-key vault, Rebuild local state (delete `state.json` and rescan).

Key material (`K_id`, epoch keys, device private keys, device token) lives in
the plugin's `data.json`, which is in the default exclusion list and never
syncs.

---

## 11. Build plan

1. **Protocol + server** (Go): schema, API, CAS, GC, invites, roster,
   keybox, rotate, epoch-gated blob replacement, TLS, `obsync serve`,
   `obsync vault create`, `obsync invite`, `obsync restore --at`.
   Conformance test suite in Go hitting the HTTP API, including concurrent
   CAS and concurrent rotation races.
2. **Plugin core, desktop:** state, crypto (formats in §5.2, ECDH wrap,
   enrolment), transport, sync loop, applier, scanner, watcher for indexed
   files. Two vaults on one machine against a local server; property-style
   tests of the sync loop with a fake server; test vectors for every
   ciphertext format checked in so a second implementation can match them.
2b. **Rotation and recovery:** Remove device, background re-encryption job,
   `min_epoch` advancement, recovery passphrase enrolment. Test: remove a
   device, confirm it cannot decrypt new ops, confirm after re-encryption it
   cannot decrypt anything the server still serves.
3. **Dot-file sync** + post-write hooks + exclusions UI.
4. **Conflicts:** diff3 for text, JSON merge for `.obsidian/*.json`, sibling
   files.
5. **Mobile hardening:** iOS and Android, background/resume, large
   attachments.
6. **History/restore UI**, then optional compression and padding.

Each step ships something usable. Step 2 alone replaces LiveSync for a desktop
user.

---

## 12. Things we explicitly refuse to do

- Support CouchDB, PouchDB, or any existing LiveSync database. Migration is
  "disable LiveSync, install obsync, let it upload the vault." Like LiveSync,
  we require that no other sync service (Obsidian Sync, iCloud, Syncthing)
  writes to the same vault.
- Resolve conflicts by modification time. LiveSync's hidden-file path does
  this with a ±2 s window; clock skew between a phone and a laptop decides
  who wins. We compare bytes and keep both.
- Add a second transport before the first is boring.
- Add a setting to work around a bug instead of fixing the bug.
- Ask the user a question that the hash check can answer.
