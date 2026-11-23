# What a human security reviewer should look at

This is the brief for an external review of obsync. Three agent review
rounds have already run (findings and fixes are in the git history and
summarised in `DESIGN.md` §5.7 and §5.8). The third, on 2026-11-07, worked
from this document area by area with proof tests and found ten things the
first two missed, all fixed the same day and pinned by
`server/internal/api/review3_*_test.go` and `plugin/test/review3-*.test.ts`:
device names forgeable by a token holder (no device id in the AAD, no
authority on the route), the admin token able to plant a key-less device
that the next rotation would wrap keys to, a token holder able to overwrite
its own keybox rows, metadata not bound to its blob, the proxy-mode limiter
keyed on a client-written address, the recovery token accepted as a device
bearer, an unbounded snapshot and uncapped metadata, GC sweeping freshly
uploaded blobs, and two spellings of the config directory that bypassed
every `$CONFIG` rule. That is the reason this document still asks for a
person: each round found real things. It lists the claims that still rest on
the author's and the agents' judgement and would benefit from a person who
breaks things for a living. It is written so that the reviewer can start
cold. Budget: one to two days for a thorough pass.

**State on 2026-11-23, release 1.0.1.** Thirteen agent rounds ran in all,
the last on 2026-11-08 against 0.1.14 (`docs/HANDOFF.md` lists them). What
has landed since then has had tests but **no adversarial round at all**,
and is where a reviewer's time is best spent first:

- 0.2.0: the admin token removed; create links and the WebAuthn admin page,
  later hidden behind register links (area C, DESIGN §5.9).
- 0.2.1: the one-way "Reset this device to the server's copy" (area I).
- 0.2.2: vault keys sealed by the device keychain on phones and tablets
  (area E).
- 1.0.0: large files stored as content-defined chunks, a change to the op
  format and to the server's liveness rules (area H).
- 1.0.1: the conflict review dialog (area I).

The codebase is small. Everything security-relevant is in these files
(about 17,000 lines of source, tests not counted):

| Area | Files |
| --- | --- |
| Crypto, key hierarchy, formats | `plugin/src/core/crypto.ts`, `plugin/test/vectors.json`, `plugin/test/crypto.test.ts` |
| Local key protection on device | `plugin/src/core/keystore.ts`, `plugin/src/obsidian/protection.ts`, the protection code in `plugin/src/obsidian/main.ts` (`setProtection`, `unlock`, `unlockFromSecret`), `plugin/test/keystore.test.ts`, `plugin/test/keychain-secret.test.ts` |
| Large files as chunks | `plugin/src/core/chunks.ts`, `fetchContent` / `chunksOf` / `gatherLocalPlain` in `plugin/src/core/engine.ts`, server `contentPresent` / `insertOp` / `DeadBlobs` / `Restore` in `store.go`, `plugin/test/chunks.test.ts`, `server/internal/api/chunks_test.go` |
| Reset and conflict review | `resetToServer` / `discardLocal` in `engine.ts`, `ConflictModal` in `plugin/src/obsidian/modals.ts`, `conflictOrigin` in `paths.ts`, `plugin/test/reset-to-server.test.ts`, `plugin/test/conflict-review.test.ts` |
| Admin page and links | `server/internal/api/admin.go`, `adminpage/`, `server/internal/store/links.go`, `admin_test.go` |
| Deployment and backups | `server/Dockerfile`, `server/deploy/` (compose service, Caddy site, backup and restic off-site scripts) |
| Enrolment, rotation, recovery, revocation | `plugin/src/core/admin.ts`, server `rotate`/`recovery`/`invites` handlers |
| HTTP client, auth headers, WebSocket | `plugin/src/core/transport.ts` |
| Path validation and file I/O containment | `plugin/src/core/paths.ts`, `plugin/src/core/node-fs.ts`, `plugin/src/obsidian/obsidian-fs.ts`, `plugin/test/merge-paths.test.ts` |
| Sync engine (apply, conflicts, failure isolation) | `plugin/src/core/engine.ts`, `plugin/src/core/merge.ts` |
| Server API, auth middleware, limits, CORS | `server/internal/api/server.go`, `ratelimit.go`, `hub.go` |
| Server storage, token hashing, invariants | `server/internal/store/store.go` |
| Server security tests | `server/internal/api/security_test.go`, `api_test.go` |
| Design and threat model | `DESIGN.md` §4.4, §4.6, §5 (all), §6.5, §7.3 |

## Assumptions to accept or challenge first

1. **The server is honest but curious.** It may read everything it stores
   and watch traffic, but it does not tamper (DESIGN §4.6, §5.7 residual 3).
   The owner chose this. A reviewer should still note anything a *malicious*
   server could do cheaply, so the owner can decide whether the assumption
   is comfortable; the design claims the formats would allow a per-device
   op-log hash later.
2. **Vault write access is code execution on every device** that syncs the
   config folder, because `.obsidian/plugins/*/main.js` is reloaded and
   `community-plugins.json` enables plugins (§7.3). The roster is the trust
   boundary. Accepted on purpose; worth a second opinion on whether the
   notices and the roster view make that visible enough.
3. **TLS is the transport security.** Nothing in the protocol is designed to
   survive plaintext HTTP. The plugin asks for confirmation before using
   http to a non-localhost host.

## Claims to verify, by area

### A. Cryptographic design (`crypto.ts`, DESIGN §5.1 to §5.6)

- Two key roots: `K_id` (identity, never rotated) and `K_e` (content, per
  epoch). Identifiers (`blob_id`, `path_id`, device names) derive from
  `K_id`; confidentiality keys derive from `K_e`. Confirm nothing derived
  from `K_e` is used as a long-lived identifier, and nothing derived from
  `K_id` protects content.
- `blob_id = HMAC-SHA-256(K_blobid, plaintext)`. Deduplication oracle: a
  member learns whether an exact plaintext exists. Is that acceptable, and is
  it true that nobody without `K_id` can test a guess (the server stores only
  ids and ciphertext)? Compare the LiveSync passphrase-oracle bug in §1.6.
- AES-256-GCM everywhere, 12-byte random nonces, per-blob HKDF salt so the
  content key is unique per blob. Check nonce generation sites for any reuse
  path (retries, re-encryption at rotation, repair uploads with
  `X-Blob-Replace`).
- AAD bindings: blobs to `"blob" ‖ blob_id ‖ epoch`, metadata to
  `"meta" ‖ path_id ‖ epoch`, names to `"name"`, keybox rows and the
  recovery wrap to their own contexts. Is anything swappable by a server
  that moves a ciphertext to a different row, path, epoch, or vault? Names
  deliberately have no device id in the AAD; is that a problem?
- Invite: P-256 ECDH with an ephemeral key, HKDF info `obsync/wrap/v1`,
  wrapping `K_e ‖ K_id`. The invite link carries a one-time server token and
  a secret; check what a link leaks and what an expired or used link can
  still do. 1 h TTL, single use.
- Recovery passphrase: PBKDF2-SHA-256, 2,000,000 iterations (600,000 for passphrases set before 0.1.3; a join tries both and re-sets at the new count), 16-byte salt,
  64-byte output split into a wrap key and an auth token. The server returns
  only the salt without authentication, and the wrapped key only against the
  auth token, rate-limited. Confirm the split does not let the auth half
  leak anything about the wrap half, and judge whether PBKDF2 at this cost
  is adequate for the offline attack by someone holding the server's disk
  (the design says: pick a long passphrase; is that enough guidance?).
- Rotation (§5.4): a new `K_e`, rewrapped to every non-revoked device via
  the keybox, `auth_next` installs the new authority hash atomically with
  the epoch bump, and old-epoch blobs are re-encrypted later. Look for a
  window in which a just-revoked device can still write, read the new key,
  or keep a usable authority token. Look at what happens if rotation is
  interrupted halfway.
- Vectors: `plugin/test/vectors.json` pins the formats. Confirm the vectors
  actually cover each format and were not regenerated to match a bug.

### B. Vault authority token (DESIGN §5.8, server `authority` middleware)

- `A_e = "va_" ‖ b64url(HKDF-SHA-256(K_e, "", "obsync/auth/v1"))`, stored
  as SHA-256 on the server, compared in constant time. The claim: a device
  token alone is read-only; every write needs `X-Obsync-Vault-Auth`.
  Enumerate the routes in `server.go` and confirm every state-changing one
  is behind `authority` (there is no admin bypass of any device route). The test
  `TestTokenOnlyAttackerCannotDestroyOrEscalate` is the current proof; look
  for a route it misses.
- Claim rules: a device may `POST /auth` only when the vault has no hash,
  the caller is the sole live non-recovery device, `seq == 0` and no blobs
  exist. Only the operator's CLI on the host (`obsync vault auth`) sets it
  unconditionally; no HTTP route does. Try to find a sequence
  (join, leave, re-enrol, recovery identity) that reaches a vault with no
  hash and more than one party eligible.
- The token travels in a header on every write and sits in memory; it never
  goes in a URL. Confirm the server never logs it and the rate limiter
  cannot be used to confirm a guess cheaply.
- A revoked device's `A_e` dies with its epoch because rotation replaces the
  hash. Confirm revocation without rotation is clearly documented as not
  removing write access from a key holder (the design says: remove, then
  rotate).

### C. Server authentication and abuse resistance (`server.go`, `ratelimit.go`, `store.go`)

- Device tokens (`dv_`), invite tokens (`in_`), recovery tokens (`rc_`),
  create links (`cr_`) and register links (`rg_`): hashing at rest,
  constant-time comparison, token entropy, single use, and whether any
  token is accepted from a query string (the design says never; WebSocket
  auth uses the `Sec-WebSocket-Protocol` list; create and invite links ride
  in URL fragments; a register link is the one token in a path, judged by
  `GET /admin/r/{t}` which redirects at once and never spends it).
- Revocation cuts open long-polls and WebSockets (`TestRevocationCutsOpenStreams`).
  Verify the liveness re-check cannot be raced.
- Per-IP token bucket on failed auth (`--auth-rate`) and on recovery joins.
  With `--trust-proxy`, `X-Forwarded-For` is trusted; without it, it is
  ignored. Check the parsing for spoofing when multiple proxies are present
  and for IPv6 handling. Check that the unthrottled `GET /recovery` leaks
  nothing beyond the salt and a device id.
- Resource limits: `MaxBlobSize` through `http.MaxBytesReader`, list
  responses clamped to 5,000, at most 5,000 blob ids per request. Look for
  an unbounded path (history, ops since, WebSocket fan-out in `hub.go`,
  SQLite query without a limit) a single member could use to exhaust the
  server.
- CORS is `*` with an explicit header allow-list and no credentials on the
  device API. The one cookie that exists is the admin page's session,
  scoped to `/admin`, where no CORS header is sent at all. Confirm the
  `/admin` prefix check cannot be bypassed (case, encoding, a path that
  reaches a device route with CORS and a cookie).
- Admin page (`admin.go`, DESIGN §5.9): WebAuthn with
  `github.com/go-webauthn/webauthn`. Check the relying-party id and origin
  come only from `--public-url`, the challenge store is one-shot and
  bounded, the session cookie is HttpOnly/Secure/SameSite=Strict and the
  `Origin` check on every POST is sufficient CSRF protection, a stolen
  session cannot register a key (that takes a register link from the host),
  the clone-counter check refuses a replayed authenticator, and that a
  signed-in admin can create vaults and list them but reach no vault's
  content, devices or keys. The page hides from strangers: confirm that
  every `/admin` path without a door, known or session cookie is
  byte-for-byte the 404 of an unknown device path (status, body, headers,
  no Set-Cookie), including a bad register token, a wrong method on the
  door, and a forged cookie; that the door and known cookies (SameSite=Lax,
  HttpOnly, `/admin`) grant only the page shell and `state` without
  `vaults`; that the door's token is spent by a finished ceremony and not
  by the redirect; and that the known-browser table is bounded
  (`TestAdminHiddenFromStrangers`, `TestAdminBrowserCap`). `admin_test.go` drives the whole flow with a
  software authenticator; try to construct an attestation or assertion it
  accepts wrongly (format `none` with a mismatched rpIdHash, a `packed`
  statement with a bogus certificate chain, an assertion for another
  credential id).
- Create links (`cr_`): one-time, 1 h, minted only by the CLI on the host or
  a signed-in admin; redeeming one makes a *new* vault and nothing else.
  Confirm it is useless against every existing vault (`TestCreateLinkLifecycle`,
  `create-link.test.ts`).
- SQLite invariants (§4.4): per-path compare-and-swap, append-only op log,
  epochs monotonic. Check the transactions in `store.go` for a lost update
  under concurrent writers; the CAS race tests in `api_test.go` are the
  starting point.
- GC (§4.5): dead-blob deletion re-checks liveness inside a transaction.
  Look for a race where a blob referenced by an op posted during GC is
  deleted.

### D. Client-side path and file safety (`paths.ts`, `engine.ts`, `*-fs.ts`, DESIGN §6.5)

A vault member, or anyone holding `K_e`, writes ops that every other device
applies to disk. The validation is the only thing between a malicious op
and the local filesystem.

- `isSafeLogicalPath`: rejects empty, `.` and `..` segments, leading `/`,
  backslashes, control characters, the Windows-forbidden `: < > " | ? *`
  (sixth review: `::$DATA` named the file itself on NTFS and escaped its
  exclusion), trailing dot or space, Windows 8.3 short names, Windows
  reserved device names, components over 255 bytes, and `$CONFIG` anywhere
  but the first segment. Try to get past it with
  Unicode normalisation tricks, overlong encodings, case folding, combining
  marks, or a path that is safe on Linux and dangerous on Windows or macOS
  (case-insensitive and normalising filesystems).
- `fold()` (NFKC, both case directions, marks stripped) is applied where
  over-matching is safe: `aliasesConfigDir`, `compileExclusions`,
  `ConfigHooks.afterApply`. The sixth review found it applied to the first
  of these only (`/obsync/i` does not match `obſync`, APFS does). Whether a
  write may land is decided by probing the volume (`refuseAliasClash` /
  `refuseCaseClash`: the path resolves but no entry is spelled exactly so);
  the seventh review found a fold-table refusal there blocked names APFS
  keeps apart and case-only folder renames.
  Check for any comparison site still using `toLowerCase()` or a bare `i`
  flag. `plugin/test/fold-volume.test.ts` measures each CI volume: APFS
  folds ASCII case, U+017F, U+212A, U+00DF, NFD and U+FB01; NTFS (GitHub's
  Windows runner) folds ASCII case only; ext4 folds nothing. `fold()` agrees
  with every pair a volume folds, and over-folds the rest, which only
  over-excludes.
- `decryptBlob(id, blob, { maxPlain })`: the engine passes the authenticated
  `meta.size`; the deflate stream is cancelled one chunk past it (sixth
  review: a 64 KiB ciphertext inflated to 64 MiB on every device before any
  check, and the crash came before the cursor advanced). Look for any other
  allocation a single hostile op controls: parallel prefetch of a batch,
  `siblingFor`'s directory scans, metadata size.
- `pathId(meta.path) === op.path_id`: the decrypted path must match the id
  the op is keyed by, so a holder of `K_e` cannot write under a path the
  server would attribute to another id. Confirm this is checked before any
  write and that failure skips the op without wedging sync.
- NodeFS and ObsidianFS containment: every absolute path is checked to be
  inside the vault root after resolution. Look at symlink handling and
  at rename/delete paths, not only writes.
- Atomic plugin updates (§7.3): a plugin's files land fully before
  Obsidian reloads it. Check for a partial-write window and for what
  happens when `main.js` is undecryptable or fails validation.
- Failure isolation: one unapplyable op is skipped and reported, never
  retried forever, never allowed to stop other ops. Confirm a skipped op
  cannot be used to silently hide a later legitimate change to the same
  path.

### E. Local key protection (`keystore.ts`, `protection.ts`, DESIGN §5.5a)

- Four modes, chosen automatically at enrolment where a keychain exists:
  none (keys in `data.json` in the clear), PIN (PBKDF2 600k, AES-GCM sealed
  identity, offline-guessable, minimum 8 characters with a warning), OS
  keychain (method `safe`: Electron `safeStorage`, desktop only, the
  desktop default, with an optional Touch ID prompt on macOS), and device
  keychain (method `secret`, 0.2.2: phones and tablets, the mobile default
  on Obsidian 1.11.4 or newer; an older mobile Obsidian is offered a PIN
  once). Review the sealed format, the AAD, what else in `data.json` is
  sensitive when sealed (device token, vault id, server URL, roster names),
  and whether the documentation's security claims for each mode are
  accurate rather than reassuring.
- `safeStorageAvailable()` refuses Electron's `basic_text` backend on
  Linux. Confirm the detection cannot be fooled into storing the key under a
  non-keychain backend.
- **Device keychain (method `secret`).** A random 32-byte wrapping key is
  handed to Obsidian's `app.secretStorage` as hex under the id
  `obsync-<vault id>-<device id>` (truncated to Obsidian's 64-character id
  rule), and the identity is sealed in `data.json` under it, as method
  `safe` does with safeStorage. Things to check:
  - *What secretStorage is.* Obsidian documents only the desktop. The
    mobile claim in DESIGN §5.5a was read out of Obsidian 1.15.1's bundled
    code: a Capacitor SecureStorage plugin, on iOS one generic-password
    Keychain item (accessible when unlocked, iCloud Keychain sync never
    switched on), on Android a preference encrypted by the Android
    Keystore, holding every secret of every vault in one item. Confirm it
    independently, and on Android in particular, where nothing has been
    run. On desktop it is safeStorage plus localStorage, and the method is
    not offered there.
  - *Accessibility class.* "When unlocked", not "this device only": judge
    whether the item travelling in an encrypted device backup to a new
    phone is acceptable (it brings the wrapping key; `data.json` comes only
    if the vault folder is restored too).
  - *The fallback window.* `setSecret` returns before the native write and
    reports no failure. So `setProtection("secret")` keeps the previous
    form in `data.json` as `protection.fallback` until a later launch reads
    the key back (`unlockFromSecret`), then deletes it. Coming from "none",
    that is the identity **in the clear, beside the new seal, until the
    next successful launch**; coming from a PIN it is the PIN-sealed blob.
    On a phone that default-enrols, the keys are therefore unsealed on disk
    for one launch. Is that window acceptable, is it documented plainly
    enough, and can it be shortened (the native plugin is reachable as
    `Capacitor.Plugins.SecureStorage`, which could confirm the write)?
  - *Any plugin can read it.* `getSecret` and `listSecrets` are open to
    every plugin in every vault of that Obsidian install. The design
    accepts this (a plugin can read the notes too). Note it is wider than
    method `safe`, where another plugin would have to call safeStorage on
    the wrapped key itself, and wider than one vault: a plugin in another
    vault on the same device can read this vault's wrapping key.
  - *A lost entry.* With no fallback left and no entry (reinstall, a
    restore without the keychain, the user deleting it under Settings →
    Keychain), `unlock` must leave `sealed` untouched and stay locked.
    Confirm no path writes `sealed: null` or regenerates the key
    (`keychain-secret.test.ts`, fourth case; the real-Obsidian case in
    `obsidian-ui.test.ts`).
  - *The test seam.* `secretStorageAvailable` is true on mobile, or when
    `globalThis.__obsyncSecretOnDesktop === true` (the end-to-end suite
    sets it). Confirm that flag can do nothing but make the option
    selectable.
  - *Evidence so far.* One physical run: iPhone 18,1, iOS 27.0.1, Obsidian
    1.15.1, 2026-11-23. A vault was created on the phone, the settings
    showed Device keychain, Obsidian was force-quit and reopened, and the
    server recorded new writes from the device with nothing typed. Android
    and iPad are unverified.

### F. Protocol-level behaviours worth a look

- WebSocket live channel: token via subprotocol, hints only (no content),
  reconnect behaviour, and whether a server can use hints to make a client
  do unbounded work.
- Long-poll `changes?since=` with a `waited` liveness re-check: look for a
  way to hold a connection after revocation.
- Blob download with `Range`: confirm partial responses are authenticated
  as a whole (GCM over the full body) and a truncated download is never
  written to disk as complete.
- Metadata and name decryption clamps `mtime` and `size` to sane integers
  (Capacitor crashed LiveSync on floats). Check other decoded fields for
  trust assumptions (flags byte, epoch field, JSON shape).

### H. Large files as chunks (1.0; `chunks.ts`, `engine.ts`, `store.go`, DESIGN §6.9)

A file over 1 MiB is cut by a gear rolling hash into chunks of 256 KiB to
4 MiB. Each chunk is an ordinary blob named `HMAC(K_blobid, chunk)`. The op
keeps `blob_id` = the id of the whole file (no blob is stored under it) and
gains `chunks`, the ordered chunk ids, in the clear beside `meta_enc`.

- **The chunk list is not authenticated.** It is not in `meta_enc`; the
  server, or anyone who can alter a response, can reorder, truncate, pad
  or substitute it. The defence is the final check in `fetchContent`: each
  chunk decrypts under its own id, the pieces must add up to the
  authenticated `meta.size`, and `blobId(reassembled)` must equal the
  `blob_id` that the metadata binds. Confirm nothing reaches disk before
  that check, on every path that reads content (`writeRemote`, the merge in
  `resolveConflict`, `versionBytes` for history), and that a failure skips
  the op without wedging the cursor (`chunks.test.ts`, last case).
- **Chunks from the local file.** `fetchContent` takes chunks the file being
  replaced already holds from disk, re-chunked and re-hashed at that
  moment, and `gatherLocalPlain` takes whole contents the device holds
  under another path (a rename elsewhere), re-hashed before use. Both skip
  the download and the per-chunk AEAD check. Is the keyed hash plus the
  final whole-file check sufficient for locally sourced bytes?
- **Memory a single op controls.** `fetchContent` holds every distinct
  chunk it fetched and then allocates `meta.size`. `MAX_CHUNKS` is 4096 and
  a chunk decrypts to at most 4 MiB. `meta.size` is authenticated but, on
  this path, not capped: the 1 GiB `MAX_PLAIN` ceiling lives in
  `decryptBlob`, which a chunked file never passes through as a whole. A
  key holder who uploads many distinct chunks, or names a huge size, can
  make every device fetch, hold or try to allocate that much before the
  size check fails. Members
  are inside the trust boundary (assumption 2), but check that the failure
  is a skipped op and not a crash loop before the cursor moves, as the
  sixth review found for inflate.
- **What the list leaks.** The server learns which blobs form one version
  and in what order, on top of sizes and timing it already saw. Chunk
  boundaries depend on content, so chunk sizes are a fingerprint of the
  file. The gear table is `HKDF(K_id, "obsync/cdc/v1")`, so someone holding
  a candidate file but not the key cannot compute its boundaries. Judge
  that claim: sizes still leak something (a file's total, how much of it
  changed between versions, and which chunks two files share). `K_id` is
  never rotated, so a removed device keeps the table.
- **Deduplication oracle, extended.** `blobs/missing` already told a member
  whether an exact file exists (area A). It now answers per chunk. The
  server cannot test a guess without `K_id`; confirm.
- **Server liveness.** `op_chunks(vault_id, blob_id, seq)` is what keeps a
  chunk alive: `DeadBlobs` and `DeleteDeadBlob` now have four NOT EXISTS
  clauses (head by `blob_id`, recent op by `blob_id`, head through
  `op_chunks`, recent op through `op_chunks`). Look for a chunk that a live
  version needs and the sweep removes: an op posted during the sweep, a
  chunk shared by a dead and a live version, a restore that makes an old
  version the head again (`chunks_test.go`; `chunks.test.ts` rotation and
  restore case).
- **Blobs before ops.** `contentPresent` requires every chunk when `chunks`
  is present and ignores `blob_id` then. Confirm an op cannot name chunks
  from another vault, and that `validateOp` (64-hex ids, at most 4096,
  never on a deletion) is reached on every insert path including `Restore`.
- **Cost of a chunked op on the server.** One op can add 4096 `op_chunks`
  rows and 4096 lookups inside the write transaction, and a request carries
  up to 1000 ops. Judge whether a member can stall other writers.
- **Restore to a point in time** re-emits a chunked version with its
  stored list and skips it when any chunk is missing. The list it re-emits
  is the one a client supplied; nothing re-validates it.
- **Rotation.** Chunks are re-encrypted as blobs by the existing worklist.
  Confirm a rotation interrupted between chunks of one file leaves it
  readable (each chunk carries its own epoch).
- **Old clients.** A 0.x plugin asks for the blob under a chunked version's
  `blob_id`, gets a 404 and skips the file. Confirm it cannot then push its
  stale copy over the chunked head as if healing it (the "re-push over an
  unusable head" path in `applyBatch`).

### I. Reset and conflict review (0.2.1, 1.0.1; `engine.ts`, `modals.ts`)

- **Reset this device to the server's copy** makes the device's files match
  the server's heads, uploads nothing, and moves every local version it
  replaces, and every file that exists only locally, to
  `.trash/obsync-reset-<time>/<path>`. It is a local command only: the
  command palette and a settings button, both behind a confirmation
  dialog. Nothing in the protocol, the WebSocket hints or the
  `obsidian://obsync-join` handler can start it. Confirm that, and note
  that a third-party plugin able to run commands by id would still meet the
  dialog. Then consider it under assumption 1: a server that lies about its
  heads (or was rolled back) turns a reset into "park my newer files". They
  are parked, not deleted; is the dialog's text clear enough about trusting
  the server at that moment? Check the park path cannot leave the vault and
  that a failure midway degrades to the ordinary, conflict-preserving sync
  (`reset-to-server.test.ts`).
- **Unsyncable names** (`? * : < > " | \`, control characters) are now
  reported once per file. The notice text contains the local file name;
  confirm it is rendered as text.
- **Conflict review dialog.** `conflictFiles()` lists every synced path
  containing ` (conflict `, and `conflictOrigin` parses the name back to
  the file it claims to be a copy of. Both the name and the content can be
  written by any vault member, so a member can create a file that the
  dialog presents as "another version" of an arbitrary note, with a **Keep
  other version** button that overwrites that note. The overwritten
  content stays in history and the write is an ordinary edit, but judge
  whether the dialog should tell real conflict copies from look-alikes
  (the engine knows which ones it made). Confirm file names and diff lines
  are inserted as text, never as HTML.

### G. Supply chain and build

- Plugin runtime dependencies: `node-diff3` (merge) and `qrcode-generator`
  (the invite QR; MIT, no dependencies, bundled). Dev dependencies: esbuild,
  vitest, TypeScript, Playwright (tests only). Server: `coder/websocket`,
  `golang.org/x/crypto`, `modernc.org/sqlite`. Review the lockfiles for
  anything unexpected, and the esbuild config (`platform: browser`,
  `external: obsidian, electron`).
- The bundle test `plugin/test/bundle-mobile.test.ts` proves no Node
  module beyond a guarded `os.hostname()` is bundled. Confirm `require` is
  not reachable from synced content in any other way.
- Releases are built in CI from the tag with provenance
  (`.github/workflows/release.yml`). The Linux jobs, the release build
  among them, run on a third-party runner service (WarpBuild, label
  `warp-ubuntu-latest-x64-4x`); macOS and Windows run on GitHub's runners.
  The release artefacts users install through BRAT are therefore produced
  on infrastructure outside GitHub. Weigh that against the attestation.
- The server ships as a Docker image built on the host by
  `server/deploy/deploy.sh` (distroless, non-root). Backups go off-site
  with restic; the bucket credentials and the restic password sit in a
  root-only file on the host. A backup is ciphertext, token hashes and
  public keys, so check only that nothing else has crept into the data
  directory.

## What the reviewer should produce

1. For each lettered area: confirmed, confirmed with notes, or a finding.
2. Findings in the usual form: impact, preconditions, proof (a test in the
   repo's style is ideal; `security_test.go` and `plugin/test/e2e.test.ts`
   show how to drive both sides), and a suggested fix.
3. An explicit verdict on the three assumptions above, since the owner can
   change them but has chosen not to so far.
4. Anything in `DESIGN.md` §5.7 that is claimed and not true, or true and
   not claimed. The threat model table is meant to be the contract with
   users; it should survive the review unchanged or be corrected.

## How to run everything

```sh
cd server && go test ./...                         # includes security_test.go
cd plugin && npm ci && npm test                    # crypto vectors, path validation, Node e2e,
                                                   # chunks, reset, keychain-secret, conflict-review
# real-Obsidian suites need a desktop Obsidian binary and xvfb:
OBSIDIAN_BIN=$(which obsidian) XVFB_RUN=$(which xvfb-run) npx vitest run
```

The server can be run with `./obsync serve --data ./data --listen
127.0.0.1:8080`; every API route is listed in `DESIGN.md` §4.3 and
`server/README.md`, and `curl` with `Authorization: Bearer dv_…` plus
`X-Obsync-Vault-Auth: va_…` is enough to exercise all of it by hand.
