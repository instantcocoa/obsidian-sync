# What a human security reviewer should look at

This is the brief for an external review of obsync. Two agent reviews have
already run (findings and fixes are in the git history and summarised in
`DESIGN.md` §5.7 and §5.8); this document lists the claims that still rest on
the author's and the agents' judgement and would benefit from a person who
breaks things for a living. It is written so that the reviewer can start
cold. Budget: one to two days for a thorough pass.

The codebase is small. Everything security-relevant is in these files
(about 7,800 lines total including tests):

| Area | Files |
| --- | --- |
| Crypto, key hierarchy, formats | `plugin/src/core/crypto.ts`, `plugin/test/vectors.json`, `plugin/test/crypto.test.ts` |
| Local key protection on device | `plugin/src/core/keystore.ts`, `plugin/src/obsidian/protection.ts`, `plugin/test/keystore.test.ts` |
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
  still do. 24 h TTL, single use.
- Recovery passphrase: PBKDF2-SHA-256, 600,000 iterations, 16-byte salt,
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
  is behind `authority` or `authorityOrAdmin`. The test
  `TestTokenOnlyAttackerCannotDestroyOrEscalate` is the current proof; look
  for a route it misses.
- Claim rules: a device may `POST /auth` only when the vault has no hash,
  the caller is the sole live non-recovery device, `seq == 0` and no blobs
  exist. Admin bearer sets it unconditionally. Try to find a sequence
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

- Device tokens (`dv_`), invite tokens, recovery tokens (`rc_`) and the admin
  token: hashing at rest, constant-time comparison, token entropy, and
  whether any token is accepted from a query string (the design says never;
  WebSocket auth uses the `Sec-WebSocket-Protocol` list).
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
- CORS is `*` with an explicit header allow-list and no credentials. Confirm
  no cookie or ambient credential exists that would make this dangerous.
- Admin bearer: generated on first run and saved to `<data>/admin-token`.
  Review the file mode, whether it can be rotated, and what an admin can do
  to a vault's *content* (it should be nothing beyond deletion, since keys
  never reach the server).
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
  backslashes, control characters, trailing dot or space, Windows 8.3 short
  names, Windows reserved device names, components over 255 bytes, and
  `$CONFIG` anywhere but the first segment. Try to get past it with
  Unicode normalisation tricks, overlong encodings, case folding, combining
  marks, or a path that is safe on Linux and dangerous on Windows or macOS
  (case-insensitive and normalising filesystems).
- `aliasesConfigDir` with `fold()` blocks writes that alias the config
  directory under a different case or with combining marks. Check it against
  the real config directory name being user-settable.
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

- Three modes: none (keys in `data.json` in the clear), PIN (PBKDF2 600k,
  AES-GCM sealed identity, offline-guessable, minimum 6 digits with a
  warning), OS keychain (Electron `safeStorage`, desktop only, with an
  optional Touch ID prompt on macOS). Review the sealed format, the AAD,
  what else in `data.json` is sensitive when sealed (device token, vault id,
  server URL, roster names), and whether the documentation's security claims
  for each mode are accurate rather than reassuring.
- `safeStorageAvailable()` refuses Electron's `basic_text` backend on
  Linux. Confirm the detection cannot be fooled into storing the key under a
  non-keychain backend.
- Mobile has only none and PIN (no keychain bridge). Judge whether the
  default of none on mobile is defensible given OS disk encryption, and
  whether the settings text makes the trade clear.

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

### G. Supply chain and build

- Plugin runtime dependency: only `node-diff3`. Dev dependencies: esbuild,
  vitest, TypeScript, Playwright (tests only). Server: `coder/websocket`,
  `golang.org/x/crypto`, `modernc.org/sqlite`. Review the lockfiles for
  anything unexpected, and the esbuild config (`platform: browser`,
  `external: obsidian, electron`).
- The bundle test `plugin/test/bundle-mobile.test.ts` proves no Node
  module beyond a guarded `os.hostname()` is bundled. Confirm `require` is
  not reachable from synced content in any other way.

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
cd plugin && npm ci && npm test                    # crypto vectors, path validation, Node e2e
# real-Obsidian suites need a desktop Obsidian binary and xvfb:
OBSIDIAN_BIN=$(which obsidian) XVFB_RUN=$(which xvfb-run) npx vitest run
```

The server can be run with `./obsync serve --data ./data --listen
127.0.0.1:8080`; every API route is listed in `DESIGN.md` §4.3 and
`server/README.md`, and `curl` with `Authorization: Bearer dv_…` plus
`X-Obsync-Vault-Auth: va_…` is enough to exercise all of it by hand.
