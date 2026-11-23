# Handoff: picking up obsync

Paste everything below the line to an agent that is continuing this project.
Written 2026-10-25 at commit `4fc0152` on `main`. The status, the summary
of 0.2.0 to 1.0.1 and the to-do list were rewritten on 2026-11-23 for
release 1.0.1; the sections in between are the record of how it got there
and are left as written.

---

You are taking over obsync, a self-hosted, end-to-end encrypted sync for
Obsidian that replaces Self-hosted LiveSync with something vastly simpler.
Repo: `github.com/instantcocoa/obsidian-sync`, branch `main`, local checkout
at `/home/emaland/scratch/obsidian-sync` on the original machine. Go server
in `server/`, TypeScript Obsidian plugin in `plugin/`, design in `DESIGN.md`.

## The goal, verbatim

> keep going until you're done and everything is working end to end, secure,
> and easy to use

The owner added: the server is honest-but-curious, "ignore that malicious
server case". Push to `github.com/instantcocoa/obsidian-sync` is authorised
once everything is tested. Working rules from the owner's CLAUDE.md: always
use `rg`, never `grep`; never run `find /`. Commit messages end with the
attribution lines your session was given; use a heredoc, never a
double-quoted `-m` (backticks get command-substituted).

## Status in one paragraph (2026-11-23, release 1.0.5)

obsync is released as 1.0.5 and in real use. The production server runs in
Docker behind Caddy on the owner's host, with a nightly local snapshot and
an encrypted off-site copy (`server/deploy/`, `server/README.md`). The
owner's main vault is live on it (a Mac and an iPhone, with a recovery
passphrase set; the server's own count of three includes the recovery
identity) after a move from Self-hosted LiveSync; LiveSync's CouchDB is
stopped with its data kept for a trial period of some days
(`docs/MIGRATION-FROM-LIVESYNC.md` has the backups taken first and how to
go back). The gate is `go test ./...` in `server/` and 268 vitest tests in
`plugin/` without a desktop Obsidian, plus the real-Obsidian suites in CI
on Linux, macOS and Windows. Since the thirteen agent review rounds of
early November, 0.2.0 to 1.0.1 added an admin page, a hidden admin page,
device-keychain key protection on phones, a one-way reset, chunked storage
for large files and a conflict review dialog. **None of that newer work has
had an adversarial review round**, and no human specialist has reviewed
anything. `docs/SECURITY-REVIEW-GUIDE.md` says where to start.

## What is done (so you do not redo it)

Server (Go 1.26, SQLite via modernc, coder/websocket):
- Append-only op log, per-path compare-and-swap, keyed content-addressed
  blobs, epochs and rotation, invites, recovery identity, GC and restore.
- Every write requires the vault authority token (`X-Obsync-Vault-Auth`,
  DESIGN §5.8). A device token alone is read-only. Claim rules: a device may
  claim only as the sole device on an empty vault; the operator installs it
  on the host with `obsync vault auth` (a CLI command; there has been no
  admin token and no admin route on the device API since 0.2.0). Tested in `security_test.go`
  (`TestTokenOnlyAttackerCannotDestroyOrEscalate`, `TestAuthorityClaimRules`).
- Tokens hashed at rest, constant-time compare, no tokens in query strings,
  WebSocket auth via the `Sec-WebSocket-Protocol` list, revocation cuts open
  long-polls and WebSockets, per-IP rate limiting (`--auth-rate`,
  `--trust-proxy`), list limits clamped to 5,000, `MaxBlobSize`, CORS `*`
  with an explicit header allow-list, `GET /` landing text.

Plugin (TypeScript, esbuild, WebCrypto only):
- Key hierarchy and formats per DESIGN §5.1 to §5.6, pinned by
  `plugin/test/vectors.json`. Device names encrypted under a `K_id`-derived
  key so they survive rotation.
- Path validation (`plugin/src/core/paths.ts`): `isSafeLogicalPath`,
  `isSafeDevicePath`, `aliasesConfigDir` with case and combining-mark
  folding, `pathId(meta.path) === op.path_id` checked before any write,
  containment checks in both filesystem adapters.
- Failure isolation: one unapplyable op is skipped and reported, never wedges
  sync; repair is the command "Re-upload current file to the server".
- Revoked device shows a pinned removed message and stops syncing.
- Config adoption rule (DESIGN §6.6): a config file this device never synced
  is adopted, not conflicted. Root cause reproduced deterministically in
  `plugin/test/obsidian-config.test.ts`.
- Onboarding UX after the walkthrough: readable network and 401 errors,
  confirmations, copyable vault id, device rename with hostname default,
  "Write protection (vault authority)" row, notices on join/create/leave/set
  recovery, PIN minimum 6 (8 since the twelfth review),
  http-to-non-localhost confirmation, docs that match the UI.
- `plugin/test/bundle-mobile.test.ts`: static proof that the production
  bundle needs nothing a Capacitor WebView lacks. When this was written it
  was the only mobile evidence; the Android and iOS device runs below came
  after.
- Conflict and recovery proof: `plugin/test/conflict-recovery.test.ts` (31
  scenarios, one per row of `docs/CONFLICT-RECOVERY-MATRIX.md`) and
  `plugin/test/convergence.test.ts` (seeded random three-device histories
  with restarts, crashes, state loss and server outages; checks convergence
  and that no last write is lost). Two gaps they found are fixed: conflict
  siblings in the same minute now get an ordinal instead of overwriting, and
  a server restored from backup is detected by op identity
  (`cursor_op_id`/`expect`) and reconciled (DESIGN §6.8). The Node and
  Obsidian filesystem adapters map NFD on-disk names to NFC so a Mac-copied
  vault does not grow NFC twins.

## How to run the gate

```sh
cd server && go test ./...
cd plugin && npm ci && npm run build && npx tsc --noEmit
OBSIDIAN_BIN=/nix/store/1qkzznz9xv4r7ish7avv3kbnlfy7p1mp-obsidian-1.12.7/bin/obsidian \
XVFB_RUN=/nix/store/g19nw2m370sincpr6i62j4g312yf4jxz-xvfb-run-1+g87f6705/bin/xvfb-run \
npx vitest run
```

On another machine, `OBSIDIAN_BIN=$(which obsidian) XVFB_RUN=$(which
xvfb-run)`; on NixOS, `NIXPKGS_ALLOW_UNFREE=1 nix-shell -p obsidian xvfb-run`.
Without `OBSIDIAN_BIN` the three real-Obsidian suites skip and the rest still
runs. Test files run sequentially on purpose (`fileParallelism: false`);
three Electron pairs starve each other. Run the whole gate before any push.

Quirks that cost time before: Obsidian notices expire after 5 s, poll with
the harness `waitForNotice`; updating a Setting's description after
`display()` wedged the headless renderer once, so settings rows render
statically; Obsidian auto-update is off in test vaults via `app.json`; the
Node e2e harness wraps `putBlob` and must pass options through; the recovery
`GET /recovery` is unthrottled by design because throttling both it and the
join livelocked the client; if review agents work in the tree, never
`git add -A` (their probe files were committed once) and give vitest an
explicit file list.

## Platform runs (2026-10-27)

All three desktop platforms and Android have been exercised with real
Obsidian; everything found is fixed and merged:

- Windows (EC2 Windows Server 2022, Obsidian 1.14.5): gate 107/107,
  `plugin/test/obsidian-windows.test.ts`, four plugin bugs fixed (case
  stat, CRLF merge, locked-file retry, reload race).
- macOS (EC2 Intel Mac, macOS 15.8, Obsidian 1.14.5, and Apple silicon on
  the macos-14 CI runner): gate 103/103,
  `plugin/test/obsidian-macos.test.ts`, fixes for case-only renames and
  case twins, Touch ID detection, unreadable state file; three harness
  fixes without which Obsidian cannot be driven on macOS.
- Android (emulator API 34, Obsidian 1.14.4 APK, real desktop peer):
  11/12 as shipped, plugin sync fixed, reload race fixed, write size
  verified; plain http works from the WebView.
- Physical Android (Google Pixel 7, Android 14, AWS Device Farm, Appium):
  install, enable, join, notes both ways, non-ASCII name, empty file, 8 MB
  attachment, backgrounding and force-stop reconnects, two runs on two
  units, 5.4 device-minutes, no code change. Report under
  `plugin/.cache/agent-devicefarm/`.
- GitHub Actions (`.github/workflows/platforms.yml`) runs the full gate on
  ubuntu, macos-14 and windows on every push, real Obsidian included. All
  four jobs are green from commit `7cb5086` on (the first runs needed the
  macOS harness fixes and two timing-tolerant tests).
- AWS is clean: the Mac dedicated host `h-05d8e91904b1d7095` (us-east-2b)
  was released at 2026-10-28 15:37 UTC after its 24-hour minimum;
  `aws ec2 describe-hosts --region us-east-2` shows it in state `released`
  with no instances, and no other hosts exist.
- Reports with verbatim evidence: `plugin/.cache/agent-{win,mac,android}/REPORT.md`
  on the original machine (gitignored).

## 0.2.0 to 1.0.1 (2026-11-16 to 2026-11-23)

What changed after the review rounds recorded further down, newest last.
DESIGN.md has the reasoning for each; the READMEs describe the result.

- **0.2.0, no admin token.** A vault is made by its first device redeeming
  a one-time create link (`obsync vault create` on the host, or the `/admin`
  page after a WebAuthn sign-in with a security key). Every admin bearer
  route is gone. Then the admin page was hidden: every `/admin` path is the
  plain 404 of an unknown path until the browser has followed a register
  link minted on the host (DESIGN §5.9, `admin_test.go`).
- **Deployment.** `server/Dockerfile` and `server/deploy/`: a compose
  service behind a shared Caddy, `deploy.sh`, a nightly snapshot timer
  (SQLite online backup plus hard-linked blobs, fourteen kept) and an
  off-site step that pushes each snapshot with restic to an S3-compatible
  bucket when `/etc/obsync/offsite.env` exists. A restore from the bucket
  was drilled once and matched the local snapshot byte for byte.
- **DESIGN §4.5 corrected.** Restore to a point in time is a plugin command
  only, by design: the route needs the vault authority token, which the
  server never holds. There is no server CLI for it and there should not
  be one.
- **0.2.1.** "Reset this device to the server's copy": the one-way
  recovery. Local differences are moved to `.trash/obsync-reset-<time>/`,
  nothing is uploaded (`engine.resetToServer`, `reset-to-server.test.ts`).
  File names that can never sync (`? * : < > " | \`) are reported once per
  file; they used to be skipped in silence. The device-test harness
  (`RemoteServer` in `plugin/test/ios-harness.ts`) gained a compose mode
  and refuses the production service name.
- **0.2.2.** Key protection method `secret`: on phones and tablets the
  wrapping key lives in Obsidian's `app.secretStorage` (the iOS Keychain,
  the Android Keystore), default on mobile from Obsidian 1.11.4, PIN still
  available. The previous form of the keys is kept until a later launch
  reads the key back (DESIGN §5.5a, `keychain-secret.test.ts`, a
  real-Obsidian case in `obsidian-ui.test.ts`). Verified by hand on an
  iPhone 18,1, iOS 27.0.1, Obsidian 1.15.1 on 2026-11-23: vault created,
  app force-quit and reopened, a note written with nothing typed.
- **Engine, between 0.2.2 and 1.0.** A rename or copy made on another
  device costs the receiver no download (`rename-no-download.test.ts`);
  blobs up to 256 KiB upload three times as wide as large ones.
- **1.0.0, chunks.** A file over 1 MiB is cut by content into chunks of
  256 KiB to 4 MiB, each an ordinary blob; the op carries the ordered
  `chunks` list and keeps `blob_id` as the id of the whole content; the
  server's table `op_chunks` makes blobs-before-ops, the sweep and
  restore-to-time honour it; a reader verifies the reassembled content
  against the authenticated size and `blob_id`; the gear table is keyed
  (DESIGN §6.9, `chunks.test.ts`, server `chunks_test.go`). Files of 1 MiB
  or less are unchanged and old vaults carry on, but every device of a
  vault must run 1.0 or newer.
- **1.0.1.** "Show conflicts" is a review dialog: per conflict copy the
  file it belongs to, the device and time, the differing lines, and Keep
  current / Keep other version / Open both (`ConflictModal`,
  `conflict-review.test.ts`). Phones, which have no status bar, get a
  ribbon icon, a "Show sync status" command and a notice when sync goes
  offline or stops.
- **CI.** `.github/workflows/platforms.yml` and `release.yml`: the Linux
  jobs run on WarpBuild (`runs-on: warp-ubuntu-latest-x64-4x`), macOS and
  Windows on GitHub's runners. Releases are built in CI from the tag.
- **A comparison with Self-hosted LiveSync** was run by a separate agent
  (measured for obsync, derived from source and issues for LiveSync). It
  judged obsync ahead on correctness and performance, and listed what the
  items above then fixed: no conflict review, re-download on rename, whole
  files re-sent for an edit.
- **1.0.2.** A chunked version's claimed size is checked against what its
  chunks can hold before anything is allocated (found while bringing the
  docs up to date); README "Everyday use" explains status and conflicts.
- **1.0.3, fourteenth review fixed** (`plugin/test/review14.test.ts`,
  `keychain-secret.test.ts`, server `chunks_test.go`,
  `trust_internal_test.go`; reviewer report graded server 4.0, plugin 3.5).
  Chunked versions bounded by `MAX_PLAIN` and by list length against size,
  fetched in order with a running total (F4, F1, F2); an op that stops the
  app twice is skipped (crash loop); feed, snapshot and history pages capped
  at 32,768 chunk ids (F3); keychain sealing confirmed by a direct native
  read or a new app context, never by a plugin reload, and no clear copy on
  disk when the read works (known item a, F5); merges of chunked text read
  the base from history, and merging no longer overflows the stack on large
  notes (node-diff3's `push(...)`, F6); the conflict dialog names the writer
  from the sync record and will not replace an unsynced file (known item b);
  `--trust-proxy` takes a host name and the deploy kit trusts `caddy` only
  (F7); restoring a backup un-removes devices, now documented (F8).
- **1.0.4, fifteenth review's smaller fixes** (`plugin/test/review15.test.ts`;
  report graded server 4.0, plugin 3.5). The crash guard keeps its skip mark
  on the file entry instead of a 50-entry list (N1), covers merges and push
  conflicts (N2) and the write to disk (N3), never arms for an already
  skipped version (found by the new test), and is cleared by a server restore
  (N6). History is paged (`before`, `more`) and the client follows the pages
  (N4). Another device's edit of a conflict copy clears "own" (N5).
  `--trust-proxy` refuses to start on a name that does not resolve and keeps
  the last good addresses (N7). The keychain-confirming restart waits for 30
  s without an edit (N8). Still open: streaming chunked writes to disk so a
  phone never holds a large file in memory (the root of N1 to N3).
- **1.0.5, sixteenth review fixed** (`plugin/test/review16.test.ts`, server
  `chunks_test.go`; report graded server 4.0, plugin 3.0). The crash guard
  covers any version over 1 MiB, single blobs that inflate included, and
  large single blobs are fetched inside it (R1). A crash on a version of
  64 MiB or more sets a per-device size ceiling, so many oversized versions
  or re-posts cost two crashes in all (R4); a server answering "rewound"
  clears skip marks but not the ceiling (R5). Edits to a skipped path go up
  as a conflict copy with a notice (R2). History pages leave chunk lists out
  and a new route returns one op whole, so junk cannot crowd out real
  versions (R3). The keychain restart also waits while an editor has focus.
  Docs corrected (R6). Root cause still open: streaming chunked writes.

## What needs to be done (2026-11-23)

1. **Human security review.** Still open, and now also the first hostile
   look at everything since 0.2.0. Hand `docs/SECURITY-REVIEW-GUIDE.md` to
   a specialist; areas E, H and I are the unreviewed ones. When findings
   come back, fix them in the style of the existing rounds: a failing test
   first (`security_test.go` for the server, a `plugin/test/` file for the
   plugin), then the fix, then a DESIGN §5.7/§5.8 update if the threat
   model changes. An agent round over 0.2.0 to 1.0.1 in the style of the
   thirteen below would be cheap and has not been run.
2. **The trial.** The owner is running the real vault on obsync for some
   days before retiring LiveSync. Do not delete the CouchDB data, the
   pre-migration backups or the restic snapshot tagged
   `pre-obsync-migration` until the owner says the trial is over. The
   owner's second vault is not connected yet.
3. **Server-side commit batching.** A first upload is bounded by the
   server: every blob PUT is its own SQLite transaction with a full sync
   (about 110 files a second on loopback, about 24 a second measured over
   the internet). The client now uploads small blobs wider; grouping the
   blob-row commits on the server is the real fix. The `putBlob` handler's
   ordering (file first, row after, previous bytes kept until the row
   commits) is deliberate crash-safety from the review rounds: change it
   only with tests for each interleaving.
4. **A separate test instance for the device suite.** `ios-devices.test.ts`
   stops the server and replaces its data directory. The harness has a
   compose mode for that (`IOS_SERVER_MODE=compose`, service `obsync-test`
   by default) but no such service is deployed. It needs its own compose
   service, data directory and hostname; never point the suite at the
   production service.
5. **On-device verification that is still missing.** The device keychain
   method on Android and on an iPad; chunked files on any phone; the
   conflict review dialog and the ribbon status icon as rendered UI (only
   their logic is tested).
6. **Known limits to keep honest in the docs.** Files are read whole into
   memory on every platform; a text file over 1 MiB merges only when its
   base version is one blob; the first launch after a phone switches from
   no protection to the device keychain still has the keys in the clear in
   `data.json` (the fallback copy), until that launch has confirmed the
   keychain entry.

## The review rounds and device runs of 2026-11-07 and 2026-11-08

Kept as the record. Everything in this list is done.


1. **iOS on a device: done 2026-11-07.** A physical iPhone 13 Pro (iOS 26)
   and iPad Pro (iPadOS 17) on the owner's Mac, driven over USB
   (`plugin/test/ios-devices.test.ts`, `docs/IOS-DEVICE-TESTING.md`),
   passed twenty scenarios against the server on the owner's EC2 box
   `util.frob.io` with a Let's Encrypt certificate; real Obsidian on Linux
   (`dev.frob.io`, `plugin/test/linux-joins.test.ts`) then joined the same
   vault and its note reached both devices. The iOS section of
   `docs/CONFLICT-RECOVERY-MATRIX.md` lists the outcomes. A third
   adversarial review round (two agents, areas A to G of the guide) found
   nine weaknesses, all fixed with regression tests
   (`server/internal/api/review3_test.go`, `plugin/test/review3-*.test.ts`)
   and recorded in DESIGN §5.7.
1b. **Fourth review (hardening, 2026-11-07): done, 3/5 → the fixes for a 4.**
   An independent hardening pass (`plugin/.cache/agent-sec-hardening/REPORT.md`
   on the Mac) graded the core hardened and the edges soft. Everything it
   asked for is in: database files private and umask 077, IPv6 limiter on
   /64 with a capped map, rotation ends unused invites and a vault holds at
   most 20, epoch regression pauses sync until "Accept server restore",
   plain-http consent on the invite and QR joins, keys sealed by default
   (keychain on desktop, PIN offered on phones) with a mirror-tool warning,
   a roster hash in the feed with a notice on every new device and
   duplicate names flagged, a security-event log, AEAD-only TLS with HSTS
   and request timeouts, recovery passphrase at four words or 20 characters
   under 2 000 000 iterations, one-hour invites, `server/obsync.service`,
   CI actions pinned by commit and releases built in CI from the tag with
   provenance (`.github/workflows/release.yml`). Regression tests:
   `review4_hardening_test.go`, `review4-hardening.test.ts`. util runs the
   server as that unit (data in `/var/lib/private/obsync`, admin token
   regenerated there). CI is green on all five jobs at `c069b18`. Not yet
   done: a device re-run of the 0.1.3 plugin (the iPhone and iPad were lent
   to another session when it was cut).
1c. **Fifth review (2026-11-07): the fourth round's own changes, 3/5 → fixed.**
   One high (the recovery KDF change would have rejected every passphrase
   set before 0.1.3; a join now tries both counts and re-sets at the new
   one), three medium (restore acceptance never expired; a lost state file
   hid newcomers; blob transfers inherited the 15-minute deadline) and four
   low (admin token printed to the journal, no timeouts on :80, sealing
   offered only at enrolment, a paused device re-downloading the snapshot).
   All fixed; `review5_test.go`, `review5.test.ts`. util's admin token was
   rotated and its journal purged afterwards.
1d. **Sixth review (2026-11-07): fresh eyes over the whole 0.1.4 system,
   3.5/5 → fixed.** Protocol and plugin half: the review-3 folding fix had
   reached one of three comparison sites (exclusions and the plugin-reload
   hook matched with a bare `i` flag, so `plugins/obſync/main.js` landed in
   the real obsync folder on APFS); `decryptBlob` inflated without bound
   (a 64 KiB ciphertext of zeros became 64 MiB on every device, before any
   check); honest devices with 0.1.0 name rows were revoked as unproven by
   the next rotation; `meta_enc` leaked path lengths; the invite link's
   server field accepted userinfo and any scheme; `:` passed path
   validation (NTFS streams); re-encryption overwrote the metadata's blob
   binding. All fixed; `plugin/test/review6-*.test.ts` (17 tests), crypto
   vectors regenerated for the padded metadata. Server half (graded 4/5):
   `--trust-proxy` read only the first `X-Forwarded-For` line, so a proxy
   that adds its own line let the client pick its limiter bucket and forge
   the logged address; enrolment stored uncapped `name_enc` and unchecked
   `pub_kex`; a write whose device was revoked while its body was still
   being read was committed afterwards (every write transaction now re-checks
   the device and the authority token: `store.Actor`); GC deleted the blob
   file outside the per-blob lock and could orphan a re-upload (locked now,
   and an orphaned index row self-heals on GET or missing-check); `POST
   /auth` answered 409 as an unthrottled equality oracle (401 via the
   failed-auth limiter now; the plugin already tolerated both); rotation
   stored keybox rows for non-devices; the live socket's hint write had no
   deadline; `synchronous=NORMAL` and no directory fsync; stale upload files
   never swept; doc drift (TTL 1 h, no delete route, `obsync.db`);
   `platforms.yml` had no `permissions:` block. All fixed;
   `server/internal/api/review6_test.go`. Released as 0.1.5.
1e. **Seventh review (2026-11-07): the sixth round's own fixes, read as
   hurried changes with edges. Both sides 3.5/5 → fixed, released as
   0.1.6.** Plugin (7 proofs, `review7-*.test.ts`): the new inconsistent-
   head refusal in `settle()` froze a path for every honest writer (now
   rebased on as a tombstone); the fold-table clash refusal blocked
   `café.md`/`cafe.md` and case-only folder renames (now a volume probe,
   plus respelling of an emptied parent folder); `reencrypt()` had no
   failure isolation (one bad member blob wedged every rotation; now a
   marked placeholder, and "Rotate keys" resumes an unfinished
   re-encryption); `applyBatch` prefetched a whole batch (now a window of
   `parallel`, and ciphertext larger than `meta.size` admits is refused
   before decryption); `ensureOwnName` could undo a rename (renames now
   wait for it). Server (5 proofs, `review7_test.go`): `POST /invites` was
   the one write without the in-transaction re-check; the in-transaction
   401 said "forbidden" so an honest device whose upload crossed a
   rotation read it as removal (the body now says why); the blob index was
   committed before the file (a crash during re-encryption would have
   pruned the only key that read the blob; file first now, orphan files
   swept); `pub_kex` was length-checked only (curve-checked now, and the
   plugin treats an unimportable key as unproven); `--trust-proxy` was a
   boolean (CIDRs now). `fold-volume.test.ts` measures each CI volume's
   folding. govulncheck still needs a run from a host with egress.
1f. **Eighth review (2026-11-07 night): the seventh round's fixes. Plugin
   3.5/5, server 4/5 → fixed, released as 0.1.7.** Plugin (9 proofs,
   `review8-*.test.ts`): the inconsistent-head rebase was a no-op for a
   local delete (now rebased as if the bad head were ours, so the delete
   lands); re-encryption still rethrew non-CryptoError failures and "no key
   for epoch" (now only transport errors abort; keys are refreshed once,
   then a placeholder); dropping the parent-level clash check let a
   case-twin folder from Linux overwrite a Mac file (every segment is
   probed again, after the empty-folder respelling); a blob shared by many
   ops was fetched once per op (refcounted); the rename guard was keyed by
   Session (per device, all in-flight rewrites); re-encryption dropped
   compression and padding (kept). Server (1 proof + 7 confirmations,
   `review8_test.go`): a row write failing after the file rename left new
   bytes under the old row (the previous file is kept aside and restored);
   plus the epoch floor the plugin review asked for (blob header and
   meta_epoch below min_epoch are refused), clearer pre-check 401 bodies,
   orphan files deleted by path, README on `--trust-proxy 0.0.0.0/0`.
1g. **Ninth review (2026-11-07 night): the eighth round's fixes. Plugin
   3.5/5, server 3.5/5 → fixed, released as 0.1.8.** Plugin (5 proofs,
   `review9-*.test.ts`): HIGH, the round-8 "placeholder on any
   non-transport error" rule would have let a device without
   DecompressionStream (older iOS WebKit) replace every compressed blob with
   a placeholder during a rotation; placeholders are now allowed only for a
   `CryptoError` of kind "defect" (and SyntaxError for metadata), every
   environment failure aborts. The delete rebase missed a bad tombstone
   head; a twin folder holding only .DS_Store counted as non-empty so a
   case-only folder rename stranded the Mac (OS junk now counts as empty,
   and a parent-alias refusal is retried like a busy file); the prefetch
   refcount decremented for uncounted ops. Server (3 proofs,
   `review9_test.go`): the swap left the blob's name empty between two
   renames (hard link now, atomic rename over); the aside copy inherited
   the old mtime so GC could sweep it mid-request (timestamped now); the
   blob epoch floor is re-checked inside the row transaction. Also: merge
   property tests (`merge-fuzz.test.ts`), Electron output and exit status
   kept in the CI artifact (three macOS runner flakes in a row were
   undiagnosable without it), govulncheck in CI.
1h. **Reload bug found by the captured renderer log (2026-11-08): 0.1.9 and
   0.1.10.** The real-Obsidian harness now writes Electron's stdout, stderr,
   renderer console and exit status to `plugin/.cache/obsidian-e2e/logs/*.log`,
   uploaded in the `obsidian-e2e-<os>` artifact (`gh run download <run> -n
   obsidian-e2e-macos-15`). The first captured log turned three "macOS
   runner flakes" into a bug: on plugin reload (what a BRAT update does)
   Obsidian still held the previous instance's `obsidian://obsync-join`
   handler and threw "already registered" out of `onload`, so the plugin
   never loaded until a restart. 0.1.9 retries the registration, forces the
   stale handler out where the app allows, and never fails the load. 0.1.9
   also over-matched the ninth round's "retry a parent-folder refusal" rule
   onto file case twins (an op loop on macOS and Windows); 0.1.10 gives the
   two refusals distinct messages and retries only the folder one. The one
   genuinely flaky real-Obsidian test is `obsidian-config`'s wait for
   Obsidian's own `app.json` rewrite.
1i. **Tenth review (2026-11-08): the ninth round's fixes plus 0.1.9 and
   0.1.10. Plugin 3.5/5 → fixed, released as 0.1.11.** Six proofs
   (`review10-*.test.ts`): two member-authored byte shapes still threw
   non-CryptoErrors out of decryption (a padded flag without a length, and
   metadata that is the JSON literal null) and so aborted every rotation
   instead of becoming placeholders (shape guards, both now defects); a
   WebView whose DecompressionStream exists but lacks deflate-raw, and an
   allocation RangeError, were wrapped as defects (the constructor is
   outside the try, RangeError is environment); a case-only rename of a
   folder with a subfolder still stranded the Mac (emptiness is now
   recursive, junk and empty folders only); the parent-folder retry rewound
   the cursor every cycle, never gave up, and said "in use by another
   program" (deferred ops are now retried in place without touching the
   cursor, dropped after 48 cycles, and the notice names the folder); the
   join-handler retry timer outlived a disabled instance (cleared at
   unload, and a handler left behind does nothing); the forced unregister
   looked on `app` where Obsidian keeps it on `app.workspace` (both tried,
   and only after a second of retries, since the old instance's own cleanup
   would wipe an early takeover). Server 4/5 (`review10_test.go`): the
   aside hard link carried the old mtime until the touch that followed it,
   and a concurrent sweep took it in most trials (the current inode is
   touched before the link now); the no-hard-links fallback compared against
   errno values Windows never produces (any link failure but "no such file"
   now falls back to the rename pair).
1j. **Eleventh review (2026-11-08): the tenth round's fixes. Plugin 3.5/5,
   server 4/5 → fixed, released as 0.1.12.** The first partial convergence:
   the crypto shape guards, the join-handler lifecycle and the folder
   emptiness check came back clean; the four plugin proofs
   (`review11-deferred.test.ts`) were all in the new deferral mechanism:
   every retry downloaded and flushed state before the folder check (a
   `VaultFS.aliasRefusal` probe now runs first); a key rotation while an op
   was parked made its stored row undecryptable and it was dropped silently
   (the entry now holds only path id, seq and age, refetches the head from
   history and runs it through the same `decodeOp` checks as a pulled op;
   every drop is reported); the budget counted sync cycles (now a day); the
   in-flight record was deleted on any error (now only on the alias
   refusal). Server (`review11_test.go`, one LOW): the pre-link touch needed
   file ownership and failed every replacing upload of a blob the service
   could not utimes; the touch is gone and `SweepStale` ages stage and aside
   files by the base-36 UnixNano nonce in their names (mtime for `.tmp-`
   and for implausible nonces). The reviewer's full crash-state enumeration
   of putBlob passed, and it recommends not re-reading `Swap` again.
1k. **Device run 11 (2026-11-08 02:17-02:25 UTC): the 0.1.12 build on the
   iPhone 13 Pro and the iPad Pro, against util's systemd server, 20 of 20.**
   The first hardware run since 0.1.2: it covers everything added in rounds
   four to eleven (sealed keys, roster alerts, restore acceptance, the
   recovery fallback, the fold-aware exclusions, bounded decompression, the
   swap-and-restore uploads, the epoch floor, the deferral mechanism). The
   restore-from-backup scenario stopped and rolled back the real util
   server; every device recovered. 25 files byte-identical across the Mac
   engine and both devices at the end. `RemoteServer` in
   `plugin/test/ios-harness.ts` now drives the systemd unit (`sudo systemctl
   stop|start obsync`, data under /var/lib/private/obsync, backups beside it).
   Screenshots: `plugin/.cache/ios/` and util's catalog (`~/obsync/shots`,
   `ssh -L 8088:localhost:8088 util`). Real Obsidian on Linux (dev.frob.io,
   0.1.12, `test/linux-joins.test.ts`) then joined the same vault with the
   invite the run left (3 of 3), and its note `notes/from-linux.md` was read
   back from both devices over USB: four platforms in one vault on the
   current build. Device file paths for `test/ios-afc.py` are
   `/Documents/<vault>/…`.
1l. **Twelfth review (2026-11-08): round-11 fixes plus the first whole-system
   read since round 6. Delta: plugin 3/5, server one proof; whole system
   4/5. Fixed, released as 0.1.13.** Delta plugin (`review12-*.test.ts`): a
   HIGH older than every round, a row whose metadata header names an epoch
   nobody has threw out of the pull after the key refresh and stopped every
   device at that row (decodeOp never throws now, and the server refuses a
   header that disagrees with meta_epoch); history was oldest-first and cut
   at 5000, so the deferred retry could take version 5000 as the head
   (newest first now); a dropped head went unreported; a re-defer restarted
   its age; the device-run harness could `rm -rf` the server's data on a
   bad name (validated, moved aside, started again in a finally, and
   refused without the host marker `~/obsync/.allow-device-tests`). Delta
   server (`review12_test.go`): stage filenames minted outside the lock
   could collide in one nanosecond (per-process counter; stage files aged
   by mtime again, aside copies by nonce). Whole system
   (`review12w-*.test.ts`, `review12w_test.go`, report in
   `plugin/.cache/agent-review12-whole/`): the "enabled/reloaded plugin"
   notices were silenceable by the Sync-notices switch (never now); no
   request had a deadline (60 s, 30 min for blobs; a timeout is a network
   error and retried); a settings save while locked erased the sealed keys
   (kept now); PIN floor 8 with a plain statement of offline strength; the
   §5.7/§5.8 sentences that overstated the contract corrected (authority
   header travels on every write; a token thief can add self rows that hand
   it nothing; PBKDF2 is 2,000,000); the malicious-server residuals listed
   explicitly in §5.7 (withhold, replay as rollback, split views, a lied
   min_epoch pruning keys, a hidden roster entry).
1m. **Thirteenth review (2026-11-08): the twelfth round's own fixes, read as
   hurried fixes with edges. Plugin 3.5/5, server 4.5/5 (first round with no
   proven server defect). Fixed, released as 0.1.14.** Plugin
   (`review13-*.test.ts`, report in `plugin/.cache/agent-review13/`): the
   settle() rebase on an unreadable or inconsistent conflict head assumed
   every honest version beneath the head had been pulled; in the window
   between a device's pull and its push a member's garbage row on top of
   another device's honest edit made that edit vanish with no sibling (a head
   above the cursor now holds the push and pulls first, bounded to two
   rounds; a head at or below it is resolved against the newest readable
   version beneath before the rebase; a device holding a readable version
   re-pushes over a bad head after the batch); the request deadline was
   `AbortSignal.timeout` (WebKit 16) on a platform whose floor is iOS 15, so
   every request would have thrown before fetch (AbortController + setTimeout
   now, and `bundle-mobile.test.ts` refuses the newer APIs); a body that
   stalled past the deadline rejected with a raw TimeoutError outside the
   offline mapping (bodies are read inside the deadline and mapped); one
   notice per unreadable row, uncapped (one per batch naming the count).
   Server (`review13_test.go`, report in `plugin/.cache/agent-review13-server/`):
   no defect; its one LOW was plugin-side and real: the op builder read the
   keyring epoch twice (encryptMeta's header, then meta_epoch), so a rotation
   landing between the two produced header N / meta_epoch N+1, exactly the
   row the round-12 HIGH was about, now refused by the server and parked by
   the plugin (read once and passed to encryptMeta; a header-mismatch
   rejection is retried; `review13-epoch-once.test.ts` forces the
   interleaving with a real rotation). Two stale comments in
   `blobstore/fs.go` reworded; the device test's outage case restarts the
   unit in a finally. Verified after release: device run 12 (2026-11-08
   04:50 UTC, 0.1.14 on the iPhone and iPad against util's systemd server)
   20 of 20; a convergence sweep of 60 fresh seeds per config
   (`CONVERGENCE_SEEDS=100-159`, 180 runs) and 60,000 merge-fuzz histories
   (`MERGE_FUZZ_SEED=20261108 MERGE_FUZZ_ROUNDS=60000`) found no history
   that fails to converge or loses a write.
Do not reopen these settled decisions: honest-but-curious server, read-only
device tokens with the vault authority token for writes, names under the
identity key, skip-and-report for bad ops, config adoption on first sync.
If a finding touches one, extend DESIGN.md rather than redesign.

## How the 2026-11-23 session ended

The owner's main vault had just been moved onto the production server and
a phone joined; 1.0.0 and 1.0.1 were released the same day on top of it.
The last CI run before this was written was green on Linux; the macOS job
had failed once on 1.0.0 in the settings-screen onboarding test and passed
on the commits either side, which reads as one of the known slow-runner
waits but was not proven. Check the latest run before trusting that.

## How the 2026-10-25 session ended

A Stop hook enforcing the goal rejected every stop for the two user-only
items. The agent exhausted what was possible locally (including checking
emulator feasibility), wrote the two briefs, and stopped. If the same hook
is active for you, the honest state is: blocked on a device run and a human
reviewer until their results arrive; do not invent busywork to satisfy it.
