# Handoff: picking up obsync

Paste everything below the line to an agent that is continuing this project.
Written 2026-10-25 at commit `4fc0152` on `main`.

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

## Status in one paragraph

Everything verifiable on a Linux desktop is done, green, and pushed. The
full gate at `4fc0152` is: `cd server && go test ./...` ok, and from
`plugin/` 60 vitest tests across 8 files pass, including three suites that
drive two real Obsidian 1.12.7 instances under xvfb. Two independent agent
reviews ran (a security review and a first-time-user walkthrough); every
finding was fixed, regression-tested, and pushed. Two things remain that
only a person or a different machine can do: a run on an actual iOS or
Android device, and a security review by a human specialist. Briefs for both
are already written: `docs/MOBILE-TEST-PROMPT.md` and
`docs/SECURITY-REVIEW-GUIDE.md`. `DESIGN.md` lines 10 to 16 state this
status honestly; keep that paragraph true.

## What is done (so you do not redo it)

Server (Go 1.26, SQLite via modernc, coder/websocket):
- Append-only op log, per-path compare-and-swap, keyed content-addressed
  blobs, epochs and rotation, invites, recovery identity, GC and restore.
- Every write requires the vault authority token (`X-Obsync-Vault-Auth`,
  DESIGN §5.8). A device token alone is read-only. Claim rules: a device may
  claim only as the sole device on an empty vault; admins install it with
  `obsync vault auth`. Tested in `security_test.go`
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
  recovery, PIN minimum 6, http-to-non-localhost confirmation, docs that
  match the UI.
- `plugin/test/bundle-mobile.test.ts`: static proof that the production
  bundle needs nothing a Capacitor WebView lacks. This is the only mobile
  evidence that exists.
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

## What needs to be done

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
2. **Human security review.** Hand `docs/SECURITY-REVIEW-GUIDE.md` to a
   specialist. When findings come back, fix them in the style of the
   existing review rounds: a failing test first (`security_test.go` for the
   server, `plugin/test/e2e.test.ts` or `merge-paths.test.ts` for the
   plugin), then the fix, then a DESIGN §5.7/§5.8 update if the threat model
   changes. If the owner decides the two agent reviews suffice, remove "and
   a security review by a human specialist" from `DESIGN.md` and say so in
   the commit.
3. **Optional, owner's call:** a GitHub release with `main.js`,
   `manifest.json`, `styles.css` so BRAT can install it; a `versions.json`
   bump; CI running the Go and Node suites on push.

Do not reopen these settled decisions: honest-but-curious server, read-only
device tokens with the vault authority token for writes, names under the
identity key, skip-and-report for bad ops, config adoption on first sync.
If a finding touches one, extend DESIGN.md rather than redesign.

## How the previous session ended

A Stop hook enforcing the goal rejected every stop for the two user-only
items. The agent exhausted what was possible locally (including checking
emulator feasibility), wrote the two briefs, and stopped. If the same hook
is active for you, the honest state is: blocked on a device run and a human
reviewer until their results arrive; do not invent busywork to satisfy it.
