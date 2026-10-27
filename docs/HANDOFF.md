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
- macOS (EC2 Intel Mac, macOS 15.8, Obsidian 1.14.5): gate 103/103,
  `plugin/test/obsidian-macos.test.ts`, fixes for case-only renames and
  case twins, Touch ID detection, unreadable state file; three harness
  fixes without which Obsidian cannot be driven on macOS.
- Android (emulator API 34, Obsidian 1.14.4 APK, real desktop peer):
  11/12 as shipped, plugin sync fixed, reload race fixed, write size
  verified; plain http works from the WebView.
- GitHub Actions (`.github/workflows/platforms.yml`) runs the full gate on
  ubuntu, macos-14 and windows on every push, real Obsidian included. All
  four jobs are green from commit `7cb5086` on (the first runs needed the
  macOS harness fixes and two timing-tolerant tests).
- One AWS loose end: the Mac dedicated host `h-05d8e91904b1d7095`
  (us-east-2b) has its instance terminated but cannot be released before
  its 24-hour minimum ends at 2026-10-28 15:20 UTC. After that, run
  `aws ec2 release-hosts --region us-east-2 --host-ids h-05d8e91904b1d7095`
  and confirm with `aws ec2 describe-hosts` that none remain.
- Reports with verbatim evidence: `plugin/.cache/agent-{win,mac,android}/REPORT.md`
  on the original machine (gitignored).

## What needs to be done

1. **iOS and a physical Android phone.** The Android emulator run is done;
   iOS needs a Mac with Xcode and an iPhone, and nobody has held the plugin
   on a real phone yet. `docs/MOBILE-TEST-PROMPT.md` still applies.
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
