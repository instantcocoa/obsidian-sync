# obsync plugin

Simple, fast, end-to-end encrypted sync for Obsidian vaults, including the
`.obsidian` folder (settings, themes, snippets, plugins and their data).
Pairs with the `obsync` server in `../server`. Design and rationale are in
`../DESIGN.md`.

## Setup in two minutes

1. Run the server (see `../server/README.md`), then on its host run
   `obsync vault create`: it prints a one-time **create link**
   (`obsync://create#…`) and a QR code of it. There is no admin token. If
   you have registered a security key (`obsync admin register`), the
   server's `/admin` page mints the same link after you touch the key,
   from any browser including Safari on an iPhone.
   Plain `http://` is fine on a desktop or a LAN (the Android app accepts it
   too); anything reachable from the internet should use HTTPS with a real
   certificate, and `--acme-domain` or Caddy in front does that for you.
2. Install the plugin. The easy way, on desktop and mobile alike, is
   [BRAT](https://github.com/TfTHacker/obsidian42-brat): install BRAT from
   Community plugins, then in its settings choose **Add beta plugin**, paste
   `instantcocoa/obsidian-sync`, and let it install and enable obsync from
   the latest GitHub release. By hand: download `main.js`, `manifest.json`
   and `styles.css` from the
   [latest release](https://github.com/instantcocoa/obsidian-sync/releases/latest)
   (or build them, see Development) into
   `<vault>/.obsidian/plugins/obsync/`, restart Obsidian, and under
   Settings → Community plugins turn off Restricted mode and enable
   **obsync**. Then open the obsync settings tab.
3. On the first device: check the **Device name** (it defaults to the
   machine's hostname; it is how this device appears on every other device
   and in conflict file names, and can be renamed later), then paste the
   create link into **Join or create with a link** and press **Connect**,
   or scan its QR code with the device's camera (Obsidian opens and asks
   before creating). The vault keys are generated on this device; the
   server never sees them, and the link dies once it is used.
4. On the first device: **Generate invite link**. It shows a QR code and
   the link. On every other device, install the plugin the same way, then
   either scan the QR code with the device's camera (it opens Obsidian,
   which asks before joining) or open the plugin's settings, paste the link
   into **Join or create with a link** and press **Connect**. A notice confirms the
   join and the status bar shows `obsync ✓` (a phone has no status bar: tap
   the obsync ribbon icon or run **Show sync status**). The link is single-use and
   expires in one hour (a key rotation ends it early). Notices about routine sync events (a conflict
   resolved, a synced plugin enabled) can be turned off under **Sync
   notices**; errors and decisions are always shown. The vault keys are
   sealed at this point without asking: by the OS keychain on a desktop, by
   the device keychain on a phone or tablet running Obsidian 1.11.4 or
   newer. An older mobile Obsidian is offered a PIN once instead
   (**Protect keys** changes any of this later). Every device
   is told when a new device joins the vault; if it was not you, remove it
   under **Manage devices** and the keys rotate.
5. Optional but recommended: **Set recovery passphrase** so a new device can
   join with only the server URL, the vault id and the passphrase if you lose
   every other device. The vault id is shown under **Status** with a Copy
   button; keep a copy of it with the passphrase.

There is nothing else to configure. Everything syncs, in both directions,
immediately, with conflicts handled without dialogs. The "two minutes" is
the part after the server is running and the plugin is installed; budget
another ten for the first time through the build and install steps. The
repository's root `README.md` walks through the same setup one tap at a
time, with what you should see after each step.

Every device of a vault must run 1.0 or newer. 1.0 stores large files as
chunks (see "Large files" below), which an older plugin cannot read.

## What syncs

Everything in the vault, including dot-files and the config folder, except a
short per-device exclusion list (Settings → What to sync → Exclusions):

```
/$CONFIG/workspace.json            window layout: per device
/$CONFIG/workspace-mobile.json
/$CONFIG/workspaces.json
/$CONFIG/plugins/obsync/           this plugin's keys and state
/$CONFIG/cache/
/.trash/  /.git/  node_modules/  .DS_Store  desktop.ini  Thumbs.db
*.obsync-tmp  *.obsync-conflict-tmp   this plugin's own temporary files
```

`$CONFIG` stands for the config folder, whatever it is called on each
device. Patterns are gitignore-style. Add a line like
`/$CONFIG/plugins/some-plugin/data.json` to keep one plugin's settings per
device, or `Private/` to keep a folder off a particular device. Exclusions
are per device; the server still holds the files.

**Names that cannot sync.** A file or folder whose name contains one of
`? * : < > " | \` or a control character stays on the device where it is.
Those characters are refused on every platform, so that a vault never holds
a file some device cannot create. The plugin says so once per file, naming
it; rename the file inside Obsidian and it syncs.

**Large files.** A file of at most 1 MiB travels as one encrypted blob. A
larger one is cut into chunks at points chosen from its content (256 KiB to
4 MiB each, about 1.25 MiB on average), and each chunk is encrypted and
stored separately. An edit uploads and downloads only the chunks it
touched, and identical chunks are stored once across versions and files.
A device verifies the reassembled file against its authenticated size and
content id before writing anything. One version can have at most 4096
chunks (several GiB). Files are still read whole into memory. A rename or
copy made on another device costs no download: the device writes the
content it already holds under the new name. `../DESIGN.md` §6.9.

After a remote change under `.obsidian`, the plugin reloads affected
community plugins, CSS snippets and themes in place, enables or disables
plugins to match `community-plugins.json`, and shows one notice asking for a
reload when a core setting changed.

## How conflicts are handled

Two devices editing the same file while offline:

- Same resulting bytes: nothing to do.
- Text files with non-overlapping edits: merged three-way against the exact
  version both started from. JSON under `.obsidian` merges per key.
- Anything else: the other device's version stays at the path and yours is
  saved next to it as `name (conflict <device> <date> <time>).md` (a second
  one in the same minute gets a number: `… <time> 2).md`). A notice tells
  you; **Show conflicts** opens the review dialog.

**Reviewing conflicts.** **Show conflicts** lists every conflict copy with
the file it belongs to, the device and time it came from and, for text, the
lines only one side has. Three buttons per copy: **Keep current** deletes
the copy, **Keep other version** makes the copy the file (what was there
stays in the server's history) and deletes the copy, **Open both** opens
the two side by side. Each choice is an ordinary edit or delete, so it
syncs to the other devices like any other. A text file above 1 MiB is
merged only when the version both sides started from is still stored as
one blob; otherwise a concurrent edit makes a conflict copy.

Nothing you wrote is ever discarded: it is at its path, in a conflict copy,
or in the server's history. That holds across restarts, crashes, lost sync
state, a server restart or outage, a removed device, a key rotation while
you were offline, and a server restored from an older backup.
`test/conflict-recovery.test.ts` has one scenario for each of those and
`test/convergence.test.ts` checks random multi-device histories for it.

Deletions are conservative: a file edited on one device and deleted on
another keeps the edit. Deleting many files at once (50+ and 20 % of the
vault) is held until you confirm, because that is what an unmounted drive
looks like.

Every version of every file stays on the server for 90 days (configurable),
and the list of versions forever. **Show history for current file** lets you
save any old version; **Restore vault to a point in time** rewinds the whole
vault as new history, so it can be undone. Restore is a plugin command
only: the server does the work but the request needs the vault keys, which
the server never holds.

**When a device has drifted.** Two commands, opposite in intent, both under
Settings → Advanced as well:

- **Rebuild local sync state** forgets what this device thinks it has
  synced and works it out again by hashing every file. Every local
  difference is kept: merged, uploaded, or saved as a conflict copy. Safe to
  run at any time.
- **Reset this device to the server's copy** is one-way. This device's files
  become exactly what the server has and nothing is uploaded. Every local
  version the server's copy replaces, and every file that exists only here,
  is moved to `.trash/obsync-reset-<time>/` inside the vault at its own
  path, not deleted. Use it when the other devices are right and this one
  is not. It asks before it does anything, and it can only be started on the
  device itself.

## Devices and keys

**Manage devices** lists every device by the name it chose (rename this
one under Status → This device). **Remove** on a device rotates the vault
keys and re-encrypts everything in the background, so the removed device can
decrypt nothing the server still holds. Removing a lost phone is one click.
The removed device, if it is still around, shows `obsync ✗` and a notice
saying it was removed; use **Leave this vault** on it, or re-join it with a
new invite link.

**Leaving and uninstalling.** Settings → Advanced → **Leave this vault**
stops syncing on this device and forgets its keys and token; your files stay
on disk. The device stays listed on other devices until you **Remove** it
there, which rotates the keys. To uninstall completely, leave first, then
delete `.obsidian/plugins/obsync/`.

Keys, the device token and the local state live in
`.obsidian/plugins/obsync/`. They are never synced. Losing that folder on
one device means re-joining with an invite link or the recovery passphrase;
your files are unaffected.

Two things worth knowing about trust:

- **Everyone in the vault can run code on every device** that syncs the
  config folder, because synced plugins are reloaded and enabled
  automatically. That is the feature. Only invite devices you control, and
  turn off "Sync config folder" in a shared vault you do not fully trust.
  The plugin shows a notice whenever sync enables a plugin.
- **A device token on its own cannot hurt you.** Rotating keys, replacing
  data, changing the recovery passphrase or inviting devices all need the
  vault keys as well, so a token that leaks through a proxy log or a copied
  `data.json` with sealed keys can at most read ciphertext. A device listed
  as "(unnamed)" never finished joining or has no keys: remove it if you do
  not recognise it.
- **Use https.** With a plain `http://` server URL the plugin asks first:
  your notes stay encrypted, but the device token would travel in the clear.

## Keys on this device

Settings → "Protect keys" chooses how the vault keys and device token are
stored on this device:

- **None**: in the plugin's `data.json`, protected only by disk encryption.
  Never the default where a keychain exists.
- **PIN at launch**: the key store is sealed under a PIN-derived key
  (PBKDF2, 600k iterations). Works on every platform. Someone who gets the
  file can try PINs offline at GPU speed, so the minimum is 8 characters
  and a long one (a short phrase) is what actually stops them. Obsidian
  prompts at startup; "Unlock vault keys" prompts again.
- **OS keychain** (desktop, the default there): a random wrapping key is
  stored in the macOS Keychain, Windows DPAPI, or Linux libsecret via
  Electron's `safeStorage`. No prompt. Resists anyone who gets the file but
  not your login session. Offered only when a real keychain backend exists.
  On macOS, **Require Touch ID** adds a prompt before the keychain is used.
- **Device keychain** (phones and tablets, the default there on Obsidian
  1.11.4 or newer): a random wrapping key is kept in Obsidian's own secret
  storage, which on iOS is an item in the system Keychain and on Android a
  value encrypted by the Android Keystore. `data.json` then holds only
  ciphertext, so a copied vault folder, a file-sharing pull or another sync
  tool carries nothing usable, and nothing is typed. Obsidian writes the
  entry in the background and reports no failure, so the plugin keeps the
  previous form of the keys beside the new one until a later launch has
  read the entry back, then drops it; a write that never landed reverts to
  what was there before. If the entry is ever gone (Obsidian reinstalled, a
  restore without the keychain) the sealed keys are left untouched and the
  plugin says to join again with an invite or the recovery passphrase. Two
  limits: any other plugin running in Obsidian on that device can read the
  entry, as it can read your notes; and the entry shows under Obsidian's
  Settings → Keychain, where deleting it locks this vault on this device.
  Confirmed on an iPhone (iOS 27, Obsidian 1.15.1) on 2026-11-23; not yet
  run on Android or an iPad. `../DESIGN.md` §5.5a.

Biometrics through WebAuthn are not possible: Obsidian's `app://` origin is
not allowed to use public-key credentials, as verified in the test suite.

## Commands

Show sync status · Sync now · Show conflicts (the review dialog) ·
Generate invite link for another device · Manage devices · Set recovery
passphrase · Rotate vault keys · Restore vault to a point in time · Show
history for current file · Rebuild local sync state · Reset this device to
the server's copy · Apply held deletions · Unlock vault keys · Accept
server restore (after the server was restored from a backup taken before a
key rotation) · Re-upload current file to the server (the repair when
another device reports it "could not apply the latest version" of a file).

## Status bar

`obsync: off` not connected · `obsync ✓` idle · `↕ 3` syncing, 3 files
pending · `… ` scanning · `⚠ offline` will retry · `✗` error (hover for the
message; "removed from the vault" means another device removed this one) ·
`re-encrypting N` a key rotation is re-encrypting data · `🔒` keys locked,
run "Unlock vault keys".

Phones and tablets have no status bar. There the obsync icon in the ribbon
menu carries the same state in its label, tapping it (or the command **Show
sync status**) says it in a notice with the number of conflict copies
waiting, and going offline or stopping shows a notice once per change of
state.

## Mobile status

The plugin is not desktop-only, and nothing in it needs Node: the bundle
uses only WebCrypto, `fetch`, `WebSocket`, `CompressionStream` (feature
detected, optional), and the Obsidian `vault`/`adapter` API. Timestamps are
floored before every write because Capacitor casts them to a Java `long`.
Config-folder changes are found by a 15-second scan rather than the
desktop-only `raw` event, so a setting or plugin change from another device
shows up on a phone within about 20 seconds rather than instantly.

Run on Android on 2026-10-27 (`docs/MOBILE-TEST-PROMPT.md`, all twelve
scenarios): Obsidian 1.14.4, the official APK, on an Android 14 emulator
(API 34 Google APIs x86_64 under KVM, 4 GB), with a real desktop Obsidian
1.14.4 peer and the real server. What passed as shipped: join with an
invite link (default device name `android`, rename to `phone` visible on the
desktop roster), notes and attachments both ways byte for byte (a
non-ASCII name, an 8 MB file, an empty file), `app.json` changes in both
directions with no conflict copy, `workspace-mobile.json` never synced,
Home/resume and force-stop/relaunch, airplane mode (the edit arrived 2.4 s
after reconnecting), concurrent edits (non-overlapping merged; overlapping
gave exactly one `(conflict phone …)` sibling, no dialog), PIN protection
(the desktop keychain option is shown as unavailable; wrong PIN refused,
right PIN resumes; this run predates the device keychain method, which has
not been run on Android), removal from the desktop (the phone shows the removed message,
stops, stays removed across a relaunch, rejoins with a new link), the
recovery passphrase (a wrong one is refused), no crash in `logcat`, and an
8 MB attachment adding 8.4 MB to the app's PSS. What needed fixing, all on
branch work from that run: a community plugin enabled on the desktop was
not enabled on the phone until the list changed again (op order), a
desktop-only plugin was skipped without a word, reloading obsync itself
(what Obsidian's plugin updater does) could wipe the sync state, and one
recovery-passphrase rejoin wrote a note as 0 bytes once, which did not
reproduce and is now caught by a size check after every write.

Plain `http://` worked from the Android app: its WebView serves Obsidian
from `http://localhost`, so a cleartext server is neither blocked nor
mixed content. Use HTTPS (`--acme-domain` or a proxy) for anything that
leaves your network all the same; the device token travels in the clear
otherwise. iOS followed on real hardware: an iPhone 13 Pro and an iPad Pro
ran twenty scenarios against a server with a Let's Encrypt certificate,
with Obsidian on Linux joining the same vault (`test/ios-devices.test.ts`,
`test/linux-joins.test.ts`, `../docs/IOS-DEVICE-TESTING.md`). Two things
to know on iOS: Obsidian asks "Trust author and enable plugins" once per
vault when the plugin arrives from outside the app, and sync runs only
while Obsidian is in the foreground, as iOS suspends it otherwise. The
device keychain method was checked separately on an iPhone 18,1 (iOS
27.0.1, Obsidian 1.15.1) on 2026-11-23: a vault created on the phone, the
settings showing Device keychain, Obsidian force-quit and reopened, and a
new note uploaded with nothing typed. Treat the first install on your own
device as a test and keep a backup.

## Development

```sh
npm install
npm test          # unit tests + two-device end-to-end against the real Go server
npm run check     # typecheck
npm run build     # main.js; set OBSYNC_TEST_VAULT=/path/to/vault to auto-copy
npm run dev       # watch mode
```

Layout:

```
src/core/      platform-free: crypto, engine, chunks, merge, paths, transport, admin
src/obsidian/  Obsidian glue: filesystem adapter, settings, modals, hooks, main
test/          vitest; e2e.test.ts spawns ../server and runs multi-device scenarios
test/vectors.json  pinned wire-format vectors for a second implementation
```

Three layers of tests:

- unit: crypto (with pinned vectors), merge, path rules;
- `test/e2e.test.ts`: the engine under Node with real files against the real
  server, two or more simulated devices;
- `test/conflict-recovery.test.ts`: one scenario per conflict shape and
  recovery path (`../docs/CONFLICT-RECOVERY-MATRIX.md` lists them), and
  `test/convergence.test.ts`: seeded random histories on three devices with
  restarts, crashes, state loss and server outages, checked for convergence
  and for no lost write;
- `test/chunks.test.ts`: the chunker (bounds, determinism, an insertion
  moving few boundaries, a different key moving all of them) and large
  files through the real server: an edit moving only the changed chunks,
  history, rename, a concurrent edit of a large binary, garbage collection,
  key rotation, restore to a point in time, and a tampered chunk list
  refused. `test/rename-no-download.test.ts`: a rename, move or copy made
  elsewhere downloads nothing. `test/reset-to-server.test.ts`: the one-way
  reset. `test/conflict-review.test.ts`: the helpers behind the review
  dialog. `test/keychain-secret.test.ts`: the device keychain method
  against a transcription of Obsidian's secret storage class, including a
  write that never lands and an entry that disappears;
- `test/obsidian.test.ts` and `test/obsidian-ui.test.ts`: the plugin as
  shipped inside real Obsidian, headless, driven over the DevTools protocol.
  Two Obsidian instances create a vault, invite, join, sync notes through
  the Obsidian API and config files from disk, update an open editor,
  produce a conflict sibling, delete, leave, rejoin by recovery passphrase,
  and rotate keys. The UI suite onboards both devices through the real
  settings dialog and modals with the server's rate limiter on, observes
  the `reconcileInternalFile` call and the snippet reload, checks that
  engine restarts never produce config conflicts, and verifies that
  passphrase brute force is throttled while a correct join still works,
  and enables PIN protection, reloads the plugin, and checks it comes up
  locked, refuses a wrong PIN, and unlocks with the right one. It also
  runs the device keychain method against real Obsidian's own secret
  storage (forced on for the test, since desktop normally uses the OS
  keychain method): sealed, reopened on reload with no prompt, locked when
  the entry is deleted behind the plugin's back, removed on switching away.
  `test/obsidian-config.test.ts` reproduces the one config conflict ever
  seen (a joining device's own `app.json`, rewritten by Obsidian itself,
  differing from the vault's) with the adoption rule switched off, then
  shows the default behaviour adopts silently.
  They run only when `OBSIDIAN_BIN` is set:

  ```sh
  OBSIDIAN_BIN=$(which obsidian) XVFB_RUN=$(which xvfb-run) npx vitest run test/obsidian.test.ts
  ```
- **Bundle mobile safety** (`test/bundle-mobile.test.ts`): builds `main.js`
  the production way and asserts it needs nothing a Capacitor WebView lacks:
  the only `require`s are `obsidian` and one `os.hostname()` behind
  `Platform.isMobile` and a `try`, Node globals appear only behind feature
  checks, I/O and crypto are `fetch`, `WebSocket` and WebCrypto. This is the
  part of iOS/Android support provable without a device; the Android and
  iOS device runs are described under "Mobile status".
- **Mobile hooks and adapters** (`test/hooks-mobile.test.ts`,
  `test/obsidian-fs-write.test.ts`, `test/state-store.test.ts`): what the
  Android run found, pinned against a stub of the `obsidian` package
  (`test/stubs/obsidian.ts`, aliased in `vitest.config.ts`): plugin enabling
  regardless of op order, the desktop-only notice, write-size verification,
  and loading state while a save is in flight.
