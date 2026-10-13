# obsync plugin

Simple, fast, end-to-end encrypted sync for Obsidian vaults, including the
`.obsidian` folder (settings, themes, snippets, plugins and their data).
Pairs with the `obsync` server in `../server`. Design and rationale are in
`../DESIGN.md`.

## Setup in two minutes

1. Run the server once (see `../server/README.md`). Note the admin token it
   prints (also saved to `<data>/admin-token`) and the URL it serves on.
   Plain `http://` is fine on a desktop or a LAN; mobile needs HTTPS with a
   real certificate, and `--acme-domain` does that for you.
2. Install the plugin: copy `main.js`, `manifest.json` and `styles.css` into
   `<vault>/.obsidian/plugins/obsync/`, restart Obsidian, and under
   Settings → Community plugins turn off Restricted mode and enable
   **obsync**. Then open the obsync settings tab.
3. On the first device: check the **Device name** (it defaults to the
   machine's hostname; it is how this device appears on every other device
   and in conflict file names, and can be renamed later), then **Create a new
   vault → Create…** with the server URL and the admin token. The vault keys
   are generated on this device; the server never sees them.
4. On the first device: **Generate invite link**. On every other device:
   install the plugin the same way, open its settings, paste the link into
   **Join with invite link** and press **Join**. A notice confirms the join
   and the status bar shows `obsync ✓`. The link is single-use and expires in
   24 hours.
5. Optional but recommended: **Set recovery passphrase** so a new device can
   join with only the server URL, the vault id and the passphrase if you lose
   every other device. The vault id is shown under **Status** with a Copy
   button; keep a copy of it with the passphrase.

There is nothing else to configure. Everything syncs, in both directions,
immediately, with conflicts handled without dialogs. The "two minutes" is
the part after the server is running and the plugin is installed; budget
another ten for the first time through the build and install steps.

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
  saved next to it as `name (conflict <device> <date> <time>).md`. A notice
  tells you; **Show conflicts** lists them.

Deletions are conservative: a file edited on one device and deleted on
another keeps the edit. Deleting many files at once (50+ and 20 % of the
vault) is held until you confirm, because that is what an unmounted drive
looks like.

Every version of every file stays on the server for 90 days (configurable),
and the list of versions forever. **Show history for current file** lets you
save any old version; **Restore vault to a point in time** rewinds the whole
vault as new history, so it can be undone.

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
  The default on mobile.
- **PIN at launch**: the key store is sealed under a PIN-derived key
  (PBKDF2, 600k iterations). Works on every platform. Someone who gets the
  file can try PINs offline at GPU speed, so the minimum is 6 characters
  and a long one (a short phrase) is what actually stops them. Obsidian
  prompts at startup; "Unlock vault keys" prompts again.
- **OS keychain** (desktop): a random wrapping key is stored in the macOS
  Keychain, Windows DPAPI, or Linux libsecret via Electron's `safeStorage`.
  No prompt. Resists anyone who gets the file but not your login session.
  Offered only when a real keychain backend exists. On macOS, **Require
  Touch ID** adds a prompt before the keychain is used.

Biometrics through WebAuthn are not possible: Obsidian's `app://` origin is
not allowed to use public-key credentials, as verified in the test suite.

## Commands

Sync now · Show conflicts · Generate invite link for another device ·
Manage devices · Set recovery passphrase · Rotate vault keys · Restore vault
to a point in time · Show history for current file · Rebuild local sync
state · Apply held deletions · Unlock vault keys.

## Status bar

`obsync: off` not connected · `obsync ✓` idle · `↕ 3` syncing, 3 files
pending · `… ` scanning · `⚠ offline` will retry · `✗` error (hover for the
message; "removed from the vault" means another device removed this one) ·
`re-encrypting N` a key rotation is re-encrypting data · `🔒` keys locked,
run "Unlock vault keys".

## Mobile status

The plugin is not desktop-only, and nothing in it needs Node: the bundle
uses only WebCrypto, `fetch`, `WebSocket`, `CompressionStream` (feature
detected, optional), and the Obsidian `vault`/`adapter` API. Timestamps are
floored before every write because Capacitor casts them to a Java `long`.
Config-folder changes are found by a 15-second scan rather than the
desktop-only `raw` event. Mobile needs HTTPS with a certificate the OS
trusts; use the server's `--acme-domain` or a proxy.

It has **not** been run on iOS or Android by the authors. Everything above
is verified on desktop Linux inside real Obsidian; mobile is verified only
by inspection. Treat the first mobile install as a test and keep a backup.

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
src/core/      platform-free: crypto, engine, merge, paths, transport, admin
src/obsidian/  Obsidian glue: filesystem adapter, settings, modals, hooks, main
test/          vitest; e2e.test.ts spawns ../server and runs multi-device scenarios
test/vectors.json  pinned wire-format vectors for a second implementation
```

Three layers of tests:

- unit: crypto (with pinned vectors), merge, path rules;
- `test/e2e.test.ts`: the engine under Node with real files against the real
  server, two or more simulated devices;
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
  locked, refuses a wrong PIN, and unlocks with the right one.
  `test/obsidian-config.test.ts` reproduces the one config conflict ever
  seen (a joining device's own `app.json`, rewritten by Obsidian itself,
  differing from the vault's) with the adoption rule switched off, then
  shows the default behaviour adopts silently.
  They run only when `OBSIDIAN_BIN` is set:

  ```sh
  OBSIDIAN_BIN=$(which obsidian) XVFB_RUN=$(which xvfb-run) npx vitest run test/obsidian.test.ts
  ```
