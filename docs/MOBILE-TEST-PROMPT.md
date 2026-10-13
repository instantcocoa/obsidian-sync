# Prompt: test obsync on Android (emulator or device)

Copy everything below the line into an agent running on a machine that has
KVM (`ls /dev/kvm`), at least 25 GB free disk, 16 GB RAM, Go 1.26+, Node 20+,
Java 17+, and a clone of `github.com/instantcocoa/obsidian-sync` at `main`
(`fe58763` or later). If a real Android phone is plugged in with USB
debugging on, skip the emulator steps and use it; everything else is the
same. iOS needs a Mac and Xcode; the plugin-side checks are identical, the
install is via Obsidian's iOS app plus a Mac-side Safari Web Inspector.

---

You are testing the obsync Obsidian plugin on Android for the first time. It
has been tested end to end only on desktop (Linux, real Obsidian under
xvfb). Your job is to find out whether it works on a phone, fix what you can
in the plugin, and write a precise report of what you saw. Do not change the
server's protocol or the crypto. Do not weaken any check to make a test pass.

Read first: `README.md`, `plugin/README.md`, `DESIGN.md` §6.7 (Mobile),
§5.5a (local key protection; the OS keychain option is desktop-only), §7.3
(plugin reload), and `plugin/test/bundle-mobile.test.ts`, which is the only
mobile evidence so far: it proves the bundle needs nothing a Capacitor
WebView lacks, and nothing more.

Keep every file you create inside the repo under `plugin/.cache/mobile/`
(gitignored) or your scratchpad. Never `git add -A`. Use `rg`, not `grep`.

## 1. Environment

1. Build the server and the plugin:
   ```sh
   cd server && go build -o obsync ./cmd/obsync && cd ..
   cd plugin && npm ci && npm run build && npm test && cd ..
   ```
   `npm test` must be green before you start (it uses the Go server; the
   real-Obsidian suites are skipped unless `OBSIDIAN_BIN` is set).
2. Android SDK, if there is no device: install command-line tools, then
   `platform-tools`, `emulator`, and `system-images;android-34;google_apis;x86_64`.
   Create an AVD (Pixel 6 class, 4 GB RAM) and boot it with `-no-window
   -no-audio -gpu swiftshader_indirect`. Wait for `adb shell getprop
   sys.boot_completed` to be `1`.
3. Obsidian APK: the official releases at
   `https://github.com/obsidianmd/obsidian-releases/releases` attach an
   `Obsidian-<version>.apk`. Download the latest into its own empty
   directory, record the version and the SHA-256, and `adb install` it. Do
   not take an APK from anywhere else.
4. Start the server on the host, reachable from the emulator at
   `10.0.2.2` (a device on the same Wi-Fi uses the host's LAN IP):
   ```sh
   ./server/obsync serve --data plugin/.cache/mobile/data --listen 0.0.0.0:8080
   ```
   Note the admin token it prints. Try plain `http://10.0.2.2:8080` first.
   If Obsidian's WebView refuses cleartext or mixed content (you will see a
   `Could not reach` notice or a `TypeError: Failed to fetch` in the console),
   the plugin README says mobile needs HTTPS with a publicly trusted
   certificate: use `--acme-domain` on a host with a public DNS name, or a
   reverse proxy with a real certificate. A user-installed CA on Android is
   not trusted by the app's WebView, so do not go down that road. Record
   which of the two worked; that is a finding in itself.

## 2. Desktop peer

The phone needs something to sync with. Use real desktop Obsidian under
xvfb exactly as `plugin/test/obsidian-harness.ts` does (`OBSIDIAN_BIN`,
`XVFB_RUN`, Chrome DevTools Protocol on a random port). If that is not
available, the Node-side engine used by `plugin/test/e2e.test.ts` through
`plugin/test/harness.ts` is an acceptable stand-in for file content, but it
does not exercise Obsidian's own config rewrites, so say so in the report.

On the desktop peer: create the vault (server URL + admin token), generate
an invite link, and copy it somewhere you can paste from.

## 3. Install on the phone

1. In the Obsidian app, create a vault in a folder you can reach with adb
   (for example `/sdcard/Documents/obsync-test`). Open it once so
   `.obsidian/` exists.
2. Push the plugin:
   ```sh
   adb push plugin/main.js plugin/manifest.json plugin/styles.css /sdcard/Documents/obsync-test/.obsidian/plugins/obsync/
   ```
3. Drive the UI. Two options, in order of preference:
   - Chrome DevTools: Obsidian's Android WebView is inspectable. Find the
     socket with `adb shell cat /proc/net/unix | rg webview_devtools_remote`
     and forward it: `adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>`.
     Then `curl localhost:9222/json` lists the page; use the CDP endpoint to
     run `app.plugins.plugins.obsync.joinWithLink(link)` and to read
     `app.plugins.plugins.obsync.engine.status`, exactly as
     `plugin/test/obsidian-harness.ts` does on desktop (`eval`, `waitFor`,
     `waitForFile`). Reuse that file's approach rather than writing a new
     driver.
   - If the WebView is not inspectable: screenshots (`adb exec-out screencap
     -p`) plus `adb shell input tap/text/keyevent`, and read results off
     disk with `adb pull`. Slower but sufficient.
4. Settings → Community plugins → turn off Restricted mode → enable obsync.
   Record the exact notices shown.

## 4. What to test, in order

Record for each: pass/fail, the notice or error text verbatim, and the
relevant lines from the plugin console (`console.log` lines prefixed
`obsync`) and from the server's stdout.

1. **Join.** Settings → obsync → paste the invite link → Join. Expect a
   notice confirming the join and the status bar `obsync ✓`. The default
   device name on Android must be `android` (see `defaultDeviceName` in
   `plugin/src/obsidian/main.ts`); rename it to `phone` through the Rename
   button and confirm the desktop roster shows the new name.
2. **Content both ways.** Create a note on the desktop; it appears on the
   phone within a few seconds. Edit a note on the phone in the editor; the
   desktop sees it. Include a note with a non-ASCII name (`Ünïcödé 日本.md`),
   an attachment of ~8 MB (streams through 4 MiB range requests on
   download), and an empty file. Verify bytes with sha256 on both sides.
3. **Config.** Toggle a setting on the phone that Obsidian writes to
   `.obsidian/app.json` (for example line numbers). The desktop's
   `app.json` must update with no conflict sibling appearing on either side.
   `workspace-mobile.json` must *not* sync (default exclusion).
4. **Backgrounding.** Press Home, wait 60 s, reopen Obsidian. Make a change
   on the desktop while the phone is in the background. On resume the
   phone must reconnect (status returns to `✓`) and receive the change
   without any manual action. Repeat with the app killed (`adb shell am
   force-stop md.obsidian`) and relaunched.
5. **Offline.** Enable airplane mode (`adb shell cmd connectivity airplane-mode enable`),
   edit on the phone, disable airplane mode. The edit must reach the desktop
   and the status must recover on its own. Record how long it took.
6. **Concurrent edit.** Edit the same note on both sides while the phone is
   in airplane mode, then reconnect. Non-overlapping edits merge; overlapping
   ones produce exactly one `(conflict phone …)` sibling and the live file
   keeps the vault's version. No dialog.
7. **Key protection.** Settings → obsync → protection. The OS keychain option
   must be shown as unavailable on Android; PIN must work: set a 6-digit PIN,
   kill and relaunch the app, expect the Unlock prompt, a wrong PIN refused,
   the right PIN unlocks and sync resumes.
8. **Removal and rotation.** On the desktop, remove the phone from the
   roster. The phone must show the removed message in the status bar and
   stop syncing, and it must stay in that state across a relaunch. Then
   rejoin with a fresh invite link.
9. **Recovery passphrase.** Set a passphrase on the desktop. On the phone,
   leave the vault, then join with server URL + vault id + passphrase. A
   wrong passphrase must say so; the right one must restore everything.
10. **Plugin sync.** Install a small community plugin on the desktop. The
    phone must receive it, show the "enabled from sync" notice, and load it
    without a restart (DESIGN §7.3). Mobile-incompatible plugins
    (`isDesktopOnly: true`) must be skipped with a clear notice, not an
    error loop.
11. **Crash check.** After all of the above, `adb logcat -d | rg -i
    "obsidian|fatal|AndroidRuntime"` must show no crash. The historic
    LiveSync crash was a float mtime handed to Capacitor (DESIGN §1.6);
    timestamps are floored in `plugin/src/core/engine.ts`. Confirm no
    `NumberFormatException` or `ClassCastException` anywhere.
12. **Memory.** Read `adb shell dumpsys meminfo md.obsidian` before and after
    the 8 MB attachment sync; the delta should stay under 50 MB.

## 5. Fixing things

If a step fails because of plugin code, fix it in `plugin/src/`, add a test
if it can be expressed without a device (unit test, or a case in
`plugin/test/bundle-mobile.test.ts`), run the whole plugin suite, and keep
going. Commit with explicit paths, one commit per fix, with a message that
names the mobile symptom. Do not push unless the repository owner has said
you may.

If a step fails because of the server (for example a header the WebView
strips, or CORS), note it precisely with the request and response headers;
the server change is probably small but needs a Go test in
`server/internal/api/api_test.go`.

## 6. Report

Write `plugin/.cache/mobile/REPORT.md` with: device or emulator and Android
version, Obsidian version and APK SHA-256, http vs https outcome, a table of
the twelve steps with pass/fail and evidence, every fix you made with its
commit hash, and anything you could not test and why. Then update the
status paragraph at the top of `DESIGN.md` (it currently says no run on a
device has happened) to state exactly what was run and what passed, and add
the same facts to the mobile note in `plugin/README.md`. Keep both honest:
if something was not exercised, say so.
