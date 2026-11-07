# Testing on a real iPhone and iPad from a Mac

`plugin/test/ios-devices.test.ts` runs the shipped plugin inside Obsidian
for iOS on physical devices plugged into a Mac, against the server on a
real host over HTTPS, with a Node engine on the Mac as the third device.
No jailbreak and no UI automation framework: Apple's `devicectl` and
pymobiledevice3 do everything over USB. This page is what you need to run
it and what it cannot do.

## What you need

- A Mac with Xcode 15 or newer (`xcrun devicectl` ships with it) and
  pymobiledevice3 (`uv tool install pymobiledevice3`; the harness looks for
  its interpreter under `~/.local/share/uv/tools/pymobiledevice3/bin/python`,
  or set `IOS_AFC_PYTHON`).
- One or two devices over USB, paired with the Mac, **Developer Mode on**
  (Settings → Privacy & Security), Obsidian installed from the App Store,
  and a vault created in the app named `obsync` (or `$IOS_VAULT`), stored
  on the device, not iCloud.
- Two one-time taps per device:
  - **Auto-Lock → Never** (Settings → Display & Brightness). iOS suspends
    Obsidian the moment the screen locks, and nothing over USB prevents the
    lock timer, so a locked screen reads as "the plugin stopped syncing".
  - **Trust author and enable plugins** the first time Obsidian opens the
    vault after the plugin is pushed in. Obsidian asks once per vault.
- A server the devices can reach. Obsidian's web view is fine with a
  public-CA certificate; the runs here used `obsync serve --acme-domain`
  on a small EC2 box. The test controls that server over ssh
  (`run.sh start|stop`, `~/obsync/data`), see `RemoteServer` in
  `plugin/test/ios-harness.ts`.

## Running

```sh
cd plugin
IOS_DEVICES=1 IOS_SERVER=https://sync.example.com IOS_SERVER_HOST=util IOS_ADMIN=ad_… \
IOS_IPHONE=<udid or device name> IOS_IPAD=<udid or device name> \
npx vitest run test/ios-devices.test.ts --reporter=verbose
```

Each run creates a fresh vault on the server, enrols the two devices from
the Mac, pushes `data.json` with the identity plus the plugin files into
the vault's `.obsidian`, relaunches Obsidian, and drives twenty scenarios.
Screenshots of both devices land in `plugin/.cache/ios/` after every
scenario, named by UTC time; at the end two invite links are written there,
one for `test/linux-joins.test.ts` and one for a person's own device.

## How the devices are driven

| Need | How |
| --- | --- |
| Launch, force quit, background, foreground | `devicectl device process launch --terminate-existing`, `terminate --kill`, launching Safari, relaunching |
| In-app edit (a typed edit, through Obsidian's vault API) | `devicectl device process openURL obsidian://new?vault=…&file=…&content=…&overwrite=true` |
| Files in and out of the vault | pymobiledevice3 `apps push/pull/rm --documents` (Obsidian exposes its Documents folder through iTunes file sharing) and `test/ios-afc.py` for single files and listings |
| Screenshot | `devicectl device capture screenshot` |

Two things that cost an hour each: devicectl's `appDataContainer` file
domain refuses App Store apps, hence pymobiledevice3; and `--device` must
precede the positional bundle id or devicectl hands it to the app as an
argument.

## What it does not prove

- Obsidian's own editor interactions (typing, the settings tab). Edits go
  through the URI handler, which uses the same vault API, and the
  settings-tab flows are covered by the desktop UI suite.
- Cellular, airplane mode, or the device sleeping with the app in the
  foreground: Auto-Lock is off for the run. Backgrounding is covered by
  switching to Safari and back.
- Key protection on iOS: the plugin offers PIN only there, and the vault
  itself sits unencrypted in the same file-sharing folder, so a copied
  `data.json` is no more exposed than the notes beside it.
