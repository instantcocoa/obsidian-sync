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
- A **test** server the devices can reach, never the one that holds real
  vaults: the suite stops it, wipes it and replaces its data directory
  (see the warning under Running). Obsidian's web view is fine with a
  public-CA certificate; the runs here used `obsync serve --acme-domain`
  on a small EC2 box. The test controls that server over ssh, see
  `RemoteServer` in `plugin/test/ios-harness.ts`.

## Running

```sh
cd plugin
IOS_DEVICES=1 IOS_SERVER=https://sync.example.com IOS_SERVER_HOST=util \
IOS_IPHONE=<udid or device name> IOS_IPAD=<udid or device name> \
npx vitest run test/ios-devices.test.ts --reporter=verbose
```

**The suite is destructive to the server it points at.** The recovery
scenarios stop the server, copy its data directory aside, move the live
directory away and put a backup in its place, and a fresh run wipes every
vault. Point it only at an instance made for testing. Two guards exist: the
host must carry the marker file `~/obsync/.allow-device-tests` before the
harness will stop or alter anything, and in compose mode the harness
refuses the service name `obsync` (the production service) unless
`IOS_ALLOW_PROD_SERVER=1` is set. Do not set it.

`RemoteServer` knows two host layouts, chosen with `IOS_SERVER_MODE`:

| | `systemd` (the default) | `compose` |
| --- | --- | --- |
| What it is | `server/obsync.service`, as on the EC2 box the runs above used | a service in a Docker compose stack in the ssh user's home directory, as in `server/deploy/` |
| Stop and start | `sudo systemctl stop\|start <service>` | `cd ~ && docker compose stop\|start <service>` |
| CLI (create links) | `sudo /usr/local/bin/obsync … --data <data>` | `docker compose exec -T <service> obsync … --data /data` |
| `IOS_SERVER_SERVICE` default | `obsync` | `obsync-test` |
| `IOS_SERVER_DATA` default | `/var/lib/private/obsync` | `/var/lib/obsync-test` (the host path of the bind mount) |
| Backups made by the run | beside the data directory, `<data>.obsync-backup-<time>` | the same |

```sh
IOS_DEVICES=1 IOS_SERVER=https://sync-test.example.com IOS_SERVER_HOST=myhost \
IOS_SERVER_MODE=compose IOS_SERVER_SERVICE=obsync-test IOS_SERVER_DATA=/var/lib/obsync-test \
IOS_IPHONE=<udid or device name> IOS_IPAD=<udid or device name> \
npx vitest run test/ios-devices.test.ts --reporter=verbose
```

The compose layout needs a second service beside the production one: its
own container name, data directory, hostname and Caddy site. The deploy kit
does not create it yet, so as of 1.0.1 no device run has been made against
a compose host; the last full run (run 12, 2026-11-08, plugin 0.1.14) used
the systemd layout.

Each run mints a create link on the host over ssh (`sudo obsync vault
create`), creates a fresh vault with it, enrols the two devices from
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

## Checking the device keychain by hand

Since 0.2.2 a phone or tablet on Obsidian 1.11.4 or newer seals the vault
keys with the device keychain (the iOS Keychain through Obsidian's secret
storage; DESIGN.md §5.5a). The USB suite does not cover it: it enrols the
devices from the Mac and pushes a ready-made `data.json`, so the plugin's
own enrolment, where the protection is chosen, never runs. Check it by
hand. It needs no cable and no pairing:

1. On the device, in an empty test vault, install the plugin through BRAT
   (`instantcocoa/obsidian-sync`) and enable it.
2. Mint a create link on the server (`obsync vault create`) and scan its QR
   code with the camera, or paste the link under **Join or create with a
   link**. Press Create.
3. A notice says the vault keys are sealed with this device's keychain
   (unless **Sync notices** is off).
   Settings → obsync → **Protect keys** reads "Device keychain". If a PIN
   is offered instead, Obsidian's secret storage was not found.
4. Force-quit Obsidian from the app switcher and open the vault again.
5. Create or edit a note. Nothing should have been asked.
6. Confirm from the server that the device wrote after the relaunch (a
   higher `seq` for the vault in `obsync vault list`).
   Writing needs the vault keys, and after a relaunch the only way to them
   is the keychain entry, so this proves the entry was written and read
   back. Obsidian's own Settings → Keychain lists an entry starting with
   `obsync-`.

Result on 2026-11-23: iPhone 18,1, iOS 27.0.1, Obsidian 1.15.1, plugin
0.2.2. Vault created at 06:58:06 UTC with 9 ops; after a force-quit and
relaunch the same device posted 4 more ops at 07:01, nothing typed. Not yet
done on an iPad or on Android.

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
