# Moving a vault from Self-hosted LiveSync to obsync

The files already live on every device, so nothing moves server to server.
The first device creates the obsync vault and uploads; every other device
joins and finds its files already identical (identical bytes converge with
no conflict copy; anything that differs is kept as a sibling, never
overwritten). LiveSync is switched off, not removed, until obsync has run
for a few days.

This is the record of the reference migration (2026-11-23: vaults `Me` and
`Base`, CouchDB at o.frob.io on kratz, obsync at ob.frob.io) and the steps
for any other.

## 1. Backups taken first, and how to restore each

| What | Where | Restore |
| --- | --- | --- |
| LiveSync's CouchDB data (all vault databases), plus its compose file, ini and credentials | kratz `/var/backups/livesync/couchdb-data-2026-11-23.tgz` (+ `.sha256`, `docker-compose.yml`, `10-livesync.ini`, `couchdb.env`). Taken with CouchDB stopped. | `cd ~ && docker compose stop couchdb && sudo mv /opt/couchdb/data /opt/couchdb/data.replaced-$(date +%s) && sudo tar -C /opt/couchdb -xzf /var/backups/livesync/couchdb-data-2026-11-23.tgz && docker compose start couchdb` |
| The Mac's vault folders, whole, `.obsidian` included (LiveSync still enabled and configured in them) | Mac `~/Backups/obsidian-pre-obsync-2026-11-23/{Me,Base}.tgz` with `SHA256SUMS`; a second copy on kratz `/var/backups/pre-obsync/mac/` | Quit Obsidian. `cd ~/scratch/Obsidian && mv Me Me.replaced && tar -xzf ~/Backups/obsidian-pre-obsync-2026-11-23/Me.tgz` (same for `Base`). Reopen. |
| Both of the above, off the host | restic snapshot tagged `pre-obsync-migration` in the off-site bucket (`/etc/obsync/offsite.env` on kratz). The nightly job only forgets snapshots tagged `obsync-nightly`, so this one is kept until someone removes it. | `sudo sh -c 'set -a; . /etc/obsync/offsite.env; restic restore latest --tag pre-obsync-migration --target /var/backups/restored'`, then the rows above from `/var/backups/restored/var/backups/…` |
| The obsync server | nightly, `/var/backups/obsync/<date>/` and the same bucket (`server/README.md`) | `server/README.md`, "In Docker" |

The phone and tablet were not attached, so they have no archive of their
own: what they had synced is inside the CouchDB backup, and their vault
folders are untouched by anything below except the plugin switch.

## 2. Before switching

1. Let LiveSync finish on every device (open each vault once, wait for it
   to go quiet). Anything a device has not synced by then is not lost, it
   arrives later as a conflict copy, but it is tidier to start level.
2. Rename files whose names obsync cannot carry: `? * : < > " | \` are
   refused on every platform so a vault stays portable. Rename them inside
   Obsidian so links follow. 0.2.1 names such files in a notice instead of
   skipping them silently. In the reference vaults: `8 ball?.md`,
   `Instant Cocoa/Amazon App Store?.md` (Me), `pxe secureboot?.md` (Base).

## 3. First device (the desktop)

1. Community plugins: turn **Self-hosted LiveSync** off, install and turn
   **obsync** on (BRAT, `instantcocoa/obsidian-sync`). Do not run both at
   once in one vault. On the reference Mac this was done on disk: the
   plugin files are in `<vault>/.obsidian/plugins/obsync/` and
   `community-plugins.json` lists `obsync` in place of `obsidian-livesync`;
   it takes effect when Obsidian is restarted.
2. Mint a create link per vault on the server:
   `docker compose exec obsync obsync vault create --data /data --ttl 24h`
3. In the vault: Settings → obsync → **Join or create with a link** →
   paste → **Connect**. The first sync uploads the vault; wait for
   `obsync ✓` in the status bar.
4. **Set recovery passphrase**, and keep it with the vault id.

## 4. Every other device

1. Turn Self-hosted LiveSync off in that vault.
2. BRAT → Add beta plugin → `instantcocoa/obsidian-sync` → enable obsync.
3. On the first device: **Generate invite link**. Scan the QR with the
   camera (or paste the link) on the joining device. One invite per device,
   good for an hour.
4. Wait for `obsync ✓`. Run **Show conflicts**: an empty list means this
   device's copy was already identical.

## 5. Switch LiveSync off, keep it

Once every device has joined: `cd ~ && docker compose stop couchdb` on the
host. The container, its data in `/opt/couchdb/data`, the Caddy site and
each vault's `.obsidian/plugins/obsidian-livesync/data.json` all stay.

## 6. The trial days

- Status bar reads `obsync ✓` on each device after an edit elsewhere.
- **Show conflicts** stays empty, or lists only edits that really were
  concurrent.
- If one device drifts and the others are right: **Reset this device to
  the server's copy** (its local differences go to `.trash/obsync-reset-…`).
- Server side: `docker compose logs obsync`, and the nightly backup line in
  `journalctl -u obsync-backup`.

## 7. Going back to LiveSync

`docker compose start couchdb`; on each device turn obsync off and
Self-hosted LiveSync on. Its settings never left the vault. Notes edited
during the obsync days are ordinary files on every device, so LiveSync
picks them up from whichever device it starts on. If CouchDB itself is
damaged, restore it from the table above first.

## 8. Retiring LiveSync for good

After the trial: remove `./couchdb/docker-compose.yml` from the stack's
`include:`, `docker compose rm -sf couchdb couchdb-init`, delete the Caddy
site file and reload Caddy, uninstall the plugin on each device. Keep the
tarball and the restic snapshot until you no longer want a way back.
