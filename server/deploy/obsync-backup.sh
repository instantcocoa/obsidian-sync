#!/usr/bin/env bash
# Nightly backup of the obsync data directory, run by obsync-backup.timer.
#
# The database is copied with SQLite's online backup API (python3's sqlite3
# module; the server image has no shell, so this runs on the host), which
# gives a consistent snapshot while the server keeps serving. Blobs are
# content-addressed and immutable, so a plain rsync is a consistent copy
# too; a blob the sweep removes later is simply absent from the next
# snapshot. Everything in the backup is ciphertext, hashes and public keys.
#
# Layout: $DEST/<UTC date>/{obsync.db,blobs/}, hard-linked against the
# previous day's blobs, keeping the last $KEEP days.
#
# Restore (server/README.md, "Backup and restore"): stop the container,
# replace /var/lib/obsync with a snapshot, chown 65532, start. Devices notice
# the rewind and push back what the server forgot.
set -euo pipefail
DATA=${OBSYNC_DATA:-/var/lib/obsync}
DEST=${OBSYNC_BACKUP_DIR:-/var/backups/obsync}
KEEP=${OBSYNC_BACKUP_KEEP:-14}

today=$(date -u +%F)
out="$DEST/$today"
prev=$(ls -1d "$DEST"/????-??-?? 2>/dev/null | grep -v "$out" | tail -1 || true)

umask 077
mkdir -p "$out"
python3 - "$DATA/obsync.db" "$out/obsync.db.tmp" <<'PY'
import sqlite3, sys
src = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
dst = sqlite3.connect(sys.argv[2])
with dst:
    src.backup(dst)
ok = dst.execute("PRAGMA integrity_check").fetchone()[0]
src.close(); dst.close()
if ok != "ok":
    sys.exit(f"integrity_check on the snapshot: {ok}")
PY
mv -f "$out/obsync.db.tmp" "$out/obsync.db"
if [[ -n "$prev" && -d "$prev/blobs" ]]; then
  rsync -a --delete --link-dest="$prev/blobs" "$DATA/blobs/" "$out/blobs/"
else
  rsync -a --delete "$DATA/blobs/" "$out/blobs/"
fi

# Keep the newest $KEEP snapshots.
ls -1d "$DEST"/????-??-?? | head -n -"$KEEP" | xargs -r rm -rf

echo "obsync backup: $out ($(du -sh "$out" | cut -f1); $(ls -1d "$DEST"/????-??-?? | wc -l) snapshots kept)"
