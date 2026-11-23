#!/usr/bin/env bash
# Off-host copy of the newest obsync snapshot, run by obsync-backup.service
# right after obsync-backup.sh (ExecStartPost). Uses restic against an
# S3-compatible bucket (Hetzner Object Storage in the reference deployment).
#
# Configuration lives in /etc/obsync/offsite.env (root, mode 600; see
# offsite.env.example). Without that file this script is a no-op, so a host
# without off-site credentials still gets its local snapshots.
#
# Restic deduplicates and encrypts; the repository password is in the env
# file and must also be kept somewhere off this host, or the copies are
# unreadable. Retention: 14 daily, 8 weekly, 12 monthly; prune on Sundays,
# a repository check on the first of the month.
set -euo pipefail
ENV=${OBSYNC_OFFSITE_ENV:-/etc/obsync/offsite.env}
DEST=${OBSYNC_BACKUP_DIR:-/var/backups/obsync}

if [[ ! -r "$ENV" ]]; then
  echo "obsync offsite: $ENV not present, skipping off-host copy"
  exit 0
fi
set -a; . "$ENV"; set +a
: "${RESTIC_REPOSITORY:?set in $ENV}" "${RESTIC_PASSWORD:?set in $ENV}"

latest=$(ls -1d "$DEST"/????-??-?? 2>/dev/null | tail -1 || true)
[[ -n "$latest" ]] || { echo "obsync offsite: no snapshot under $DEST"; exit 1; }

export RESTIC_CACHE_DIR=${RESTIC_CACHE_DIR:-/var/cache/obsync-restic}
mkdir -p "$RESTIC_CACHE_DIR"

restic cat config >/dev/null 2>&1 || restic init

# The snapshot directory changes name every day, so group by tag, not path.
restic backup --quiet --tag obsync-nightly --host obsync "$latest"
restic forget --quiet --tag obsync-nightly --group-by host,tags \
  --keep-daily 14 --keep-weekly 8 --keep-monthly 12
if [[ $(date -u +%u) == 7 ]]; then restic prune --quiet; fi
if [[ $(date -u +%d) == 01 ]]; then restic check --quiet --read-data-subset=10%; fi

echo "obsync offsite: $latest -> $RESTIC_REPOSITORY ($(restic snapshots --tag obsync-nightly --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))') snapshots kept)"
