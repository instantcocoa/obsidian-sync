#!/usr/bin/env bash
# Deploy the obsync server to a host that runs a compose stack with a shared
# Caddy (kratz). Idempotent: run it again to ship a new build.
#
#   server/deploy/deploy.sh [host]          default host: kratz
#
# What it does on the host:
#   ~/obsync/src                 the server source (rsync of server/)
#   ~/obsync/docker-compose.yml  deploy/docker-compose.yml
#   ~/caddy/conf/sites/ob.caddy  the Caddy site file (deploy/ob.caddy)
#   ~/docker-compose.yml         gains "- ./obsync/docker-compose.yml" under include:
#   /var/lib/obsync              data, owned by uid 65532 (the image's user)
#   /usr/local/sbin/obsync-backup.sh + obsync-backup.{service,timer}
#                                nightly snapshot to /var/backups/obsync (14 kept)
# then builds the image, starts the service, reloads Caddy and checks
# https://<site>/healthz.
set -euo pipefail
host=${1:-kratz}
site=${OBSYNC_SITE:-ob.frob.io}
sitefile=${site%%.*}.caddy   # ob.frob.io -> ob.caddy, the stack's naming
here=$(cd "$(dirname "$0")" && pwd)
server=$(cd "$here/.." && pwd)

echo "== sync source and config to $host"
ssh "$host" 'mkdir -p ~/obsync ~/caddy/conf/sites'
rsync -az --delete --exclude '/obsync' --exclude '/obsync-*' --exclude '*.db*' --exclude '/deploy/' "$server/" "$host:obsync/src/"
rsync -az "$here/docker-compose.yml" "$host:obsync/docker-compose.yml"
rsync -az "$here/$sitefile" "$host:caddy/conf/sites/$sitefile"
rsync -az "$here/obsync-backup.sh" "$here/obsync-backup.service" "$here/obsync-backup.timer" "$host:obsync/"

echo "== wire into the stack"
ssh "$host" bash -s <<'REMOTE'
set -euo pipefail
cd ~
if ! grep -q 'obsync/docker-compose.yml' docker-compose.yml; then
  # Add to the include: list right after the line that opens it.
  awk '{print} /^include:/ && !done {print "  - ./obsync/docker-compose.yml"; done=1}' docker-compose.yml > docker-compose.yml.new
  mv docker-compose.yml.new docker-compose.yml
fi
sudo mkdir -p /var/lib/obsync
sudo chown 65532:65532 /var/lib/obsync
sudo chmod 700 /var/lib/obsync
sudo install -m 755 ~/obsync/obsync-backup.sh /usr/local/sbin/obsync-backup.sh
sudo install -m 644 ~/obsync/obsync-backup.service ~/obsync/obsync-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now obsync-backup.timer >/dev/null 2>&1
docker compose build --pull obsync
docker compose up -d obsync
docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile >/dev/null
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
REMOTE

echo "== health"
for i in $(seq 1 30); do
  if curl -fsS "https://$site/healthz" >/dev/null 2>&1; then
    echo "https://$site is up"
    exit 0
  fi
  sleep 2
done
echo "https://$site did not answer; see: ssh $host docker compose logs obsync caddy" >&2
exit 1
