# obsync

Self-hosted, end-to-end encrypted sync for Obsidian that syncs the whole
vault, `.obsidian` included, and is set up in two minutes.

- `DESIGN.md` — why, and the full design (data model, protocol, crypto,
  conflict rules). Starts with what we learned from reading Self-hosted
  LiveSync.
- `server/` — the Go server: one static binary, SQLite + a blob directory.
  See `server/README.md` for flags, TLS and the API.
- `plugin/` — the Obsidian plugin (TypeScript). See `plugin/README.md` for
  setup, what syncs, conflicts, devices and keys.
- `docs/` — `MOBILE-TEST-PROMPT.md`, a brief for an agent with an Android
  emulator or phone (the plugin has not yet been run on a device), and
  `SECURITY-REVIEW-GUIDE.md`, what a human security reviewer should check.

## Quick start

```sh
# server (try it locally first; https with --acme-domain or a reverse proxy when phones join)
cd server && go build -o obsync ./cmd/obsync
./obsync serve --data ./data --listen 127.0.0.1:8080
# it prints an admin token on first run and saves it to ./data/admin-token
# opening http://127.0.0.1:8080 in a browser confirms it is up

# plugin (warnings about esbuild install scripts are harmless)
cd plugin && npm install && npm run build
# copy main.js, manifest.json, styles.css into <vault>/.obsidian/plugins/obsync/
# restart Obsidian → Settings → Community plugins → turn off Restricted mode → enable obsync
# then: Settings → obsync → check the Device name → Create a new vault (server URL + admin token)
# other devices: same install, then Settings → obsync → Join with invite link
```

## Tests

```sh
cd server && go test ./...          # HTTP API end to end, incl. CAS races and rotation
cd plugin && npm test               # crypto vectors, merge, and multi-device e2e against the real server
```
