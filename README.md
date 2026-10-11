# obsync

Self-hosted, end-to-end encrypted sync for Obsidian that syncs the whole
vault, `.obsidian` included, and is set up in two minutes.

- `DESIGN.md` — why, and the full design (data model, protocol, crypto,
  conflict rules). Starts with what we learned from reading Self-hosted
  LiveSync.
- `server/` — the Go server: one static binary, SQLite + a blob directory.
- `plugin/` — the Obsidian plugin (TypeScript).

## Quick start

```sh
# server
cd server && go build -o obsync ./cmd/obsync
./obsync serve --data /var/lib/obsync --acme-domain sync.example.com   # or --listen :8080 behind a proxy
# it prints an admin token on first run

# plugin
cd plugin && npm install && npm run build
# copy main.js, manifest.json, styles.css into <vault>/.obsidian/plugins/obsync/
# then: Settings → obsync → Create a new vault (server URL + admin token)
# other devices: Settings → obsync → Join with invite link
```

## Tests

```sh
cd server && go test ./...          # HTTP API end to end, incl. CAS races and rotation
cd plugin && npm test               # crypto vectors, merge, and multi-device e2e against the real server
```
