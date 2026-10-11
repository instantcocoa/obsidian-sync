// Builds the Go server once so the end-to-end tests can spawn it.
import { execSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

export default function setup() {
  const serverDir = resolve(__dirname, "../../server");
  const out = resolve(__dirname, "../.cache/obsync-server");
  mkdirSync(resolve(__dirname, "../.cache"), { recursive: true });
  execSync(`go build -o ${JSON.stringify(out)} ./cmd/obsync`, { cwd: serverDir, stdio: "inherit" });
  process.env.OBSYNC_SERVER_BIN = out;
}
