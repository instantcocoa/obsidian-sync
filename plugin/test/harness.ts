/**
 * Test harness: spawns the Go server on a free port and builds "devices"
 * (a temp vault directory + an Engine) so tests can script multi-device
 * scenarios without Obsidian.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, promises as fsp } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { Engine, type EngineConfig, type EngineHooks } from "../src/core/engine";
import { NodeFS, FileStateStore } from "../src/core/node-fs";
import { openSession, syncIdentityKeys, type Session } from "../src/core/admin";
import { DEFAULT_EXCLUSIONS } from "../src/core/paths";

export const ADMIN = "ad_test-admin";

async function freePort(): Promise<number> {
  return new Promise((res) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => res(p));
    });
  });
}

export class TestServer {
  proc!: ChildProcess;
  url!: string;
  dir!: string;

  /** `rateLimit` keeps the production limiter on (the Obsidian suite); the Node suite redeems too many invites for that. */
  static async start(opts: { rateLimit?: boolean } = {}): Promise<TestServer> {
    const t = new TestServer();
    const bin = process.env.OBSYNC_SERVER_BIN!;
    t.dir = mkdtempSync(join(tmpdir(), "obsync-srv-"));
    const port = await freePort();
    t.url = `http://127.0.0.1:${port}`;
    t.proc = spawn(bin, ["serve", "--data", t.dir, "--listen", `127.0.0.1:${port}`, "--admin-token", ADMIN, "--gc-interval", "0", "--auth-rate", opts.rateLimit ? "10" : "-1"], { stdio: ["ignore", "ignore", "pipe"] });
    let log = "";
    t.proc.stderr!.on("data", (d) => (log += d));
    for (let i = 0; i < 100; i++) {
      try {
        if ((await fetch(t.url + "/healthz")).ok) return t;
      } catch {
        /* not up yet */
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error("server did not start: " + log);
  }

  async stop(): Promise<void> {
    this.proc.kill("SIGTERM");
    await new Promise((r) => this.proc.once("exit", r));
    rmSync(this.dir, { recursive: true, force: true });
  }

  /** Run the server's gc with the given retention (seconds) via a second process. */
  async gc(retention = "0s"): Promise<void> {
    await new Promise<void>((res, rej) => {
      const p = spawn(process.env.OBSYNC_SERVER_BIN!, ["gc", "--data", this.dir, "--retention", retention]);
      p.on("exit", (c) => (c === 0 ? res() : rej(new Error("gc failed"))));
    });
  }
}

export class Device {
  engine!: Engine;
  fs!: NodeFS;
  dir!: string;
  logs: string[] = [];
  conflicts: [string, string][] = [];
  uploads = 0;
  posts = 0;

  constructor(
    public name: string,
    public session: Session,
    public opts: Partial<EngineConfig> & { exclusions?: string[]; hooks?: EngineHooks; configDir?: string } = {},
  ) {}

  async start(dir?: string): Promise<this> {
    this.dir = dir ?? mkdtempSync(join(tmpdir(), `obsync-${this.name}-`));
    this.fs = new NodeFS(this.dir, this.opts.configDir ?? ".obsidian");
    const { identity } = this.session;
    // Count network writes so tests can assert "rename uploads nothing".
    const client = this.session.client;
    const origPut = client.putBlob.bind(client);
    client.putBlob = async (v, id, d) => {
      this.uploads++;
      return origPut(v, id, d);
    };
    const origPost = client.postOps.bind(client);
    client.postOps = async (v, ops) => {
      this.posts += ops.length;
      return origPost(v, ops);
    };
    this.engine = new Engine(
      this.fs,
      new FileStateStore(join(this.dir, this.fs.configDir, "plugins/obsync/state.json")),
      client,
      this.session.vc,
      {
        vaultId: identity.vaultId,
        deviceId: identity.deviceId,
        deviceName: this.name,
        privJwk: identity.privJwk,
        exclusions: this.opts.exclusions ?? DEFAULT_EXCLUSIONS,
        noLive: true,
        pollIntervalMs: 3_600_000,
        dotScanIntervalMs: 3_600_000,
        debounceMs: 50,
        ...this.opts,
      },
      {
        log: (lvl, msg, data) => this.logs.push(`${lvl}: ${msg}${data ? " " + String((data as Error)?.message ?? data) : ""}`),
        onConflict: (p, s) => this.conflicts.push([p, s]),
        onKeysChanged: () => syncIdentityKeys(this.session),
        ...(this.opts.hooks ?? {}),
      },
    );
    // Do not auto-start timers/watchers: tests drive sync explicitly for determinism.
    await (this.engine as unknown as { loadState: () => Promise<void> }).loadState();
    (this.engine as unknown as { stopped: boolean }).stopped = false;
    return this;
  }

  /** Full cycle: scan disk, then pull/push. */
  async sync(): Promise<void> {
    await this.engine.scan();
    await this.engine.sync();
    const st = this.engine.getStatus();
    if (st.phase === "error" || st.phase === "offline") throw new Error(`${this.name} sync ${st.phase}: ${st.message}`);
  }

  /**
   * Simulate restart: new Engine over the same directory and identity.
   * `crash` skips flushing state, so whatever is on disk (possibly doctored
   * by the test) is what the new engine sees.
   */
  async restart(opts: { crash?: boolean } = {}): Promise<void> {
    if (!opts.crash) await this.engine.flushState();
    this.session = openSession(this.session.identity);
    await this.start(this.dir);
  }

  async write(path: string, content: string | Uint8Array, mtime?: number): Promise<void> {
    const data = typeof content === "string" ? new TextEncoder().encode(content) : content;
    await this.fs.write(path, data, mtime ?? Date.now());
  }
  async read(path: string): Promise<string> {
    return new TextDecoder().decode(await this.fs.read(path));
  }
  async readBytes(path: string): Promise<Uint8Array> {
    return this.fs.read(path);
  }
  async exists(path: string): Promise<boolean> {
    return (await this.fs.stat(path)) !== null;
  }
  async remove(path: string): Promise<void> {
    await this.fs.remove(path);
  }
  async files(): Promise<string[]> {
    return (await this.fs.list())
      .map((f) => f.path)
      .filter((p) => !p.startsWith(`${this.fs.configDir}/plugins/obsync/`))
      .sort();
  }
  async stateFile(): Promise<string> {
    return join(this.dir, this.fs.configDir, "plugins/obsync/state.json");
  }
  async cleanup(): Promise<void> {
    await this.engine.stop();
    rmSync(this.dir, { recursive: true, force: true });
  }
  async rawWrite(path: string, data: Uint8Array): Promise<void> {
    await fsp.mkdir(join(this.dir, path, ".."), { recursive: true });
    await fsp.writeFile(join(this.dir, path), data);
  }
}
