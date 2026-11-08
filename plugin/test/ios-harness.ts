/**
 * Drives Obsidian for iOS on a physical iPhone or iPad plugged into a Mac,
 * through Xcode's `devicectl` (Xcode 15+, Developer Mode on the device) and
 * pymobiledevice3 (`uv tool install pymobiledevice3`). No jailbreak, no UI
 * automation: files go in and out of Obsidian's iTunes file-sharing folder
 * (its Documents, where "On My iPhone" vaults live), the app is launched and
 * killed by bundle id through devicectl, and in-app edits
 * are made through `obsidian://new` URIs, which Obsidian handles through its
 * vault API exactly as a typed edit.
 *
 * Every call shells out, so expect one to three seconds each. Tests should
 * poll with `waitFor` rather than sleep.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const OBSIDIAN_IOS = "md.obsidian";
const SAFARI = "com.apple.mobilesafari";
const AFC_SCRIPT = join(__dirname, "ios-afc.py");
/** The interpreter that has pymobiledevice3 installed (`uv tool install pymobiledevice3`). */
const AFC_PYTHON = process.env.IOS_AFC_PYTHON ?? join(process.env.HOME ?? "", ".local/share/uv/tools/pymobiledevice3/bin/python");

/** Obsidian's URI parser takes `+` literally, so spaces must be %20: not URLSearchParams. */
function query(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join("&");
}

export class IosDevice {
  /** Vault root inside the app container, e.g. `Documents/obsync`. */
  readonly vaultDir: string;
  constructor(
    public name: string,
    public udid: string,
    public vaultName = "obsync",
    public shots = join(process.cwd(), ".cache", "ios"),
  ) {
    this.vaultDir = `Documents/${vaultName}`;
    mkdirSync(shots, { recursive: true });
  }

  /** Run `xcrun devicectl <args>`; returns stdout+stderr; throws unless `ok` says the output is acceptable. */
  dc(args: string[], opts: { ok?: (out: string) => boolean; timeoutMs?: number } = {}): string {
    // --device must precede a positional bundle id, or devicectl hands it to the app as an argument.
    const r = spawnSync("xcrun", ["devicectl", ...args.slice(0, 3), "--device", this.udid, ...args.slice(3)], { encoding: "utf8", timeout: opts.timeoutMs ?? 180_000 });
    const out = (r.stdout ?? "") + (r.stderr ?? "");
    if (r.status !== 0 && !(opts.ok && opts.ok(out))) throw new Error(`devicectl ${args.slice(0, 3).join(" ")} on ${this.name} failed (${r.status}): ${out.slice(-800)}`);
    return out;
  }

  // ---- files ----
  //
  // devicectl's appDataContainer domain refuses App Store apps, so files go
  // through the app's iTunes file-sharing view (AFC house_arrest, what the
  // Files app and Finder use) via pymobiledevice3: `apps push|pull|rm
  // --documents`. Semantics probed on iOS 17 and 26: pushing a directory
  // creates it under the destination (merging into an existing one), pushing
  // a file to a directory keeps its name, parents are not created, and a
  // missing path answers OBJECT_NOT_FOUND.

  /** Run `pymobiledevice3 apps <cmd> --documents …`; returns combined output; `ok` says which failures are acceptable. */
  apps(cmd: string, args: string[], opts: { ok?: (out: string) => boolean } = {}): string {
    const r = spawnSync("pymobiledevice3", ["apps", cmd, "--documents", "--udid", this.udid, OBSIDIAN_IOS, ...args], { encoding: "utf8", timeout: 600_000 });
    const out = (r.stdout ?? "") + (r.stderr ?? "");
    if (r.status !== 0 && !(opts.ok && opts.ok(out))) throw new Error(`pymobiledevice3 apps ${cmd} on ${this.name} failed (${r.status}): ${out.slice(-800)}`);
    return out;
  }

  private remote(rel: string): string {
    return rel ? `/${this.vaultDir}/${rel}` : `/${this.vaultDir}`;
  }

  /** Upload a local file or directory into the vault directory `relDir` (a directory lands as `relDir/<basename>`). */
  push(local: string, relDir = ""): void {
    this.apps("push", [local, this.remote(relDir)]);
  }

  /** Download `rel` to `local` (a file lands at `local`, a directory at `local/<basename>`). False when it does not exist. */
  pull(rel: string, local: string): boolean {
    const out = this.apps("pull", [this.remote(rel), local], { ok: (o) => /OBJECT_NOT_FOUND/.test(o) });
    return !/OBJECT_NOT_FOUND/.test(out);
  }

  /**
   * Single-file operations go through test/ios-afc.py (pymobiledevice3's
   * library): one round trip each, instead of the CLI's pull of a whole tree.
   */
  private afc(cmd: string, path: string, input?: Uint8Array): { status: number; out: Buffer } {
    const r = spawnSync(AFC_PYTHON, [AFC_SCRIPT, this.udid, cmd, this.remote(path)], { input, timeout: 300_000, maxBuffer: 256 * 1024 * 1024 });
    if (r.status !== 0 && r.status !== 2) throw new Error(`ios-afc ${cmd} ${path} on ${this.name} failed (${r.status}): ${String(r.stderr).slice(-600)}`);
    return { status: r.status ?? 1, out: r.stdout as Buffer };
  }

  /** Write a vault file, creating parent directories. */
  async write(path: string, content: string | Uint8Array): Promise<void> {
    this.afc("write", path, typeof content === "string" ? new TextEncoder().encode(content) : content);
  }

  async readBytes(path: string): Promise<Uint8Array | null> {
    const r = this.afc("cat", path);
    return r.status === 0 ? new Uint8Array(r.out) : null;
  }

  async read(path: string): Promise<string | null> {
    const b = await this.readBytes(path);
    return b ? new TextDecoder().decode(b) : null;
  }

  async exists(path: string): Promise<boolean> {
    return this.afc("exists", path).status === 0;
  }

  /** Every vault file as a `/`-separated path, except the config dir, like Device.files(). */
  async files(): Promise<string[]> {
    const r = this.afc("ls", "");
    return String(r.out)
      .split("\n")
      .filter((p) => p && !p.startsWith(".obsidian/"))
      .sort();
  }

  /** Delete a file or directory tree; a missing path is not an error. */
  async remove(path: string): Promise<void> {
    this.afc("rm", path);
  }

  /** Empty the vault of everything but Obsidian's own config: a fresh start for a run. */
  async wipe(): Promise<void> {
    const r = this.afc("ls", "");
    const tops = new Set(
      String(r.out)
        .split("\n")
        .filter(Boolean)
        .map((p) => p.split("/")[0]),
    );
    for (const t of tops) if (t !== ".obsidian") await this.remove(t);
    await this.remove(".obsidian/plugins/obsync");
  }

  /** The plugin's persisted engine state, or null before the first sync. */
  async state(): Promise<Record<string, unknown> | null> {
    const s = await this.read(".obsidian/plugins/obsync/state.json");
    return s ? (JSON.parse(s) as Record<string, unknown>) : null;
  }

  // ---- the app ----

  /** Run a devicectl command with `--json-output` into a file (its human-readable chatter shares stdout otherwise) and return the parsed result. */
  private dcJson<T>(args: string[]): T {
    const tmp = mkdtempSync(join(tmpdir(), "ios-j-"));
    try {
      const f = join(tmp, "out.json");
      this.dc([...args, "--json-output", f]);
      return (JSON.parse(readFileSync(f, "utf8")) as { result?: T }).result as T;
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }

  pid(): number | null {
    const r = this.dcJson<{ runningProcesses?: { executable?: string; processIdentifier: number }[] }>(["device", "info", "processes"]);
    const p = (r?.runningProcesses ?? []).find((x) => /\/Obsidian\.app\/Obsidian$/.test(x.executable ?? ""));
    return p?.processIdentifier ?? null;
  }

  /** Launch (or relaunch) Obsidian in the foreground; returns its pid. */
  launch(opts: { fresh?: boolean } = {}): number {
    const r = this.dcJson<{ process?: { processIdentifier: number } }>(["device", "process", "launch", ...(opts.fresh ? ["--terminate-existing"] : []), "--activate", OBSIDIAN_IOS]);
    const pid = r?.process?.processIdentifier;
    if (!pid) throw new Error(`launch on ${this.name}: no pid in ${JSON.stringify(r).slice(-300)}`);
    return pid;
  }

  /** SIGKILL Obsidian: a force quit, nothing flushed. No-op when it is not running. */
  kill(): void {
    const pid = this.pid();
    if (pid) this.dc(["device", "process", "terminate", "--kill", "--pid", String(pid)], { ok: () => true });
  }

  /** Put Obsidian in the background by bringing Safari to the front. */
  background(): void {
    this.dc(["device", "process", "launch", "--activate", SAFARI]);
  }

  /** Bring Obsidian back to the front without restarting it. */
  foreground(): void {
    this.launch();
  }

  openURL(url: string): void {
    this.dc(["device", "process", "openURL", url]);
  }

  /** Create or overwrite a note through Obsidian itself (`obsidian://new`), the way a typed edit reaches the vault API. */
  newNote(path: string, content: string): void {
    this.openURL(`obsidian://new?${query({ vault: this.vaultName, file: path.replace(/\.md$/, ""), content, overwrite: "true" })}`);
  }

  /** Append to a note through Obsidian (`obsidian://new?append`). */
  appendNote(path: string, content: string): void {
    this.openURL(`obsidian://new?${query({ vault: this.vaultName, file: path.replace(/\.md$/, ""), content, append: "true" })}`);
  }

  /** Open the vault (and optionally a file) in Obsidian. */
  open(file?: string): void {
    this.openURL(`obsidian://open?${query({ vault: this.vaultName, ...(file ? { file: file.replace(/\.md$/, "") } : {}) })}`);
  }

  /** Save a screenshot as `<UTC time>-<device>-<label>.png`, so a directory of them reads as a timeline. */
  screenshot(label: string): string {
    const ts = new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
    const f = join(this.shots, `${ts}-${this.name}-${label.replace(/[^\w.-]+/g, "_").slice(0, 60)}.png`);
    this.dc(["device", "capture", "screenshot", "--destination", f], { ok: () => true });
    return f;
  }
}

/**
 * The obsync server on a real host reached over ssh, with the halt/resume/
 * backup/restore surface of TestServer so the recovery scenarios read the
 * same. `host` is an ssh config alias; the server lives in `~/obsync` there
 * as the systemd unit `obsync.service` (server/obsync.service), data under
 * /var/lib/private/obsync (DynamicUser's StateDirectory); the ssh user can sudo.
 */
export class RemoteServer {
  constructor(
    public url: string,
    public host: string,
    public admin: string,
  ) {}

  sh(cmd: string): string {
    const r = spawnSync("ssh", ["-o", "BatchMode=yes", this.host, cmd], { encoding: "utf8", timeout: 120_000 });
    if (r.status !== 0) throw new Error(`ssh ${this.host}: ${cmd}: ${(r.stdout + r.stderr).slice(-500)}`);
    return r.stdout;
  }

  async healthy(): Promise<boolean> {
    try {
      return (await fetch(`${this.url}/healthz`, { signal: AbortSignal.timeout(8_000) })).ok;
    } catch {
      return false;
    }
  }

  private static readonly DATA = "/var/lib/private/obsync";

  /** The server must carry an operator-placed marker before this harness stops, wipes or restores it. */
  private assertTestServer(): void {
    const r = spawnSync("ssh", ["-o", "BatchMode=yes", this.host, "test -f ~/obsync/.allow-device-tests"], { encoding: "utf8", timeout: 60_000 });
    if (r.status !== 0) throw new Error(`${this.host} has no ~/obsync/.allow-device-tests marker; refusing to stop or alter it (create the file on the host to allow device runs)`);
  }

  async halt(): Promise<void> {
    this.assertTestServer();
    this.sh("sudo systemctl stop obsync");
    await waitFor("server down", async () => !(await this.healthy()), 60_000, 2_000);
  }

  async resume(): Promise<void> {
    this.sh("sudo systemctl start obsync");
    await waitFor("server up", () => this.healthy(), 90_000, 2_000);
  }

  async restart(): Promise<void> {
    await this.halt();
    await this.resume();
  }

  /** Snapshot the data directory while stopped (the ACME cache included, so the certificate survives a restore). */
  /** Run `fn` with the unit stopped; the unit is started again whatever happens. */
  private async whileStopped(fn: () => void): Promise<void> {
    await this.halt();
    try {
      fn();
    } finally {
      await this.resume();
    }
  }

  private static backupName(name: string): string {
    if (!/^obsync-backup-\d{10,16}$/.test(name)) throw new Error(`not a backup name this harness made: ${JSON.stringify(name)}`);
    return name;
  }

  async backup(): Promise<string> {
    const name = `obsync-backup-${Date.now()}`;
    await this.whileStopped(() => this.sh(`sudo cp -a ${RemoteServer.DATA} /var/lib/private/${name}`));
    return name;
  }

  /** Restore a backup made by `backup()`: the live data directory is moved aside, never deleted. */
  async restoreFrom(name: string): Promise<void> {
    const n = RemoteServer.backupName(name);
    await this.whileStopped(() => this.sh(`sudo test -d /var/lib/private/${n} && sudo mv ${RemoteServer.DATA} ${RemoteServer.DATA}.replaced-${Date.now()} && sudo cp -a /var/lib/private/${n} ${RemoteServer.DATA}`));
  }

  /** Remove every vault and blob but keep the ACME cache and the admin token: a fresh server for the next run. */
  async wipe(): Promise<void> {
    await this.whileStopped(() => this.sh(`sudo find ${RemoteServer.DATA} -mindepth 1 -maxdepth 1 ! -name acme ! -name admin-token -exec rm -rf {} +`));
  }
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Poll `probe` until it returns a non-null, non-false value or `ms` elapse; throws with `what` on timeout. */
export async function waitFor<T>(what: string, probe: () => Promise<T | null | false | undefined>, ms = 120_000, everyMs = 4_000): Promise<T> {
  const t0 = Date.now();
  let last: unknown;
  while (Date.now() - t0 < ms) {
    try {
      const v = await probe();
      if (v !== null && v !== false && v !== undefined) return v;
    } catch (e) {
      last = e;
    }
    await sleep(everyMs);
  }
  throw new Error(`timed out after ${Math.round((Date.now() - t0) / 1000)}s waiting for ${what}${last ? `: ${String((last as Error).message ?? last)}` : ""}`);
}
