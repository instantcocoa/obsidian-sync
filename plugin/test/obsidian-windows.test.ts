/**
 * Windows-specific behaviour of the shipped plugin inside real Obsidian on
 * Windows. The other device is "a Linux device": a Node engine over a
 * case-sensitive NTFS directory (`fsutil file setCaseSensitiveInfo`), which
 * really holds `Note.md` beside `note.md`, plus hand-built ops for the names
 * NTFS cannot hold at all (the way e2e.test.ts forges ops).
 *
 * Scenarios: reserved and invalid names, case twins, case-only rename, long
 * paths, DPAPI key protection, a file locked by another process, CRLF/LF
 * merge. Each one records what happened in its console output so the run
 * log is evidence, and asserts only the invariants: no crash, no loop, no
 * silent overwrite, and either a clean sync or a report.
 *
 * Runs only on win32 with OBSIDIAN_BIN set:
 *   $env:OBSIDIAN_BIN="$env:LOCALAPPDATA\Programs\Obsidian\Obsidian.exe"; npx vitest run test/obsidian-windows.test.ts
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, promises as fsp } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { ObsidianInstance, OBSIDIAN_BIN } from "./obsidian-harness";
import { joinWithLink, type Session } from "../src/core/admin";
import { fromB64, hex, randomBytes, utf8 } from "../src/core/encoding";

const WIN = process.platform === "win32";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Upload `content` under `path` as if a device whose file system allows the name had synced it. */
async function forgePut(s: Session, path: string, content: string): Promise<number> {
  const { vc, client, identity } = s;
  const bytes = utf8(content);
  const bid = await vc.blobId(bytes);
  const pid = await vc.pathId(path);
  if ((await client.missingBlobs(identity.vaultId, [bid])).includes(bid)) await client.putBlob(identity.vaultId, bid, await vc.encryptBlob(bid, bytes));
  const base = (await client.history(identity.vaultId, pid)).at(-1)?.seq ?? 0;
  const r = await client.postOps(identity.vaultId, [
    { op_id: hex(randomBytes(12)), path_id: pid, blob_id: bid, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: bytes.length }), meta_epoch: vc.keyring.current, base_seq: base },
  ]);
  const seq = r.results[0].seq;
  if (!seq) throw new Error(`forged op for ${path} rejected: ${JSON.stringify(r.results[0])}`);
  return seq;
}

/** Every file under `root` as a "/"-separated relative path, except the config dir. */
async function listVault(root: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (rel: string) => {
    for (const e of await fsp.readdir(join(root, rel), { withFileTypes: true })) {
      const p = rel ? `${rel}/${e.name}` : e.name;
      if (p === ".obsidian") continue;
      if (e.isDirectory()) await walk(p);
      else out.push(p);
    }
  };
  await walk("");
  return out.sort();
}

describe.skipIf(!OBSIDIAN_BIN || !WIN)("real Obsidian on Windows", () => {
  let srv: TestServer;
  let w: ObsidianInstance; // the Windows device
  let linux: Device; // Node engine on a case-sensitive directory: the Linux device

  /** Capture the engine's skip/conflict hooks and warn/error log on W. Call again after an engine restart. */
  async function observe(): Promise<void> {
    await w.eval((plugin) => {
      const g = globalThis as any;
      g.__skipped = [];
      g.__log = [];
      g.__conflicts = [];
      const h = plugin.engine.hooks;
      const [os, ol, oc] = [h.onSkipped, h.log, h.onConflict];
      h.onSkipped = (p: string, why: string) => {
        g.__skipped.push([p, why]);
        os?.(p, why);
      };
      h.log = (l: string, m: string, d: any) => {
        if (l === "warn" || l === "error") g.__log.push(`${l}: ${m}${d ? " " + JSON.stringify(d?.path ?? d?.message ?? d) : ""}`);
        ol?.(l, m, d);
      };
      h.onConflict = (p: string, s: string) => {
        g.__conflicts.push([p, s]);
        oc?.(p, s);
      };
    });
  }
  const taken = async (name: string): Promise<any[]> =>
    w.eval((_p, _a, n) => {
      const g = globalThis as any;
      const v = g[n] ?? [];
      g[n] = [];
      return v;
    }, name);
  async function waitCursor(seq: number, timeoutMs = 45_000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (((await w.eval((p) => p.engine?.state.cursor)) ?? 0) >= seq) return true;
      await sleep(300);
    }
    return false;
  }
  async function waitSkipped(path: string, timeoutMs = 30_000): Promise<[string, string] | null> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const hit = ((await w.eval(() => (globalThis as any).__skipped)) as [string, string][]).find(([p]) => p === path);
      if (hit) return hit;
      await sleep(300);
    }
    return null;
  }
  /** Sync the Linux device until `pred` holds or the time is up. */
  async function linuxUntil(pred: () => Promise<boolean>, timeoutMs = 45_000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await linux.sync();
      if (await pred()) return true;
      await sleep(500);
    }
    return false;
  }
  /**
   * Which paths got new ops on the server while both devices idle. Obsidian
   * itself may save a config file once; a put/delete loop shows as the same
   * note again and again. Returns the device paths, with "$CONFIG" for the
   * config dir.
   */
  async function idleOps(ms = 8_000): Promise<string[]> {
    await linux.sync();
    const c1 = linux.engine.state.cursor;
    await sleep(ms);
    const { vc, client, identity } = linux.session;
    const feed = await client.changes(identity.vaultId, c1, { limit: 500 });
    const paths: string[] = [];
    for (const op of feed.ops) paths.push(await vc.decryptMeta(op.path_id, fromB64(op.meta_enc)).then((m) => m.path, () => `<undecryptable ${op.path_id.slice(0, 8)}>`));
    if (paths.length) console.log(`ops while idle: ${JSON.stringify(paths)}`);
    await linux.sync();
    return paths;
  }
  /** Idle ops that touch notes (not Obsidian's own config saves). */
  const noteOps = async () => (await idleOps()).filter((p) => !p.startsWith("$CONFIG/"));
  const wStatus = () => w.eval((p) => p.engine?.getStatus());

  beforeAll(async () => {
    srv = await TestServer.start();
    w = await ObsidianInstance.launch("win");
    await w.eval((plugin, _app, url, admin) => plugin.createVault(url, admin), srv.url, ADMIN);
    expect((await w.eval((p) => p.settings.identity)).vaultId).toMatch(/^[0-9a-f]{32}$/);
    expect(await w.waitFor(() => (globalThis as any).app.plugins.plugins.obsync.engine?.ws?.readyState === 1, 20_000)).toBe(true);
    const link: string = await w.eval((plugin) => plugin.inviteLink());
    const session = await joinWithLink(link, "linux");
    const dir = mkdtempSync(join(tmpdir(), "obsync-linux-"));
    const cs = spawnSync("fsutil", ["file", "setCaseSensitiveInfo", dir, "enable"], { encoding: "utf8" });
    if (cs.status !== 0) throw new Error(`cannot make a case-sensitive directory: ${cs.stdout}${cs.stderr}`);
    linux = await new Device("linux", session).start(dir);
    await linux.sync();
    await observe();
  }, 180_000);

  afterAll(async () => {
    await linux?.cleanup().catch(() => {});
    await w?.stop();
    await srv?.stop();
  });

  it("1. names NTFS cannot hold are refused and reported; everything else keeps syncing", async () => {
    // Reserved device names, a trailing dot or space, and the characters
    // Windows forbids. None can exist on NTFS; "semi:colon.md" is the
    // dangerous one because NTFS would silently write it as an alternate
    // data stream of a file called "semi".
    const bad = ["CON.md", "aux.txt", "notes/NUL", "trailing.", "space ", "semi:colon.md", "pipe|x.md", "quest?.md"];
    // Valid on NTFS: only the final character of a name may not be a dot or a space.
    const ok = ["trailing. .md", "space .md"];
    for (const p of [...bad, ...ok]) await forgePut(linux.session, p, `content of ${p}\n`);
    const seq = await forgePut(linux.session, "after-bad-names.md", "still syncing\n");
    expect(await w.waitForFile("after-bad-names.md", "still syncing\n")).not.toBeNull();
    expect(await waitCursor(seq)).toBe(true);
    await sleep(3000);
    const files = await listVault(w.vault);
    const skipped = (await taken("__skipped")) as [string, string][];
    const log = (await taken("__log")) as string[];
    console.log(`files on W: ${JSON.stringify(files)}\nskipped: ${JSON.stringify(skipped)}\nlog: ${JSON.stringify(log, null, 1)}`);
    for (const p of bad) {
      expect(files).not.toContain(p);
      // Nothing written under a different name either: no "semi" (+ADS), no "trailing", no "space", no stripped punctuation.
      const stem = p.split("/").pop()!.replace(/[.:|? ].*$/, "");
      expect(files.filter((f) => !ok.includes(f) && f.split("/").pop()!.toLowerCase().startsWith(stem.toLowerCase()))).toEqual([]);
      // Either reported to the user (onSkipped) or refused in the error log; the report says which.
      const reported = skipped.some(([q]) => q === p);
      const refused = log.some((l) => l.includes(p));
      console.log(`${p}: ${reported ? "reported via onSkipped" : refused ? "refused (error log only)" : "NOT MENTIONED"}`);
      expect(reported || refused).toBe(true);
    }
    for (const p of ok) expect(files).toContain(p);
    expect((await wStatus()).phase).not.toBe("error");
    expect(await noteOps()).toEqual([]);
  }, 120_000);

  it("2. case twins from Linux (Note.md and note.md) never silently overwrite each other", async () => {
    await linux.write("Note.md", "upper\n");
    await linux.write("note.md", "lower\n");
    await linux.sync();
    expect(await waitCursor(linux.engine.state.cursor)).toBe(true);
    await sleep(4000);
    const files = (await listVault(w.vault)).filter((f) => f.toLowerCase() === "note.md" || /^note \(conflict/i.test(f));
    const contents: Record<string, string> = {};
    for (const f of files) contents[f] = await fsp.readFile(join(w.vault, f), "utf8");
    const skipped = (await taken("__skipped")) as [string, string][];
    const conflicts = (await taken("__conflicts")) as [string, string][];
    const log = (await taken("__log")) as string[];
    console.log(`W holds: ${JSON.stringify(contents)}\nskipped: ${JSON.stringify(skipped)}\nconflicts: ${JSON.stringify(conflicts)}\nlog: ${JSON.stringify(log, null, 1)}`);
    // No crash, and nothing bounced back to the server in a loop.
    expect((await wStatus()).phase).not.toBe("error");
    expect(await noteOps()).toEqual([]);
    // Linux still has both, byte for byte.
    expect(await linux.read("Note.md")).toBe("upper\n");
    expect(await linux.read("note.md")).toBe("lower\n");
    // W holds at least one of them under its own name, and the other was not lost silently:
    // it is either on disk too (sibling or exact twin), or it was reported.
    expect(files.length).toBeGreaterThan(0);
    const held = new Set(Object.values(contents));
    const missing = [["Note.md", "upper\n"], ["note.md", "lower\n"]].filter(([, c]) => !held.has(c));
    for (const [name] of missing) {
      const reported = skipped.some(([p]) => p.toLowerCase() === "note.md") || conflicts.some(([p]) => p.toLowerCase() === "note.md");
      console.log(`${name} is not on W: ${reported ? "reported" : "SILENTLY DROPPED"}`);
      expect(reported).toBe(true);
    }
  }, 120_000);

  it("3. case-only rename on Windows reaches the other device as one file with the new casing", async () => {
    await w.eval((_p, app) => app.vault.create("Readme.md", "readme\n"));
    expect(await linuxUntil(async () => (await linux.files()).includes("Readme.md"))).toBe(true);
    await w.eval(async (_p, app) => app.fileManager.renameFile(app.vault.getAbstractFileByPath("Readme.md"), "README.md"));
    const ok = await linuxUntil(async () => {
      const f = await linux.files();
      return f.includes("README.md") && !f.includes("Readme.md");
    }, 60_000);
    const onLinux = (await linux.files()).filter((f) => f.toLowerCase() === "readme.md");
    const onW = (await listVault(w.vault)).filter((f) => f.toLowerCase() === "readme.md");
    console.log(`after case-only rename: linux=${JSON.stringify(onLinux)} W=${JSON.stringify(onW)} log=${JSON.stringify(await taken("__log"))}`);
    expect(onW).toEqual(["README.md"]);
    expect(ok).toBe(true);
    expect(onLinux).toEqual(["README.md"]);
    expect(await linux.read("README.md")).toBe("readme\n");
    expect(await noteOps()).toEqual([]);
  }, 150_000);

  it("4. long paths: a 240-character component and a 300-character path sync cleanly or are reported, never crash", async () => {
    const comp = "c".repeat(240) + ".md"; // 243 bytes: under the 255-byte component limit
    const deep = ["d".repeat(60), "e".repeat(60), "f".repeat(60), "g".repeat(60), "h".repeat(56) + ".md"].join("/"); // 300 chars
    const cases = [comp, deep];
    for (const p of cases) await forgePut(linux.session, p, `long ${p.length}\n`);
    const seq = await forgePut(linux.session, "after-long.md", "after long\n");
    expect(await w.waitForFile("after-long.md", "after long\n")).not.toBeNull();
    expect(await waitCursor(seq)).toBe(true);
    await sleep(3000);
    const files = await listVault(w.vault);
    const skipped = (await taken("__skipped")) as [string, string][];
    const log = (await taken("__log")) as string[];
    const vaultLen = w.vault.length;
    for (const p of cases) {
      const synced = files.includes(p) && (await fsp.readFile(join(w.vault, p), "utf8")) === `long ${p.length}\n`;
      const reported = skipped.find(([q]) => q === p);
      console.log(`${p.length}-char path (absolute ${vaultLen + 1 + p.length}): ${synced ? "synced cleanly" : reported ? `skipped and reported: ${reported[1]}` : "NEITHER"}`);
      expect(synced || Boolean(reported)).toBe(true);
    }
    console.log(`log: ${JSON.stringify(log, null, 1)}`);
    expect((await wStatus()).phase).not.toBe("error");
    expect(await noteOps()).toEqual([]);
  }, 120_000);

  it("5. OS keychain (DPAPI): keys sealed on disk, plugin reload unlocks without a prompt", async () => {
    const opts: { method: string; available: boolean }[] = await w.eval((plugin) => plugin.protectionOptions());
    expect(opts.find((o) => o.method === "safe")!.available).toBe(true);
    await w.eval((plugin) => plugin.setProtection("safe"));
    const file = join(w.vault, ".obsidian/plugins/obsync/data.json");
    const raw = await fsp.readFile(file, "utf8");
    const onDisk = JSON.parse(raw);
    expect(onDisk.identity).toBeNull();
    expect(onDisk.sealed.method).toBe("safe");
    expect(typeof onDisk.protection.safeWrap).toBe("string");
    expect(raw).not.toContain("dv_");
    expect(raw).not.toMatch(/"k_id"/);
    console.log(`data.json with DPAPI protection: sealed=${JSON.stringify(Object.keys(onDisk.sealed))} safeWrap=${onDisk.protection.safeWrap.slice(0, 24)}… (${onDisk.protection.safeWrap.length} chars)`);
    await w.eval(async (_p, app) => {
      await app.plugins.disablePlugin("obsync");
      await app.plugins.enablePlugin("obsync");
    });
    const up = await w.waitFor(() => {
      const p = (globalThis as any).app.plugins.plugins.obsync;
      return Boolean(p?.engine) && p.locked === false;
    }, 30_000);
    expect(up).toBe(true);
    expect(await w.eval(() => document.querySelectorAll('.modal input[type="password"]').length)).toBe(0);
    await observe();
    console.log(`after reload: ${await w.diagnostics()}`);
    // Really started (timers, live channel), not just constructed: see the reload test in obsidian.test.ts.
    expect(await w.eval((plugin) => Boolean(plugin.engine.pollTimer))).toBe(true);
    // And it syncs: a change from Linux lands.
    await linux.write("after-dpapi.md", "unlocked by DPAPI\n");
    await linux.sync();
    const landed = await w.waitForFile("after-dpapi.md", "unlocked by DPAPI\n");
    if (landed === null) console.log(`did not land: ${await w.diagnostics()}\n--- console tail ---\n${w.log.split("\n").slice(-40).join("\n")}`);
    expect(landed).not.toBeNull();
    await w.eval((plugin) => plugin.setProtection("none"));
    expect(JSON.parse(await fsp.readFile(file, "utf8")).identity).not.toBeNull();
  }, 120_000);

  it("6. a note locked by another process: the remote edit is reported, nothing partial is left, and it lands once the lock goes", async () => {
    await w.eval((_p, app) => app.vault.create("locked.md", "before lock\n"));
    expect(await linuxUntil(async () => (await linux.files()).includes("locked.md"))).toBe(true);
    const abs = join(w.vault, "locked.md");
    const before = await fsp.stat(abs);
    const locker: ChildProcess = spawn("powershell", [
      "-NoProfile",
      "-Command",
      `$f=[IO.File]::Open('${abs.replace(/'/g, "''")}','Open','ReadWrite','None'); Write-Output LOCKED; Start-Sleep -Seconds 120; $f.Close()`,
    ]);
    let out = "";
    locker.stdout!.on("data", (d) => (out += d));
    const deadline = Date.now() + 15_000;
    while (!out.includes("LOCKED") && Date.now() < deadline) await sleep(100);
    expect(out).toContain("LOCKED");
    try {
      await linux.write("locked.md", "remote edit\n");
      await linux.sync();
      const skip = await waitSkipped("locked.md", 40_000);
      console.log(`while locked: skipped=${JSON.stringify(skip)} log=${JSON.stringify(await taken("__log"), null, 1)}`);
      expect(skip).not.toBeNull();
      // The lock is exclusive, so look at the file from outside: same size and mtime as before.
      const st = await fsp.stat(abs);
      expect([st.size, st.mtimeMs]).toEqual([before.size, before.mtimeMs]);
      const leftovers = (await fsp.readdir(w.vault)).filter((f) => /^locked/.test(f) && f !== "locked.md");
      expect(leftovers).toEqual([]);
      expect((await wStatus()).phase).not.toBe("error");
    } finally {
      locker.kill();
      await new Promise((r) => locker.once("exit", r));
    }
    // Lock released: the edit must land without anyone touching the file again.
    expect(await fsp.readFile(abs, "utf8")).toBe("before lock\n");
    const healed = await w.waitForFile("locked.md", "remote edit\n", 60_000);
    console.log(`after release: ${healed === null ? "NOT applied within 60 s" : "applied"}; log=${JSON.stringify(await taken("__log"), null, 1)}`);
    expect(healed).toBe("remote edit\n");
    expect(await noteOps()).toEqual([]);
  }, 180_000);

  it("7. CRLF on Windows, LF edit on Linux: a three-way merge, not a conflict per line", async () => {
    await w.eval((_p, app) => app.vault.create("eol.md", "one\r\ntwo\r\nthree\r\n"));
    expect(await linuxUntil(async () => (await linux.files()).includes("eol.md"))).toBe(true);
    expect(await linux.read("eol.md")).toBe("one\r\ntwo\r\nthree\r\n");
    // Windows edits line 3 and keeps CRLF; Linux rewrites every line ending to LF and edits line 1, concurrently.
    const { vc, client, identity } = linux.session;
    const pid = await vc.pathId("eol.md");
    const before = (await client.history(identity.vaultId, pid)).length;
    await w.eval(async (_p, app) => app.vault.modify(app.vault.getAbstractFileByPath("eol.md"), "one\r\ntwo\r\nthree (win)\r\n"));
    const pushed = await (async () => {
      const deadline = Date.now() + 30_000;
      while (Date.now() < deadline) {
        if ((await client.history(identity.vaultId, pid)).length > before) return true;
        await sleep(300);
      }
      return false;
    })();
    expect(pushed).toBe(true);
    await linux.write("eol.md", "one (linux)\ntwo\nthree\n");
    await linux.sync();
    const merged = await linux.read("eol.md");
    console.log(`linux after merge: ${JSON.stringify(merged)} conflicts=${JSON.stringify(linux.conflicts)} logs=${JSON.stringify(linux.logs.filter((l) => /eol|merge|conflict/.test(l)))}`);
    expect(linux.conflicts.filter(([p]) => p === "eol.md")).toEqual([]);
    expect(merged).toContain("one (linux)");
    expect(merged).toContain("three (win)");
    // And Windows converges on the same bytes.
    await linux.sync();
    expect(await w.waitForFile("eol.md", merged)).not.toBeNull();
    expect(await noteOps()).toEqual([]);
  }, 120_000);
});
