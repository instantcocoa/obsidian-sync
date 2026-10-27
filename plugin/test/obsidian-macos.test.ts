/**
 * macOS-only behaviour of the plugin inside real Obsidian: case-insensitive
 * APFS (case-only renames, case-colliding names from a case-sensitive
 * device), NFD file names, the OS keychain protection through Electron's
 * safeStorage, shell/Finder-style edits, and recovery after the server's
 * WebSocket goes away.
 *
 * Runs only on darwin with OBSIDIAN_BIN set:
 *   OBSIDIAN_BIN=/Applications/Obsidian.app/Contents/MacOS/Obsidian npx vitest run test/obsidian-macos.test.ts
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { promises as fsp } from "node:fs";
import { join } from "node:path";
import { TestServer, ADMIN } from "./harness";
import { ObsidianInstance, OBSIDIAN_BIN } from "./obsidian-harness";
import { joinWithLink, type Session } from "../src/core/admin";
import { utf8 } from "../src/core/encoding";

const NFC = "café.md";
const NFD = "café.md";

describe.skipIf(!OBSIDIAN_BIN || process.platform !== "darwin")("real Obsidian on macOS", () => {
  let srv: TestServer;
  let a: ObsidianInstance;
  let b: ObsidianInstance;
  let vaultId = "";

  beforeAll(async () => {
    srv = await TestServer.start();
    [a, b] = await Promise.all([ObsidianInstance.launch("mac-a"), ObsidianInstance.launch("mac-b")]);
    await a.eval((plugin, _app, url, admin) => plugin.createVault(url, admin), srv.url, ADMIN);
    vaultId = (await a.eval((plugin) => plugin.settings.identity)).vaultId;
    const link: string = await a.eval((plugin) => plugin.inviteLink());
    await b.eval((plugin, _app, l) => plugin.joinWithLink(l), link);
    for (const inst of [a, b]) expect(await inst.waitFor(() => (globalThis as any).app.plugins.plugins.obsync.engine?.ws?.readyState === 1, 20_000)).toBe(true);
  }, 240_000);

  afterAll(async () => {
    await Promise.all([a?.stop(), b?.stop()]);
    await srv?.stop();
  });

  /** Names in the vault root as the file system actually stores them (casing and normalisation preserved). */
  const rootNames = async (inst: ObsidianInstance, re: RegExp) => (await fsp.readdir(inst.vault)).filter((f) => re.test(f.normalize("NFC"))).sort();
  const conflicts = async (inst: ObsidianInstance) => (await fsp.readdir(inst.vault)).filter((f) => / \(conflict /.test(f));
  const headSeq = async () => (await a.eval(async (plugin, _app, v) => (await plugin.engine.client.vault(v)).seq, vaultId)) as number;
  const history = async (path: string): Promise<{ seq: number; blob_id: string | null }[]> =>
    a.eval(async (plugin, _app, v, p) => plugin.engine.client.history(v, await plugin.engine.vc.pathId(p)), vaultId, path);
  const settle = async (ms: number) => new Promise((r) => setTimeout(r, ms));
  /** Wait until a predicate over both vaults holds, polling disk. */
  const until = async (fn: () => Promise<boolean>, timeoutMs = 45_000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await fn()) return true;
      await settle(300);
    }
    return false;
  };

  it("1. case-only rename on A (Note.md → note.md) leaves one correctly cased file on B, no sibling, no op loop", async () => {
    await a.eval((_p, app) => app.vault.create("Note.md", "same bytes\n"));
    expect(await b.waitForFile("Note.md", "same bytes\n")).not.toBeNull();
    expect(await rootNames(b, /^note\.md$/i)).toEqual(["Note.md"]);
    const seqBefore = await headSeq();
    await a.eval(async (_p, app) => {
      const f = app.vault.getAbstractFileByPath("Note.md");
      await app.vault.rename(f, "note.md");
    });
    expect(await rootNames(a, /^note\.md$/i)).toEqual(["note.md"]);
    const renamedOnB = await until(async () => (await rootNames(b, /^note\.md$/i)).join() === "note.md", 60_000);
    const namesB = await rootNames(b, /^note\.md$/i);
    console.log(`scenario 1: B root after rename: ${JSON.stringify(namesB)}; A: ${JSON.stringify(await rootNames(a, /^note\.md$/i))}`);
    if (!renamedOnB) throw new Error(`B did not end with exactly "note.md": ${JSON.stringify(namesB)}\nA: ${await a.diagnostics()}\nB: ${await b.diagnostics()}`);
    expect(await fsp.readFile(join(b.vault, "note.md"), "utf8")).toBe("same bytes\n");
    expect(await conflicts(a)).toEqual([]);
    expect(await conflicts(b)).toEqual([]);
    // No delete/put loop: the history settles. A rename is at most delete(old) + put(new).
    await settle(20_000);
    const s1 = await headSeq();
    await settle(15_000);
    const s2 = await headSeq();
    const hOld = await history("Note.md");
    const hNew = await history("note.md");
    console.log(`scenario 1: seq ${seqBefore} → ${s1} → ${s2}; Note.md ops ${JSON.stringify(hOld.map((o) => [o.seq, o.blob_id ? "put" : "del"]))}; note.md ops ${JSON.stringify(hNew.map((o) => [o.seq, o.blob_id ? "put" : "del"]))}`);
    expect(s2).toBe(s1);
    expect(hNew.filter((o) => o.blob_id).length).toBe(1);
    expect(hOld.length).toBeLessThanOrEqual(2);
    expect(hOld.at(-1)!.blob_id).toBeNull(); // the old casing is a tombstone on the server, so a case-sensitive device will not keep both
    expect(s2 - seqBefore).toBeLessThanOrEqual(3);
  }, 180_000);

  it("3. an NFD-named note created on A syncs as one file, survives an edit on B, and comes back as one file", async () => {
    await a.eval((_p, app, n) => app.vault.create(n, "nfd\n"), NFD);
    expect(await until(async () => (await rootNames(b, /^café\.md$/)).length === 1)).toBe(true);
    const onB = await rootNames(b, /^café\.md$/);
    console.log(`scenario 3: A stores ${JSON.stringify((await rootNames(a, /^café\.md$/)).map((n) => (n === NFD ? "NFD" : n === NFC ? "NFC" : n)))}, B stores ${JSON.stringify(onB.map((n) => (n === NFD ? "NFD" : n === NFC ? "NFC" : n)))}`);
    expect(await fsp.readFile(join(b.vault, onB[0]), "utf8")).toBe("nfd\n");
    // Edit on B through the Obsidian API, whatever form B's index holds.
    await b.eval(async (_p, app, nfc) => {
      const f = app.vault.getFiles().find((x: any) => x.path.normalize("NFC") === nfc);
      await app.vault.modify(f, "nfd edited on B\n");
    }, NFC);
    expect(
      await until(async () => {
        const n = await rootNames(a, /^café\.md$/);
        return n.length === 1 && (await fsp.readFile(join(a.vault, n[0]), "utf8")) === "nfd edited on B\n";
      }),
    ).toBe(true);
    await settle(5_000);
    for (const [name, inst] of [["A", a], ["B", b]] as const) {
      const disk = await rootNames(inst, /^café\.md$/);
      const index: string[] = await inst.eval((_p, app, nfc) => app.vault.getFiles().filter((x: any) => x.path.normalize("NFC") === nfc).map((x: any) => x.path), NFC);
      console.log(`scenario 3: ${name} disk=${disk.length} index=${index.length}`);
      expect(disk).toHaveLength(1);
      expect(index).toHaveLength(1);
      expect(await conflicts(inst)).toEqual([]);
    }
    const h = await history(NFC);
    expect(h.length).toBe(2);
    expect(await history(NFD)).toEqual(h); // pathId normalises, so both spellings are the same path
  }, 150_000);

  it("5. shell edits while Obsidian is open: `echo >` syncs as a put, `mv` as delete + put", async () => {
    execFileSync("/bin/sh", ["-c", `echo "from the shell" > "${join(a.vault, "Shell.md")}"`]);
    expect(await b.waitForFile("Shell.md", "from the shell\n", 60_000)).not.toBeNull();
    expect((await history("Shell.md")).map((o) => (o.blob_id ? "put" : "del"))).toEqual(["put"]);
    execFileSync("/bin/mv", [join(a.vault, "Shell.md"), join(a.vault, "Moved.md")]);
    expect(await b.waitForFile("Moved.md", "from the shell\n", 60_000)).not.toBeNull();
    expect(await b.waitForGone("Shell.md", 60_000)).toBe(true);
    await settle(3_000);
    expect((await history("Shell.md")).map((o) => (o.blob_id ? "put" : "del"))).toEqual(["put", "del"]);
    expect((await history("Moved.md")).map((o) => (o.blob_id ? "put" : "del"))).toEqual(["put"]);
    expect(await conflicts(b)).toEqual([]);
  }, 150_000);

  it("2. two names differing only in case from a case-sensitive device: the Mac keeps one, reports or siblings the other, clobbers nothing", async () => {
    // A Linux-style device: a Node session that posts hand-built ops, as e2e.test.ts does.
    const link: string = await a.eval((plugin) => plugin.inviteLink());
    const linux: Session = await joinWithLink(link, "linux");
    const { vc, client, identity } = linux;
    const put = async (path: string, text: string) => {
      const bytes = utf8(text);
      const bid = await vc.blobId(bytes);
      await client.putBlob(identity.vaultId, bid, await vc.encryptBlob(bid, bytes));
      const pid = await vc.pathId(path);
      const r = await client.postOps(identity.vaultId, [{ op_id: Math.random().toString(16).slice(2).padEnd(24, "0").slice(0, 24), path_id: pid, blob_id: bid, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: bytes.length }), meta_epoch: vc.keyring.current, base_seq: 0 }]);
      expect(r.results[0].seq ?? 0).toBeGreaterThan(0);
      return bid;
    };
    for (const inst of [a, b]) {
      await inst.eval((plugin) => {
        (globalThis as any).__skipped = [];
        const hooks = plugin.engine.hooks;
        const orig = hooks.onSkipped;
        hooks.onSkipped = (p: string, why: string) => {
          (globalThis as any).__skipped.push([p, why]);
          orig?.(p, why);
        };
      });
    }
    const upper = await put("A.md", "upper\n");
    const lower = await put("a.md", "lower\n");
    // Give both Macs time to apply, push back whatever they think changed, and settle.
    await until(async () => (await rootNames(b, /^a\.md$/i)).length > 0, 60_000);
    await settle(25_000);
    const report: Record<string, unknown> = {};
    for (const [name, inst] of [["A", a], ["B", b]] as const) {
      const names = await rootNames(inst, /^a\.md$/i);
      const contents: Record<string, string> = {};
      for (const n of names) contents[n] = await fsp.readFile(join(inst.vault, n), "utf8");
      const sib = (await conflicts(inst)).filter((f) => /^a \(conflict/i.test(f));
      for (const n of sib) contents[n] = await fsp.readFile(join(inst.vault, n), "utf8");
      const skipped = await inst.eval(() => (globalThis as any).__skipped);
      report[name] = { names, contents, skipped };
      // Exactly one file for the two names (the volume cannot hold both), and nothing clobbered silently:
      // the other content is either reported as skipped or kept as a sibling.
      expect(names).toHaveLength(1);
      const kept = contents[names[0]];
      const other = kept === "upper\n" ? "lower\n" : "upper\n";
      expect(["upper\n", "lower\n"]).toContain(kept);
      const reported = (skipped as [string, string][]).some(([p]) => /^a\.md$/i.test(p));
      const siblingHasOther = sib.some((f) => contents[f] === other);
      expect(reported || siblingHasOther).toBe(true);
    }
    console.log(`scenario 2: ${JSON.stringify(report, null, 1)}`);
    // The server's two paths keep their own bytes: no Mac pushed one name's content under the other.
    const hA = await history("A.md");
    const ha = await history("a.md");
    console.log(`scenario 2: server A.md ${JSON.stringify(hA)} a.md ${JSON.stringify(ha)}`);
    expect(hA.at(-1)!.blob_id).toBe(upper);
    expect(ha.at(-1)!.blob_id).toBe(lower);
    // And nothing keeps flapping.
    const s1 = await headSeq();
    await settle(15_000);
    expect(await headSeq()).toBe(s1);
  }, 240_000);

  it("4. OS keychain protection: available on macOS, unlocks without a prompt after a reload, keys not in the clear; Touch ID reported unavailable", async () => {
    const opts: { method: string; available: boolean }[] = await a.eval((plugin) => plugin.protectionOptions());
    const backend = await a.eval(() => {
      const ss = (globalThis as any).require("electron").remote?.safeStorage;
      return { avail: ss?.isEncryptionAvailable?.(), backend: ss?.getSelectedStorageBackend?.() ?? "n/a" };
    });
    const touch = await a.eval(() => {
      const sp = (globalThis as any).require("electron").remote?.systemPreferences;
      return { can: typeof sp?.canPromptTouchID === "function" ? sp.canPromptTouchID() : "no canPromptTouchID", prompt: typeof sp?.promptTouchID };
    });
    const touchAvail: boolean = await a.eval((plugin) => plugin.touchIdAvailable());
    console.log(`scenario 4: safeStorage ${JSON.stringify(backend)}; touch ${JSON.stringify(touch)}; plugin touchIdAvailable=${touchAvail}`);
    expect(opts.find((o) => o.method === "safe")!.available).toBe(true);
    // An EC2 Mac mini has no Touch ID sensor: the plugin must not offer it.
    expect(touch.can).toBe(false);
    expect(touchAvail).toBe(false);

    await a.eval((plugin) => plugin.setProtection("safe"));
    const dataPath = join(a.vault, ".obsidian/plugins/obsync/data.json");
    const raw = await fsp.readFile(dataPath, "utf8");
    const onDisk = JSON.parse(raw);
    expect(onDisk.identity).toBeNull();
    expect(onDisk.sealed.method).toBe("safe");
    expect(typeof onDisk.protection.safeWrap).toBe("string");
    expect(raw).not.toMatch(/"k_id"/);
    expect(raw).not.toMatch(/"privJwk"/);
    expect(raw).not.toContain("dv_");
    expect(raw).not.toContain(vaultId.length ? (await a.eval((plugin) => plugin.settings.identity)).deviceToken : "never");

    // Reload the plugin as Obsidian would at startup: no PIN modal, unlocked by the keychain, syncing.
    await a.eval(async (_p, app) => {
      await app.plugins.disablePlugin("obsync");
      await app.plugins.enablePlugin("obsync");
    });
    const unlocked = await a.waitFor(() => Boolean((globalThis as any).app.plugins.plugins.obsync.engine) && !(globalThis as any).app.plugins.plugins.obsync.locked, 45_000);
    if (!unlocked) {
      const st = await a.eval((plugin) => ({ locked: plugin.locked, engine: Boolean(plugin.engine), identity: Boolean(plugin.settings.identity), sealed: plugin.settings.sealed?.method, notices: [...document.querySelectorAll(".notice")].map((n) => n.textContent) }));
      throw new Error(`keychain unlock after reload failed: ${JSON.stringify(st)}\n${await a.diagnostics()}`);
    }
    expect(await a.eval(() => document.querySelectorAll('.modal input[type="password"]').length)).toBe(0);
    const live = await a.waitFor(() => (globalThis as any).app.plugins.plugins.obsync.engine?.ws?.readyState === 1, 20_000);
    if (!live) {
      const st = await a.eval(async (plugin, app) => ({
        stopped: plugin.engine.stopped,
        cursor: plugin.engine.state.cursor,
        epoch: plugin.engine.state.epoch,
        files: Object.keys(plugin.engine.state.files).length,
        status: plugin.engine.getStatus(),
        ws: plugin.engine.ws ? plugin.engine.ws.readyState : null,
        manifestDir: plugin.manifest.dir,
        stateExists: await app.vault.adapter.exists(`${plugin.manifest.dir}/state.json`),
        identity: Boolean(plugin.settings.identity),
        session: Boolean(plugin.session),
        notices: [...document.querySelectorAll(".notice")].map((n) => n.textContent),
      }));
      throw new Error(`engine after keychain unlock has no live channel: ${JSON.stringify(st)}\n${await a.diagnostics()}`);
    }
    // Obsidian does not await onunload: the reloaded engine may read state.json while the old one's
    // flush replaces it. Record whether that happened here (timing-dependent, so not asserted).
    console.log(`scenario 4: reload raced the previous flush: ${/state\.json could not be read/.test(a.log)}`);
    await a.eval((_p, app) => app.vault.create("After keychain.md", "unlocked by the keychain\n"));
    expect(await b.waitForFile("After keychain.md", "unlocked by the keychain\n", 60_000)).not.toBeNull();
    // Still sealed on disk after the reload-and-save cycle.
    expect(JSON.parse(await fsp.readFile(dataPath, "utf8")).identity).toBeNull();
    await a.eval((plugin) => plugin.setProtection("none"));
    expect(JSON.parse(await fsp.readFile(dataPath, "utf8")).identity).not.toBeNull();
  }, 150_000);

  it("6. the server goes away and comes back (sleep/wake stand-in): the plugin reconnects and catches up without a restart", async () => {
    await a.eval((plugin) => void ((plugin.engine as any).__mark = "before"));
    await b.eval((plugin) => void ((plugin.engine as any).__mark = "before"));
    await srv.halt();
    expect(await a.waitFor(() => (globalThis as any).app.plugins.plugins.obsync.engine?.ws?.readyState !== 1, 20_000)).toBe(true);
    // A change made while the server is down is queued, not lost.
    await a.eval((_p, app) => app.vault.create("While down.md", "written while the server was down\n"));
    await settle(4_000);
    await srv.resume();
    for (const [name, inst] of [["A", a], ["B", b]] as const) {
      const back = await inst.waitFor(() => (globalThis as any).app.plugins.plugins.obsync.engine?.ws?.readyState === 1, 90_000);
      if (!back) throw new Error(`${name}'s live channel did not come back after the server restart\nA: ${await a.diagnostics()}\nB: ${await b.diagnostics()}`);
    }
    expect(await b.waitForFile("While down.md", "written while the server was down\n", 60_000)).not.toBeNull();
    await b.eval((_p, app) => app.vault.create("After restart.md", "after the restart\n"));
    expect(await a.waitForFile("After restart.md", "after the restart\n", 60_000)).not.toBeNull();
    expect(await a.eval((plugin) => (plugin.engine as any).__mark)).toBe("before");
    expect(await b.eval((plugin) => (plugin.engine as any).__mark)).toBe("before");
  }, 240_000);

});
