/**
 * Root cause of the one config conflict ever seen in the real-Obsidian suite
 * (`.obsidian/app (conflict desktop 2026-10-08 2035).json`, before §6.6 was
 * added), reproduced deterministically and shown fixed.
 *
 * Mechanism: every Obsidian vault already has its own `app.json` before the
 * plugin ever runs, and Obsidian rewrites it on its own (debounced
 * `saveConfig`) whenever a setting changes. So at the moment a second device
 * joins, its `app.json` can differ from the version the first device
 * uploaded, with no common base. Under the generic rule that is a
 * concurrent edit and produces a conflict sibling. §6.6 says: a config file
 * this device has never synced is adopted from the vault instead.
 *
 * This file turns the rule off (test-only `adoptConfig` option), performs
 * the join, and expects the conflict copy; then turns it back on, joins
 * again from a clean state, and expects silent adoption.
 *
 * Runs only when OBSIDIAN_BIN is set (see obsidian.test.ts).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { promises as fsp } from "node:fs";
import { join } from "node:path";
import { TestServer, ADMIN } from "./harness";
import { ObsidianInstance, OBSIDIAN_BIN } from "./obsidian-harness";

const SEED = JSON.stringify({ legacyEditor: false, safeMode: false, autoUpdate: false }); // what the harness writes before launch

describe.skipIf(!OBSIDIAN_BIN)("real Obsidian, config conflict root cause", () => {
  let srv: TestServer;
  let a: ObsidianInstance;
  let b: ObsidianInstance;

  beforeAll(async () => {
    srv = await TestServer.start();
    [a, b] = await Promise.all([ObsidianInstance.launch("cfg-a"), ObsidianInstance.launch("cfg-b")]);
  }, 180_000);

  afterAll(async () => {
    await Promise.all([a?.stop(), b?.stop()]);
    await srv?.stop();
  });

  const appJson = (inst: ObsidianInstance) => fsp.readFile(join(inst.vault, ".obsidian/app.json"), "utf8");
  const conflictsOnDisk = async (inst: ObsidianInstance) =>
    (await fsp.readdir(join(inst.vault, ".obsidian"))).filter((f) => / \(conflict /.test(f)).sort();

  it("every vault has an app.json before the plugin runs, and Obsidian rewrites it by itself", async () => {
    // Before any sync exists, both instances already own an app.json.
    const [ja, jb] = await Promise.all([appJson(a), appJson(b)]);
    console.log(`A app.json at startup: ${ja}\nB app.json at startup: ${jb}\n(seed was ${SEED})`);
    expect(ja.length).toBeGreaterThan(0);
    expect(jb.length).toBeGreaterThan(0);

    // A real user action on B (toggle a setting through Obsidian's own API) makes
    // Obsidian rewrite the file on disk with no plugin involvement.
    await b.eval((_p, app) => app.vault.setConfig("showLineNumber", true));
    const rewritten = await (async () => {
      const deadline = Date.now() + 15_000;
      while (Date.now() < deadline) {
        const cur = await appJson(b);
        if (cur !== jb && /showLineNumber/.test(cur)) return cur;
        await new Promise((r) => setTimeout(r, 250));
      }
      return null;
    })();
    expect(rewritten).not.toBeNull();
    console.log(`B app.json after Obsidian's own rewrite: ${rewritten}`);
  }, 60_000);

  it("WITHOUT the adoption rule, joining B reproduces the config conflict copy", async () => {
    await a.eval((plugin, _app, url, admin) => plugin.createVault(url, admin), srv.url, ADMIN);
    expect(await a.waitFor(() => Boolean((globalThis as any).app.plugins.plugins.obsync.engine))).toBe(true);

    // Wait until A has actually uploaded its app.json (server history for the logical path is non-empty).
    const uploaded = await a.waitFor(async () => {
      const plugin = (globalThis as any).app.plugins.plugins.obsync;
      const pid = await plugin.engine.vc.pathId("$CONFIG/app.json");
      const ops = await plugin.engine.client.history(plugin.settings.identity.vaultId, pid);
      return ops.length > 0;
    }, 30_000);
    expect(uploaded).toBe(true);

    // The two sides disagree with no shared base: that is the precondition.
    const [ja, jb] = await Promise.all([appJson(a), appJson(b)]);
    expect(jb).not.toBe(ja);
    // B's bytes are not any version A ever uploaded (so there is nothing to "converge" with).
    const bIsKnown: boolean = await a.eval(async (plugin, _app, bytes) => {
      const vc = plugin.engine.vc;
      const id = await vc.blobId(new TextEncoder().encode(bytes));
      const pid = await vc.pathId("$CONFIG/app.json");
      const ops = await plugin.engine.client.history(plugin.settings.identity.vaultId, pid);
      return ops.some((o: any) => o.blob_id === id);
    }, jb);
    expect(bIsKnown).toBe(false);

    // Join with the rule disabled: the generic conflict path runs.
    await b.eval((plugin) => {
      plugin.engineOverrides = { adoptConfig: false };
    });
    const link: string = await a.eval((plugin) => plugin.inviteLink());
    await b.eval((plugin, _app, l) => plugin.joinWithLink(l), link);
    const conflict = await (async () => {
      const deadline = Date.now() + 45_000;
      while (Date.now() < deadline) {
        const c = await conflictsOnDisk(b);
        if (c.length) return c;
        await new Promise((r) => setTimeout(r, 300));
      }
      return [];
    })();
    console.log(`conflict copies on B with adoptConfig=false: ${JSON.stringify(conflict)}`);
    // app.json always conflicts. Depending on when Obsidian rewrites its other
    // config files (community-plugins.json on 1.14 after the plugin loads),
    // they can conflict too: the same pathology, one more file. Never zero,
    // and the app.json copy must hold B's own bytes.
    expect(conflict.length).toBeGreaterThanOrEqual(1);
    const appCopy = conflict.find((f) => /^app \(conflict /.test(f))!;
    expect(appCopy).toBeDefined();
    // The sibling holds B's own pre-join bytes; the live app.json is the vault's.
    expect(await fsp.readFile(join(b.vault, ".obsidian", appCopy), "utf8")).toBe(jb);
    expect(await b.waitForFile(".obsidian/app.json", ja, 20_000)).toBe(ja);
    // The siblings are listed once B has pushed them (state entries get a hash then).
    expect(await b.waitFor(() => (globalThis as any).app.plugins.plugins.obsync.engine.conflictFiles().length >= 1, 30_000)).toBe(true);
    const listed: string[] = await b.eval((plugin) => plugin.engine.conflictFiles());
    expect(listed).toContain(`.obsidian/${appCopy}`);
  }, 120_000);

  it("WITH the adoption rule (default), the same join adopts the vault's app.json silently", async () => {
    // Leave, wipe B's local sync state, delete the conflict copy on both sides, and put B's own
    // differing app.json back, so B is again "a device that has never synced this file".
    await b.eval((plugin) => plugin.leaveVault());
    const copies = await conflictsOnDisk(b);
    for (const c of copies) await a.eval(async (_p, app, p) => app.vault.adapter.remove(p), `.obsidian/${c}`);
    for (const c of copies) await fsp.rm(join(b.vault, ".obsidian", c), { force: true });
    await fsp.rm(join(b.vault, ".obsidian/plugins/obsync/state.json"), { force: true });
    // Change keys the vault's app.json does not have, so Obsidian's debounced
    // rewrite is guaranteed to differ from A's file whatever it held before.
    await b.eval((_p, app) => app.vault.setConfig("showLineNumber", true));
    await b.eval((_p, app) => app.vault.setConfig("readableLineLength", false));
    await b.eval((_p, app) => app.vault.setConfig("spellcheck", false));
    const ownB = await (async () => {
      const deadline = Date.now() + 40_000; // a loaded CI runner can take a while to flush app.json
      const ja = await appJson(a);
      while (Date.now() < deadline) {
        const cur = await appJson(b);
        if (cur !== ja) return cur;
        await new Promise((r) => setTimeout(r, 250));
      }
      return null;
    })();
    expect(ownB).not.toBeNull();
    const ja = await appJson(a);
    expect(ownB).not.toBe(ja);

    await b.eval((plugin) => {
      plugin.engineOverrides = {};
    });
    const link: string = await a.eval((plugin) => plugin.inviteLink());
    await b.eval((plugin, _app, l) => plugin.joinWithLink(l), link);
    expect(await b.waitForFile(".obsidian/app.json", ja, 30_000)).toBe(ja);
    // Give the engine time to misbehave if it were going to.
    await new Promise((r) => setTimeout(r, 5000));
    expect(await conflictsOnDisk(b)).toEqual([]);
    expect(await conflictsOnDisk(a)).toEqual([]);
    expect(await b.eval((plugin) => plugin.engine.conflictFiles())).toEqual([]);
    expect(await a.eval((plugin) => plugin.engine.conflictFiles())).toEqual([]);
    expect(await appJson(b)).toBe(await appJson(a));
  }, 120_000);
});
