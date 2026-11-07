/**
 * Sixth review (2026-11-07), guide area D. The third review taught
 * `aliasesConfigDir` to fold the way APFS and NTFS do (NFKC, both case
 * directions, strip marks) because ".obſidian" IS ".obsidian" on a Mac. The
 * same folding was not applied to the two other places that decide what a
 * remote op may touch:
 *
 *   1. `compileExclusions` matches with a plain `i` regex flag. Per the
 *      ECMAScript Canonicalize rule, a non-ASCII character whose upper case
 *      is ASCII is left alone, so /obsync/i does not match "obſync" while
 *      the volume treats them as the same directory. Every default
 *      exclusion containing an "s" (plugins/obsync/, workspace.json,
 *      .trash/, .DS_Store, node_modules/, Thumbs.db, desktop.ini) can be
 *      bypassed by a member on a case-insensitive volume, including the
 *      always-on self-exclusion that keeps obsync's own main.js, data.json
 *      and state.json out of reach.
 *   2. `ConfigHooks.afterApply` recognises plugin code by the literal
 *      prefix "plugins/". A write to "pluginſ/<id>/main.js" lands in
 *      plugins/<id>/main.js but raises no reload and no notice: the code
 *      runs at the next launch, silently.
 *
 * These tests fail on HEAD (8319950) on a case-insensitive volume and skip
 * themselves where the volume is case-sensitive (Linux CI).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";
import { DEFAULT_EXCLUSIONS, compileExclusions, isSafeLogicalPath, logicalAliasesConfigDir } from "../src/core/paths";
import { utf8 } from "../src/core/encoding";
import { ConfigHooks } from "../src/obsidian/hooks";

const LONG_S = "ſ"; // ſ: toLowerCase() is a no-op, Unicode case folding and APFS/NTFS map it to "s"

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

/** Does this machine's temp volume treat `alias` as the same directory as `real`? */
function volumeFolds(real: string, alias: string): boolean {
  const d = mkdtempSync(join(tmpdir(), "obsync-fold6-"));
  try {
    mkdirSync(join(d, real));
    writeFileSync(join(d, real, "marker"), "x");
    return existsSync(join(d, alias, "marker"));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

async function evilPut(s: Session, path: string, content: string): Promise<void> {
  const { vc, client, identity } = s;
  const payload = utf8(content);
  const bid = await vc.blobId(payload);
  await client.putBlob(identity.vaultId, bid, await vc.encryptBlob(bid, payload));
  const pid = await vc.pathId(path);
  const r = await client.postOps(identity.vaultId, [
    {
      op_id: Math.random().toString(16).slice(2).padEnd(24, "0"),
      path_id: pid,
      blob_id: bid,
      meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: payload.length, blob: bid }),
      meta_epoch: vc.keyring.current,
      base_seq: 0,
    },
  ]);
  expect(r.results[0].seq ?? 0).toBeGreaterThan(0);
}

async function pair(): Promise<[Device, Device]> {
  const sa = await createVault(srv.url, ADMIN, "attacker");
  const link = await createInviteLink(sa);
  const sb = await joinWithLink(link, "victim");
  const a = await new Device("attacker", sa).start();
  const b = await new Device("victim", sb).start();
  return [a, b];
}

describe("exclusions are matched with /i, which does not fold the way the volume does", () => {
  const excluded = compileExclusions(DEFAULT_EXCLUSIONS);

  it("unit: the self-exclusion and workspace.json are bypassed by a long-s spelling that passes every other check", () => {
    for (const p of [`$CONFIG/plugins/ob${LONG_S}ync/main.js`, `$CONFIG/plugin${LONG_S}/obsync/data.json`, `$CONFIG/work${LONG_S}pace.json`, `.tra${LONG_S}h/x.md`, `.DS_${LONG_S}tore`]) {
      expect(isSafeLogicalPath(p)).toBe(true);
      expect(logicalAliasesConfigDir(p, ".obsidian")).toBe(false);
      // Each of these is excluded in its ASCII spelling...
      expect(excluded(p.replace(LONG_S, "s"))).toBe(true);
      // ...and must be excluded in the spelling the volume folds to it.
      expect(excluded(p)).toBe(true);
    }
  });

  it("e2e: a member overwrites the victim's own obsync main.js and workspace.json despite both being excluded", async () => {
    if (!volumeFolds("obsync", `ob${LONG_S}ync`)) return; // case-sensitive volume: the alias is a different directory there
    const [a, b] = await pair();
    await a.write("note.md", "hello\n");
    await a.sync();
    await b.sync();
    // The victim's installed plugin (never synced: /$CONFIG/plugins/obsync/ is always excluded) and its per-device workspace.
    const pluginDir = join(b.dir, ".obsidian/plugins/obsync");
    mkdirSync(pluginDir, { recursive: true });
    writeFileSync(join(pluginDir, "main.js"), "// the real obsync\n");
    writeFileSync(join(b.dir, ".obsidian/workspace.json"), '{"mine":true}\n');
    await evilPut(a.session, `$CONFIG/plugins/ob${LONG_S}ync/main.js`, "// pwned\n");
    await evilPut(a.session, `$CONFIG/work${LONG_S}pace.json`, '{"pwned":true}\n');
    await b.sync();
    expect(readFileSync(join(pluginDir, "main.js"), "utf8")).toBe("// the real obsync\n");
    expect(readFileSync(join(b.dir, ".obsidian/workspace.json"), "utf8")).toBe('{"mine":true}\n');
    await a.cleanup();
    await b.cleanup();
  });
});

describe("the plugin-reload hook recognises plugin code by a literal prefix", () => {
  function hooks(): { h: ConfigHooks; pending: () => Set<string> } {
    const app = { vault: { configDir: ".obsidian", adapter: { exists: async () => false, read: async () => "[]" } }, plugins: undefined } as unknown as ConstructorParameters<typeof ConfigHooks>[0];
    const h = new ConfigHooks(app, "obsync", () => {});
    const priv = h as unknown as { pendingReload: Set<string>; reloadTimer: ReturnType<typeof setTimeout> | null };
    return {
      h,
      pending: () => {
        if (priv.reloadTimer) clearTimeout(priv.reloadTimer);
        priv.reloadTimer = null;
        return priv.pendingReload;
      },
    };
  }

  it("unit: 'plugins/x/main.js' schedules a reload (and a notice); the spelling the volume folds to it does not", () => {
    const honest = hooks();
    honest.h.afterApply(".obsidian/plugins/dataview/main.js", "put");
    expect([...honest.pending()]).toEqual(["dataview"]);
    const sneaky = hooks();
    sneaky.h.afterApply(`.obsidian/plugin${LONG_S}/dataview/main.js`, "put");
    // On a folding volume the bytes are now plugins/dataview/main.js and run at the next launch; nobody was told.
    expect([...sneaky.pending()]).toEqual(["dataview"]);
  });

  it("e2e: a member replaces an installed plugin's code without the reload notice", async () => {
    if (!volumeFolds("plugins", `plugin${LONG_S}`)) return;
    const [a, b] = await pair();
    await a.write("note.md", "hello\n");
    await a.sync();
    await b.sync();
    const applied: string[] = [];
    b.engine["hooks"].afterApply = (p: string) => applied.push(p);
    mkdirSync(join(b.dir, ".obsidian/plugins/dataview"), { recursive: true });
    writeFileSync(join(b.dir, ".obsidian/plugins/dataview/main.js"), "// dataview\n");
    await b.sync(); // the victim now has the honest spelling in its state
    await evilPut(a.session, `$CONFIG/plugin${LONG_S}/dataview/main.js`, "// evil\n");
    await b.sync();
    const onDisk = readFileSync(join(b.dir, ".obsidian/plugins/dataview/main.js"), "utf8");
    // Either the write was refused, or the hook saw it under the real plugin path. Neither holds on HEAD.
    const announced = applied.some((p) => /^\.obsidian\/plugins\/dataview\/main\.js$/.test(p));
    expect(onDisk === "// dataview\n" || announced).toBe(true);
    await a.cleanup();
    await b.cleanup();
  });
});
