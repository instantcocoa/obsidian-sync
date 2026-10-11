/**
 * The plugin as shipped, inside real Obsidian, end to end against the real
 * server: create vault → invite → join → sync both ways (notes via the
 * Obsidian API, dot-files via disk), open-editor update, conflict sibling,
 * delete, leave, recovery-passphrase join, device roster.
 *
 * Runs only when OBSIDIAN_BIN is set:
 *   OBSIDIAN_BIN=$(which obsidian) XVFB_RUN=$(which xvfb-run) npx vitest run test/obsidian.test.ts
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { promises as fsp } from "node:fs";
import { join } from "node:path";
import { TestServer, ADMIN } from "./harness";
import { ObsidianInstance, OBSIDIAN_BIN } from "./obsidian-harness";

describe.skipIf(!OBSIDIAN_BIN)("inside real Obsidian", () => {
  let srv: TestServer;
  let a: ObsidianInstance;
  let b: ObsidianInstance;
  let sibling = "";
  let vaultId = "";

  beforeAll(async () => {
    srv = await TestServer.start();
    [a, b] = await Promise.all([ObsidianInstance.launch("a"), ObsidianInstance.launch("b")]);
  }, 180_000);

  afterAll(async () => {
    await Promise.all([a?.stop(), b?.stop()]);
    await srv?.stop();
  });

  it("plugin loaded with no identity", async () => {
    expect(await a.eval((plugin) => plugin.settings.identity)).toBeNull();
    expect(await a.eval((plugin) => plugin.engine)).toBeNull();
    expect(await a.eval((plugin) => plugin.manifest.id)).toBe("obsync");
  });

  it("create vault on A, join B with an invite link", async () => {
    await a.eval((plugin, _app, url, admin) => plugin.createVault(url, admin), srv.url, ADMIN);
    const idA = await a.eval((plugin) => plugin.settings.identity);
    vaultId = idA.vaultId;
    expect(vaultId).toMatch(/^[0-9a-f]{32}$/);
    expect(await a.waitFor(() => Boolean((globalThis as any).app.plugins.plugins.obsync.engine))).toBe(true);
    const link: string = await a.eval((plugin) => plugin.inviteLink());
    expect(link.startsWith("obsync://join#")).toBe(true);
    await b.eval((plugin, _app, l) => plugin.joinWithLink(l), link);
    const idB = await b.eval((plugin) => plugin.settings.identity);
    expect(idB.vaultId).toBe(vaultId);
    expect(idB.deviceId).not.toBe(idA.deviceId);
    // Keys live only in the plugin's own data.json.
    const dataA = JSON.parse(await fsp.readFile(join(a.vault, ".obsidian/plugins/obsync/data.json"), "utf8"));
    expect(dataA.identity.keyring.k_id).toMatch(/^[0-9a-f]{64}$/);
    // Status bar shows a state.
    expect(await a.waitFor(() => /obsync/.test(document.querySelector(".status-bar")?.textContent ?? ""))).toBe(true);
    // The live WebSocket channel is up on both sides (otherwise propagation would fall back to 60 s polling).
    expect(await a.waitFor(() => (globalThis as any).app.plugins.plugins.obsync.engine?.ws?.readyState === 1, 15_000)).toBe(true);
    expect(await b.waitFor(() => (globalThis as any).app.plugins.plugins.obsync.engine?.ws?.readyState === 1, 15_000)).toBe(true);
  }, 120_000);

  it("a note created through the Obsidian API on A appears on B, and B's edit returns", async () => {
    await a.eval((_p, app) => app.vault.create("Hello.md", "# Hello from A\n"));
    const got = await b.waitForFile("Hello.md", "# Hello from A\n");
    if (got === null) throw new Error(`Hello.md did not reach B\nA: ${await a.diagnostics()}\nB: ${await b.diagnostics()}`);
    // B's vault index knows it: it was written through the API, not just to disk.
    expect(await b.waitFor(() => Boolean((globalThis as any).app.vault.getAbstractFileByPath("Hello.md")))).toBe(true);
    await b.eval(async (_p, app) => {
      const f = app.vault.getAbstractFileByPath("Hello.md");
      await app.vault.modify(f, "# Hello from A\n\nedited on B\n");
    });
    expect(await a.waitForFile("Hello.md", "# Hello from A\n\nedited on B\n")).not.toBeNull();
    // Open-editor path: A has it open, B changes it, A's editor shows the new text.
    await a.eval((_p, app) => app.workspace.openLinkText("Hello.md", "", false));
    expect(await a.waitFor(() => (globalThis as any).app.workspace.getActiveFile()?.path === "Hello.md", 15_000)).toBe(true);
    await b.eval(async (_p, app) => app.vault.modify(app.vault.getAbstractFileByPath("Hello.md"), "third version\n"));
    expect(await a.waitForFile("Hello.md", "third version\n")).not.toBeNull();
    expect(await a.waitFor(() => (globalThis as any).app.workspace.activeEditor?.editor?.getValue() === "third version\n", 15_000)).toBe(true);
    // Binary attachment round trip.
    await a.eval((_p, app) => app.vault.createBinary("pic.bin", new Uint8Array([0, 255, 1, 254, 137, 80, 78, 71]).buffer));
    expect(await b.waitForFile("pic.bin")).not.toBeNull();
    expect([...(await fsp.readFile(join(b.vault, "pic.bin")))]).toEqual([0, 255, 1, 254, 137, 80, 78, 71]);
  }, 120_000);

  it("config-dir files written to disk on A reach B (raw event / dot scan path)", async () => {
    await fsp.mkdir(join(a.vault, ".obsidian/snippets"), { recursive: true });
    await fsp.writeFile(join(a.vault, ".obsidian/snippets/obsync-test.css"), "body { --obsync: 1; }\n");
    await fsp.writeFile(join(a.vault, ".obsidian/appearance.json"), JSON.stringify({ enabledCssSnippets: ["obsync-test"] }));
    expect(await b.waitForFile(".obsidian/snippets/obsync-test.css", "body { --obsync: 1; }\n", 75_000)).not.toBeNull();
    expect(await b.waitForFile(".obsidian/appearance.json", undefined, 60_000)).not.toBeNull();
    // Obsidian on B sees the snippet (reconcileInternalFile / customCss reload worked, or at least exists via adapter).
    expect(await b.waitFor(() => (globalThis as any).app.vault.adapter.exists(".obsidian/snippets/obsync-test.css"), 10_000)).toBe(true);
    // A plugin folder (not enabled) syncs as plain files without the reload hook interfering.
    await fsp.mkdir(join(a.vault, ".obsidian/plugins/dummy"), { recursive: true });
    await fsp.writeFile(join(a.vault, ".obsidian/plugins/dummy/manifest.json"), JSON.stringify({ id: "dummy", name: "Dummy", version: "0.0.1", minAppVersion: "1.0.0", description: "", author: "" }));
    await fsp.writeFile(join(a.vault, ".obsidian/plugins/dummy/main.js"), "module.exports = class extends require('obsidian').Plugin {}");
    expect(await b.waitForFile(".obsidian/plugins/dummy/main.js", undefined, 75_000)).not.toBeNull();
    // Workspace layout never syncs; our own folder never syncs.
    await new Promise((r) => setTimeout(r, 2000));
    const stB = JSON.parse(await fsp.readFile(join(b.vault, ".obsidian/plugins/obsync/state.json"), "utf8"));
    const synced = Object.keys(stB.files);
    expect(synced.some((p) => p.endsWith("workspace.json"))).toBe(false);
    expect(synced.some((p) => p.includes("plugins/obsync/"))).toBe(false);
    expect(synced).toContain("$CONFIG/snippets/obsync-test.css");
  }, 180_000);

  it("concurrent offline edits produce a conflict sibling, not a dialog; deletes propagate", async () => {
    await b.eval(async (plugin) => {
      await plugin.engine.stop();
      plugin.engine = null;
    });
    await a.eval(async (_p, app) => app.vault.modify(app.vault.getAbstractFileByPath("Hello.md"), "A offline edit\n"));
    await b.eval(async (_p, app) => app.vault.modify(app.vault.getAbstractFileByPath("Hello.md"), "B offline edit\n"));
    await new Promise((r) => setTimeout(r, 3000));
    await b.eval(async (plugin) => plugin.startEngine());
    expect(await b.waitForFile("Hello.md", "A offline edit\n")).not.toBeNull();
    const deadline = Date.now() + 30_000;
    while (!sibling && Date.now() < deadline) {
      const files = await fsp.readdir(b.vault);
      sibling = files.find((f) => /^Hello \(conflict .* \d{4}-\d{2}-\d{2} \d{4}\)\.md$/.test(f)) ?? "";
      if (!sibling) await new Promise((r) => setTimeout(r, 300));
    }
    expect(sibling).not.toBe("");
    expect(await fsp.readFile(join(b.vault, sibling), "utf8")).toBe("B offline edit\n");
    expect(await a.waitForFile(sibling, "B offline edit\n")).not.toBeNull();
    expect(await b.eval(() => document.querySelectorAll(".modal").length)).toBe(0);
    const conflicts: string[] = await b.eval((plugin) => plugin.engine.conflictFiles());
    expect(conflicts).toContain(sibling);
    // Obsidian itself rewrites files under .obsidian on both instances; if two
    // rewrites collide with un-mergeable JSON, the design keeps both copies.
    // That is allowed here, but report it so the content is visible.
    for (const c of conflicts.filter((x) => x !== sibling)) {
      expect(c.startsWith(".obsidian/")).toBe(true);
      const orig = c.replace(/ \(conflict [^)]*\)/, "");
      console.warn(`config conflict copy on B: ${c}\n--- copy:\n${await fsp.readFile(join(b.vault, c), "utf8").catch(() => "?")}\n--- ${orig} on B:\n${await fsp.readFile(join(b.vault, orig), "utf8").catch(() => "?")}\n--- ${orig} on A:\n${await fsp.readFile(join(a.vault, orig), "utf8").catch(() => "?")}`);
    }
    // Delete the sibling on A → gone on B.
    await a.eval(async (_p, app, p) => app.vault.delete(app.vault.getAbstractFileByPath(p)), sibling);
    expect(await b.waitForGone(sibling)).toBe(true);
  }, 150_000);

  it("recovery passphrase: B leaves, then rejoins with only server, vault id and passphrase", async () => {
    await a.eval((plugin) => plugin.setRecovery("correct horse battery staple"));
    await b.eval((plugin) => plugin.leaveVault());
    expect(await b.eval((plugin) => plugin.settings.identity)).toBeNull();
    // Scrub B so it has to decrypt existing data with recovered keys.
    await fsp.rm(join(b.vault, ".obsidian/plugins/obsync/state.json"), { force: true });
    await fsp.rm(join(b.vault, "Hello.md"), { force: true });
    await expect(b.eval((plugin, _app, url, v) => plugin.joinWithPassphrase(url, v, "wrong wrong wrong"), srv.url, vaultId)).rejects.toThrow(/passphrase/);
    await b.eval((plugin, _app, url, v) => plugin.joinWithPassphrase(url, v, "correct horse battery staple"), srv.url, vaultId);
    expect(await b.waitForFile("Hello.md", "A offline edit\n", 60_000)).not.toBeNull();
    expect((await b.eval((plugin) => plugin.settings.identity)).vaultId).toBe(vaultId);
    const names: string[] = await a.eval(async (plugin) => (await plugin.devices()).filter((d: any) => !d.revoked_at).map((d: any) => d.name));
    // A, the recovery identity, the old B (left but not removed), and the new B.
    expect(names.filter((n) => n === "(recovery passphrase)").length).toBe(1);
    expect(names.length).toBe(4);
  }, 150_000);

  it("removing a device from A rotates keys; a note written afterwards still reaches B", async () => {
    const devs: any[] = await a.eval(async (plugin) => plugin.devices());
    const stale = devs.find((d) => !d.isSelf && !d.recovery && !d.revoked_at);
    expect(stale).toBeDefined();
    await a.eval(async (plugin, _app, id) => plugin.removeDeviceById(id), stale.id);
    const info = await fetch(`${srv.url}/v1/vaults/${vaultId}`, { headers: { Authorization: `Bearer ${(await a.eval((p) => p.settings.identity)).deviceToken}` } }).then((r) => r.json());
    expect(info.epoch).toBe(2);
    await a.eval((_p, app) => app.vault.create("After rotation.md", "post-rotation\n"));
    expect(await b.waitForFile("After rotation.md", "post-rotation\n", 60_000)).not.toBeNull();
  }, 180_000);
});
