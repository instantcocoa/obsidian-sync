/**
 * Onboarding through the real settings UI (no plugin methods), with the
 * server's rate limiter ON, plus direct observation of the Obsidian
 * integration points the engine relies on: reconcileInternalFile, snippet
 * reload, and what Obsidian itself writes under .obsidian on each instance.
 *
 * Runs only when OBSIDIAN_BIN is set (see obsidian.test.ts).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { promises as fsp } from "node:fs";
import { join } from "node:path";
import { TestServer, ADMIN } from "./harness";
import { ObsidianInstance, OBSIDIAN_BIN } from "./obsidian-harness";

describe.skipIf(!OBSIDIAN_BIN)("real Obsidian, settings UI onboarding, rate limiter on", () => {
  let srv: TestServer;
  let a: ObsidianInstance;
  let b: ObsidianInstance;

  beforeAll(async () => {
    srv = await TestServer.start({ rateLimit: true });
    [a, b] = await Promise.all([ObsidianInstance.launch("ui-a"), ObsidianInstance.launch("ui-b")]);
  }, 180_000);

  afterAll(async () => {
    await Promise.all([a?.stop(), b?.stop()]);
    await srv?.stop();
  });

  it("first device: Settings → Create a new vault → server URL + admin token → Create", async () => {
    await a.openSettings();
    await a.clickButton("Create…");
    // Empty fields are refused with a notice, not silently closed.
    await a.clickModalButton("Create");
    expect(await a.waitForNotice(/fill in/, 5_000)).not.toBeNull();
    await a.fill("https://sync.example.com", srv.url); // first prompt field (server URL)
    await a.page.locator('input[type="password"]').first().fill(ADMIN);
    await a.clickModalButton("Create");
    expect(await a.waitForNotice(/vault created/)).not.toBeNull();
    expect(await a.waitFor(() => Boolean((globalThis as any).app.plugins.plugins.obsync.settings.identity), 20_000)).toBe(true);
    expect(await a.waitFor(() => Boolean((globalThis as any).app.plugins.plugins.obsync.engine), 20_000)).toBe(true);
    // The tab re-rendered into the "joined" view.
    expect(await a.page.locator('button:has-text("Generate")').count()).toBeGreaterThan(0);
    await a.closeSettings();
  }, 60_000);

  it("second device: Settings → paste invite link → Join", async () => {
    // Generate via the UI on A: the modal shows the link in a textarea.
    await a.openSettings();
    await a.clickButton("Generate");
    const link = await a.page.locator("textarea[readonly]").first().inputValue({ timeout: 10_000 });
    expect(link.startsWith("obsync://join#")).toBe(true);
    await a.page.keyboard.press("Escape");
    await a.closeSettings();

    await b.openSettings();
    await b.fill("obsync://join#…", link);
    await b.clickButton("Join");
    const joined = await b.waitFor(() => Boolean((globalThis as any).app.plugins.plugins.obsync.settings.identity), 20_000);
    if (!joined) {
      const notices = await b.eval(() => Array.from(document.querySelectorAll(".notice")).map((n) => n.textContent));
      const field = await b.page.locator('input[placeholder="obsync://join#…"]').first().inputValue().catch(() => "?");
      throw new Error(`UI join failed. notices=${JSON.stringify(notices)} field=${field.slice(0, 40)}…\n${await b.diagnostics()}`);
    }
    await b.closeSettings();
    await a.eval((_p, app) => app.vault.create("UI.md", "joined through the UI\n"));
    expect(await b.waitForFile("UI.md", "joined through the UI\n")).not.toBeNull();
  }, 90_000);

  it("reconcileInternalFile is called and Obsidian sees synced snippets", async () => {
    // Observe the undocumented call on B by wrapping it in place.
    await b.eval((_p, app) => {
      const ad = app.vault.adapter;
      (globalThis as any).__reconcileCalls = [];
      (globalThis as any).__reconcileExists = typeof ad.reconcileInternalFile === "function";
      if (typeof ad.reconcileInternalFile === "function") {
        const orig = ad.reconcileInternalFile.bind(ad);
        ad.reconcileInternalFile = (p: string) => {
          (globalThis as any).__reconcileCalls.push(p);
          return orig(p);
        };
      }
    });
    await fsp.mkdir(join(a.vault, ".obsidian/snippets"), { recursive: true });
    await fsp.writeFile(join(a.vault, ".obsidian/snippets/ui-test.css"), "body { --ui-test: 1; }\n");
    expect(await b.waitForFile(".obsidian/snippets/ui-test.css", "body { --ui-test: 1; }\n", 60_000)).not.toBeNull();
    const exists = await b.eval(() => (globalThis as any).__reconcileExists);
    const calls: string[] = await b.eval(() => (globalThis as any).__reconcileCalls);
    expect(exists).toBe(true);
    expect(calls).toContain(".obsidian/snippets/ui-test.css");
    // The hook asked customCss to reload; Obsidian lists the snippet.
    expect(await b.waitFor(() => ((globalThis as any).app.customCss?.snippets ?? []).includes("ui-test"), 15_000)).toBe(true);
  }, 90_000);

  it("what Obsidian itself writes under .obsidian, and whether engine restarts cause config conflicts", async () => {
    // Restart B's engine several times while both instances idle; Obsidian
    // may rewrite app.json/appearance.json on its own. Record what happens.
    for (let i = 0; i < 4; i++) {
      await b.eval(async (plugin) => {
        await plugin.engine.stop();
        plugin.engine = null;
        await plugin.startEngine();
      });
      await new Promise((r) => setTimeout(r, 2500));
    }
    await new Promise((r) => setTimeout(r, 4000));
    const report: string[] = [];
    for (const [name, inst] of [["A", a], ["B", b]] as const) {
      for (const f of (await fsp.readdir(join(inst.vault, ".obsidian"))).filter((x) => x.endsWith(".json")).sort()) {
        report.push(`${name} .obsidian/${f}: ${await fsp.readFile(join(inst.vault, ".obsidian", f), "utf8")}`);
      }
    }
    console.log(report.join("\n"));
    const conflictsB: string[] = await b.eval((plugin) => plugin.engine.conflictFiles());
    const conflictsA: string[] = await a.eval((plugin) => plugin.engine.conflictFiles());
    expect(conflictsA).toEqual([]);
    expect(conflictsB).toEqual([]);
    // Both instances agree on every config file.
    for (const f of ["app.json", "appearance.json", "community-plugins.json"]) {
      const fa = await fsp.readFile(join(a.vault, ".obsidian", f), "utf8").catch(() => null);
      const fb = await fsp.readFile(join(b.vault, ".obsidian", f), "utf8").catch(() => null);
      expect(fb).toBe(fa);
    }
  }, 120_000);

  it("PIN protection: keys sealed on disk, plugin reload locks, wrong PIN refused, right PIN unlocks", async () => {
    // OS keychain is not available on a headless Linux box (basic_text backend): the plugin must say so, not pretend.
    const opts: { method: string; available: boolean }[] = await a.eval((plugin) => plugin.protectionOptions());
    expect(opts.find((o) => o.method === "safe")!.available).toBe(false);
    await expect(a.eval((plugin) => plugin.setProtection("safe"))).rejects.toThrow(/keychain/);

    await a.eval((plugin) => plugin.setProtection("pin", { pin: "4321-abcd" }));
    const onDisk = JSON.parse(await fsp.readFile(join(a.vault, ".obsidian/plugins/obsync/data.json"), "utf8"));
    expect(onDisk.identity).toBeNull();
    expect(onDisk.sealed.method).toBe("pin");
    const raw = await fsp.readFile(join(a.vault, ".obsidian/plugins/obsync/data.json"), "utf8");
    expect(raw).not.toContain("dv_"); // device token not in the clear
    expect(raw).not.toMatch(/"k_id"/);

    // Reload the plugin as Obsidian would at startup: it must come up locked and prompt.
    await a.eval(async (_p, app) => {
      await app.plugins.disablePlugin("obsync");
      await app.plugins.enablePlugin("obsync");
    });
    expect(await a.waitFor(() => (globalThis as any).app.plugins.plugins.obsync?.locked === true, 15_000)).toBe(true);
    expect(await a.eval((plugin) => plugin.engine)).toBeNull();
    expect(await a.waitFor(() => document.querySelectorAll('.modal input[type="password"]').length > 0, 15_000)).toBe(true);
    // Wrong PIN: still locked, a notice explains.
    await a.page.locator('.modal input[type="password"]').first().fill("wrong-pin");
    await a.clickModalButton("Unlock");
    expect(await a.waitFor(() => /wrong PIN/.test(document.querySelector(".notice")?.textContent ?? ""), 10_000)).toBe(true);
    expect(await a.eval((plugin) => plugin.locked)).toBe(true);
    // Right PIN via the "Unlock vault keys" command path.
    await a.eval((plugin) => void plugin.unlock());
    expect(await a.waitFor(() => document.querySelectorAll('.modal input[type="password"]').length > 0, 10_000)).toBe(true);
    await a.page.locator('.modal input[type="password"]').first().fill("4321-abcd");
    await a.clickModalButton("Unlock");
    expect(await a.waitFor(() => Boolean((globalThis as any).app.plugins.plugins.obsync.engine) && !(globalThis as any).app.plugins.plugins.obsync.locked, 20_000)).toBe(true);
    // And it syncs again.
    await a.eval((_p, app) => app.vault.create("After unlock.md", "unlocked\n"));
    expect(await b.waitForFile("After unlock.md", "unlocked\n")).not.toBeNull();
    // Back to none for the remaining tests.
    await a.eval((plugin) => plugin.setProtection("none"));
    const clear = JSON.parse(await fsp.readFile(join(a.vault, ".obsidian/plugins/obsync/data.json"), "utf8"));
    expect(clear.identity).not.toBeNull();
    expect(clear.sealed).toBeNull();
  }, 150_000);

  it("recovery passphrase brute force is throttled; the UI reports it", async () => {
    await a.eval((plugin) => plugin.setRecovery("correct horse battery staple"));
    const vaultId = (await a.eval((p) => p.settings.identity)).vaultId;
    await b.eval((plugin) => plugin.leaveVault());
    const codes: string[] = [];
    for (let i = 0; i < 25; i++) {
      const msg = await b.eval((plugin, _app, url, v, i) => plugin.joinWithPassphrase(url, v, "wrong " + i).then(() => "ok", (e: Error) => e.message), srv.url, vaultId, i);
      codes.push(msg);
      if (/429|rate limited|too many/i.test(msg)) break;
    }
    expect(codes.some((m) => /429|rate limited|too many/i.test(m))).toBe(true);
    expect(codes.filter((m) => /passphrase/.test(m)).length).toBeGreaterThan(0);
    // Legitimate join still works once the bucket refills: a join costs two
    // throttled requests (salt fetch, then the proof), so at 10/min that is
    // up to ~12 s of refill after a burst. Retry until it goes through.
    let ok = "";
    for (let i = 0; i < 20 && ok !== "ok"; i++) {
      await new Promise((r) => setTimeout(r, 4000));
      ok = await b.eval((plugin, _app, url, v) => plugin.joinWithPassphrase(url, v, "correct horse battery staple").then(() => "ok", (e: Error) => e.message), srv.url, vaultId);
    }
    expect(ok).toBe("ok");
    expect(await b.waitForFile("UI.md", "joined through the UI\n")).not.toBeNull();
  }, 120_000);
});
