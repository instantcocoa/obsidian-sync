/**
 * Drives a real Obsidian (headless under Xvfb) with the built plugin
 * installed, over the Chrome DevTools Protocol via playwright-core.
 *
 * Requires OBSIDIAN_BIN (the obsidian executable) and, without a display,
 * XVFB_RUN (path to xvfb-run). Each instance gets its own vault, HOME,
 * XDG dirs and user-data dir so instances do not share state.
 *
 * The recipe for an unattended start (vault registry file, `safeMode:false`,
 * `community-plugins.json`, the `enable-plugin-<id>` localStorage flag) is
 * the one LiveSync's e2e suite uses via @vrtmrz/obsidian-test-session.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, writeFileSync, copyFileSync, rmSync, existsSync, promises as fsp } from "node:fs";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import { chromium, type Browser, type Locator, type Page } from "playwright-core";

export const OBSIDIAN_BIN = process.env.OBSIDIAN_BIN;
const XVFB = process.env.XVFB_RUN;
const ROOT = resolve(__dirname, "..");
const CACHE = resolve(ROOT, ".cache/obsidian-e2e");

async function freePort(): Promise<number> {
  return new Promise((res) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => res(p));
    });
  });
}

export class ObsidianInstance {
  vault!: string;
  state!: string;
  id!: string;
  port!: number;
  proc!: ChildProcess;
  browser!: Browser;
  page!: Page;
  log = "";

  static async launch(name: string): Promise<ObsidianInstance> {
    if (!OBSIDIAN_BIN) throw new Error("OBSIDIAN_BIN not set");
    const o = new ObsidianInstance();
    const base = join(CACHE, `${name}-${process.pid}-${Date.now()}`);
    o.vault = join(base, "vault");
    o.state = join(base, "state");
    o.id = `obsync-e2e-${name}-${Date.now()}`;
    for (const d of ["vault/.obsidian/plugins/obsync", "state/home/.config/obsidian", "state/xdg-config/obsidian", "state/xdg-cache", "state/xdg-data", "state/user-data"]) {
      mkdirSync(join(base, d), { recursive: true });
    }
    for (const f of ["main.js", "manifest.json", "styles.css"]) copyFileSync(join(ROOT, f), join(o.vault, ".obsidian/plugins/obsync", f));
    // autoUpdate:false keeps Obsidian from downloading a newer release mid-test.
    writeFileSync(join(o.vault, ".obsidian/app.json"), JSON.stringify({ legacyEditor: false, safeMode: false, autoUpdate: false }));
    writeFileSync(join(o.vault, ".obsidian/community-plugins.json"), JSON.stringify(["obsync"]));
    const record = { path: o.vault, ts: Date.now(), open: true, name: `vault-${name}` };
    const registry = JSON.stringify({ cli: true, vaults: { [o.id]: record } });
    for (const d of ["state/home/.config/obsidian", "state/xdg-config/obsidian", "state/user-data"]) writeFileSync(join(base, d, "obsidian.json"), registry);
    writeFileSync(join(o.state, "user-data", `${o.id}.json`), JSON.stringify(record));

    o.port = await freePort();
    const args = [
      "--no-sandbox",
      "--disable-gpu",
      "--disable-software-rasterizer",
      `--user-data-dir=${join(o.state, "user-data")}`,
      `--remote-debugging-port=${o.port}`,
      `obsidian://open?path=${encodeURIComponent(o.vault)}`,
    ];
    // macOS and Windows always have a desktop session for a GUI process; only
    // a display-less Linux needs a virtual X server.
    const useXvfb = process.platform === "linux" && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY;
    if (useXvfb && !XVFB) throw new Error("no DISPLAY and XVFB_RUN not set");
    const cmd = useXvfb ? XVFB! : OBSIDIAN_BIN;
    const cmdArgs = useXvfb ? ["-a", "-s", "-screen 0 1280x800x24", OBSIDIAN_BIN, ...args] : args;
    o.proc = spawn(cmd, cmdArgs, {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        HOME: join(o.state, "home"),
        XDG_CONFIG_HOME: join(o.state, "xdg-config"),
        XDG_CACHE_HOME: join(o.state, "xdg-cache"),
        XDG_DATA_HOME: join(o.state, "xdg-data"),
        OBSIDIAN_DISABLE_GPU: "1",
      },
    });
    o.proc.stdout!.on("data", (d) => (o.log += d));
    o.proc.stderr!.on("data", (d) => (o.log += d));
    await o.connect();
    return o;
  }

  private async connect(): Promise<void> {
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      try {
        if ((await fetch(`http://127.0.0.1:${this.port}/json/version`)).ok) break;
      } catch {
        /* not yet */
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    this.browser = await chromium.connectOverCDP(`http://127.0.0.1:${this.port}`, { timeout: 30_000 });
    for (const ctx of this.browser.contexts()) for (const p of ctx.pages()) p.on("console", (m) => (this.log += `[console.${m.type()}] ${m.text()}\n`));
    // Find the renderer page that owns the vault; trust the plugin; wait for it to load.
    while (Date.now() < deadline) {
      for (const ctx of this.browser.contexts()) {
        for (const p of ctx.pages()) {
          const owns = await p.evaluate(() => Boolean((globalThis as { app?: { vault?: unknown } }).app?.vault)).catch(() => false);
          if (owns) {
            this.page = p;
            await p.evaluate((id) => localStorage.setItem(`enable-plugin-${id}`, "true"), this.id);
            const loaded = await this.waitFor(() => {
              // Obsidian 1.14+ asks "Do you trust the author of this vault?" when a
              // vault it has never opened ships plugins; nothing loads until it is
              // answered. Trust it (the vault is ours) and keep waiting.
              const trust = [...document.querySelectorAll(".modal.mod-trust-folder button")].find((b) => !b.classList.contains("mod-cancel")) as HTMLButtonElement | undefined;
              trust?.click();
              return Boolean((globalThis as unknown as { app: { plugins: { plugins: Record<string, unknown> } } }).app.plugins.plugins["obsync"]);
            }, 30_000).catch(() => false);
            if (!loaded) {
              // Restricted mode may have blocked plugins before the flag was set: reload once.
              await p.evaluate(() => location.reload());
              await new Promise((r) => setTimeout(r, 3000));
              continue;
            }
            return;
          }
        }
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error("Obsidian renderer with the plugin did not appear:\n" + this.log.slice(-2000));
  }

  /**
   * Evaluate in the renderer. The function receives the plugin instance, the
   * Obsidian `app`, and any extra JSON-serialisable arguments. It cannot
   * close over test variables; pass them as args.
   */
  async eval<T>(fn: (plugin: any, app: any, ...args: any[]) => T | Promise<T>, ...args: unknown[]): Promise<T> {
    // Results go through JSON so Obsidian objects (TFile etc.) do not trip the CDP serialiser.
    const src = `(async (args) => { const app = globalThis.app; const plugin = app.plugins.plugins["obsync"]; const r = await (${fn.toString()})(plugin, app, ...args); try { return JSON.parse(JSON.stringify(r ?? null)); } catch { return null; } })(${JSON.stringify(args)})`;
    return this.page.evaluate(src) as Promise<T>;
  }

  async waitFor(fn: () => boolean | Promise<boolean>, timeoutMs = 30_000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await this.page.evaluate(`(async () => (${fn.toString()})())()`).catch(() => false)) return true;
      await new Promise((r) => setTimeout(r, 300));
    }
    return false;
  }

  /**
   * Every renderer window of this instance, popouts first. Since Obsidian
   * 1.14 the settings dialog is its own window, and modals opened from it
   * live there too; before that everything was in the vault window. UI
   * helpers search all of them so one suite drives both.
   */
  private windows(): Page[] {
    const all = this.browser.contexts().flatMap((c) => c.pages()).filter((p) => !p.isClosed());
    return [...all.filter((p) => p !== this.page).reverse(), this.page];
  }

  /** First window where `build(page)` yields a locator with a match. */
  private async locate(build: (p: Page) => Locator, what: string, timeoutMs = 10_000): Promise<Locator> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      for (const p of this.windows()) {
        const l = build(p);
        if ((await l.count().catch(() => 0)) > 0) return l.first();
      }
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error(`no window shows ${what}`);
  }

  /** A locator for `selector` in whichever window currently shows it. */
  async locator(selector: string, timeoutMs = 10_000): Promise<Locator> {
    return this.locate((p) => p.locator(selector), selector, timeoutMs);
  }

  /** Find a settings/modal control by its visible text and click it. */
  async clickButton(text: string): Promise<void> {
    await (await this.locate((p) => p.locator(`button:has-text("${text}")`), `button "${text}"`)).click({ timeout: 10_000 });
  }

  /**
   * Same, but only in the topmost modal and by exact text: the settings
   * dialog is itself a modal and has e.g. a "Create…" button behind the
   * "Create" prompt.
   */
  async clickModalButton(text: string): Promise<void> {
    await (await this.locate((p) => p.locator(".modal-container").last().locator(`button:text-is("${text}")`), `modal button "${text}"`)).click({ timeout: 10_000 });
  }

  /** Type into the input whose placeholder matches. */
  async fill(placeholder: string, value: string): Promise<void> {
    await (await this.locate((p) => p.locator(`input[placeholder="${placeholder}"]`), `input "${placeholder}"`)).fill(value, { timeout: 10_000 });
  }

  /** Open this plugin's settings tab in the real settings dialog (a modal before 1.14, its own window since). */
  async openSettings(): Promise<void> {
    await this.eval((_p, app) => {
      app.setting.open();
      app.setting.openTabById("obsync");
    });
    await this.locate((p) => p.locator(".vertical-tab-content"), "the settings tab");
  }

  async closeSettings(): Promise<void> {
    await this.eval((_p, app) => app.setting.close());
  }

  /** Engine status plus WebSocket state, for failure diagnostics. */
  async diagnostics(): Promise<string> {
    const st = await this.eval((plugin) => ({ status: plugin.engine?.getStatus(), ws: plugin.engine?.ws?.readyState, cursor: plugin.engine?.state.cursor, dirty: plugin.engine?.state.dirty })).catch((e) => String(e));
    return JSON.stringify(st) + "\n--- console tail ---\n" + this.log.split("\n").filter((l) => l.includes("obsync")).slice(-25).join("\n");
  }

  /**
   * Watch notices for up to `timeoutMs` and resolve with the first one that
   * matches. Notices expire after ~5 s, so a single late query can miss one.
   */
  async waitForNotice(re: RegExp, timeoutMs = 20_000): Promise<string | null> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      for (const p of this.windows()) {
        const texts = (await p.evaluate(`[...document.querySelectorAll(".notice")].map((n) => n.textContent)`).catch(() => [])) as string[];
        const hit = texts.find((t) => re.test(t));
        if (hit) return hit;
      }
      await new Promise((r) => setTimeout(r, 150));
    }
    return null;
  }

  /** Wait until a file exists on this instance's disk with the given content (or at all). */
  async waitForFile(rel: string, content?: string, timeoutMs = 45_000): Promise<string | null> {
    const p = join(this.vault, rel);
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const c = await fsp.readFile(p, "utf8");
        if (content === undefined || c === content) return c;
      } catch {
        /* absent */
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    return null;
  }

  async waitForGone(rel: string, timeoutMs = 45_000): Promise<boolean> {
    const p = join(this.vault, rel);
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (!existsSync(p)) return true;
      await new Promise((r) => setTimeout(r, 300));
    }
    return false;
  }

  async stop(keep = false): Promise<void> {
    try {
      await this.browser?.close();
    } catch {
      /* ignore */
    }
    if (process.platform === "win32" && this.proc.pid) {
      // No process groups on Windows: kill the tree explicitly.
      spawn("taskkill", ["/pid", String(this.proc.pid), "/T", "/F"], { stdio: "ignore" });
    }
    try {
      if (this.proc.pid) process.kill(-this.proc.pid, "SIGTERM");
    } catch {
      this.proc.kill("SIGTERM");
    }
    await new Promise((r) => setTimeout(r, 1500));
    try {
      if (this.proc.pid) process.kill(-this.proc.pid, "SIGKILL");
    } catch {
      /* gone */
    }
    if (!keep) rmSync(resolve(this.vault, ".."), { recursive: true, force: true });
  }
}
