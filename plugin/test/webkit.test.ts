/**
 * The plugin's core inside a real WebKit engine, which is what Obsidian for
 * iOS runs plugins in (WKWebView). test/webkit/entry.ts is bundled with
 * esbuild the way the plugin is, served by the obsync server itself (so
 * every request is same-origin, like Capacitor's), and driven through
 * Playwright's WebKit build. It runs the crypto vectors, a two-engine sync
 * round trip with a conflict, the WebSocket live channel with bearer
 * subprotocol auth, and an identity JSON round trip.
 *
 * Runs only with WEBKIT=1 and a Playwright WebKit build installed
 * (`npx playwright-core install --with-deps webkit`); CI does this on
 * ubuntu. It is not an iOS device run: it proves the JavaScript engine and
 * the web APIs the plugin needs, not Obsidian's iOS app around them.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { build } from "esbuild";
import { resolve } from "node:path";
import { TestServer, ADMIN } from "./harness";

const ON = process.env.WEBKIT === "1";

describe.skipIf(!ON)("plugin core under WebKit (the iOS engine)", () => {
  let srv: TestServer;
  let js: string;
  beforeAll(async () => {
    srv = await TestServer.start();
    const r = await build({
      entryPoints: [resolve(__dirname, "webkit/entry.ts")],
      bundle: true,
      write: false,
      format: "iife",
      platform: "browser",
      target: "safari15",
      loader: { ".json": "json" },
    });
    js = r.outputFiles[0].text;
  }, 120_000);
  afterAll(async () => {
    await srv?.stop();
  });

  it("runs the crypto vectors, a sync round trip with a conflict, and the live channel", async () => {
    const { webkit } = await import("playwright-core");
    const browser = await webkit.launch({ headless: true });
    try {
      const page = await browser.newPage();
      const logs: string[] = [];
      page.on("console", (m) => logs.push(`[${m.type()}] ${m.text()}`));
      await page.goto(`${srv.url}/?admin=${encodeURIComponent(ADMIN)}`);
      await page.addScriptTag({ content: js });
      const result = (await page.evaluate("window.__obsync")) as Record<string, unknown>;
      if (result.error) throw new Error(`${result.error}\n--- console ---\n${logs.join("\n")}`);
      console.log(`WebKit: ${result.ua}`);
      expect(result.steps).toEqual(["crypto ok", "sync ok", "websocket ok", "identity ok"]);
      expect(result.ws).toBe("open");
      expect(result.compression).toBe(true);
      expect(String(result.sibling)).toMatch(/^notes\/hello \(conflict webkit-b /);
      expect(String(result.ua)).toMatch(/WebKit/);
    } finally {
      await browser.close();
    }
  }, 120_000);
});
