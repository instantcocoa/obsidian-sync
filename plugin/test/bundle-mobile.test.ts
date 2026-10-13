/**
 * Mobile safety of the shipped bundle, checked statically.
 *
 * Obsidian mobile runs plugins in a Capacitor WebView with no Node runtime:
 * a bare `require("fs")`, `process`, or `node:` import at load time throws
 * and the plugin fails to enable. This builds main.js the way `npm run
 * build` does and asserts the only CommonJS requires are `obsidian` and the
 * one `require("os")` that is guarded by `Platform.isMobile` and a try/catch
 * (device-name default, main.ts). Everything else must be WebCrypto,
 * `fetch`, `WebSocket`, and the Obsidian API, which exist on iOS and Android.
 *
 * This is not a run on a phone. It is the part of mobile compatibility that
 * can be proven without one.
 */
import { describe, expect, it } from "vitest";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(__dirname, "..");

describe("shipped bundle is mobile-safe", () => {
  const manifest = JSON.parse(readFileSync(resolve(root, "manifest.json"), "utf8"));
  const js = (() => {
    execSync("node esbuild.config.mjs production", { cwd: root, stdio: "pipe" });
    return readFileSync(resolve(root, "main.js"), "utf8");
  })();

  it("declares itself usable on mobile", () => {
    expect(manifest.isDesktopOnly).toBe(false);
  });

  it("pulls in no Node module other than the guarded os.hostname()", () => {
    const requires = [...js.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g)].map((m) => m[1]);
    const modules = new Set(requires);
    expect([...modules].sort()).toEqual(["obsidian", "os"]);
    // The single os require sits behind Platform.isMobile and inside try{}.
    const osUses = [...js.matchAll(/require\(\s*["']os["']\s*\)/g)];
    expect(osUses).toHaveLength(1);
    const before = js.slice(Math.max(0, osUses[0].index! - 200), osUses[0].index!);
    expect(before).toMatch(/Platform\.isMobile|\.isMobile\)/);
    expect(before).toMatch(/try\{/);
    expect(js).not.toMatch(/\bnode:[a-z]+/);
    expect(js).not.toMatch(/\b__dirname\b|\b__filename\b/);
  });

  it("touches Node globals only behind feature checks", () => {
    // Buffer: base64 fast path (encoding.ts) and keychain unwrap (desktop only).
    for (const m of js.matchAll(/\bBuffer\b/g)) {
      const ctx = js.slice(Math.max(0, m.index! - 120), m.index! + 60);
      expect(ctx, ctx).toMatch(/typeof Buffer<"u"|globalThis\.Buffer/);
    }
    // process.* must not appear at all (esbuild platform:browser strips the import).
    expect(js).not.toMatch(/\bprocess\.(env|platform|versions|argv)\b/);
  });

  it("uses only WebView-available primitives for I/O and crypto", () => {
    expect(js).toMatch(/\bfetch\(/);
    expect(js).toMatch(/new WebSocket\(/);
    expect(js).toMatch(/crypto\.subtle/);
    // Electron is reached only through a guarded globalThis.require probe
    // (protection.ts remote()), never a bundled require("electron").
    const electron = [...js.matchAll(/\brequire\(\s*["']electron["']\s*\)/g)];
    expect(electron).toHaveLength(0);
    for (const m of js.matchAll(/["']electron["']/g)) {
      const ctx = js.slice(Math.max(0, m.index! - 160), m.index!);
      expect(ctx, ctx).toMatch(/try\{/);
    }
  });
});
