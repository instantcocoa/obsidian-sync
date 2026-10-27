/**
 * The config-dir hooks that the Android run (docs/MOBILE-TEST-PROMPT.md step
 * 10) found wanting, pinned without a device:
 *
 * 1. Ops arrive in any order. When community-plugins.json lands before the
 *    plugin's own files, the reconcile finds no manifest; when the files land
 *    the reload path must enable the plugin, not wait for the list to change
 *    again (on the phone it waited until the next unrelated change).
 * 2. On mobile a desktop-only plugin enabled in the vault is skipped with a
 *    notice that says why, once, instead of silently.
 *
 * "obsidian" is the runtime that real Obsidian provides; here it is a stub
 * with just Notice and Platform.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const stub = vi.hoisted(() => ({ notices: [] as string[], platform: { isMobile: true, isDesktop: false } }));
vi.mock("obsidian", () => ({
  Notice: class {
    constructor(msg: string) {
      stub.notices.push(msg);
    }
  },
  Platform: stub.platform,
}));

import { ConfigHooks } from "../src/obsidian/hooks";

function fakeApp() {
  const files = new Map<string, string>();
  const onDisk: Record<string, { id: string; isDesktopOnly?: boolean }> = {};
  const enabled = new Set<string>();
  const calls: string[] = [];
  const app = {
    vault: {
      configDir: ".obsidian",
      adapter: {
        exists: async (p: string) => files.has(p),
        read: async (p: string) => {
          if (!files.has(p)) throw new Error("File does not exist");
          return files.get(p)!;
        },
      },
    },
    plugins: {
      enabledPlugins: enabled,
      manifests: {} as Record<string, { id: string; isDesktopOnly?: boolean } | undefined>,
      loadManifests: async () => {
        app.plugins.manifests = { ...onDisk };
      },
      enablePlugin: async (id: string) => {
        calls.push(`enable:${id}`);
        enabled.add(id);
      },
      disablePlugin: async (id: string) => {
        calls.push(`disable:${id}`);
        enabled.delete(id);
      },
    },
  };
  return { app, files, onDisk, enabled, calls };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

describe("plugin hooks on mobile", () => {
  beforeEach(() => {
    stub.notices.length = 0;
    stub.platform.isMobile = true;
    vi.useRealTimers();
  });

  it("enables a plugin whose files arrive after community-plugins.json", async () => {
    vi.useFakeTimers();
    const f = fakeApp();
    const hooks = new ConfigHooks(f.app as never, "obsync");
    f.files.set(".obsidian/community-plugins.json", JSON.stringify(["obsync", "hello"]));
    hooks.afterApply(".obsidian/community-plugins.json", "put");
    await vi.advanceTimersByTimeAsync(10);
    expect(f.enabled.has("hello")).toBe(false); // no manifest yet: nothing to enable
    expect(stub.notices).toEqual([]);
    // Now the plugin's files land.
    f.onDisk.hello = { id: "hello" };
    hooks.afterApply(".obsidian/plugins/hello/manifest.json", "put");
    hooks.afterApply(".obsidian/plugins/hello/main.js", "put");
    await vi.advanceTimersByTimeAsync(2500);
    expect(f.enabled.has("hello")).toBe(true);
    expect(f.calls).toEqual(["enable:hello"]);
    expect(stub.notices).toEqual(['obsync: enabled plugin "hello" because it is enabled in the vault']);
  });

  it("leaves a plugin alone when the vault list has not synced yet, without a restart notice", async () => {
    vi.useFakeTimers();
    const f = fakeApp();
    const hooks = new ConfigHooks(f.app as never, "obsync");
    f.onDisk.hello = { id: "hello" };
    hooks.afterApply(".obsidian/plugins/hello/main.js", "put");
    await vi.advanceTimersByTimeAsync(2500);
    expect(f.calls).toEqual([]);
    expect(stub.notices).toEqual([]);
  });

  it("still reloads an already enabled plugin when its files change", async () => {
    vi.useFakeTimers();
    const f = fakeApp();
    const hooks = new ConfigHooks(f.app as never, "obsync");
    f.onDisk.hello = { id: "hello" };
    f.enabled.add("hello");
    hooks.afterApply(".obsidian/plugins/hello/main.js", "put");
    await vi.advanceTimersByTimeAsync(2500);
    expect(f.calls).toEqual(["disable:hello", "enable:hello"]);
    expect(stub.notices).toEqual(["obsync: reloaded plugin hello"]);
  });

  it("skips a desktop-only plugin on mobile with one notice, whichever file arrives last", async () => {
    vi.useFakeTimers();
    const f = fakeApp();
    const hooks = new ConfigHooks(f.app as never, "obsync");
    f.onDisk.deskonly = { id: "deskonly", isDesktopOnly: true };
    f.files.set(".obsidian/community-plugins.json", JSON.stringify(["obsync", "deskonly"]));
    hooks.afterApply(".obsidian/community-plugins.json", "put");
    await vi.advanceTimersByTimeAsync(10);
    hooks.afterApply(".obsidian/plugins/deskonly/main.js", "put");
    await vi.advanceTimersByTimeAsync(2500);
    hooks.afterApply(".obsidian/community-plugins.json", "put");
    await vi.advanceTimersByTimeAsync(10);
    expect(f.calls).toEqual([]);
    expect(f.enabled.has("deskonly")).toBe(false);
    expect(stub.notices).toEqual(['obsync: plugin "deskonly" is enabled in the vault but is desktop-only, so it was not enabled on this device.']);
  });

  it("enables the same desktop-only plugin on desktop", async () => {
    stub.platform.isMobile = false;
    const f = fakeApp();
    const hooks = new ConfigHooks(f.app as never, "obsync");
    f.onDisk.deskonly = { id: "deskonly", isDesktopOnly: true };
    f.files.set(".obsidian/community-plugins.json", JSON.stringify(["obsync", "deskonly"]));
    hooks.afterApply(".obsidian/community-plugins.json", "put");
    await flush();
    await flush();
    expect(f.enabled.has("deskonly")).toBe(true);
    expect(stub.notices).toEqual(['obsync: enabled plugin "deskonly" because it is enabled in the vault']);
  });

  it("disables what the vault no longer lists and never touches itself", async () => {
    const f = fakeApp();
    const hooks = new ConfigHooks(f.app as never, "obsync");
    f.enabled.add("obsync");
    f.enabled.add("gone");
    f.files.set(".obsidian/community-plugins.json", JSON.stringify(["obsync"]));
    hooks.afterApply(".obsidian/community-plugins.json", "put");
    await flush();
    await flush();
    expect(f.calls).toEqual(["disable:gone"]);
    expect(f.enabled.has("obsync")).toBe(true);
  });
});
