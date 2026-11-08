/**
 * Tenth review (2026-11-08): `registerJoinHandler` (0.1.9) against the
 * semantics of the installed Obsidian 1.15.0 (read out of its app.asar; the
 * public d.ts declares only `Plugin.registerObsidianProtocolHandler`):
 *
 *   Component.register(cb)  { this._events.push(cb) }
 *   Component.unload()      { if (!this._loaded) return; this._loaded = false;
 *                             while (_events.length) _events.pop()(); this.onunload() }
 *   Plugin.registerObsidianProtocolHandler(a, h) {
 *       const r = this.app.workspace.protocolHandler; r.register(a, h);
 *       this.register(() => r.unregister(a, h)) }
 *   ProtocolHandler.register(a, h)   { if (handlers.has(a)) throw Error(`Action "${a}" is already registered as a handler.`); handlers.set(a, h) }
 *   ProtocolHandler.unregister(a, h) { (!h || handlers.get(a) === h) && handlers.delete(a) }
 *   Workspace.unregisterObsidianProtocolHandler(a, h) { this.protocolHandler.unregister(a, h) }
 *
 * The fake `obsidian` module below reproduces exactly these; nothing else in
 * `onload` is exercised beyond no-op stubs. Two findings:
 *
 *  G. The retry timer is a bare setTimeout: it outlives the plugin. Disable
 *     the plugin while the retry is pending (the previous instance's handler
 *     has meanwhile been released) and the timer fires on the unloaded
 *     instance: `registerObsidianProtocolHandler` succeeds, and the unregister
 *     callback it pushes to `_events` never runs because `unload()` already
 *     did. The dead instance owns `obsidian://obsync-join` until Obsidian
 *     restarts; the next enable hits "already registered" ten times and gives
 *     up; a scanned QR runs the DEAD instance's `joinFromProtocol`. Fails on
 *     HEAD (167804c).
 *
 *  H. The forced unregister looks for `unregisterObsidianProtocolHandler` on
 *     `this.app`; in 1.15.0 it is on `this.app.workspace` (and undocumented).
 *     The cast to `App & {...}` hides this from the compiler. So the "force
 *     the stale one out where the app allows" path never runs, and a stale
 *     handler that is not released by itself keeps the join handler dead for
 *     the session, which is what 0.1.9 set out to fix. Fails on HEAD. Whether
 *     the stale handler seen in the captured log is released on its own
 *     within 2.5 s is not established by this test; if it always is, H is a
 *     dead-code note rather than a bug.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type Handler = (params: Record<string, string>) => void;

class ProtocolHandler {
  handlers = new Map<string, Handler>();
  register(a: string, h: Handler): void {
    if (this.handlers.has(a)) throw new Error(`Action "${a}" is already registered as a handler.`);
    this.handlers.set(a, h);
  }
  unregister(a: string, h?: Handler): void {
    if (!h || this.handlers.get(a) === h) this.handlers.delete(a);
  }
}

vi.mock("obsidian", () => {
  class Component {
    _loaded = false;
    _events: (() => void)[] = [];
    load(): Promise<void> | void {
      if (this._loaded) return;
      this._loaded = true;
      return this.onload();
    }
    onload(): Promise<void> | void {}
    unload(): void {
      if (!this._loaded) return;
      this._loaded = false;
      while (this._events.length > 0) this._events.pop()!();
      void this.onunload();
    }
    onunload(): Promise<void> | void {}
    register(cb: () => void): void {
      this._events.push(cb);
    }
    registerEvent(): void {}
    registerDomEvent(): void {}
  }
  class Plugin extends Component {
    constructor(
      public app: { workspace: { protocolHandler: ProtocolHandler } },
      public manifest: { id: string; name: string },
    ) {
      super();
    }
    addCommand(): void {}
    addSettingTab(): void {}
    addStatusBarItem(): { setText(): void } {
      return { setText() {} };
    }
    async loadData(): Promise<null> {
      return null;
    }
    async saveData(): Promise<void> {}
    registerObsidianProtocolHandler(a: string, h: Handler): void {
      const r = this.app.workspace.protocolHandler;
      r.register(a, h);
      this.register(() => r.unregister(a, h));
    }
  }
  class Notice {
    constructor(_m: string, _t?: number) {}
  }
  class PluginSettingTab {
    constructor(_a: unknown, _p: unknown) {}
  }
  class Setting {}
  class Modal {
    constructor(_a: unknown) {}
  }
  class TFile {}
  class TFolder {}
  const Platform = { isMobile: false, isDesktop: true, isIosApp: false, isAndroidApp: false, isMacOS: true };
  const normalizePath = (p: string) => p;
  return { Component, Plugin, Notice, PluginSettingTab, Setting, Modal, TFile, TFolder, Platform, normalizePath };
});

import ObsyncPlugin from "../src/obsidian/main";

function fakeApp() {
  const protocolHandler = new ProtocolHandler();
  const workspace = {
    protocolHandler,
    on: () => ({}),
    onLayoutReady: (_cb: () => void) => {},
    // Real 1.15.0 shape: on the workspace, not on the app.
    unregisterObsidianProtocolHandler(a: string, h?: Handler) {
      protocolHandler.unregister(a, h);
    },
  };
  return { app: { workspace, vault: { configDir: ".obsidian", adapter: {} } }, ph: protocolHandler };
}

const manifest = { id: "obsync", name: "obsync" };
type Loadable = ObsyncPlugin & { load(): Promise<void> | void; unload(): void; _events: unknown[] };

beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal("document", { visibilityState: "visible", addEventListener() {}, removeEventListener() {} });
  vi.stubGlobal("window", { addEventListener() {}, removeEventListener() {} });
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("registerJoinHandler against Obsidian 1.15.0 semantics", () => {
  it("G. the retry timer outlives the plugin: a disabled instance ends up owning the handler, and the next instance cannot take it", async () => {
    const { app, ph } = fakeApp();
    const stale: Handler = () => {};
    ph.handlers.set("obsync-join", stale); // the previous instance's handler, still held when onload runs

    const p1 = new ObsyncPlugin(app as never, manifest as never) as Loadable;
    const join1 = vi.spyOn(p1, "joinFromProtocol").mockResolvedValue();
    await p1.load();
    expect(ph.handlers.get("obsync-join")).toBe(stale); // first attempt failed; a retry is pending

    ph.handlers.delete("obsync-join"); // the old instance's unload releases it meanwhile
    p1.unload(); // ... and the user (or BRAT) disables the plugin before the retry fires
    await vi.advanceTimersByTimeAsync(300);

    expect(ph.handlers.has("obsync-join"), "a disabled plugin must hold no protocol handler").toBe(false);

    // Consequences on HEAD, for the record: the next instance cannot register,
    // and a scanned QR reaches the dead instance.
    const p2 = new ObsyncPlugin(app as never, manifest as never) as Loadable;
    const join2 = vi.spyOn(p2, "joinFromProtocol").mockResolvedValue();
    await p2.load();
    await vi.advanceTimersByTimeAsync(3000);
    ph.handlers.get("obsync-join")?.({ link: "obsync://join#x" });
    expect(join2, "the live instance must receive the QR").toHaveBeenCalledTimes(1);
    expect(join1, "the dead instance must not").not.toHaveBeenCalled();
  });

  it("H. the forced unregister never runs: the method is on app.workspace, so a stale handler that is not released keeps the join dead", async () => {
    const { app, ph } = fakeApp();
    const stale: Handler = () => {};
    ph.handlers.set("obsync-join", stale); // never released by anyone

    const p = new ObsyncPlugin(app as never, manifest as never) as Loadable;
    const join = vi.spyOn(p, "joinFromProtocol").mockResolvedValue();
    await p.load();
    await vi.advanceTimersByTimeAsync(5000); // well past 10 x 250 ms

    ph.handlers.get("obsync-join")?.({ link: "obsync://join#x" });
    expect(join, "the app offers workspace.unregisterObsidianProtocolHandler; the plugin never used it").toHaveBeenCalledTimes(1);
  });

  it("soundness: a stale handler released within the retry window is taken over, and unload releases ours", async () => {
    const { app, ph } = fakeApp();
    const stale: Handler = () => {};
    ph.handlers.set("obsync-join", stale);
    const p = new ObsyncPlugin(app as never, manifest as never) as Loadable;
    const join = vi.spyOn(p, "joinFromProtocol").mockResolvedValue();
    await p.load();
    ph.handlers.delete("obsync-join");
    await vi.advanceTimersByTimeAsync(300);
    ph.handlers.get("obsync-join")?.({ link: "obsync://join#x" });
    expect(join).toHaveBeenCalledTimes(1);
    p.unload();
    expect(ph.handlers.has("obsync-join")).toBe(false);
  });
});
