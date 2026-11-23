/**
 * Method "secret": the vault keys sealed under a wrapping key that lives in
 * Obsidian's secret storage (the iOS Keychain / Android Keystore on a phone).
 *
 * The fake below is a transcription of Obsidian 1.15.1's SecretStorage class
 * as shipped (app.js): an in-memory map filled by load() before plugins
 * start, setSecret() that updates the map and fires an un-awaited native
 * save, getSecret() that reads the map only. `persist: false` models the
 * native write failing silently, which is the case the plugin's fallback
 * exists for. A "relaunch" is a new plugin instance over the same data.json
 * and a new store loaded from what the native side kept.
 */
import { describe, expect, it, vi } from "vitest";

const stub = vi.hoisted(() => ({ data: null as unknown }));
vi.mock("obsidian", () => {
  class Component {
    register(): void {}
    registerEvent(): void {}
    registerDomEvent(): void {}
  }
  class Plugin extends Component {
    constructor(
      public app: unknown,
      public manifest: unknown,
    ) {
      super();
    }
    async loadData(): Promise<unknown> {
      return stub.data;
    }
    async saveData(d: unknown): Promise<void> {
      stub.data = JSON.parse(JSON.stringify(d));
    }
    addCommand(): void {}
    addSettingTab(): void {}
    addRibbonIcon(): { setAttribute(): void; toggleClass(): void } {
      return { setAttribute() {}, toggleClass() {} };
    }
    addStatusBarItem(): { setText(): void; title: string } {
      return { setText() {}, title: "" };
    }
    registerObsidianProtocolHandler(): void {}
  }
  class Modal {
    constructor(public app: unknown) {}
    open(): void {}
    close(): void {}
  }
  class Setting {
    setName(): this {
      return this;
    }
    setDesc(): this {
      return this;
    }
    addButton(): this {
      return this;
    }
    addText(): this {
      return this;
    }
    addToggle(): this {
      return this;
    }
    addDropdown(): this {
      return this;
    }
    addTextArea(): this {
      return this;
    }
    addExtraButton(): this {
      return this;
    }
  }
  class PluginSettingTab {
    constructor(
      public app: unknown,
      public plugin: unknown,
    ) {}
  }
  return {
    Plugin,
    Modal,
    Setting,
    PluginSettingTab,
    Notice: class {
      constructor(_m: string, _t?: number) {}
    },
    Platform: { isMobile: true, isDesktop: false, isIosApp: false, isAndroidApp: false, isMacOS: false },
    TFile: class {},
    TFolder: class {},
    normalizePath: (p: string) => p,
  };
});


import ObsyncPlugin from "../src/obsidian/main";
import { openWithPin } from "../src/core/keystore";

class FakeNative {
  kept: Record<string, string> = {};
  persist = true;
}
class FakeSecretStorage {
  private secrets: Record<string, string> = {};
  constructor(private native: FakeNative) {
    this.secrets = { ...native.kept }; // load(), before plugins
  }
  setSecret(id: string, v: string): void {
    if (!/^[a-z0-9-]+$/.test(id) || id.length > 64) throw new Error("invalid id");
    this.secrets[id] = v;
    if (this.native.persist) this.native.kept = { ...this.secrets }; // adapter.save(), not awaited
  }
  getSecret(id: string): string | null {
    return Object.hasOwn(this.secrets, id) ? this.secrets[id] : null;
  }
  deleteSecret(id: string): boolean {
    if (!Object.hasOwn(this.secrets, id)) return false;
    delete this.secrets[id];
    if (this.native.persist) this.native.kept = { ...this.secrets };
    return true;
  }
  listSecrets(): string[] {
    return Object.keys(this.secrets);
  }
}

const identity = {
  server: "https://sync.example",
  vaultId: "25ed1a48f951da6f62766b28bad51765",
  deviceId: "0f3c9a7712ab45de",
  deviceToken: "dt_secret-token",
  deviceName: "phone",
  pub: "cHVi",
  privJwk: { kty: "EC", d: "private-scalar" },
  keyring: { current: 1, keys: { 1: "vault-key-bytes" } },
};

type P = InstanceType<typeof ObsyncPlugin>;

async function launch(native: FakeNative): Promise<P> {
  const app = { vault: { configDir: ".obsidian", adapter: {} }, workspace: { on: () => ({}), onLayoutReady: () => {} }, secretStorage: new FakeSecretStorage(native) };
  const plugin = new ObsyncPlugin(app as never, { id: "obsync", dir: ".obsidian/plugins/obsync" } as never) as P;
  (plugin as unknown as { startEngine: () => Promise<void> }).startEngine = async () => {};
  await plugin.loadSettings();
  return plugin;
}

const disk = () => stub.data as { identity: unknown; sealed: { method: string } | null; protection: { method: string; secretId?: string; fallback?: unknown } };
const clearKeysOnDisk = () => JSON.stringify(stub.data).includes("dt_secret-token");

describe("device keychain protection (method secret)", () => {
  it("seals with a keychain-held key, keeps the old form until a relaunch reads the key back, then drops it", async () => {
    const native = new FakeNative();
    stub.data = { identity, sealed: null, protection: { method: "none", touchId: false }, deviceName: "phone", protectionOffered: true };
    const p = await launch(native);
    expect(p.protectionOptions().find((o) => o.method === "secret")!.available).toBe(true);
    await p.setProtection("secret");

    expect(disk().protection.method).toBe("secret");
    expect(disk().protection.secretId).toBe("obsync-25ed1a48f951da6f62766b28bad51765-0f3c9a7712ab45de");
    expect(disk().sealed!.method).toBe("secret");
    expect(disk().identity).toBeNull();
    expect(disk().protection.fallback).toBeTruthy(); // not yet confirmed
    expect(Object.keys(native.kept)).toEqual([disk().protection.secretId]);
    expect(native.kept[disk().protection.secretId!]).toMatch(/^[0-9a-f]{64}$/);

    // Relaunch: the keychain answers, the keys open, the fallback goes.
    const q = await launch(native);
    expect(q.settings.identity).toBeNull();
    expect(await q.unlock()).toBe(true);
    expect(q.settings.identity).toEqual(identity);
    expect(disk().protection.fallback).toBeUndefined();
    expect(disk().identity).toBeNull();
    expect(clearKeysOnDisk()).toBe(false); // data.json now holds ciphertext only

    // And again: still opens, nothing typed, nothing in the clear.
    const r = await launch(native);
    expect(await r.unlock()).toBe(true);
    expect(r.settings.identity).toEqual(identity);
    expect(clearKeysOnDisk()).toBe(false);
  });

  it("a keychain write that never landed reverts to unprotected keys instead of losing them", async () => {
    const native = new FakeNative();
    native.persist = false;
    stub.data = { identity, sealed: null, protection: { method: "none", touchId: false }, deviceName: "phone", protectionOffered: true };
    await (await launch(native)).setProtection("secret");
    expect(native.kept).toEqual({});

    const q = await launch(native);
    expect(await q.unlock()).toBe(true);
    expect(q.settings.identity).toEqual(identity);
    expect(disk().protection.method).toBe("none");
    expect(disk().identity).toEqual(identity);
    expect(disk().sealed).toBeNull();
  });

  it("from a PIN: a lost keychain write puts the PIN-sealed keys back, still openable with the PIN", async () => {
    const native = new FakeNative();
    stub.data = { identity, sealed: null, protection: { method: "none", touchId: false }, deviceName: "phone", protectionOffered: true };
    const p = await launch(native);
    await p.setProtection("pin", { pin: "correct horse 9" });
    expect(disk().sealed!.method).toBe("pin");
    native.persist = false;
    await p.setProtection("secret");
    expect(disk().sealed!.method).toBe("secret");
    expect(clearKeysOnDisk()).toBe(false); // the fallback is the PIN seal, never the clear keys

    const q = await launch(native);
    expect(await q.unlock()).toBe(false); // must type the PIN now
    expect(disk().protection.method).toBe("pin");
    expect(disk().sealed!.method).toBe("pin");
    expect(await openWithPin(disk().sealed as never, "correct horse 9")).toEqual(identity);
  });

  it("a confirmed entry that later vanishes (reinstall, restore) leaves the sealed keys untouched and stays locked", async () => {
    const native = new FakeNative();
    stub.data = { identity, sealed: null, protection: { method: "none", touchId: false }, deviceName: "phone", protectionOffered: true };
    await (await launch(native)).setProtection("secret");
    expect(await (await launch(native)).unlock()).toBe(true); // confirmed; fallback dropped
    const before = JSON.stringify(stub.data);

    native.kept = {}; // the keychain item is gone
    const q = await launch(native);
    expect(await q.unlock()).toBe(false);
    expect(q.settings.identity).toBeNull();
    expect(JSON.stringify(stub.data)).toBe(before);
  });

  it("switching away removes the keychain entry; desktop never offers the method", async () => {
    const native = new FakeNative();
    stub.data = { identity, sealed: null, protection: { method: "none", touchId: false }, deviceName: "phone", protectionOffered: true };
    const p = await launch(native);
    await p.setProtection("secret");
    await p.setProtection("none");
    expect(native.kept).toEqual({});
    expect(disk().identity).toEqual(identity);
    expect(disk().protection.fallback).toBeUndefined();
  });
});
