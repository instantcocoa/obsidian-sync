/**
 * Twelfth review, whole-system pass (2026-11-08): `ObsyncPlugin.saveSettings`
 * (main.ts) writes `sealed: null` whenever `settings.identity` is null, which
 * is exactly the state of a device whose keys are sealed and not yet
 * unlocked (`locked = true`, identity null, sealed set). Any call to
 * saveSettings() in that state destroys the only copy of the device's keys,
 * token and private key on disk; the device is then out of the vault and
 * re-joins with an invite or the passphrase.
 *
 * Today no UI path reaches saveSettings() while locked (the settings tab
 * shows only "Unlock", the engine is not running, defaultProtection and
 * warnIfMirrored are gated on the identity), so this is a latent hazard,
 * pinned here so the next feature that saves a setting while locked (a
 * notices toggle, a device-name field, a "remember roster" write) has a
 * failing test rather than a support ticket. The fix is one guard: never
 * write `sealed: null` unless protection is "none" or identity is present.
 *
 * `obsidian` is mocked with the few classes main.ts and its imports touch;
 * the plugin is instantiated with a minimal App and an in-memory data store.
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
    Platform: { isMobile: false, isDesktop: true, isIosApp: false, isAndroidApp: false, isMacOS: false },
    TFile: class {},
    TFolder: class {},
    normalizePath: (p: string) => p,
  };
});

import ObsyncPlugin from "../src/obsidian/main";

describe("review 12 (whole system): saveSettings while locked", () => {
  it("a saveSettings() call on a locked device keeps the sealed keys exactly as loaded (fixed after the twelfth review)", async () => {
    const sealed = { v: 1, method: "pin", salt: "c2FsdA==", nonce: "bm9uY2Vub25jZQ==", ct: "Y2lwaGVydGV4dA==" };
    stub.data = { identity: null, sealed, protection: { method: "pin", touchId: false }, deviceName: "phone", protectionOffered: true };
    const app = { vault: { configDir: ".obsidian", adapter: {} }, workspace: { on: () => ({}), onLayoutReady: () => {} } };
    const plugin = new ObsyncPlugin(app as never, { id: "obsync", dir: ".obsidian/plugins/obsync" } as never);
    await plugin.loadSettings();
    expect(plugin.settings.identity).toBeNull();
    expect(plugin.settings.sealed).toEqual(sealed);
    // The state onload() would leave this device in before the PIN is typed.
    plugin.locked = true;

    // Any setting saved now (the shape of a future "remember X" write) ...
    plugin.settings.syncNotices = false;
    await plugin.saveSettings();

    // ... and the sealed identity is no longer on disk.
    const onDisk = stub.data as { sealed: unknown; identity: unknown; protection: { method: string } };
    expect(onDisk.identity).toBeNull();
    expect(onDisk.protection.method).toBe("pin");
    expect(onDisk.sealed).toEqual(sealed); // the keys survive a settings save made before the PIN is typed
  });
});
