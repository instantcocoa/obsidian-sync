/**
 * Twelfth review, whole-system pass (2026-11-08): DESIGN §5.7, accepted
 * residual 2, rests on "the plugin announces every plugin it enables", and
 * the Sync-notices setting promises "Errors and anything that needs your
 * decision are always shown". Code from another device starting to run on
 * this one is the single most consequential event the plugin can report,
 * and it is wired as a routine notice: main.ts hands ConfigHooks
 * `(msg, ms) => this.routineNotice(msg, ms)`, and routineNotice is a no-op
 * when `settings.syncNotices` is false. A member (or a holder of a leaked
 * invite link) who enables a plugin in the vault then runs code on every
 * device whose owner turned the chatter off, without a word.
 *
 * The fake app mirrors Obsidian's plugin registry the way
 * hooks-mobile.test.ts does. Two cases: notices on (soundness: the enable is
 * announced) and notices off (the finding: the same enable says nothing).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const stub = vi.hoisted(() => ({ notices: [] as string[], platform: { isMobile: false, isDesktop: true } }));
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
  const loaded: Record<string, unknown> = {};
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
      plugins: loaded,
      manifests: {} as Record<string, { id: string; isDesktopOnly?: boolean } | undefined>,
      loadManifests: async () => {
        app.plugins.manifests = { ...onDisk };
      },
      enablePlugin: async (id: string) => {
        calls.push(`enable:${id}`);
        loaded[id] = {};
      },
      disablePlugin: async (id: string) => {
        calls.push(`disable:${id}`);
        delete loaded[id];
      },
    },
  };
  return { app, files, onDisk, calls };
}

/** What main.ts does: `routineNotice` shows the message only while "Sync notices" is on. */
function pluginNotify(syncNotices: boolean): (msg: string, ms?: number) => void {
  return (msg) => {
    if (syncNotices) stub.notices.push(msg);
  };
}

const tick = () => new Promise((r) => setTimeout(r, 20));

describe("review 12 (whole system): the code-execution notice is a routine notice", () => {
  beforeEach(() => (stub.notices.length = 0));

  async function enableFromVault(syncNotices: boolean) {
    const { app, files, onDisk, calls } = fakeApp();
    const hooks = new ConfigHooks(app as never, "obsync", pluginNotify(syncNotices));
    // Another device synced a plugin's files and the list that enables it.
    onDisk["evil-helper"] = { id: "evil-helper" };
    files.set(".obsidian/community-plugins.json", JSON.stringify(["evil-helper"]));
    hooks.afterApply(".obsidian/plugins/evil-helper/main.js", "put");
    hooks.afterApply(".obsidian/community-plugins.json", "put");
    await tick();
    return calls;
  }

  it("soundness: with Sync notices on, enabling a plugin from the vault is announced", async () => {
    const calls = await enableFromVault(true);
    expect(calls).toContain("enable:evil-helper");
    expect(stub.notices.some((n) => /enabled plugin "evil-helper"/.test(n))).toBe(true);
  });

  it("with Sync notices off, enabling a plugin from the vault is still announced (fixed after the twelfth review)", async () => {
    const calls = await enableFromVault(false);
    expect(calls).toContain("enable:evil-helper"); // code from the vault is now running here
    expect(stub.notices.some((n) => /enabled plugin "evil-helper"/.test(n)), `notices: ${JSON.stringify(stub.notices)}`).toBe(true); // code from another device running here is always announced
  });
});
