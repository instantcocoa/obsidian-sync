/**
 * ObsidianStateStore.load() during a save in flight. A save is write tmp →
 * remove → rename; a plugin reload runs the next instance's load() inside
 * that window (Obsidian does not await onunload). Seen on the Android run and
 * on the desktop peer: exists() true, read() ENOENT, uncaught, and the engine
 * then saved an empty state over the real one.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("obsidian", () => ({ TFile: class {}, TFolder: class {}, normalizePath: (p: string) => p, Notice: class {}, Platform: {} }));

import { ObsidianStateStore } from "../src/obsidian/obsidian-fs";

function fakeAdapter() {
  const files = new Map<string, string>();
  const app = {
    vault: {
      adapter: {
        exists: async (p: string) => files.has(p),
        read: async (p: string) => {
          if (!files.has(p)) throw new Error(`ENOENT: no such file or directory, open '${p}'`);
          return files.get(p)!;
        },
        write: async (p: string, s: string) => void files.set(p, s),
        remove: async (p: string) => void files.delete(p),
        rename: async (a: string, b: string) => {
          files.set(b, files.get(a)!);
          files.delete(a);
        },
        mkdir: async () => {},
      },
    },
  };
  return { app, files };
}

const FILE = ".obsidian/plugins/obsync/state.json";

describe("ObsidianStateStore.load during a save in flight", () => {
  afterEach(() => vi.useRealTimers());

  it("returns null for a vault that never synced", async () => {
    const f = fakeAdapter();
    expect(await new ObsidianStateStore(f.app as never, FILE).load()).toBeNull();
  });

  it("round-trips a save", async () => {
    const f = fakeAdapter();
    const s = new ObsidianStateStore(f.app as never, FILE);
    await s.save('{"version":1,"cursor":7}');
    expect(await s.load()).toBe('{"version":1,"cursor":7}');
    expect(f.files.has(FILE + ".tmp")).toBe(false);
  });

  it("waits out the remove→rename window instead of throwing or reading nothing", async () => {
    vi.useFakeTimers();
    const f = fakeAdapter();
    const real = f.app.vault.adapter;
    // The old engine's flush: tmp written, state.json removed, rename pending.
    f.files.set(FILE + ".tmp", '{"version":1,"cursor":39}');
    // First exists() says the file is there, but it is gone by the time read() runs.
    let firstExists = true;
    f.app.vault.adapter = {
      ...real,
      exists: async (p: string) => {
        if (p === FILE && firstExists) {
          firstExists = false;
          return true;
        }
        return f.files.has(p);
      },
    } as typeof real;
    const load = new ObsidianStateStore(f.app as never, FILE).load();
    // The rename lands 250 ms later.
    setTimeout(() => void real.rename(FILE + ".tmp", FILE), 250);
    await vi.advanceTimersByTimeAsync(1000);
    expect(await load).toBe('{"version":1,"cursor":39}');
  });

  it("falls back to a tmp file that a crash left behind", async () => {
    vi.useFakeTimers();
    const f = fakeAdapter();
    f.files.set(FILE + ".tmp", '{"version":1,"cursor":12}');
    const load = new ObsidianStateStore(f.app as never, FILE).load();
    await vi.advanceTimersByTimeAsync(3000);
    expect(await load).toBe('{"version":1,"cursor":12}');
  });
});
