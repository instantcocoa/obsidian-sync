/**
 * ObsidianFS.write must not report success for a short write. The Android
 * run (docs/MOBILE-TEST-PROMPT.md step 9) once got a 0-byte note back from a
 * recovery-passphrase rejoin while the state recorded the version as applied;
 * the adapter had returned normally. The write path now checks the size the
 * adapter reports, rewrites once through the adapter, and throws if the file
 * is still wrong so the engine skips and reports the op.
 *
 * "obsidian" is stubbed: TFile/TFolder for instanceof, normalizePath identity.
 */
import { describe, expect, it, vi } from "vitest";

vi.mock("obsidian", () => ({
  TFile: class {},
  TFolder: class {},
  normalizePath: (p: string) => p,
  Notice: class {},
  Platform: { isMobile: true },
}));

import { ObsidianFS } from "../src/obsidian/obsidian-fs";

/** A vault whose first `n` writes land as 0-byte files, like the one seen on Android. */
function fakeApp(shortWrites: number) {
  const disk = new Map<string, Uint8Array>();
  const log: string[] = [];
  let remaining = shortWrites;
  const put = (how: string, path: string, data: ArrayBuffer) => {
    log.push(`${how}:${path}`);
    disk.set(path, remaining-- > 0 ? new Uint8Array(0) : new Uint8Array(data));
  };
  const app = {
    vault: {
      configDir: ".obsidian",
      getAbstractFileByPath: () => null,
      createFolder: async () => {},
      createBinary: async (path: string, data: ArrayBuffer) => put("createBinary", path, data),
      modifyBinary: async () => {
        throw new Error("not used: nothing is indexed in this fake");
      },
      adapter: {
        exists: async (p: string) => disk.has(p),
        mkdir: async () => {},
        stat: async (p: string) => (disk.has(p) ? { type: "file", size: disk.get(p)!.length, mtime: 0, ctime: 0 } : null),
        writeBinary: async (path: string, data: ArrayBuffer) => put("adapter.writeBinary", path, data),
        readBinary: async (p: string) => disk.get(p)!.buffer,
      },
    },
  };
  return { app, disk, log };
}

const bytes = new TextEncoder().encode("# Hello from desktop\n\nninety-five bytes or so of note content that must not come back empty\n");

describe("ObsidianFS.write verifies what landed", () => {
  it("passes a normal write through untouched", async () => {
    const f = fakeApp(0);
    await new ObsidianFS(f.app as never).write("Hello.md", bytes, 1700000000000);
    expect(f.log).toEqual(["createBinary:Hello.md"]);
    expect([...f.disk.get("Hello.md")!]).toEqual([...bytes]);
  });

  it("rewrites once through the adapter when the file came out short", async () => {
    const f = fakeApp(1);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await new ObsidianFS(f.app as never).write("Hello.md", bytes, 1700000000000);
    expect(f.log).toEqual(["createBinary:Hello.md", "adapter.writeBinary:Hello.md"]);
    expect(f.disk.get("Hello.md")!.length).toBe(bytes.length);
    expect(warn.mock.calls.map((c) => String(c[0]))).toEqual(["obsync: Hello.md was short after writing; rewritten through the adapter"]);
    warn.mockRestore();
  });

  it("throws, instead of reporting success, when the rewrite is short too", async () => {
    const f = fakeApp(2);
    await expect(new ObsidianFS(f.app as never).write("Hello.md", bytes, 1700000000000)).rejects.toThrow(/write verification failed for Hello.md: wrote \d+ bytes, the adapter reports 0/);
  });

  it("checks config-dir writes the same way", async () => {
    const f = fakeApp(1);
    vi.spyOn(console, "warn").mockImplementation(() => {});
    await new ObsidianFS(f.app as never).write(".obsidian/app.json", bytes, 1700000000000);
    expect(f.log).toEqual(["adapter.writeBinary:.obsidian/app.json", "adapter.writeBinary:.obsidian/app.json"]);
    expect(f.disk.get(".obsidian/app.json")!.length).toBe(bytes.length);
    vi.restoreAllMocks();
  });
});
