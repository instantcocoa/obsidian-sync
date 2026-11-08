/**
 * Ninth review (2026-11-07): ObsidianFS.refuseCaseClash / alignParentSpelling
 * against an adapter that behaves like Obsidian's on APFS: `exists`, `stat`
 * and `list` answer for any casing of a name; `list(dir)` returns the
 * children's on-disk spelling under the *requested* spelling of `dir`
 * (Obsidian's desktop adapter joins the caller's path with readdir names);
 * dot entries are listed (ObsidianFS.listDot relies on that too); accents
 * are not folded (APFS keeps café/cafe apart). Real Obsidian is not driven
 * here; the adapter semantics are the assumption and are stated per test.
 *
 *  1. Same as the NodeFS case: `.DS_Store` left in `Notes/` keeps the folder
 *     from being renamed to `notes/`, and a new file `notes/a.md` is refused.
 *     Fails on HEAD (5a88779).
 *  2-6. Soundness (pass): emptied twin realigned; populated twin refused;
 *     missing parents; a new file under the config dir when `list("")`
 *     includes it; café/cafe.
 */
import { describe, expect, it } from "vitest";
import { ObsidianFS } from "../src/obsidian/obsidian-fs";
import { utf8 } from "../src/core/encoding";

type Entry = { path: string; data?: Uint8Array };

/** An APFS-like vault behind Obsidian's adapter API. Keys fold case only. */
function apfs(initial: Record<string, Uint8Array | "dir">) {
  const entries = new Map<string, Entry>();
  const key = (p: string) => p.toLowerCase();
  const add = (p: string, data?: Uint8Array) => {
    if (!entries.has(key(p))) entries.set(key(p), { path: p, data });
    else if (data) entries.get(key(p))!.data = data;
  };
  const parentOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
  const addWithParents = (p: string, data?: Uint8Array) => {
    const parts = p.split("/");
    for (let i = 1; i < parts.length; i++) add(parts.slice(0, i).join("/"));
    add(p, data);
  };
  for (const [p, v] of Object.entries(initial)) addWithParents(p, v === "dir" ? undefined : v);
  const log: string[] = [];
  const adapter = {
    exists: async (p: string) => entries.has(key(p)),
    stat: async (p: string) => {
      const e = entries.get(key(p));
      if (!e) return null;
      return e.data ? { type: "file", size: e.data.length, mtime: 0, ctime: 0 } : { type: "folder", size: 0, mtime: 0, ctime: 0 };
    },
    list: async (dir: string) => {
      if (dir && !entries.has(key(dir))) throw new Error("ENOENT");
      const files: string[] = [];
      const folders: string[] = [];
      for (const e of entries.values()) {
        if (key(parentOf(e.path)) !== key(dir)) continue;
        const name = e.path.slice(e.path.lastIndexOf("/") + 1);
        (e.data ? files : folders).push(dir ? `${dir}/${name}` : name);
      }
      return { files, folders };
    },
    mkdir: async (p: string) => addWithParents(p),
    rename: async (from: string, to: string) => {
      log.push(`rename ${from} -> ${to}`);
      const moved = [...entries.values()].filter((e) => key(e.path) === key(from) || key(e.path).startsWith(key(from) + "/"));
      for (const e of moved) entries.delete(key(e.path));
      for (const e of moved) add(to + e.path.slice(from.length), e.data);
    },
    writeBinary: async (p: string, buf: ArrayBuffer) => {
      log.push(`write ${p}`);
      addWithParents(p, new Uint8Array(buf));
    },
    readBinary: async (p: string) => entries.get(key(p))!.data!.buffer,
    remove: async (p: string) => void entries.delete(key(p)),
  };
  const app = {
    vault: {
      configDir: ".obsidian",
      getAbstractFileByPath: () => null,
      getFiles: () => [],
      getAllLoadedFiles: () => [],
      createFolder: async (p: string) => addWithParents(p),
      createBinary: async (p: string, buf: ArrayBuffer) => adapter.writeBinary(p, buf),
      modifyBinary: async () => {
        throw new Error("not used: nothing is indexed in this fake");
      },
      adapter,
    },
  };
  const fs = new ObsidianFS(app as never);
  const spelled = () => [...entries.values()].map((e) => e.path).sort();
  return { fs, log, spelled, read: (p: string) => new TextDecoder().decode(entries.get(key(p))!.data!) };
}

const cfg = { ".obsidian/app.json": utf8("{}") };

describe("ObsidianFS per-segment probe on an APFS-like adapter", () => {
  it("1. .DS_Store left in Notes/ blocks the rename to notes/ and the new file is refused", async () => {
    const v = apfs({ ...cfg, "Notes/.DS_Store": new Uint8Array(32) });
    // The deletes of Notes/a.md and Notes/b.md have landed; only Finder's file is left.
    await v.fs.write("notes/a.md", utf8("a\n"), 1);
    expect(v.spelled(), v.log.join("\n")).toContain("notes/a.md");
    expect(v.spelled()).not.toContain("Notes");
  });

  it("2. an emptied twin folder is realigned to the new spelling", async () => {
    const v = apfs({ ...cfg, Notes: "dir" });
    await v.fs.write("notes/a.md", utf8("a\n"), 1);
    expect(v.spelled()).toEqual([".obsidian", ".obsidian/app.json", "notes", "notes/a.md"]);
  });

  it("3. a populated twin folder is refused (by design) and its file is untouched", async () => {
    const v = apfs({ ...cfg, "Notes/A.md": utf8("honest\n") });
    await expect(v.fs.write("notes/A.md", utf8("other\n"), 1)).rejects.toThrow(/spelled differently/);
    expect(v.read("Notes/A.md")).toBe("honest\n");
  });

  it("4. parents that do not exist yet, five deep", async () => {
    const v = apfs(cfg);
    await v.fs.write("p1/p2/p3/p4/leaf.md", utf8("deep\n"), 1);
    expect(v.read("p1/p2/p3/p4/leaf.md")).toBe("deep\n");
  });

  it("5. a new file under the config dir passes when list('') includes the dot folder (assumed; listDot relies on it too)", async () => {
    const v = apfs({ ...cfg, ".obsidian/snippets": "dir" });
    await v.fs.write(".obsidian/snippets/new.css", utf8("a{}\n"), 1);
    expect(v.read(".obsidian/snippets/new.css")).toBe("a{}\n");
  });

  it("6. café.md and cafe.md stay two files", async () => {
    const v = apfs(cfg);
    await v.fs.write("café.md", utf8("accent\n"), 1);
    await v.fs.write("cafe.md", utf8("plain\n"), 1);
    expect(v.read("café.md")).toBe("accent\n");
    expect(v.read("cafe.md")).toBe("plain\n");
  });
});
