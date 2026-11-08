/**
 * VaultFS and StateStore over a plain directory with Node's fs. Used by the
 * end-to-end tests and usable for a headless CLI. Never imported by the
 * plugin bundle.
 */
import type { FileStat, StateStore, VaultFS } from "./fs";
import { promises as fsp, watch, type FSWatcher } from "node:fs";
import { isOsJunk } from "./paths";
import * as nodePath from "node:path";

export class NodeFS implements VaultFS {
  readonly configDir: string;
  private watchers: FSWatcher[] = [];
  /**
   * NFC path -> the name actually on disk, for files whose on-disk name is
   * not NFC (a vault copied from a Mac keeps NFD names on Linux). Every
   * path the engine sees is NFC; this map keeps reads and writes going to
   * the existing file instead of creating an NFC twin beside it.
   */
  private raw = new Map<string, string>();

  constructor(
    public readonly root: string,
    configDir = ".obsidian",
  ) {
    this.configDir = configDir;
  }

  private abs(p: string): string {
    p = this.raw.get(p) ?? p;
    // Defence in depth: the engine validates paths, but the file layer must
    // never step outside the vault root whatever it is handed.
    const abs = nodePath.resolve(this.root, ...p.split("/"));
    const root = nodePath.resolve(this.root);
    if (abs !== root && !abs.startsWith(root + nodePath.sep)) throw new Error(`path escapes vault: ${p}`);
    return abs;
  }

  async list(): Promise<FileStat[]> {
    const out: FileStat[] = [];
    const walk = async (rel: string) => {
      const entries = await fsp.readdir(this.abs(rel) || this.root, { withFileTypes: true });
      for (const e of entries) {
        const p = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) await walk(p);
        else if (e.isFile()) {
          // Files can vanish between readdir and stat (editor temp files,
          // our own atomic renames). They are simply not part of this listing.
          const st = await fsp.stat(this.abs(p)).catch(() => null);
          const nfc = p.normalize("NFC");
          if (nfc !== p) this.raw.set(nfc, p);
          if (st) out.push({ path: nfc, size: st.size, mtime: Math.floor(st.mtimeMs) });
        }
      }
    };
    await walk("");
    return out;
  }

  async stat(path: string): Promise<FileStat | null> {
    try {
      const st = await fsp.stat(this.abs(path));
      if (!st.isFile()) return null;
      return { path, size: st.size, mtime: Math.floor(st.mtimeMs) };
    } catch {
      return null;
    }
  }

  async read(path: string): Promise<Uint8Array> {
    return new Uint8Array(await fsp.readFile(this.abs(path)));
  }

  /**
   * Refuse to write under a name that this volume resolves to an existing,
   * differently spelled entry: on a case-insensitive or normalising volume
   * the bytes would silently replace that entry's. Measured by asking the
   * volume (does the path resolve, and is any entry in its folder spelled
   * exactly so?), not by a folding table, so names the volume keeps apart
   * ("café.md" and "cafe.md" on APFS) stay apart here too. Same rule as
   * ObsidianFS.refuseCaseClash; the engine skips and reports.
   */
  private async refuseAliasClash(path: string): Promise<void> {
    // Every segment, not just the last: "notes/A.md" written through a
    // folder the volume resolves to "Notes/" would replace Notes/A.md. An
    // empty twin folder has been renamed by alignParentSpelling before this
    // runs, so a differently spelled parent that still resolves has contents.
    const segs = (this.raw.get(path) ?? path).split("/");
    let rel = "";
    for (const seg of segs) {
      const want = rel ? `${rel}/${seg}` : seg;
      const resolves = await fsp.stat(this.abs(want)).then(
        () => true,
        () => false,
      );
      if (!resolves) return; // nothing answers for this name here or below: new entries
      const entries = await fsp.readdir(this.abs(rel)).catch(() => null);
      if (entries) {
        const nfc = seg.normalize("NFC");
        if (!entries.some((e) => e === seg || e.normalize("NFC") === nfc)) {
          throw new Error(`"${want}" resolves to an entry spelled differently on this volume; refusing to write through it`);
        }
      }
      rel = want;
    }
  }

  /**
   * A case-only folder rename reaches us as deletes under the old spelling
   * and puts under the new one, and Obsidian leaves the emptied folder
   * behind. On a case-insensitive volume the puts would land inside that
   * old-spelled folder and the scanner would report them under the old name
   * forever. When a parent of `path` resolves to an existing folder spelled
   * differently and that folder is empty, rename it to the requested
   * spelling first; a folder that still has contents is left as it is.
   */
  private async alignParentSpelling(path: string): Promise<void> {
    const segs = (this.raw.get(path) ?? path).split("/");
    let rel = "";
    for (const seg of segs.slice(0, -1)) {
      const want = rel ? `${rel}/${seg}` : seg;
      const st = await fsp.stat(this.abs(want)).catch(() => null);
      if (st?.isDirectory()) {
        const siblings = await fsp.readdir(this.abs(rel)).catch(() => [] as string[]);
        const nfc = seg.normalize("NFC");
        if (!siblings.some((e) => e === seg || e.normalize("NFC") === nfc)) {
          // Spelled differently on disk. Find which entry it is by inode.
          for (const e of siblings) {
            const es = await fsp.stat(this.abs(rel ? `${rel}/${e}` : e)).catch(() => null);
            if (!es || !es.isDirectory() || es.ino !== st.ino) continue;
            // Finder's .DS_Store and Explorer's desktop.ini are never synced
            // and never deleted by sync, so a folder holding only those is
            // empty for this purpose (they move with the rename).
            const inside = (await fsp.readdir(this.abs(rel ? `${rel}/${e}` : e)).catch(() => ["?"])).filter((n) => !isOsJunk(n));
            if (inside.length === 0) await fsp.rename(this.abs(rel ? `${rel}/${e}` : e), this.abs(want)).catch(() => {});
            break;
          }
        }
      }
      rel = want;
    }
  }

  async write(path: string, data: Uint8Array, mtime: number): Promise<void> {
    const abs = this.abs(path);
    await this.alignParentSpelling(path);
    await this.refuseAliasClash(path);
    await fsp.mkdir(nodePath.dirname(abs), { recursive: true });
    const tmp = `${abs}.obsync-tmp`;
    await fsp.writeFile(tmp, data);
    const t = new Date(mtime);
    await fsp.utimes(tmp, t, t);
    await fsp.rename(tmp, abs);
  }

  async remove(path: string): Promise<void> {
    await fsp.rm(this.abs(path), { force: true });
  }

  onChange(cb: (path: string) => void): () => void {
    // Recursive fs.watch is supported on Linux since Node 20 and on macOS/Windows.
    try {
      const w = watch(this.root, { recursive: true }, (_ev, name) => {
        if (name) cb(String(name).split(nodePath.sep).join("/").normalize("NFC"));
      });
      this.watchers.push(w);
      return () => w.close();
    } catch {
      return () => {};
    }
  }
}

export class FileStateStore implements StateStore {
  constructor(private file: string) {}
  async load(): Promise<string | null> {
    try {
      return await fsp.readFile(this.file, "utf8");
    } catch {
      return null;
    }
  }
  async save(json: string): Promise<void> {
    await fsp.mkdir(nodePath.dirname(this.file), { recursive: true });
    await fsp.writeFile(this.file + ".tmp", json);
    await fsp.rename(this.file + ".tmp", this.file);
  }
}
