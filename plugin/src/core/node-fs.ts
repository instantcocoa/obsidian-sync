/**
 * VaultFS and StateStore over a plain directory with Node's fs. Used by the
 * end-to-end tests and usable for a headless CLI. Never imported by the
 * plugin bundle.
 */
import type { FileStat, StateStore, VaultFS } from "./fs";
import { promises as fsp, watch, type FSWatcher } from "node:fs";
import * as nodePath from "node:path";

export class NodeFS implements VaultFS {
  readonly configDir: string;
  private watchers: FSWatcher[] = [];

  constructor(
    public readonly root: string,
    configDir = ".obsidian",
  ) {
    this.configDir = configDir;
  }

  private abs(p: string): string {
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
          if (st) out.push({ path: p.normalize("NFC"), size: st.size, mtime: Math.floor(st.mtimeMs) });
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

  async write(path: string, data: Uint8Array, mtime: number): Promise<void> {
    const abs = this.abs(path);
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
