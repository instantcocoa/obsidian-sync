/**
 * VaultFS over the Obsidian API.
 *
 * Indexed files (everything Obsidian shows) go through `app.vault` so open
 * editors update and the file index stays coherent. Dot-files and the config
 * dir are invisible to the index and go through `app.vault.adapter`.
 *
 * Lessons baked in (DESIGN.md §1.5): always read bytes with
 * `adapter.readBinary` (`vault.read` strips a BOM), always floor mtimes
 * (Capacitor casts them to a Java long), call the undocumented
 * `adapter.reconcileInternalFile` after writing under the config dir so
 * Obsidian notices.
 */
import { App, TFile, TFolder, normalizePath } from "obsidian";
import { isSafeDevicePath } from "../core/paths";
import type { FileStat, VaultFS, StateStore } from "../core/fs";

type AdapterExt = App["vault"]["adapter"] & {
  reconcileInternalFile?: (path: string) => Promise<void>;
};

export class ObsidianFS implements VaultFS {
  readonly configDir: string;
  private rawHandlers = new Set<(p: string) => void>();

  constructor(private app: App) {
    this.configDir = app.vault.configDir;
  }

  private isDot(path: string): boolean {
    return path.startsWith(".") || path.includes("/.");
  }

  /** Obsidian's adapter does not resolve ".." itself; never pass one through. */
  private checked(path: string): string {
    if (!isSafeDevicePath(path)) throw new Error(`path escapes vault: ${path}`);
    return path;
  }

  async list(): Promise<FileStat[]> {
    const out: FileStat[] = [];
    for (const f of this.app.vault.getFiles()) {
      out.push({ path: f.path.normalize("NFC"), size: f.stat.size, mtime: Math.floor(f.stat.mtime) });
    }
    // Dot entries are not indexed. Walk every folder once and descend into
    // dot-folders fully. The config dir is a dot-folder at the root.
    const seen = new Set(out.map((f) => f.path));
    const walkDot = async (dir: string) => {
      let l: { files: string[]; folders: string[] };
      try {
        l = await this.app.vault.adapter.list(dir);
      } catch {
        return;
      }
      for (const f of l.files) {
        const p = normalizePath(f).normalize("NFC");
        if (seen.has(p)) continue;
        const st = await this.app.vault.adapter.stat(p).catch(() => null);
        if (st?.type === "file") {
          out.push({ path: p, size: st.size, mtime: Math.floor(st.mtime) });
          seen.add(p);
        }
      }
      for (const d of l.folders) await walkDot(normalizePath(d));
    };
    const folders: string[] = [""];
    for (const f of this.app.vault.getAllLoadedFiles()) if (f instanceof TFolder && f.path !== "/") folders.push(f.path);
    for (const dir of folders) {
      let l: { files: string[]; folders: string[] };
      try {
        l = await this.app.vault.adapter.list(dir);
      } catch {
        continue;
      }
      for (const f of l.files) {
        const p = normalizePath(f).normalize("NFC");
        if (seen.has(p) || !this.isDot(p)) continue;
        const st = await this.app.vault.adapter.stat(p).catch(() => null);
        if (st?.type === "file") {
          out.push({ path: p, size: st.size, mtime: Math.floor(st.mtime) });
          seen.add(p);
        }
      }
      for (const d of l.folders) {
        const p = normalizePath(d);
        if (this.isDot(p)) await walkDot(p);
      }
    }
    return out;
  }

  /** Root-level dot entries only (config dir, .trash, …), recursively. Cheap. */
  async listDot(): Promise<FileStat[]> {
    const out: FileStat[] = [];
    let root: { files: string[]; folders: string[] };
    try {
      root = await this.app.vault.adapter.list("");
    } catch {
      return out;
    }
    const walk = async (dir: string) => {
      let l: { files: string[]; folders: string[] };
      try {
        l = await this.app.vault.adapter.list(dir);
      } catch {
        return;
      }
      for (const f of l.files) {
        const p = normalizePath(f).normalize("NFC");
        const st = await this.app.vault.adapter.stat(p).catch(() => null);
        if (st?.type === "file") out.push({ path: p, size: st.size, mtime: Math.floor(st.mtime) });
      }
      for (const d of l.folders) await walk(normalizePath(d));
    };
    for (const f of root.files) {
      const p = normalizePath(f).normalize("NFC");
      if (!p.startsWith(".")) continue;
      const st = await this.app.vault.adapter.stat(p).catch(() => null);
      if (st?.type === "file") out.push({ path: p, size: st.size, mtime: Math.floor(st.mtime) });
    }
    for (const d of root.folders) {
      const p = normalizePath(d);
      if (p.startsWith(".")) await walk(p);
    }
    return out;
  }

  async stat(path: string): Promise<FileStat | null> {
    const f = this.app.vault.getAbstractFileByPath(path);
    if (f instanceof TFile) return { path, size: f.stat.size, mtime: Math.floor(f.stat.mtime) };
    const st = await this.app.vault.adapter.stat(path).catch(() => null);
    if (!st || st.type !== "file") return null;
    return { path, size: st.size, mtime: Math.floor(st.mtime) };
  }

  async read(path: string): Promise<Uint8Array> {
    return new Uint8Array(await this.app.vault.adapter.readBinary(path));
  }

  private async ensureFolder(path: string): Promise<void> {
    const i = path.lastIndexOf("/");
    if (i < 0) return;
    const dir = path.slice(0, i);
    if (this.isDot(dir)) {
      if (!(await this.app.vault.adapter.exists(dir))) await this.app.vault.adapter.mkdir(dir);
      return;
    }
    // Create each level explicitly; createFolder does not promise recursion.
    const parts = dir.split("/");
    for (let i = 1; i <= parts.length; i++) {
      const sub = parts.slice(0, i).join("/");
      if (!this.app.vault.getAbstractFileByPath(sub)) await this.app.vault.createFolder(sub).catch(() => {});
    }
  }

  async write(path: string, data: Uint8Array, mtime: number): Promise<void> {
    path = this.checked(path);
    const opts = { mtime: Math.floor(mtime) };
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
    await this.ensureFolder(path);
    if (this.isDot(path)) {
      await this.app.vault.adapter.writeBinary(path, buf, opts);
      await (this.app.vault.adapter as AdapterExt).reconcileInternalFile?.(path).catch(() => {});
      return;
    }
    const existing = this.app.vault.getAbstractFileByPath(path);
    if (existing instanceof TFile) await this.app.vault.modifyBinary(existing, buf, opts);
    else await this.app.vault.createBinary(path, buf, opts);
  }

  async remove(path: string): Promise<void> {
    path = this.checked(path);
    const f = this.app.vault.getAbstractFileByPath(path);
    if (f instanceof TFile) {
      // Respects the user's "deleted files" preference (system trash / .trash / permanent).
      await this.app.fileManager.trashFile(f);
      return;
    }
    if (await this.app.vault.adapter.exists(path)) await this.app.vault.adapter.remove(path);
    await (this.app.vault.adapter as AdapterExt).reconcileInternalFile?.(path).catch(() => {});
  }

  onChange(cb: (path: string) => void): () => void {
    const v = this.app.vault;
    const refs = [
      v.on("create", (f) => cb(f.path)),
      v.on("modify", (f) => cb(f.path)),
      v.on("delete", (f) => cb(f.path)),
      v.on("rename", (f, old) => {
        cb(old);
        cb(f.path);
      }),
      // Undocumented: fires for adapter-level changes under the config dir
      // (and on reads). The engine treats it as a hint and hashes to decide.
      (v as unknown as { on: (n: string, h: (p: string) => void) => ReturnType<typeof v.on> }).on("raw", (p: string) => {
        if (typeof p === "string") cb(normalizePath(p));
      }),
    ];
    return () => refs.forEach((r) => v.offref(r));
  }
}

/** state.json in the plugin's own folder (excluded from sync by default). */
export class ObsidianStateStore implements StateStore {
  constructor(
    private app: App,
    private file: string,
  ) {}
  async load(): Promise<string | null> {
    const a = this.app.vault.adapter;
    if (!(await a.exists(this.file))) return null;
    return a.read(this.file);
  }
  async save(json: string): Promise<void> {
    const a = this.app.vault.adapter;
    const dir = this.file.slice(0, this.file.lastIndexOf("/"));
    if (!(await a.exists(dir))) await a.mkdir(dir);
    await a.write(this.file + ".tmp", json);
    if (await a.exists(this.file)) await a.remove(this.file);
    await a.rename(this.file + ".tmp", this.file);
  }
}
