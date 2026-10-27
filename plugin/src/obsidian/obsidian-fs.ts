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
    return this.raw.get(path) ?? path;
  }

  /**
   * NFC path -> the name Obsidian actually reports, for files whose on-disk
   * name is not NFC (Linux keeps whatever bytes a Mac wrote). The engine
   * works in NFC; this keeps reads and writes on the existing file.
   */
  private raw = new Map<string, string>();

  private nfc(p: string): string {
    const n = p.normalize("NFC");
    if (n !== p) this.raw.set(n, p);
    return n;
  }

  async list(): Promise<FileStat[]> {
    const out: FileStat[] = [];
    for (const f of this.app.vault.getFiles()) {
      out.push({ path: this.nfc(f.path), size: f.stat.size, mtime: Math.floor(f.stat.mtime) });
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
        const p = this.nfc(normalizePath(f));
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
        const p = this.nfc(normalizePath(f));
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
        const p = this.nfc(normalizePath(f));
        const st = await this.app.vault.adapter.stat(p).catch(() => null);
        if (st?.type === "file") out.push({ path: p, size: st.size, mtime: Math.floor(st.mtime) });
      }
      for (const d of l.folders) await walk(normalizePath(d));
    };
    for (const f of root.files) {
      const p = this.nfc(normalizePath(f));
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
    path = this.raw.get(path) ?? path;
    const f = this.app.vault.getAbstractFileByPath(path);
    if (f instanceof TFile) return { path, size: f.stat.size, mtime: Math.floor(f.stat.mtime) };
    const st = await this.app.vault.adapter.stat(path).catch(() => null);
    if (!st || st.type !== "file") return null;
    // On a case-insensitive volume (Windows, macOS) the adapter answers for
    // "note.md" with the stat of "Note.md". The engine keys files by exact
    // name, so that answer would make a case-only rename look like a new
    // file beside a surviving old one, and a remote case twin look like a
    // local edit of the other file. Only an exact-name entry counts.
    if (!(await this.exactName(path))) return null;
    return { path, size: st.size, mtime: Math.floor(st.mtime) };
  }

  /** Does an entry with exactly this name (case and all) exist in its folder? */
  private async exactName(path: string): Promise<boolean> {
    const i = path.lastIndexOf("/");
    const dir = i < 0 ? "" : path.slice(0, i);
    try {
      const l = await this.app.vault.adapter.list(dir);
      return l.files.some((f) => normalizePath(f) === path);
    } catch {
      return false;
    }
  }

  async read(path: string): Promise<Uint8Array> {
    return new Uint8Array(await this.app.vault.adapter.readBinary(this.raw.get(path) ?? path));
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
      await this.verifyWrite(path, buf, opts);
      await (this.app.vault.adapter as AdapterExt).reconcileInternalFile?.(path).catch(() => {});
      return;
    }
    const existing = this.app.vault.getAbstractFileByPath(path);
    if (existing instanceof TFile) await this.app.vault.modifyBinary(existing, buf, opts);
    else await this.app.vault.createBinary(path, buf, opts);
    await this.verifyWrite(path, buf, opts);
  }

  /**
   * Seen once on Android 14 (Obsidian 1.14.4, recovery-passphrase rejoin): a
   * write returned normally and left a 0-byte file, and the engine recorded
   * the version as applied. The next join turned the empty file into a
   * conflict copy, so nothing was lost, but a silent short write must not
   * count as success. Compare the size the adapter reports with what was
   * written; rewrite once through the adapter; if it still differs, throw so
   * the engine skips and reports this op instead of recording it.
   */
  private async verifyWrite(path: string, buf: ArrayBuffer, opts: { mtime: number }): Promise<void> {
    const size = async () => (await this.app.vault.adapter.stat(path).catch(() => null))?.size;
    if ((await size()) === buf.byteLength) return;
    await this.app.vault.adapter.writeBinary(path, buf, opts);
    const after = await size();
    if (after !== buf.byteLength) throw new Error(`write verification failed for ${path}: wrote ${buf.byteLength} bytes, the adapter reports ${after ?? "no file"}`);
    console.warn(`obsync: ${path} was short after writing; rewritten through the adapter`);
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
  /**
   * A save is write tmp → remove → rename, so the file is briefly absent.
   * That window met a reload on both Android and desktop: Obsidian does not
   * await an async onunload, so the next plugin instance loads state while
   * the previous engine's final flush is still running; exists() said yes,
   * read() threw ENOENT, the engine started with an empty state and later
   * saved it over the real one. While the tmp file is there a rename is
   * imminent: wait for it. A tmp file that never goes away (a crash mid-save)
   * is the newest state there is and is used.
   */
  async load(): Promise<string | null> {
    const a = this.app.vault.adapter;
    const tmp = this.file + ".tmp";
    for (let attempt = 0; attempt < 20; attempt++) {
      if (await a.exists(this.file)) {
        try {
          return await a.read(this.file);
        } catch {
          /* removed between exists and read: a save is in flight */
        }
      }
      if (!(await a.exists(tmp))) return null;
      await new Promise((r) => setTimeout(r, 100));
    }
    return (await a.exists(tmp)) ? a.read(tmp).catch(() => null) : null;
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
