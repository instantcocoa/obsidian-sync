/**
 * The filesystem surface the sync engine needs, and nothing more.
 *
 * Two implementations: `ObsidianFS` (src/obsidian) over app.vault and
 * app.vault.adapter, and `NodeFS` (src/core/node-fs.ts) over a directory,
 * used by the end-to-end tests and usable for a headless CLI. This file
 * must stay free of Node imports: it is bundled into the plugin.
 *
 * Paths are always vault-relative, "/"-separated, NFC-normalised, and never
 * start with "/" or "./". Every byte of a file is opaque to this layer.
 */

export interface FileStat {
  path: string;
  size: number;
  mtime: number; // ms since epoch, integer
}

export interface VaultFS {
  /** Name of the config directory at the vault root, usually ".obsidian". */
  readonly configDir: string;
  /** Every file in the vault, including dot-files and the config dir. */
  list(): Promise<FileStat[]>;
  /**
   * Optional cheaper listing of only the root-level dot entries (the config
   * dir and siblings like .trash), walked recursively. Used by the periodic
   * dot-file scan, which must not re-list a large vault every 30 s.
   */
  listDot?(): Promise<FileStat[]>;
  stat(path: string): Promise<FileStat | null>;
  read(path: string): Promise<Uint8Array>;
  /** Create or replace, creating parent folders, setting mtime when supported. */
  write(path: string, data: Uint8Array, mtime: number): Promise<void>;
  /** Remove a file; implementations may move it to a trash. */
  remove(path: string): Promise<void>;
  /** Change hints. The engine only uses them to schedule a stat+hash. */
  onChange(cb: (path: string) => void): () => void;
}

/** Persistence for the engine's state.json. */
export interface StateStore {
  load(): Promise<string | null>;
  save(json: string): Promise<void>;
}
