/**
 * The sync engine (DESIGN.md §6). Platform-free: it talks to a VaultFS, a
 * StateStore, a Client and a VaultCrypto, and reports through EngineHooks.
 *
 * Three rules carry everything:
 *   1. Local state is a cache. Truth is "hash of bytes on disk" versus
 *      "head blob on the server". Losing state.json costs a rescan, nothing
 *      else.
 *   2. Every write to disk is preceded by an intent record (`inflight`) and
 *      a fresh disk check under a per-path lock. We never overwrite bytes we
 *      have not hashed.
 *   3. Conflicts never block. Same bytes collapse, text merges three-way
 *      against the exact base blob, everything else becomes a sibling file.
 */

import { VaultCrypto, CryptoError, unwrapEpochKey, type FileMeta } from "./crypto";
import { fromB64, bytesEqual } from "./encoding";
import type { FileStat, StateStore, VaultFS } from "./fs";
import { mergeJson, mergeText } from "./merge";
import { aliasesConfigDir, compileExclusions, conflictPath, fromLogical, isJsonPath, isSafeDevicePath, isSafeLogicalPath, isTextPath, toLogical, CONFIG_TOKEN } from "./paths";
import { NetworkError, Client, HttpError, type OpInput, type OpResult, type WireOp } from "./transport";

// ---------- types ----------

export interface FileEntry {
  /** blob_id of the bytes last synced for this path; null = known deleted. */
  hash: string | null;
  /** Server head seq this entry corresponds to (the base for local edits). */
  seq: number;
  /** Server time (ms) of the op behind this entry; decides "which side is newer" after a server restore (§6.8). */
  at?: number;
  /** Disk stat at the time of sync; a cheap "maybe changed" check. */
  size: number;
  mtime: number;
  /** Set when the remote head was recorded but not written because the path is excluded here. */
  excluded?: true;
}

export interface Inflight {
  blob: string | null;
  seq: number;
  size: number;
  mtime: number;
}

export interface State {
  version: 1;
  cursor: number;
  /** op_id at `cursor`, when known; the server checks it so a restore from backup is never mistaken for "nothing new". */
  cursorOp?: string;
  epoch: number;
  /** keyed by logical path ($CONFIG-mapped) */
  files: Record<string, FileEntry>;
  dirty: string[];
  inflight: Record<string, Inflight>;
}

export interface EngineConfig {
  vaultId: string;
  deviceId: string;
  deviceName: string;
  /** Device ECDH private key, to unwrap keybox rows after a rotation. */
  privJwk: JsonWebKey;
  exclusions: string[];
  compress?: boolean;
  pad?: boolean;
  debounceMs?: number;
  pollIntervalMs?: number;
  dotScanIntervalMs?: number;
  parallel?: number;
  massDelete?: { min: number; fraction: number };
  /** Disable the WebSocket (tests, or environments without one). */
  noLive?: boolean;
  /**
   * When a config-folder file this device has never synced differs from the
   * vault's version, adopt the vault's version instead of keeping a conflict
   * copy (§6.6). Default true. Tests set false to reproduce the pre-rule
   * behaviour; there is no reason to turn it off in normal use.
   */
  adoptConfig?: boolean;
}

export type Phase = "idle" | "scanning" | "syncing" | "offline" | "error";

export interface Status {
  phase: Phase;
  pending: number;
  lastSync?: number;
  message?: string;
  progress?: { done: number; total: number };
}

export interface EngineHooks {
  log?: (level: "debug" | "info" | "warn" | "error", msg: string, data?: unknown) => void;
  onStatus?: (s: Status) => void;
  /** A remote op could not be applied (undecryptable blob, unusable name) and was skipped. */
  onSkipped?: (devPath: string, reason: string) => void;
  /** Called after a remote change was written (or removed) on disk. Device path. */
  afterApply?: (path: string, kind: "put" | "delete") => void;
  /** Called when a conflict sibling was created. Device paths. */
  onConflict?: (path: string, siblingPath: string) => void;
  /** Asked before applying a suspiciously large set of local deletions. */
  confirmMassDelete?: (paths: string[]) => Promise<boolean>;
  /** Keys changed (rotation seen); persist them. */
  onKeysChanged?: () => void;
}

const DEFAULTS = {
  adoptConfig: true,
  debounceMs: 1500,
  pollIntervalMs: 20_000,
  dotScanIntervalMs: 15_000,
  parallel: 8,
  massDelete: { min: 50, fraction: 0.2 },
};

export class SyncError extends Error {}

/** A write refused because another program holds the file (Windows sharing violation, a read-only or locked file). */
function isFileInUse(e: unknown): boolean {
  return /\b(EBUSY|EPERM|EACCES|EAGAIN|ETXTBSY)\b|sharing violation|being used by another process/i.test(String((e as Error)?.message ?? e));
}

// ---------- engine ----------

export class Engine {
  state: State = { version: 1, cursor: 0, epoch: 1, files: {}, dirty: [], inflight: {} };
  private dirty = new Set<string>();
  /** Remote puts whose write failed because the file was in use; retried each cycle (see retryBusy). */
  private busy = new Set<string>();
  private busyReported = new Set<string>();
  private locks = new Map<string, Promise<void>>();
  private excluded: (p: string) => boolean;
  private syncing: Promise<void> | null = null;
  private wantSync = false;
  private kickTimer: ReturnType<typeof setTimeout> | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private dotTimer: ReturnType<typeof setInterval> | null = null;
  private saveTimer: ReturnType<typeof setTimeout> | null = null;
  private unsub: (() => void) | null = null;
  private ws: WebSocket | null = null;
  private wsBackoff = 1000;
  private wsLastMessage = 0;
  /** What a device sees once its token is revoked (another device removed it). */
  static readonly REMOVED_MESSAGE = "This device was removed from the vault. Leave this vault, or re-join with an invite link.";
  /** Server heartbeats every 25 s; three missed ones means the channel is dead. */
  private static readonly WS_STALE_MS = 80_000;
  private stopped = true;
  private status: Status = { phase: "idle", pending: 0 };
  /** Local deletions held back by the mass-deletion guard, awaiting confirmation. */
  heldDeletes: string[] = [];
  private cfg: Required<Omit<EngineConfig, "noLive" | "compress" | "pad">> & EngineConfig;

  constructor(
    public readonly fs: VaultFS,
    private readonly store: StateStore,
    public readonly client: Client,
    public readonly vc: VaultCrypto,
    config: EngineConfig,
    private readonly hooks: EngineHooks = {},
  ) {
    this.cfg = { ...DEFAULTS, ...config };
    this.excluded = compileExclusions(config.exclusions);
  }

  // ----- lifecycle -----

  async start(): Promise<void> {
    this.stopped = false;
    await this.loadState();
    this.unsub = this.fs.onChange((p) => this.noteChange(p));
    if (!this.cfg.noLive) this.connectLive();
    this.pollTimer = setInterval(() => {
      // Fallback poll, and a liveness check on the WebSocket: a silently dead
      // socket (sleep, NAT timeout, proxy) would otherwise never reconnect.
      if (this.ws && this.ws.readyState === WebSocket.OPEN && Date.now() - this.wsLastMessage > Engine.WS_STALE_MS) {
        this.log("info", "live channel stale; reconnecting");
        const dead = this.ws;
        this.ws = null;
        dead.close();
        this.connectLive();
      }
      this.kick(0);
    }, this.cfg.pollIntervalMs);
    this.dotTimer = setInterval(() => void this.scan({ onlyDot: true }).catch((e) => this.log("warn", "dot scan failed", e)), this.cfg.dotScanIntervalMs);
    // Startup: reconcile disk with state in the background, then sync.
    void this.scan()
      .catch((e) => this.log("error", "startup scan failed", e))
      .then(() => this.kick(0));
  }

  async stop(): Promise<void> {
    this.stopped = true;
    this.unsub?.();
    this.unsub = null;
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.dotTimer) clearInterval(this.dotTimer);
    if (this.kickTimer) clearTimeout(this.kickTimer);
    this.pollTimer = this.dotTimer = this.kickTimer = null;
    this.ws?.close();
    this.ws = null;
    if (this.syncing) await this.syncing.catch(() => {});
    await this.flushState();
  }

  setExclusions(patterns: string[]): Promise<void> {
    this.cfg.exclusions = patterns;
    this.excluded = compileExclusions(patterns);
    return this.scan()
      .catch((e) => this.log("error", "scan after exclusion change failed", e))
      .then(() => this.kick(0));
  }

  /** Request a sync soon (debounced). `delay` 0 = as soon as the loop is free. */
  /** Set once the server said our token is revoked; nothing short of a restart clears it. */
  private revoked = false;

  kick(delay = this.cfg.debounceMs): void {
    if (this.stopped || this.revoked) return;
    if (this.kickTimer) clearTimeout(this.kickTimer);
    this.kickTimer = setTimeout(() => {
      this.kickTimer = null;
      void this.sync();
    }, delay);
  }

  getStatus(): Status {
    return this.status;
  }

  // ----- state persistence -----

  private async loadState(): Promise<void> {
    let raw: string | null = null;
    try {
      raw = await this.store.load();
    } catch (e) {
      // Obsidian does not await onunload, so a plugin reload can read the
      // state file while the previous instance's final flush is still
      // replacing it (seen with OS-keychain protection, whose unlock needs no
      // user input: the new engine started and died here, leaving the vault
      // without a live channel until the next Obsidian restart). State is a
      // cache: start empty and rescan.
      this.log("warn", "state.json could not be read; rescanning", e);
    }
    if (raw) {
      try {
        const s = JSON.parse(raw) as State;
        if (s.version === 1) this.state = s;
      } catch (e) {
        this.log("warn", "state.json unreadable; rescanning", e);
      }
    }
    this.dirty = new Set(this.state.dirty);
    if (this.state.epoch > this.vc.keyring.current) this.vc.keyring.current = this.state.epoch;
  }

  private saveChain: Promise<void> = Promise.resolve();

  private scheduleSave(): void {
    if (this.saveTimer || this.stopped) return; // stop() does its own final flush
    this.saveTimer = setTimeout(() => void this.flushState(), 500);
  }

  /** Persist state. Saves are serialised so two never race on the temp file. */
  flushState(): Promise<void> {
    if (this.saveTimer) clearTimeout(this.saveTimer);
    this.saveTimer = null;
    this.state.dirty = [...this.dirty];
    const json = JSON.stringify(this.state);
    this.saveChain = this.saveChain.then(() => this.store.save(json)).catch((e) => this.log("warn", "state save failed", e));
    return this.saveChain;
  }

  /** Forget everything and rescan; the next sync re-derives state from hashes. */
  async rebuildState(): Promise<void> {
    this.state = { version: 1, cursor: 0, epoch: this.vc.keyring.current, files: {}, dirty: [], inflight: {} };
    this.dirty.clear();
    await this.flushState();
    await this.scan();
    this.kick(0);
  }

  // ----- helpers -----

  private log(level: "debug" | "info" | "warn" | "error", msg: string, data?: unknown): void {
    this.hooks.log?.(level, msg, data);
  }

  private setStatus(patch: Partial<Status>): void {
    this.status = { ...this.status, ...patch, pending: this.dirty.size };
    // Once revoked, nothing (a scan finishing, a manual kick) may show ✓ again.
    if (this.revoked) this.status = { ...this.status, phase: "error", message: Engine.REMOVED_MESSAGE };
    this.hooks.onStatus?.(this.status);
  }

  private logical(devPath: string): string {
    return toLogical(devPath.normalize("NFC"), this.fs.configDir);
  }

  /** Local paths that must never be synced: unsafe shapes, or a real folder literally named $CONFIG. */
  private unsyncable(devPath: string): boolean {
    return !isSafeDevicePath(devPath.normalize("NFC"));
  }

  private device(logical: string): string {
    return fromLogical(logical, this.fs.configDir);
  }

  private async withLock<T>(path: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.locks.get(path) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => (release = r));
    this.locks.set(path, prev.then(() => mine));
    await prev;
    try {
      return await fn();
    } finally {
      release();
      if (this.locks.get(path) === mine) this.locks.delete(path);
    }
  }

  private statMatches(e: FileEntry | Inflight | undefined, st: FileStat): boolean {
    return !!e && e.size === st.size && e.mtime === st.mtime;
  }

  private async hashFile(devPath: string): Promise<{ bytes: Uint8Array; hash: string }> {
    const bytes = await this.fs.read(devPath);
    return { bytes, hash: await this.vc.blobId(bytes) };
  }

  private markDirty(logical: string): void {
    if (!this.dirty.has(logical)) {
      this.dirty.add(logical);
      this.scheduleSave();
    }
    this.setStatus({});
  }

  // ----- watcher input -----

  /** A change hint for a device path. Cheap: stat now, hash only if the stat moved. */
  noteChange(devPath: string): void {
    if (this.unsyncable(devPath)) return;
    const logical = this.logical(devPath);
    if (this.excluded(logical)) return;
    void this.withLock(logical, async () => {
      const st = await this.fs.stat(devPath);
      const e = this.state.files[logical];
      if (!st) {
        if (e && e.hash !== null) this.markDirty(logical);
        return;
      }
      if (this.statMatches(e, st) || this.statMatches(this.state.inflight[logical], st)) return;
      const { hash } = await this.hashFile(devPath);
      if (e && e.hash === hash) {
        // Touched, not changed (e.g. a tool rewrote identical bytes). Update the stat.
        e.size = st.size;
        e.mtime = st.mtime;
        this.scheduleSave();
        return;
      }
      this.markDirty(logical);
    })
      .then(() => this.kick())
      .catch((err) => this.log("warn", `change check failed for ${devPath}`, err));
  }

  // ----- scanner -----

  /**
   * Full reconcile of disk against state (DESIGN.md §6.3). Uses stats to
   * skip unchanged files, hashes the rest, and queues local puts and deletes.
   */
  async scan(opts: { onlyDot?: boolean } = {}): Promise<void> {
    if (this.stopped || this.revoked) return;
    this.setStatus({ phase: "scanning" });
    try {
      // The dot-only scan covers root-level dot entries (config dir, .trash…),
      // which is also exactly what listDot() returns, so "missing" below is
      // judged against the same universe.
      const inDotScope = (logical: string) => logical.startsWith(CONFIG_TOKEN) || logical.startsWith(".");
      const all = opts.onlyDot && this.fs.listDot ? await this.fs.listDot() : await this.fs.list();
      const seen = new Set<string>();
      let n = 0;
      for (const st of all) {
        if (this.unsyncable(st.path)) continue;
        const logical = this.logical(st.path);
        if (opts.onlyDot && !inDotScope(logical)) continue;
        seen.add(logical);
        if (this.excluded(logical)) continue;
        const e = this.state.files[logical];
        const inflight = this.state.inflight[logical];
        if (inflight) {
          await this.resolveInflight(logical, st);
          continue;
        }
        if (e && e.hash !== null && this.statMatches(e, st)) continue;
        if (this.dirty.has(logical)) continue; // will be hashed at push time
        // Stat moved or unknown file: hash to decide.
        const { hash } = await this.hashFile(st.path);
        if (e && e.hash === hash) {
          e.size = st.size;
          e.mtime = st.mtime;
          this.scheduleSave();
        } else {
          this.markDirty(logical);
        }
        if (++n % 200 === 0) await new Promise((r) => setTimeout(r, 0)); // yield to UI
      }
      // Files in state but gone from disk → local deletions (with guard).
      const missing: string[] = [];
      for (const [logical, e] of Object.entries(this.state.files)) {
        if (opts.onlyDot && !inDotScope(logical)) continue;
        if (seen.has(logical) || e.hash === null || e.excluded || this.excluded(logical)) continue;
        if (this.state.inflight[logical]) continue;
        missing.push(logical);
      }
      await this.queueDeletions(missing, Object.keys(this.state.files).length);
      await this.flushState();
    } finally {
      this.setStatus({ phase: this.status.phase === "scanning" ? "idle" : this.status.phase });
    }
  }

  private async queueDeletions(missing: string[], total: number): Promise<void> {
    if (missing.length === 0) return;
    const g = this.cfg.massDelete;
    if (missing.length >= g.min && missing.length >= total * g.fraction) {
      this.log("warn", `holding ${missing.length} local deletions pending confirmation`);
      this.heldDeletes = missing;
      const ok = this.hooks.confirmMassDelete ? await this.hooks.confirmMassDelete(missing.map((p) => this.device(p))) : false;
      if (!ok) return;
      this.heldDeletes = [];
    }
    for (const p of missing) this.markDirty(p);
  }

  /** Apply deletions previously held by the mass-deletion guard. */
  applyHeldDeletes(): void {
    for (const p of this.heldDeletes) this.markDirty(p);
    this.heldDeletes = [];
    this.kick(0);
  }

  /** An interrupted write: decide from the bytes on disk what actually happened. */
  private async resolveInflight(logical: string, st: FileStat | null): Promise<void> {
    const inf = this.state.inflight[logical];
    const devPath = this.device(logical);
    if (inf.blob === null) {
      // A delete was in flight. If the file is gone, the delete completed.
      if (!st) this.state.files[logical] = { hash: null, seq: inf.seq, size: 0, mtime: 0 };
      delete this.state.inflight[logical];
      this.scheduleSave();
      return;
    }
    if (!st) {
      // Never written. Replay from before this op.
      this.rewindCursor(inf.seq - 1);
      delete this.state.inflight[logical];
      return;
    }
    const { hash } = await this.hashFile(devPath);
    if (hash === inf.blob) {
      this.state.files[logical] = { hash, seq: inf.seq, size: st.size, mtime: st.mtime };
    } else if (hash === this.state.files[logical]?.hash) {
      // Old bytes still there: the write never happened. Replay.
      this.rewindCursor(inf.seq - 1);
    } else {
      // Partial bytes of our own interrupted write. They are not a user edit:
      // record them as "what we last synced" at the old base so the pending
      // remote op simply overwrites them instead of spawning a conflict copy.
      this.log("warn", `interrupted write detected for ${devPath}; re-applying remote version`);
      const old = this.state.files[logical];
      this.state.files[logical] = { hash, seq: old?.seq ?? 0, size: st.size, mtime: st.mtime };
      this.dirty.delete(logical);
      this.rewindCursor(inf.seq - 1);
    }
    delete this.state.inflight[logical];
    this.scheduleSave();
  }

  private rewindCursor(to: number): void {
    if (to < this.state.cursor) {
      this.state.cursor = Math.max(0, to);
      this.state.cursorOp = undefined;
    }
  }

  // ----- sync loop -----

  /** Run one pull → merge → push cycle. Concurrent calls coalesce. */
  async sync(): Promise<void> {
    if (this.stopped) return;
    if (this.syncing) {
      this.wantSync = true;
      return this.syncing;
    }
    this.syncing = (async () => {
      try {
        do {
          this.wantSync = false;
          this.setStatus({ phase: "syncing", message: undefined });
          await this.retryBusy();
          await this.pull();
          await this.push();
          this.setStatus({ phase: "idle", lastSync: Date.now() });
        } while (this.wantSync && !this.stopped);
      } catch (err) {
        const offline = err instanceof TypeError || err instanceof NetworkError || (err instanceof HttpError && err.transient);
        let message = String((err as Error).message ?? err);
        if (err instanceof HttpError && err.status === 401) {
          if (/vault authority/i.test(err.body)) {
            // Our authority token is stale: another device rotated between
            // our pull and push. The next sync adopts the new epoch.
            message = "keys changed on another device; syncing again";
            this.wantSync = true;
          } else {
            // Token revoked. Retrying would only flap the status between
            // ✓ and ✗ every poll; stay put until the user leaves or re-joins.
            message = Engine.REMOVED_MESSAGE;
            this.revoked = true;
            this.ws?.close();
            this.ws = null;
          }
        }
        this.setStatus({ phase: offline ? "offline" : "error", message });
        this.log(offline ? "info" : "error", "sync failed", err);
      } finally {
        await this.flushState();
        this.syncing = null;
      }
    })();
    return this.syncing;
  }

  /**
   * Writes that failed because the file was in use: decide from the bytes on
   * disk what happened, exactly as after a crash. Old bytes still there means
   * the write never happened and the cursor rewinds so the pull applies the
   * op again; it fails again while the lock is held and lands once it goes.
   */
  private async retryBusy(): Promise<void> {
    for (const logical of [...this.busy]) {
      this.busy.delete(logical);
      await this.withLock(logical, async () => {
        if (!this.state.inflight[logical]) return;
        await this.resolveInflight(logical, await this.fs.stat(this.device(logical)));
      });
    }
  }

  /**
   * The server's head sequence is below our cursor: it was restored from a
   * backup and has forgotten ops we (and maybe other devices) already
   * synced, and it is handing out sequence numbers we have already seen.
   * Reconcile every state entry against the server's current heads
   * (DESIGN.md §6.8):
   *   - the server has our last synced version in the path's history: it
   *     moved on legitimately after the restore; take its head as usual;
   *   - it has never seen our version (that op was lost): our copy is the
   *     newer one; rebase it on the server's head and push it again, which
   *     also re-uploads any blob the restore dropped;
   *   - the path is unknown to the server: push it as a new file.
   * Nothing on disk is touched here; the pull and push that follow do the
   * work through the ordinary conflict rules, so nothing can be lost.
   */
  private async recoverFromRewind(serverSeq: number): Promise<void> {
    const v = this.cfg.vaultId;
    this.log("warn", `server sequence went backwards (${this.state.cursor} -> ${serverSeq}); reconciling against a restored server`);
    const snap = await this.client.snapshot(v);
    await this.adoptEpoch(snap.epoch, snap.min_epoch);
    const heads = new Map<string, WireOp>();
    for (const op of snap.ops) heads.set(op.path_id, op);
    let rebased = 0;
    for (const [logical, e] of Object.entries(this.state.files)) {
      if (this.state.inflight[logical]) continue;
      const pid = await this.vc.pathId(logical);
      const head = heads.get(pid);
      if (head && head.seq === e.seq && head.blob_id === e.hash) continue;
      if (!head) {
        // Never reached the restored server. A tombstone needs nothing; a file is created again.
        delete this.state.files[logical];
        if (e.hash !== null) this.markDirty(logical);
        rebased++;
        continue;
      }
      const known = e.hash === head.blob_id || (e.hash !== null && (await this.client.history(v, pid)).some((o) => o.blob_id === e.hash));
      if (known) {
        // The server moved on after the restore; let the snapshot apply its head on top of our base.
        e.seq = e.hash === head.blob_id ? head.seq : 0;
      } else if (e.at === undefined || head.created_at <= e.at) {
        // Our synced version was lost and the server's head predates it: ours is
        // the newer one. Rebase on the head and push it.
        e.hash = head.blob_id;
        e.seq = head.seq;
        this.markDirty(logical);
        rebased++;
      } else {
        // Our synced version was lost, and another device has written this path
        // since the restore. Neither side knows the other's bytes: treat ours
        // as a local edit with no base, so the pull resolves it like any
        // concurrent edit (sibling copy, head applied) and nothing is dropped.
        e.hash = null;
        e.seq = 0;
        rebased++;
      }
    }
    this.state.cursor = 0;
    this.state.cursorOp = undefined;
    this.scheduleSave();
    this.log("info", `restored-server reconciliation: ${rebased} path(s) reconciled`);
  }

  // ----- keys -----

  /** Fetch keybox rows and adopt any epoch keys we do not have. */
  async refreshKeys(minEpoch?: number): Promise<void> {
    const rows = await this.client.keybox(this.cfg.vaultId);
    let changed = false;
    for (const r of rows) {
      if (this.vc.keyring.epochs.has(r.epoch)) continue;
      try {
        const { epochKey } = await unwrapEpochKey(this.cfg.privJwk, this.cfg.vaultId, r.epoch, this.cfg.deviceId, fromB64(r.wrapped));
        this.vc.addEpoch(r.epoch, epochKey);
        changed = true;
      } catch (e) {
        this.log("warn", `could not unwrap epoch ${r.epoch} key`, e);
      }
    }
    if (minEpoch && minEpoch > 1) {
      const before = this.vc.keyring.epochs.size;
      this.vc.pruneBelow(minEpoch);
      if (this.vc.keyring.epochs.size !== before) changed = true;
    }
    if (changed) {
      this.state.epoch = this.vc.keyring.current;
      this.hooks.onKeysChanged?.();
    }
  }

  // ----- pull -----

  private async pull(): Promise<void> {
    const v = this.cfg.vaultId;
    if (this.state.cursor === 0) {
      const snap = await this.client.snapshot(v);
      await this.adoptEpoch(snap.epoch, snap.min_epoch);
      await this.applyBatch(snap.ops);
      this.state.cursor = snap.cursor;
      this.state.cursorOp = snap.cursor_op_id;
      this.scheduleSave();
      return;
    }
    for (;;) {
      const feed = await this.client.changes(v, this.state.cursor, { limit: 500, expect: this.state.cursorOp });
      if (feed.rewound || (feed.seq !== undefined && feed.seq < this.state.cursor)) {
        await this.recoverFromRewind(feed.seq ?? 0);
        return this.pull();
      }
      await this.adoptEpoch(feed.epoch, feed.min_epoch);
      if (feed.ops.length === 0) break;
      await this.applyBatch(feed.ops);
      this.state.cursor = feed.cursor;
      if (feed.cursor_op_id) this.state.cursorOp = feed.cursor_op_id;
      this.scheduleSave();
      if (!feed.more) break;
    }
  }

  private async adoptEpoch(epoch: number, minEpoch: number): Promise<void> {
    if (epoch !== this.vc.keyring.current || !this.vc.keyring.epochs.has(epoch) || minEpoch > 1) {
      await this.refreshKeys(minEpoch);
      if (!this.vc.keyring.epochs.has(epoch)) throw new SyncError(`no key for vault epoch ${epoch}; this device may have been removed`);
      if (epoch < this.vc.keyring.current) {
        // The server's epoch went backwards: it was restored from a backup
        // taken before a rotation (§6.8). Its authority hash and its keybox
        // are the old epoch's, and refreshKeys just re-learned that key from
        // the restored keybox, so everything we encrypt or sign from now on
        // uses it again. A later rotation moves forward as usual.
        this.log("warn", `vault epoch went backwards (${this.vc.keyring.current} -> ${epoch}); using the restored epoch key`);
        this.vc.keyring.current = epoch;
        // Keys for epochs the server no longer knows would only be offered to
        // the next device we invite, which the server would then refuse.
        for (const e of [...this.vc.keyring.epochs.keys()]) if (e > epoch) this.vc.keyring.epochs.delete(e);
        this.hooks.onKeysChanged?.();
      }
      this.state.epoch = epoch;
    }
  }

  /** Decrypt metadata, prefetch needed blobs in parallel, then apply in order. */
  private async applyBatch(ops: WireOp[]): Promise<void> {
    type Decoded = { op: WireOp; meta: FileMeta | null; logical: string };
    const decoded: Decoded[] = [];
    for (const op of ops) {
      let meta: FileMeta | null = null;
      try {
        meta = await this.vc.decryptMeta(op.path_id, fromB64(op.meta_enc));
      } catch (e) {
        if (e instanceof CryptoError && /epoch/.test(e.message)) {
          await this.refreshKeys();
          meta = await this.vc.decryptMeta(op.path_id, fromB64(op.meta_enc));
        } else {
          this.log("error", `cannot decrypt metadata for op ${op.seq}; skipping`, e);
        }
      }
      // The path comes from another device. It must be a plain relative
      // vault path and it must be the path this op is actually keyed by;
      // otherwise a compromised member could write outside the vault or
      // smuggle a file past the exclusion rules under another path's id.
      if (meta && (!isSafeLogicalPath(meta.path) || (await this.vc.pathId(meta.path)) !== op.path_id || aliasesConfigDir(this.device(meta.path), this.fs.configDir))) {
        this.log("error", `op ${op.seq} carries an unsafe or mismatched path; refusing to apply it`, { path: meta.path });
        // Report it like any other skipped op: the user should know a file
        // exists in the vault that this device will never show.
        this.hooks.onSkipped?.(meta.path, "the name is not allowed on this device");
        meta = null;
      }
      // Paths are keyed by their NFC form (path_id above proves meta.path is
      // already NFC, since pathId normalises); keep the string NFC too so the
      // on-disk name matches what the scanner will see.
      if (meta) meta.path = meta.path.normalize("NFC");
      decoded.push({ op, meta, logical: meta?.path ?? "" });
    }
    // Only the last op per path in this batch matters. Deletes go first: a
    // rename on a case-insensitive volume ("Note.md" -> "note.md") is a delete
    // and a put whose names are the same file there, and the put can only
    // land once the old name is gone.
    const last = new Map<string, Decoded>();
    for (const d of decoded) if (d.meta) last.set(d.logical, d);
    const ordered = [...last.values()].sort((x, y) => Number(x.op.blob_id !== null) - Number(y.op.blob_id !== null));
    // Prefetch blobs we will probably write (skip excluded and already-synced).
    const want = new Set<string>();
    for (const d of ordered) {
      if (this.excluded(d.logical) || !d.op.blob_id) continue;
      if (this.state.files[d.logical]?.hash === d.op.blob_id) continue;
      want.add(d.op.blob_id);
    }
    const blobs = new Map<string, Uint8Array>();
    await this.parallel([...want], async (id) => {
      try {
        blobs.set(id, await this.client.getBlob(this.cfg.vaultId, id));
      } catch (e) {
        this.log("warn", `blob ${id.slice(0, 8)} fetch failed; will retry`, e);
      }
    });
    let done = 0;
    for (const d of ordered) {
      try {
        await this.withLock(d.logical, () => this.applyRemote(d.logical, d.op, d.meta!, blobs));
      } catch (e) {
        // One bad op must never wedge the vault: an undecryptable blob (a
        // key holder uploaded garbage under a real id), a name the local
        // file system refuses, or a vanished parent. Transport failures are
        // retried as a whole; everything else is logged and skipped, and the
        // cursor moves on. A later op for the path heals it.
        if (e instanceof NetworkError || (e instanceof HttpError && e.transient)) throw e;
        if (isFileInUse(e) && this.state.inflight[d.logical]) {
          // Another program holds the file open (Windows: EBUSY/EPERM for a
          // note open in an editor or being scanned). The inflight record
          // says what we meant to write; retry at the next cycle instead of
          // waiting for someone to edit the file again. Reported once.
          this.busy.add(d.logical);
          this.log("warn", `op ${d.op.seq} for ${d.logical} could not be written because the file is in use; will retry`, e);
          if (!this.busyReported.has(d.logical)) {
            this.busyReported.add(d.logical);
            this.hooks.onSkipped?.(this.device(d.logical), "the file is in use by another program; it will be retried");
          }
        } else {
          this.log("error", `op ${d.op.seq} for ${d.logical} could not be applied; skipping`, e);
          this.hooks.onSkipped?.(this.device(d.logical), String((e as Error).message ?? e));
        }
      }
      this.setStatus({ progress: { done: ++done, total: last.size } });
    }
    this.setStatus({ progress: undefined });
  }

  private async parallel<T>(items: T[], fn: (t: T) => Promise<void>): Promise<void> {
    const q = [...items];
    const workers = Array.from({ length: Math.min(this.cfg.parallel, q.length) }, async () => {
      while (q.length) await fn(q.shift()!);
    });
    await Promise.all(workers);
  }

  /**
   * Apply one remote op to disk (DESIGN.md §6.5). Caller holds the path lock.
   * `blobs` is a prefetch cache; a miss fetches on demand.
   */
  private async applyRemote(logical: string, op: WireOp, meta: FileMeta, blobs: Map<string, Uint8Array>): Promise<void> {
    const devPath = this.device(logical);
    const e = this.state.files[logical];
    if (e && e.seq >= op.seq) return; // already applied (replay after a rewind)
    if (this.excluded(logical)) {
      this.state.files[logical] = { hash: op.blob_id, seq: op.seq, at: op.created_at, size: meta.size, mtime: meta.mtime, excluded: true };
      this.scheduleSave();
      return;
    }
    const st = await this.fs.stat(devPath);
    // What is on disk, relative to what we last synced?
    let diskHash: string | null = null;
    let diskBytes: Uint8Array | null = null;
    if (st) {
      if (this.statMatches(e, st) && e!.hash) diskHash = e!.hash;
      else {
        const h = await this.hashFile(devPath);
        diskHash = h.hash;
        diskBytes = h.bytes;
      }
    }
    // Present and different from what we last synced means a local edit.
    const localEdited = !!st && diskHash !== (e?.hash ?? null);

    if (op.blob_id === null) {
      // Remote deletion.
      if (!st) {
        this.state.files[logical] = { hash: null, seq: op.seq, at: op.created_at, size: 0, mtime: 0 };
        this.dirty.delete(logical);
      } else if (diskHash !== (e?.hash ?? null)) {
        // Local edit vs remote delete: the edit wins; re-upload on top of the tombstone.
        this.log("info", `remote deleted ${devPath} but it was edited here; keeping local`);
        this.state.files[logical] = { hash: null, seq: op.seq, at: op.created_at, size: 0, mtime: 0 };
        this.markDirty(logical);
      } else {
        this.state.inflight[logical] = { blob: null, seq: op.seq, size: 0, mtime: 0 };
        await this.flushState();
        await this.fs.remove(devPath);
        delete this.state.inflight[logical];
        this.state.files[logical] = { hash: null, seq: op.seq, at: op.created_at, size: 0, mtime: 0 };
        this.dirty.delete(logical);
        this.hooks.afterApply?.(devPath, "delete");
      }
      this.scheduleSave();
      return;
    }

    // Remote put.
    if (diskHash === op.blob_id) {
      // Converged (echo of our own upload, or both sides wrote the same bytes).
      this.state.files[logical] = { hash: op.blob_id, seq: op.seq, at: op.created_at, size: st!.size, mtime: st!.mtime };
      this.dirty.delete(logical);
      this.scheduleSave();
      return;
    }
    if (st && localEdited) {
      if (!e && this.cfg.adoptConfig && logical.startsWith(CONFIG_TOKEN)) {
        // A device that has never synced this config file (typically one that
        // just joined) is adopting the vault's configuration: its own copy is
        // Obsidian's defaults, not an edit worth preserving. Remote wins.
        this.log("info", `adopting vault configuration for ${devPath}`);
        await this.writeRemote(logical, op, meta, blobs);
        return;
      }
      // Concurrent local edit. Resolve (merge or sibling), never overwrite.
      const local = diskBytes ?? (await this.fs.read(devPath));
      await this.resolveConflict(logical, local, diskHash!, op, meta, blobs);
      return;
    }
    if (!st && e && e.hash !== null && this.dirty.has(logical)) {
      // Locally deleted, remotely changed: remote content wins (nothing of ours is lost, the
      // deletion was of an older version). Fall through and write it.
      this.dirty.delete(logical);
    }
    await this.writeRemote(logical, op, meta, blobs);
  }

  private async fetchBlob(id: string, blobs?: Map<string, Uint8Array>): Promise<Uint8Array> {
    const cached = blobs?.get(id);
    if (cached) return cached;
    const b = await this.client.getBlob(this.cfg.vaultId, id);
    blobs?.set(id, b);
    return b;
  }

  /** Download (if needed), decrypt, verify, and write a remote put to disk. */
  private async writeRemote(logical: string, op: WireOp, meta: FileMeta, blobs?: Map<string, Uint8Array>): Promise<void> {
    const devPath = this.device(logical);
    const blobId = op.blob_id!;
    let plain: Uint8Array;
    try {
      plain = await this.vc.decryptBlob(blobId, await this.fetchBlob(blobId, blobs));
    } catch (e) {
      if (e instanceof CryptoError && /epoch/.test(e.message)) {
        await this.refreshKeys();
        plain = await this.vc.decryptBlob(blobId, await this.fetchBlob(blobId, blobs));
      } else throw e;
    }
    const mtime = Math.floor(meta.mtime || Date.now());
    this.state.inflight[logical] = { blob: blobId, seq: op.seq, size: plain.length, mtime };
    await this.flushState();
    await this.fs.write(devPath, plain, mtime);
    const st = (await this.fs.stat(devPath)) ?? { path: devPath, size: plain.length, mtime };
    delete this.state.inflight[logical];
    this.busyReported.delete(logical);
    this.state.files[logical] = { hash: blobId, seq: op.seq, at: op.created_at, size: st.size, mtime: st.mtime };
    this.dirty.delete(logical);
    this.scheduleSave();
    this.hooks.afterApply?.(devPath, "put");
  }

  // ----- conflicts -----

  /**
   * Local bytes differ from both our base and the remote head (DESIGN.md §6.6).
   * 1. identical → converge. 2. text with a readable base → diff3 / JSON merge,
   * write merged, leave dirty so it uploads on top of the head. 3. otherwise
   * sibling copy of the local bytes, head applied to the path.
   */
  private async resolveConflict(
    logical: string,
    local: Uint8Array,
    localHash: string,
    head: WireOp,
    meta: FileMeta,
    blobs?: Map<string, Uint8Array>,
  ): Promise<void> {
    const devPath = this.device(logical);
    const e = this.state.files[logical];
    if (head.blob_id === localHash) {
      this.state.files[logical] = { hash: localHash, seq: head.seq, at: head.created_at, size: local.length, mtime: e?.mtime ?? Date.now() };
      this.dirty.delete(logical);
      this.scheduleSave();
      return;
    }
    if (head.blob_id === null) {
      // Remote delete vs local edit: keep local, rebase on the tombstone.
      this.state.files[logical] = { hash: null, seq: head.seq, at: head.created_at, size: 0, mtime: 0 };
      this.markDirty(logical);
      return;
    }
    // Try a three-way merge against the exact base we synced.
    if (e?.hash && isTextPath(logical)) {
      try {
        const [base, remote] = await Promise.all([
          this.fetchBlob(e.hash).then((b) => this.vc.decryptBlob(e.hash!, b)),
          this.fetchBlob(head.blob_id, blobs).then((b) => this.vc.decryptBlob(head.blob_id!, b)),
        ]);
        const m = isJsonPath(logical) && logical.startsWith(CONFIG_TOKEN) ? mergeJson(base, local, remote) : mergeText(base, local, remote);
        if (m.ok && m.merged) {
          const mergedHash = await this.vc.blobId(m.merged);
          const mtime = Date.now();
          this.state.inflight[logical] = { blob: mergedHash, seq: head.seq, size: m.merged.length, mtime };
          await this.flushState();
          await this.fs.write(devPath, m.merged, mtime);
          delete this.state.inflight[logical];
          // Base is now the head; disk holds the merge, which is dirty and uploads next.
          this.state.files[logical] = { hash: head.blob_id, seq: head.seq, at: head.created_at, size: -1, mtime: -1 };
          this.markDirty(logical);
          this.log("info", `merged concurrent edits of ${devPath}`);
          this.hooks.afterApply?.(devPath, "put");
          return;
        }
      } catch (err) {
        this.log("warn", `three-way merge unavailable for ${devPath}`, err);
      }
    }
    // Sibling copy, then apply the head.
    const sibLogical = await this.siblingFor(logical, local);
    const sibDev = this.device(sibLogical);
    await this.fs.write(sibDev, local, Date.now());
    this.markDirty(sibLogical);
    await this.writeRemote(logical, head, meta, blobs);
    this.log("warn", `conflict on ${devPath}; local version saved as ${sibDev}`);
    this.hooks.onConflict?.(devPath, sibDev);
  }

  /**
   * A sibling name that does not clobber an earlier conflict copy: the
   * stamp has minute resolution, and two conflicts on one file within a
   * minute are not rare when two devices are being used at once. An
   * existing copy with identical bytes (the same conflict resolved twice,
   * e.g. after an interrupted apply) is reused rather than duplicated.
   */
  private async siblingFor(logical: string, local: Uint8Array): Promise<string> {
    const now = new Date();
    for (let n = 1; n < 10_000; n++) {
      const sib = conflictPath(logical, this.cfg.deviceName, now, n);
      const st = await this.fs.stat(this.device(sib));
      if (!st) return sib;
      if (st.size === local.length && bytesEqual(await this.fs.read(this.device(sib)), local)) return sib;
    }
    throw new Error(`too many conflict copies of ${logical}`);
  }

  // ----- push -----

  private async push(): Promise<void> {
    for (let round = 0; round < 5 && this.dirty.size > 0 && !this.stopped; round++) {
      const paths = [...this.dirty];
      type Pending = { logical: string; op: OpInput; bytes?: Uint8Array; st?: FileStat };
      const pending: Pending[] = [];
      for (const logical of paths) {
        if (this.excluded(logical)) {
          this.dirty.delete(logical);
          continue;
        }
        const p = await this.withLock(logical, () => this.prepareLocalOp(logical));
        if (p) pending.push(p);
        else this.dirty.delete(logical);
      }
      if (pending.length === 0) break;
      // Deletes before puts, so a rename reaches other devices as "old name
      // gone, then new name" in that order (see applyBatch).
      pending.sort((x, y) => Number(x.op.blob_id !== null) - Number(y.op.blob_id !== null));
      // Upload missing blobs first (server enforces blobs-before-ops).
      const byBlob = new Map<string, Uint8Array>();
      for (const p of pending) if (p.op.blob_id && p.bytes) byBlob.set(p.op.blob_id, p.bytes);
      const missing = await this.client.missingBlobs(this.cfg.vaultId, [...byBlob.keys()]);
      let done = 0;
      await this.parallel(missing, async (id) => {
        const ct = await this.vc.encryptBlob(id, byBlob.get(id)!, { compress: this.cfg.compress, pad: this.cfg.pad });
        await this.client.putBlob(this.cfg.vaultId, id, ct);
        this.setStatus({ progress: { done: ++done, total: missing.length } });
      });
      this.setStatus({ progress: undefined });
      // Post ops in chunks.
      for (let i = 0; i < pending.length; i += 200) {
        const chunk = pending.slice(i, i + 200);
        const res = await this.client.postOps(this.cfg.vaultId, chunk.map((p) => p.op));
        for (let j = 0; j < chunk.length; j++) {
          const p = chunk[j];
          const r = res.results[j];
          await this.withLock(p.logical, async () => {
            try {
              await this.settle(p, r);
            } catch (e) {
              // A head we cannot read (garbage blob) must not turn every
              // sync red: leave the path dirty, report once, carry on.
              if (e instanceof NetworkError || (e instanceof HttpError && e.transient)) throw e;
              this.log("error", `could not settle ${p.logical} against the server head; will retry after the next change`, e);
              this.hooks.onSkipped?.(this.device(p.logical), String((e as Error).message ?? e));
              this.dirty.delete(p.logical);
            }
          });
        }
        if (res.cursor > this.state.cursor) {
          // Other devices' ops may have landed; a pull will fetch them. Do not skip them.
        }
      }
      this.scheduleSave();
    }
    this.setStatus({});
  }

  /** Apply one post result to local state: accepted, conflicting, or rejected. */
  private async settle(p: { logical: string; op: OpInput; bytes?: Uint8Array; st?: FileStat }, r: OpResult): Promise<void> {
    if (r.seq && !r.conflict && !r.error) {
      this.state.files[p.logical] = { hash: p.op.blob_id, seq: r.seq, at: r.created_at, size: p.st?.size ?? 0, mtime: p.st?.mtime ?? 0 };
      this.dirty.delete(p.logical);
      // The server's cursor can jump past our own op; keep cursor in step so we do not re-pull it.
      if (r.seq === this.state.cursor + 1) {
        this.state.cursor = r.seq;
        this.state.cursorOp = p.op.op_id;
      }
    } else if (r.conflict) {
      const meta = await this.vc.decryptMeta(r.conflict.path_id, fromB64(r.conflict.meta_enc));
      if (p.bytes) await this.resolveConflict(p.logical, p.bytes, p.op.blob_id!, r.conflict, meta);
      else {
        // We tried to delete, but the remote moved on: remote wins, drop the delete.
        await this.applyRemote(p.logical, r.conflict, meta, new Map());
        this.dirty.delete(p.logical);
      }
    } else {
      this.log("error", `op rejected for ${p.logical}: ${r.error}`);
      if (/blob not uploaded/.test(r.error ?? "")) return; // retry next round
      this.dirty.delete(p.logical);
    }
  }


  /**
   * Re-upload a file's current bytes, replacing whatever the server holds
   * under that blob id, and post a fresh op so every device fetches it
   * again. The repair for "could not apply the latest version of X":
   * the author's normal push would see the id as already present and
   * upload nothing.
   */
  async reupload(devPath: string): Promise<void> {
    const logical = this.logical(devPath);
    await this.withLock(logical, async () => {
      const st = await this.fs.stat(devPath);
      if (!st) throw new Error(`${devPath} does not exist`);
      const { bytes, hash } = await this.hashFile(devPath);
      const ct = await this.vc.encryptBlob(hash, bytes, { compress: this.cfg.compress, pad: this.cfg.pad });
      await this.client.putBlob(this.cfg.vaultId, hash, ct, { replace: true });
      const pathId = await this.vc.pathId(logical);
      const e = this.state.files[logical];
      const meta: FileMeta = { path: logical, mtime: st.mtime, size: st.size };
      const op: OpInput = { op_id: opId(), path_id: pathId, blob_id: hash, meta_enc: await this.vc.encryptMeta(pathId, meta), meta_epoch: this.vc.keyring.current, base_seq: e?.seq ?? 0 };
      let r = (await this.client.postOps(this.cfg.vaultId, [op])).results[0];
      if (r.conflict) {
        // An explicit repair means "these bytes win": rebase onto the current head once.
        r = (await this.client.postOps(this.cfg.vaultId, [{ ...op, op_id: opId(), base_seq: r.conflict.seq }])).results[0];
      }
      if (!r.seq || r.conflict || r.error) throw new Error(r.error ?? "the file changed elsewhere; sync first, then retry");
      this.state.files[logical] = { hash, seq: r.seq, at: r.created_at, size: st.size, mtime: st.mtime };
      this.dirty.delete(logical);
      if (r.seq === this.state.cursor + 1) {
        this.state.cursor = r.seq;
        this.state.cursorOp = r.op_id;
      }
      this.scheduleSave();
    });
    this.kick(0);
  }

  /** Build the op for a dirty path from what is on disk right now. */
  private async prepareLocalOp(logical: string): Promise<{ logical: string; op: OpInput; bytes?: Uint8Array; st?: FileStat } | null> {
    const devPath = this.device(logical);
    const e = this.state.files[logical];
    const st = await this.fs.stat(devPath);
    const pathId = await this.vc.pathId(logical);
    if (!st) {
      if (!e || e.hash === null) return null; // nothing to delete
      const meta: FileMeta = { path: logical, mtime: Date.now(), size: 0 };
      return { logical, op: { op_id: opId(), path_id: pathId, blob_id: null, meta_enc: await this.vc.encryptMeta(pathId, meta), meta_epoch: this.vc.keyring.current, base_seq: e.seq } };
    }
    const { bytes, hash } = await this.hashFile(devPath);
    if (e && e.hash === hash) {
      e.size = st.size;
      e.mtime = st.mtime;
      return null; // unchanged after all
    }
    const meta: FileMeta = { path: logical, mtime: st.mtime, size: st.size };
    return {
      logical,
      bytes,
      st,
      op: { op_id: opId(), path_id: pathId, blob_id: hash, meta_enc: await this.vc.encryptMeta(pathId, meta), meta_epoch: this.vc.keyring.current, base_seq: e?.seq ?? 0 },
    };
  }

  // ----- live channel -----

  private connectLive(): void {
    if (this.stopped || this.revoked || typeof WebSocket === "undefined") return;
    try {
      const ws = new WebSocket(this.client.liveUrl(this.cfg.vaultId), this.client.liveProtocols());
      this.ws = ws;
      ws.onopen = () => {
        this.wsBackoff = 1000;
        this.wsLastMessage = Date.now();
        this.kick(0);
      };
      ws.onmessage = (ev) => {
        this.wsLastMessage = Date.now();
        try {
          const h = JSON.parse(String(ev.data)) as { seq: number; epoch: number };
          if (h.seq > this.state.cursor || h.epoch !== this.vc.keyring.current) this.kick(0);
        } catch {
          /* ignore */
        }
      };
      ws.onclose = ws.onerror = () => {
        if (this.ws !== ws) return;
        this.ws = null;
        if (this.stopped) return;
        setTimeout(() => this.connectLive(), this.wsBackoff);
        this.wsBackoff = Math.min(60_000, this.wsBackoff * 2);
      };
    } catch (e) {
      this.log("warn", "websocket unavailable; polling", e);
    }
  }

  /** Call on app resume / network online: reconnect and sync now. */
  resume(): void {
    if (this.stopped) return;
    if (!this.ws && !this.cfg.noLive) this.connectLive();
    this.kick(0);
  }

  // ----- introspection -----

  /** Paths of conflict siblings known to this device (for the "Show conflicts" command). */
  conflictFiles(): string[] {
    return Object.keys(this.state.files)
      .filter((p) => this.state.files[p].hash !== null && / \(conflict /.test(p))
      .map((p) => this.device(p));
  }
}

function opId(): string {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export { bytesEqual };
