/**
 * obsync — Obsidian plugin entry point.
 *
 * Wires the platform-free engine (src/core) to Obsidian: filesystem, state
 * file, settings, commands, status bar, lifecycle events, and the config-dir
 * post-write hooks. Keys and the device token live in this plugin's
 * data.json, which the default exclusions keep out of sync.
 */
import { Notice, Plugin, Platform } from "obsidian";
import { Engine, type EngineConfig, type Status } from "../core/engine";
import { DEFAULT_EXCLUSIONS, CONFIG_TOKEN } from "../core/paths";
import {
  createInviteLink,
  createVault,
  joinWithLink,
  joinWithPassphrase,
  listDevices,
  openSession,
  removeDevice,
  setRecoveryPassphrase,
  syncIdentityKeys,
  type Identity,
  type Session,
} from "../core/admin";
import { ObsidianFS, ObsidianStateStore } from "./obsidian-fs";
import { ConfigHooks } from "./hooks";
import { ObsyncSettingTab } from "./settings";
import { ConfirmModal, ListModal, PromptModal, ShowSecretModal } from "./modals";
import { deriveWrapKeyFromPin, newWrapKey, open as openKeystore, seal as sealKeystore, type ProtectionMethod, type SealedKeystore } from "../core/keystore";
import { fromB64, randomBytes } from "../core/encoding";
import { promptTouchId, safeStorageAvailable, safeUnwrap, safeWrap, touchIdAvailable } from "./protection";

interface Protection {
  method: ProtectionMethod;
  /** macOS: require Touch ID before unwrapping (method "safe" only). */
  touchId: boolean;
  /** method "safe": the random wrapping key, encrypted by the OS keychain (base64). */
  safeWrap?: string;
}

interface Settings {
  /** Stored in the clear only when protection.method is "none". */
  identity: Identity | null;
  /** Stored instead of `identity` when protection is enabled. */
  sealed: SealedKeystore | null;
  protection: Protection;
  deviceName: string;
  exclusions: string[];
  syncConfig: boolean;
  compress: boolean;
  pad: boolean;
  debounceMs: number;
}

const DEFAULT_SETTINGS: Settings = {
  identity: null,
  sealed: null,
  protection: { method: "none", touchId: false },
  deviceName: "",
  exclusions: [...DEFAULT_EXCLUSIONS],
  syncConfig: true,
  compress: false,
  pad: false,
  debounceMs: 1500,
};

export default class ObsyncPlugin extends Plugin {
  override settings: Settings = { ...DEFAULT_SETTINGS };
  engine: Engine | null = null;
  session: Session | null = null;
  /** True when a sealed identity exists but has not been unlocked this session. */
  locked = false;
  private wrapKey: Uint8Array | null = null;
  private statusEl!: HTMLElement;
  private hooks!: ConfigHooks;

  override async onload(): Promise<void> {
    await this.loadSettings();
    this.hooks = new ConfigHooks(this.app, this.manifest.id);
    this.statusEl = this.addStatusBarItem();
    this.statusEl.setText("obsync: off");
    this.addSettingTab(new ObsyncSettingTab(this));

    this.addCommand({ id: "sync-now", name: "Sync now", callback: () => this.engine?.kick(0) });
    this.addCommand({ id: "show-conflicts", name: "Show conflicts", callback: () => this.cmdConflicts() });
    this.addCommand({ id: "invite", name: "Generate invite link for another device", callback: () => this.cmdInvite() });
    this.addCommand({ id: "devices", name: "Manage devices", callback: () => this.cmdDevices() });
    this.addCommand({ id: "set-recovery", name: "Set recovery passphrase", callback: () => this.cmdSetRecovery() });
    this.addCommand({ id: "rotate", name: "Rotate vault keys", callback: () => this.cmdRotate() });
    this.addCommand({ id: "restore", name: "Restore vault to a point in time", callback: () => this.cmdRestore() });
    this.addCommand({ id: "history", name: "Show history for current file", callback: () => this.cmdHistory() });
    this.addCommand({ id: "rebuild", name: "Rebuild local sync state", callback: () => this.engine?.rebuildState() });
    this.addCommand({ id: "apply-held-deletes", name: "Apply held deletions", callback: () => this.engine?.applyHeldDeletes() });
    this.addCommand({ id: "unlock", name: "Unlock vault keys", callback: () => void this.unlock() });

    // Lifecycle: flush edits when a file is opened/closed, resync on resume and reconnect.
    this.registerEvent(this.app.workspace.on("file-open", () => this.engine?.kick(300)));
    this.registerDomEvent(document, "visibilitychange", () => {
      if (document.visibilityState === "visible") this.engine?.resume();
      else void this.engine?.sync();
    });
    this.registerDomEvent(window, "online", () => this.engine?.resume());

    if (this.settings.identity) this.app.workspace.onLayoutReady(() => void this.startEngine());
    else if (this.settings.sealed) {
      this.locked = true;
      this.statusEl.setText("obsync 🔒");
      this.app.workspace.onLayoutReady(() => void this.unlock());
    }
  }

  override async onunload(): Promise<void> {
    await this.engine?.stop();
    this.engine = null;
  }

  // ---------- settings ----------

  async loadSettings(): Promise<void> {
    this.settings = { ...DEFAULT_SETTINGS, ...((await this.loadData()) ?? {}) };
    this.settings.protection = { ...DEFAULT_SETTINGS.protection, ...(this.settings.protection ?? {}) };
    if (!this.settings.deviceName) this.settings.deviceName = Platform.isMobile ? (Platform.isIosApp ? "iphone" : "android") : "desktop";
  }

  /**
   * Persist settings. With protection on, the identity is sealed under the
   * in-memory wrapping key and never written in the clear.
   */
  async saveSettings(): Promise<void> {
    const s = this.settings;
    const onDisk: Settings = { ...s };
    if (s.protection.method !== "none" && s.identity) {
      if (!this.wrapKey) throw new Error("key store is locked; cannot save");
      onDisk.sealed = await sealKeystore(s.identity, s.protection.method, this.wrapKey, s.protection.method === "pin" ? this.pinSalt : undefined);
      onDisk.identity = null;
    } else {
      onDisk.sealed = null;
    }
    await this.saveData(onDisk);
  }

  private pinSalt: Uint8Array | undefined;

  // ---------- key protection ----------

  /** What this device can offer in the settings UI. */
  protectionOptions(): { method: ProtectionMethod; label: string; available: boolean }[] {
    return [
      { method: "none", label: "None (keys in data.json, protected only by disk encryption)", available: true },
      { method: "pin", label: "PIN at launch (PBKDF2-wrapped; works everywhere)", available: true },
      { method: "safe", label: "OS keychain (Keychain / DPAPI / libsecret; desktop only)", available: safeStorageAvailable() },
    ];
  }

  touchIdAvailable(): boolean {
    return touchIdAvailable();
  }

  /**
   * Switch protection method. Requires an unlocked identity. `pin` is the new
   * PIN when method is "pin". Re-seals and saves; the server is not involved.
   */
  async setProtection(method: ProtectionMethod, opts: { pin?: string; touchId?: boolean } = {}): Promise<void> {
    if (!this.settings.identity) throw new Error("not connected");
    const p: Protection = { method, touchId: false };
    if (method === "pin") {
      if (!opts.pin || opts.pin.length < 4) throw new Error("PIN must be at least 4 characters");
      this.pinSalt = randomBytes(16);
      this.wrapKey = await deriveWrapKeyFromPin(opts.pin, this.pinSalt);
    } else if (method === "safe") {
      if (!safeStorageAvailable()) throw new Error("OS keychain protection is not available on this device (no keychain backend)");
      this.wrapKey = newWrapKey();
      p.safeWrap = safeWrap(this.wrapKey);
      p.touchId = Boolean(opts.touchId) && touchIdAvailable();
    } else {
      this.wrapKey = null;
      this.pinSalt = undefined;
    }
    this.settings.protection = p;
    await this.saveSettings();
  }

  /** Unlock a sealed identity (prompting as the method requires) and start the engine. */
  async unlock(): Promise<boolean> {
    const s = this.settings;
    if (s.identity) return true;
    if (!s.sealed) return false;
    try {
      if (s.sealed.method === "safe") {
        if (s.protection.touchId) await promptTouchId("unlock your obsync vault keys");
        if (!s.protection.safeWrap) throw new Error("keychain entry missing");
        this.wrapKey = safeUnwrap(s.protection.safeWrap);
        s.identity = await openKeystore<Identity>(s.sealed, this.wrapKey);
      } else {
        const v = await PromptModal.ask(this.app, "Unlock obsync", [{ name: "PIN", secret: true }]);
        if (!v) return false;
        this.pinSalt = fromB64(s.sealed.salt!);
        const k = await deriveWrapKeyFromPin(v[0], this.pinSalt);
        s.identity = await openKeystore<Identity>(s.sealed, k);
        this.wrapKey = k;
      }
    } catch (e) {
      new Notice(`obsync: ${(e as Error).message}. Use “Unlock vault keys” to try again.`, 8000);
      return false;
    }
    this.locked = false;
    await this.startEngine();
    return true;
  }

  effectiveExclusions(): string[] {
    const ex = [...this.settings.exclusions];
    if (!this.settings.syncConfig) ex.push(`/${CONFIG_TOKEN}/`);
    // Always keep ourselves out, whatever the user typed.
    ex.push(`/${CONFIG_TOKEN}/plugins/${this.manifest.id}/`);
    return ex;
  }

  applyExclusions(): void {
    this.engine?.setExclusions(this.effectiveExclusions());
  }

  // ---------- engine ----------

  /**
   * Extra engine configuration merged last when the engine starts. Not a
   * user setting and never persisted: the test suites use it to flip engine
   * behaviour (for example `adoptConfig`) before a join.
   */
  engineOverrides: Partial<EngineConfig> = {};

  async startEngine(): Promise<void> {
    if (this.engine || !this.settings.identity) return;
    const identity = this.settings.identity;
    this.session = openSession(identity);
    const fs = new ObsidianFS(this.app);
    const store = new ObsidianStateStore(this.app, `${this.manifest.dir ?? this.app.vault.configDir + "/plugins/" + this.manifest.id}/state.json`);
    this.engine = new Engine(
      fs,
      store,
      this.session.client,
      this.session.vc,
      {
        vaultId: identity.vaultId,
        deviceId: identity.deviceId,
        deviceName: identity.deviceName,
        privJwk: identity.privJwk,
        exclusions: this.effectiveExclusions(),
        compress: this.settings.compress,
        pad: this.settings.pad,
        debounceMs: this.settings.debounceMs,
        ...this.engineOverrides,
      },
      {
        log: (level, msg, data) => {
          if (level === "debug") return;
          const fn = level === "error" ? console.error : level === "warn" ? console.warn : console.info;
          fn(`obsync: ${msg}`, data ?? "");
        },
        onStatus: (s) => this.renderStatus(s),
        afterApply: (p, k) => this.hooks.afterApply(p, k),
        onConflict: (p, sib) => new Notice(`obsync: conflict on ${p}. Your version was saved as ${sib}.`, 10000),
        confirmMassDelete: (paths) =>
          ConfirmModal.ask(
            this.app,
            `Delete ${paths.length} files on all devices?`,
            [
              `${paths.length} files that were synced are no longer in this vault. This can be normal (you deleted a folder) or a sign that the vault folder was moved or unmounted.`,
              `First few: ${paths.slice(0, 5).join(", ")}${paths.length > 5 ? ", …" : ""}`,
              "Cancel to keep them on the other devices; you can apply later with “Apply held deletions”.",
            ],
            "Delete on all devices",
          ),
        onKeysChanged: () => {
          syncIdentityKeys(this.session!);
          this.settings.identity = this.session!.identity;
          void this.saveSettings();
        },
      },
    );
    await this.engine.start();
  }

  async restartEngine(): Promise<void> {
    await this.engine?.stop();
    this.engine = null;
    await this.startEngine();
  }

  private renderStatus(s: Status): void {
    const icon = { idle: "✓", scanning: "…", syncing: "↕", offline: "⚠ offline", error: "✗" }[s.phase];
    let txt = `obsync ${icon}`;
    if (s.pending) txt += ` ${s.pending}`;
    if (s.progress) txt += ` ${s.progress.done}/${s.progress.total}`;
    this.statusEl.setText(txt);
    this.statusEl.title = s.message ?? (s.lastSync ? `last sync ${new Date(s.lastSync).toLocaleTimeString()}` : "");
  }

  // ---------- enrolment ----------

  private async adopt(session: Session): Promise<void> {
    this.settings.identity = session.identity;
    await this.saveSettings();
    await this.restartEngine();
    new Notice("obsync: connected. Initial sync running.");
  }

  async joinWithLink(link: string): Promise<void> {
    if (!link) throw new Error("paste an invite link first");
    await this.adopt(await joinWithLink(link, this.settings.deviceName));
  }

  async joinWithPassphrase(server: string, vaultId: string, passphrase: string): Promise<void> {
    await this.adopt(await joinWithPassphrase(server, vaultId, passphrase, this.settings.deviceName));
  }

  async createVault(server: string, adminToken: string): Promise<void> {
    await this.adopt(await createVault(server, adminToken, this.settings.deviceName));
  }

  async leaveVault(): Promise<void> {
    await this.engine?.stop();
    this.engine = null;
    this.session = null;
    this.settings.identity = null;
    this.settings.sealed = null;
    this.settings.protection = { method: "none", touchId: false };
    this.wrapKey = null;
    this.locked = false;
    await this.saveSettings();
    this.statusEl.setText("obsync: off");
  }

  // ---------- commands ----------

  private need(): Session {
    if (!this.session) throw new Error("not connected");
    return this.session;
  }

  private async guard(fn: () => Promise<void>): Promise<void> {
    try {
      await fn();
    } catch (e) {
      console.error("obsync", e);
      new Notice(`obsync: ${(e as Error).message}`, 8000);
    }
  }

  /** Mint an invite link (also used by the in-Obsidian tests). */
  inviteLink(): Promise<string> {
    return createInviteLink(this.need());
  }

  /** Set the recovery passphrase without the modal (also used by the in-Obsidian tests). */
  async setRecovery(passphrase: string): Promise<void> {
    await setRecoveryPassphrase(this.need(), passphrase);
  }

  /** Remove a device: rotate keys and re-encrypt (also used by the in-Obsidian tests). */
  async removeDeviceById(id: string, onProgress?: (done: number) => void): Promise<void> {
    const s = this.need();
    await removeDevice(s, id, (done) => onProgress?.(done));
    this.settings.identity = s.identity;
    await this.saveSettings();
  }

  /** Decrypted device roster (also used by the in-Obsidian tests). */
  devices(): ReturnType<typeof listDevices> {
    return listDevices(this.need());
  }

  cmdInvite(): Promise<void> {
    return this.guard(async () => {
      const link = await this.inviteLink();
      new ShowSecretModal(this.app, "Invite link", link, "Valid for 24 hours, single use. It contains the vault keys: send it over a channel you trust and delete it afterwards.").open();
    });
  }

  cmdDevices(): Promise<void> {
    return this.guard(async () => {
      const s = this.need();
      const devs = await this.devices();
      new ListModal(
        this.app,
        "Devices",
        devs
          .filter((d) => !d.revoked_at)
          .map((d) => ({
            label: d.name + (d.isSelf ? " (this device)" : ""),
            detail: `${d.recovery ? "recovery identity" : "added " + new Date(d.created_at).toLocaleDateString()}${d.last_seen ? ", seen " + new Date(d.last_seen).toLocaleString() : ""}`,
            action:
              d.isSelf || d.recovery
                ? undefined
                : {
                    label: "Remove",
                    warning: true,
                    run: async () => {
                      if (!(await ConfirmModal.ask(this.app, `Remove ${d.name}?`, "The vault keys will be rotated and all data re-encrypted. This can take a while on large vaults and runs in the background.", "Remove and rotate"))) return;
                      new Notice("obsync: rotating keys and re-encrypting…");
                      await this.removeDeviceById(d.id, (done) => this.statusEl.setText(`obsync re-encrypting ${done}`));
                      new Notice("obsync: device removed, re-encryption complete.");
                    },
                  },
          })),
      ).open();
    });
  }

  cmdSetRecovery(): Promise<void> {
    return this.guard(async () => {
      const v = await PromptModal.ask(this.app, "Set recovery passphrase", [
        { name: "Passphrase (12+ characters)", secret: true },
        { name: "Repeat", secret: true },
      ]);
      if (!v) return;
      if (v[0].length < 12) throw new Error("use at least 12 characters");
      if (v[0] !== v[1]) throw new Error("passphrases differ");
      await this.setRecovery(v[0]);
      new Notice("obsync: recovery passphrase set.");
    });
  }

  cmdRotate(): Promise<void> {
    return this.guard(async () => {
      if (!(await ConfirmModal.ask(this.app, "Rotate vault keys?", "New data uses a fresh key and all existing data is re-encrypted. Nothing is removed.", "Rotate"))) return;
      const s = this.need();
      await removeDevice(s, "", (done) => this.statusEl.setText(`obsync re-encrypting ${done}`));
      this.settings.identity = s.identity;
      await this.saveSettings();
      new Notice("obsync: keys rotated.");
    });
  }

  cmdConflicts(): Promise<void> {
    return this.guard(async () => {
      const files = this.engine?.conflictFiles() ?? [];
      new ListModal(
        this.app,
        "Conflict copies",
        files.map((p) => ({ label: p, action: { label: "Open", run: async () => void this.app.workspace.openLinkText(p, "", true) } })),
        "No conflict copies. 🎉",
      ).open();
    });
  }

  cmdRestore(): Promise<void> {
    return this.guard(async () => {
      const v = await PromptModal.ask(this.app, "Restore vault to a point in time", [{ name: "Date and time", placeholder: "2026-10-08 14:30 (local)" }]);
      if (!v) return;
      const t = new Date(v[0].replace(" ", "T"));
      if (Number.isNaN(t.getTime())) throw new Error("could not parse that date");
      if (!(await ConfirmModal.ask(this.app, `Restore to ${t.toLocaleString()}?`, "Every file is set back to its version at that time, as new history. Nothing is lost: you can restore forward again.", "Restore"))) return;
      const s = this.need();
      const r = await s.client.restore(s.identity.vaultId, t.getTime());
      new Notice(`obsync: restored ${r.emitted} files${r.skipped_path_ids.length ? `, ${r.skipped_path_ids.length} skipped (content no longer on server)` : ""}.`);
      this.engine?.kick(0);
    });
  }

  cmdHistory(): Promise<void> {
    return this.guard(async () => {
      const f = this.app.workspace.getActiveFile();
      if (!f) throw new Error("no active file");
      const s = this.need();
      const ops = await s.client.history(s.identity.vaultId, await s.vc.pathId(f.path));
      new ListModal(
        this.app,
        `History: ${f.path}`,
        ops.reverse().map((o) => ({
          label: new Date(o.created_at).toLocaleString(),
          detail: o.blob_id ? `version ${o.seq}` : `deleted (${o.seq})`,
          action: o.blob_id
            ? {
                label: "Save copy",
                run: async () => {
                  const bytes = await s.vc.decryptBlob(o.blob_id!, await s.client.getBlob(s.identity.vaultId, o.blob_id!));
                  const dot = f.path.lastIndexOf(".");
                  const out = (dot > 0 ? f.path.slice(0, dot) : f.path) + ` (version ${o.seq})` + (dot > 0 ? f.path.slice(dot) : "");
                  await this.app.vault.createBinary(out, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer);
                  new Notice(`obsync: saved ${out}`);
                },
              }
            : undefined,
        })),
      ).open();
    });
  }
}
