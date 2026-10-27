/**
 * Post-write hooks for paths under the config dir (DESIGN.md §7.2). Every
 * integration here uses undocumented but long-stable Obsidian internals and
 * is wrapped so a failure degrades to "reload Obsidian", never to a broken
 * sync.
 */
import { App, Notice, Platform } from "obsidian";

type AppInternals = App & {
  plugins?: {
    enabledPlugins: Set<string>;
    manifests: Record<string, { isDesktopOnly?: boolean } | undefined>;
    disablePlugin(id: string): Promise<void>;
    enablePlugin(id: string): Promise<void>;
    loadManifests?: () => Promise<void>;
  };
  customCss?: {
    theme?: string;
    setTheme?: (t: string) => void;
    requestLoadSnippets?: () => void;
    loadSnippets?: () => void;
    loadCss?: () => void;
    requestLoadTheme?: () => void;
  };
};

export class ConfigHooks {
  private pendingReload = new Set<string>();
  private reloadTimer: ReturnType<typeof setTimeout> | null = null;
  private noticedRestart = false;
  private cssTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private app: App,
    private selfId: string,
  ) {}

  /** Called by the engine after it wrote or removed `path` (device path). */
  afterApply(path: string, _kind: "put" | "delete"): void {
    const cfg = this.app.vault.configDir + "/";
    if (!path.startsWith(cfg)) return;
    const rel = path.slice(cfg.length);
    const m = /^plugins\/([^/]+)\/(main\.js|manifest\.json|styles\.css)$/.exec(rel);
    if (m) {
      if (m[1] !== this.selfId) this.schedulePluginReload(m[1]);
      return;
    }
    if (rel === "community-plugins.json") {
      void this.reconcileEnabledPlugins();
      return;
    }
    if (rel.startsWith("snippets/") || rel === "appearance.json" || rel.startsWith("themes/")) {
      this.scheduleCssReload();
      return;
    }
    if (/^(app|hotkeys|core-plugins|graph|types|command-palette|daily-notes|templates)\.json$/.test(rel) || /^plugins\/[^/]+\/data\.json$/.test(rel)) {
      this.noticeRestartOnce();
    }
  }

  private schedulePluginReload(id: string): void {
    this.pendingReload.add(id);
    if (this.reloadTimer) clearTimeout(this.reloadTimer);
    // main.js, manifest.json and styles.css usually arrive together; reload once.
    this.reloadTimer = setTimeout(() => void this.reloadPlugins(), 2000);
  }

  private async reloadPlugins(): Promise<void> {
    const ids = [...this.pendingReload];
    this.pendingReload.clear();
    const p = (this.app as AppInternals).plugins;
    if (!p) return;
    try {
      await p.loadManifests?.();
    } catch {
      /* ignore */
    }
    let want: Set<string> | null | undefined;
    for (const id of ids) {
      try {
        if (p.enabledPlugins.has(id)) {
          await p.disablePlugin(id);
          await p.enablePlugin(id);
          new Notice(`obsync: reloaded plugin ${id}`);
          continue;
        }
        // Seen on Android: community-plugins.json arrives before the plugin's
        // own files, so the reconcile it triggered found no manifest and the
        // plugin stayed off until the list changed again. The files are here
        // now; enable it if the vault wants it.
        if (want === undefined) want = await this.wantedPlugins();
        if (want?.has(id)) await this.enableFromVault(p, id);
      } catch (e) {
        console.warn("obsync: plugin reload failed", id, e);
        this.noticeRestartOnce();
      }
    }
  }

  /** The vault's enabled-plugin list (community-plugins.json), or null when it has not synced yet. */
  private async wantedPlugins(): Promise<Set<string> | null> {
    const file = this.app.vault.configDir + "/community-plugins.json";
    if (!(await this.app.vault.adapter.exists(file))) return null;
    return new Set<string>(JSON.parse(await this.app.vault.adapter.read(file)));
  }

  private noticedDesktopOnly = new Set<string>();

  /**
   * Enable `id` because the vault has it enabled. On a phone a desktop-only
   * plugin is skipped and said so, once; Obsidian itself would refuse it
   * without a word. Returns true when the plugin was enabled.
   */
  private async enableFromVault(p: NonNullable<AppInternals["plugins"]>, id: string): Promise<boolean> {
    if (p.enabledPlugins.has(id) || id === this.selfId) return false;
    const m = p.manifests[id];
    if (!m) return false;
    if (Platform.isMobile && m.isDesktopOnly) {
      if (!this.noticedDesktopOnly.has(id)) {
        this.noticedDesktopOnly.add(id);
        new Notice(`obsync: plugin "${id}" is enabled in the vault but is desktop-only, so it was not enabled on this device.`, 10000);
      }
      return false;
    }
    await p.enablePlugin(id);
    // Code from another device just started running here. Say so.
    new Notice(`obsync: enabled plugin "${id}" because it is enabled in the vault`);
    return true;
  }

  private async reconcileEnabledPlugins(): Promise<void> {
    const p = (this.app as AppInternals).plugins;
    if (!p) return;
    try {
      const want = await this.wantedPlugins();
      if (!want) return;
      await p.loadManifests?.();
      for (const id of want) await this.enableFromVault(p, id);
      for (const id of [...p.enabledPlugins]) if (!want.has(id) && id !== this.selfId) await p.disablePlugin(id);
    } catch (e) {
      console.warn("obsync: community-plugins reconcile failed", e);
      this.noticeRestartOnce();
    }
  }

  private scheduleCssReload(): void {
    if (this.cssTimer) clearTimeout(this.cssTimer);
    this.cssTimer = setTimeout(() => {
      const c = (this.app as AppInternals).customCss;
      try {
        c?.requestLoadSnippets?.() ?? c?.loadSnippets?.();
        c?.requestLoadTheme?.() ?? c?.loadCss?.();
        if (c?.theme && c.setTheme) c.setTheme(c.theme);
      } catch (e) {
        console.warn("obsync: css reload failed", e);
      }
    }, 1000);
  }

  private noticeRestartOnce(): void {
    if (this.noticedRestart) return;
    this.noticedRestart = true;
    new Notice("obsync: settings changed on another device. Reload Obsidian to apply all of them.", 8000);
  }
}
