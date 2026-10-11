/**
 * Post-write hooks for paths under the config dir (DESIGN.md §7.2). Every
 * integration here uses undocumented but long-stable Obsidian internals and
 * is wrapped so a failure degrades to "reload Obsidian", never to a broken
 * sync.
 */
import { App, Notice } from "obsidian";

type AppInternals = App & {
  plugins?: {
    enabledPlugins: Set<string>;
    manifests: Record<string, unknown>;
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
    for (const id of ids) {
      try {
        if (p.enabledPlugins.has(id)) {
          await p.disablePlugin(id);
          await p.enablePlugin(id);
          new Notice(`obsync: reloaded plugin ${id}`);
        }
      } catch (e) {
        console.warn("obsync: plugin reload failed", id, e);
        this.noticeRestartOnce();
      }
    }
  }

  private async reconcileEnabledPlugins(): Promise<void> {
    const p = (this.app as AppInternals).plugins;
    if (!p) return;
    try {
      const raw = await this.app.vault.adapter.read(this.app.vault.configDir + "/community-plugins.json");
      const want = new Set<string>(JSON.parse(raw));
      await p.loadManifests?.();
      for (const id of want) if (!p.enabledPlugins.has(id) && id !== this.selfId && p.manifests[id]) await p.enablePlugin(id);
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
