/**
 * Path rules: config-dir mapping, exclusions, conflict-copy naming, and the
 * text/binary decision used by the merge step.
 */

export const CONFIG_TOKEN = "$CONFIG";

/** Replace the device's config dir with $CONFIG so devices with different config dir names line up. */
export function toLogical(path: string, configDir: string): string {
  if (path === configDir) return CONFIG_TOKEN;
  if (path.startsWith(configDir + "/")) return CONFIG_TOKEN + path.slice(configDir.length);
  return path;
}

export function fromLogical(path: string, configDir: string): string {
  if (path === CONFIG_TOKEN) return configDir;
  if (path.startsWith(CONFIG_TOKEN + "/")) return configDir + path.slice(CONFIG_TOKEN.length);
  return path;
}

/**
 * Default per-device exclusions (DESIGN.md §7.1). Patterns are matched
 * against the *logical* path, so $CONFIG works whatever the config dir is.
 * Syntax: gitignore-like. `*` matches within a segment, `**` across
 * segments, a trailing `/` matches a directory subtree, a leading `/`
 * anchors to the vault root, otherwise the pattern matches at any depth.
 */
export const DEFAULT_EXCLUSIONS = [
  "/$CONFIG/workspace.json",
  "/$CONFIG/workspace-mobile.json",
  "/$CONFIG/workspaces.json",
  "/$CONFIG/plugins/obsync/",
  "/$CONFIG/cache/",
  "/.trash/",
  "/.git/",
  "node_modules/",
  ".DS_Store",
  "desktop.ini",
  "Thumbs.db",
  "*.obsync-tmp",
  "*.obsync-conflict-tmp",
];

export function compileExclusions(patterns: string[]): (logicalPath: string) => boolean {
  const res: RegExp[] = [];
  for (let raw of patterns) {
    raw = raw.trim();
    if (!raw || raw.startsWith("#")) continue;
    let anchored = false;
    if (raw.startsWith("/")) {
      anchored = true;
      raw = raw.slice(1);
    }
    let dirOnly = false;
    if (raw.endsWith("/")) {
      dirOnly = true;
      raw = raw.slice(0, -1);
    }
    let re = "";
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (c === "*") {
        if (raw[i + 1] === "*") {
          re += ".*";
          i++;
          if (raw[i + 1] === "/") i++;
        } else re += "[^/]*";
      } else if (c === "?") re += "[^/]";
      else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
    const prefix = anchored ? "^" : "(?:^|/)";
    const suffix = dirOnly ? "(?:/|$)" : "$";
    // A non-dir pattern also matches a directory of that name (gitignore semantics).
    res.push(new RegExp(prefix + re + (dirOnly ? suffix : "(?:/|$)")));
  }
  return (p) => res.some((r) => r.test(p));
}

/** Extensions we are willing to three-way merge (plus a UTF-8 validity check). */
const TEXT_EXT = new Set(["md", "txt", "json", "css", "js", "ts", "yaml", "yml", "csv", "canvas", "html", "xml", "svg", "org", "tex", "bib"]);

export function isTextPath(path: string): boolean {
  const i = path.lastIndexOf(".");
  return i >= 0 && TEXT_EXT.has(path.slice(i + 1).toLowerCase());
}

export function isJsonPath(path: string): boolean {
  return path.toLowerCase().endsWith(".json") || path.toLowerCase().endsWith(".canvas");
}

/** `notes/a.md` → `notes/a (conflict laptop 2026-10-08 1432).md` */
export function conflictPath(path: string, device: string, when = new Date()): string {
  const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/") + 1) : "";
  const base = path.slice(dir.length);
  const dot = base.lastIndexOf(".");
  const stem = dot > 0 ? base.slice(0, dot) : base;
  const ext = dot > 0 ? base.slice(dot) : "";
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp = `${when.getFullYear()}-${pad(when.getMonth() + 1)}-${pad(when.getDate())} ${pad(when.getHours())}${pad(when.getMinutes())}`;
  const safeDev = device.replace(/[\\/:*?"<>|]/g, "_").slice(0, 32) || "device";
  return `${dir}${stem} (conflict ${safeDev} ${stamp})${ext}`;
}

export const CONFLICT_RE = / \(conflict [^()]* \d{4}-\d{2}-\d{2} \d{4}\)(\.[^.]+)?$/;

/** Path components over 255 UTF-8 bytes fail on Android/Linux (DESIGN.md §1.5). */
export function overlongComponents(path: string): string[] {
  const enc = new TextEncoder();
  return path.split("/").filter((c) => enc.encode(c).length > 255);
}
