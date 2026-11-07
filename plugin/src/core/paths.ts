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

/**
 * Is this a path the engine may act on? Paths arrive from other devices'
 * encrypted metadata, so a compromised member (or a stolen invite link)
 * could send anything. Rejects empty, absolute, "." and ".." segments,
 * backslashes and control characters, and the $CONFIG token anywhere but
 * as the first segment. The engine additionally checks that the path hashes
 * to the op's path_id.
 */
export function isSafeLogicalPath(p: string): boolean {
  if (!p || p.length > 4096 || p.startsWith("/") || p.endsWith("/")) return false;
  // Backslashes, control characters, and the characters Windows forbids in
  // names. Obsidian refuses all of them in a file name on every platform, so
  // no honest op carries one; on NTFS a ":" names an alternate data stream
  // ("workspace.json::$DATA" is workspace.json itself), which would slip a
  // per-device file past its exclusion.
  // eslint-disable-next-line no-control-regex
  if (/[\\\x00-\x1f\x7f:<>"|?*]/.test(p)) return false;
  const enc = new TextEncoder();
  const segs = p.split("/");
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    if (seg === "" || seg === "." || seg === "..") return false;
    if (seg === CONFIG_TOKEN && i !== 0) return false;
    // Windows strips trailing dots and spaces ("x." == "x"), has 8.3 aliases
    // ("OBSIDI~1" == ".obsidian") and reserved device names; a component over
    // 255 bytes fails on Linux and Android. None of these is a name a human
    // gives a note, and each could alias a path the rules above protect.
    if (seg.endsWith(".") || seg.endsWith(" ")) return false;
    if (/^[^.]{1,8}~\d+(\..*)?$/i.test(seg)) return false;
    if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i.test(seg)) return false;
    if (enc.encode(seg).length > 255) return false;
  }
  return true;
}

/**
 * Does this device path alias the config dir without being it? Case-only
 * variants (".Obsidian") are the same directory on macOS and Windows and
 * would slip past the $CONFIG mapping and its exclusions.
 */
export function aliasesConfigDir(devPath: string, configDir: string): boolean {
  const first = devPath.split("/")[0];
  return first !== configDir && fold(first) === fold(configDir);
}

/**
 * A *logical* path (what an op carries) names the config directory only
 * through the `$CONFIG` token. One whose first segment is the directory's
 * real name, in any spelling a case-insensitive or normalising volume would
 * treat as the same, is a second route into `.obsidian` that bypasses the
 * `$CONFIG` exclusions and the plugin-folder protection.
 */
export function logicalAliasesConfigDir(logical: string, configDir: string): boolean {
  const first = logical.split("/")[0];
  return first !== CONFIG_TOKEN && fold(first) === fold(configDir);
}

/**
 * Fold the way a case-insensitive, normalising file system might: NFKC first
 * (ſ → s, K → k, ligatures), both case directions ("ı" upper-cases to "I"),
 * then strip combining marks ("İ" → "i̇" → "i").
 */
export function fold(s: string): string {
  return s.normalize("NFKC").toUpperCase().toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
}

/**
 * Do two names land on the same entry of a case-insensitive, normalising
 * volume although they are spelled differently? ("ob\u017fync" and "obsync" on
 * APFS; "Note.md" and "note.md" on NTFS.) Equal spellings are not a clash.
 */
export function foldClash(a: string, b: string): boolean {
  return a !== b && fold(a) === fold(b);
}

/** Is this logical path the config dir or inside it? ("$CONFIGx" is a plain folder.) */
export function isConfigLogical(logical: string): boolean {
  return logical === CONFIG_TOKEN || logical.startsWith(CONFIG_TOKEN + "/");
}

/** Same rules for a device path (no $CONFIG token allowed at all). */
export function isSafeDevicePath(p: string): boolean {
  return isSafeLogicalPath(p) && p.split("/").every((s) => s !== CONFIG_TOKEN);
}

export function compileExclusions(patterns: string[]): (logicalPath: string) => boolean {
  const res: RegExp[] = [];
  for (let raw of patterns) {
    // Pattern and path are both folded the way a case-insensitive volume
    // folds names (see `fold`): "obſync" is the obsync directory on APFS,
    // and the regex `i` flag alone would not match it, so an exclusion a
    // remote path could sidestep by respelling would be no exclusion.
    // Over-matching an exclusion is harmless; under-matching is not.
    raw = fold(raw.trim());
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
    // Case-insensitive: on macOS and Windows volumes "Workspace.json" and
    // "plugins/Obsync/" are the excluded files, and an exclusion that a
    // remote path can sidestep by changing case is no exclusion.
    res.push(new RegExp(prefix + re + (dirOnly ? suffix : "(?:/|$)"), "i"));
  }
  return (p) => {
    const f = fold(p);
    return res.some((r) => r.test(f));
  };
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
/**
 * Name of the conflict sibling for `path`. `n` > 1 adds an ordinal so a
 * second conflict on the same file in the same minute gets its own file
 * instead of overwriting the first copy.
 */
export function conflictPath(path: string, device: string, when = new Date(), n = 1): string {
  const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/") + 1) : "";
  const base = path.slice(dir.length);
  const dot = base.lastIndexOf(".");
  const stem = dot > 0 ? base.slice(0, dot) : base;
  const ext = dot > 0 ? base.slice(dot) : "";
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp = `${when.getFullYear()}-${pad(when.getMonth() + 1)}-${pad(when.getDate())} ${pad(when.getHours())}${pad(when.getMinutes())}`;
  const safeDev = device.replace(/[\\/:*?"<>|]/g, "_").slice(0, 32) || "device";
  const ord = n > 1 ? ` ${n}` : "";
  return `${dir}${stem} (conflict ${safeDev} ${stamp}${ord})${ext}`;
}

export const CONFLICT_RE = / \(conflict [^()]* \d{4}-\d{2}-\d{2} \d{4}( \d+)?\)(\.[^.]+)?$/;

/** Path components over 255 UTF-8 bytes fail on Android/Linux (DESIGN.md §1.5). */
export function overlongComponents(path: string): string[] {
  const enc = new TextEncoder();
  return path.split("/").filter((c) => enc.encode(c).length > 255);
}
