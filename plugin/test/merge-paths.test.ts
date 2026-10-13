import { describe, expect, it } from "vitest";
import { mergeJson, mergeText } from "../src/core/merge";
import { utf8, fromUtf8 } from "../src/core/encoding";
import { compileExclusions, DEFAULT_EXCLUSIONS, conflictPath, CONFLICT_RE, toLogical, fromLogical, isTextPath, isSafeLogicalPath, isSafeDevicePath } from "../src/core/paths";

const t = (s: string) => utf8(s);

describe("mergeText", () => {
  it("merges non-overlapping edits and keeps CRLF/BOM", () => {
    const base = t("﻿a\r\nb\r\nc\r\nd\r\n");
    const local = t("﻿A\r\nb\r\nc\r\nd\r\n");
    const remote = t("﻿a\r\nb\r\nc\r\nD\r\n");
    const m = mergeText(base, local, remote);
    expect(m.ok).toBe(true);
    expect(fromUtf8(m.merged!)).toBe("﻿A\r\nb\r\nc\r\nD\r\n");
  });
  it("refuses overlapping edits", () => {
    const m = mergeText(t("a\nb\n"), t("a\nB1\n"), t("a\nB2\n"));
    expect(m.ok).toBe(false);
  });
  it("keeps a one-sided deletion and a distant insertion", () => {
    const m = mergeText(t("a\nb\nc\nd\ne\n"), t("a\nc\nd\ne\n"), t("a\nb\nc\nd\ne\nf\n"));
    expect(m.ok).toBe(true);
    expect(fromUtf8(m.merged!)).toBe("a\nc\nd\ne\nf\n");
  });
  it("same edit on both sides is not a conflict", () => {
    const m = mergeText(t("a\n"), t("a\nx\n"), t("a\nx\n"));
    expect(m.ok).toBe(true);
    expect(fromUtf8(m.merged!)).toBe("a\nx\n");
  });
  it("refuses binary", () => {
    expect(mergeText(new Uint8Array([0xff, 0xfe]), t("a"), t("b")).ok).toBe(false);
  });
});

describe("mergeJson", () => {
  it("merges disjoint key changes, nested", () => {
    const base = t('{\n  "a": 1,\n  "b": {"x": 1, "y": 2},\n  "c": 3\n}\n');
    const local = t('{\n  "a": 2,\n  "b": {"x": 1, "y": 2},\n  "c": 3\n}\n');
    const remote = t('{"a": 1, "b": {"x": 1, "y": 9}, "d": 4}');
    const m = mergeJson(base, local, remote);
    expect(m.ok).toBe(true);
    expect(JSON.parse(fromUtf8(m.merged!))).toEqual({ a: 2, b: { x: 1, y: 9 }, d: 4 });
    expect(fromUtf8(m.merged!).endsWith("\n")).toBe(true);
  });
  it("conflicts on the same key changed differently", () => {
    expect(mergeJson(t('{"a":1}'), t('{"a":2}'), t('{"a":3}')).ok).toBe(false);
  });
  it("handles arrays as atomic values", () => {
    const m = mergeJson(t('{"p":["a"]}'), t('{"p":["a","b"]}'), t('{"p":["a"],"q":1}'));
    expect(m.ok).toBe(true);
    expect(JSON.parse(fromUtf8(m.merged!))).toEqual({ p: ["a", "b"], q: 1 });
    expect(mergeJson(t('{"p":["a"]}'), t('{"p":["a","b"]}'), t('{"p":["a","c"]}')).ok).toBe(false);
  });
});

describe("paths", () => {
  it("maps the config dir both ways", () => {
    expect(toLogical(".obsidian/app.json", ".obsidian")).toBe("$CONFIG/app.json");
    expect(toLogical("notes/.obsidian/x", ".obsidian")).toBe("notes/.obsidian/x");
    expect(fromLogical("$CONFIG/plugins/x/main.js", ".config-phone")).toBe(".config-phone/plugins/x/main.js");
    expect(fromLogical("a.md", ".obsidian")).toBe("a.md");
  });
  it("default exclusions behave like gitignore", () => {
    const ex = compileExclusions(DEFAULT_EXCLUSIONS);
    expect(ex("$CONFIG/workspace.json")).toBe(true);
    expect(ex("$CONFIG/workspace-mobile.json")).toBe(true);
    expect(ex("$CONFIG/app.json")).toBe(false);
    expect(ex("$CONFIG/plugins/obsync/data.json")).toBe(true);
    expect(ex("$CONFIG/plugins/dataview/data.json")).toBe(false);
    expect(ex(".trash/old.md")).toBe(true);
    expect(ex("notes/.trash/x.md")).toBe(false); // anchored
    expect(ex("proj/node_modules/x/y.js")).toBe(true); // unanchored dir
    expect(ex("notes/.DS_Store")).toBe(true);
    expect(ex("notes/x.obsync-tmp")).toBe(true);
    expect(ex("notes/readme.md")).toBe(false);
    const custom = compileExclusions(["Private/**", "*.tmp", "/Daily/2020-*.md", "# comment", ""]);
    expect(custom("Private/a/b.md")).toBe(true);
    expect(custom("Private")).toBe(false); // the pattern covers contents, not the entry itself
    expect(custom("x/y.tmp")).toBe(true);
    expect(custom("Daily/2020-01-01.md")).toBe(true);
    expect(custom("Daily/2021-01-01.md")).toBe(false);
    expect(custom("Other/Daily/2020-01-01.md")).toBe(false);
  });
  it("conflict path naming", () => {
    const p = conflictPath("notes/a.b.md", "my/laptop", new Date(2026, 9, 8, 14, 32));
    expect(p).toBe("notes/a.b (conflict my_laptop 2026-10-08 1432).md");
    expect(CONFLICT_RE.test(p)).toBe(true);
    expect(conflictPath("README", "x", new Date(2026, 0, 1))).toMatch(/^README \(conflict x 2026-01-01 \d{4}\)$/);
    expect(CONFLICT_RE.test("notes/a.md")).toBe(false);
  });
  it("text detection", () => {
    expect(isTextPath("a.md")).toBe(true);
    expect(isTextPath("a.PNG")).toBe(false);
  });
});

describe("path safety (what another device may make us write)", () => {
  it("accepts ordinary vault paths, including $CONFIG as the first segment", () => {
    for (const p of ["a.md", "notes/a b/ç.md", "$CONFIG/app.json", "$CONFIG/plugins/x/main.js", ".trash/x.md", "a/.hidden"]) {
      expect(isSafeLogicalPath(p), p).toBe(true);
    }
  });
  it("rejects traversal, absolute, empty segments, backslashes, control chars and a misplaced $CONFIG", () => {
    for (const p of ["", "../x", "a/../x", "a/..", "/etc/passwd", "a//b", "a/./b", "a\\b", "a\u0000b", "a\nb", "notes/$CONFIG/app.json", "a/", "."]) {
      expect(isSafeLogicalPath(p), JSON.stringify(p)).toBe(false);
    }
  });
  it("a device path may never contain the $CONFIG token (a real folder with that name is not synced)", () => {
    expect(isSafeDevicePath("$CONFIG/app.json")).toBe(false);
    expect(isSafeDevicePath(".obsidian/app.json")).toBe(true);
  });
});
