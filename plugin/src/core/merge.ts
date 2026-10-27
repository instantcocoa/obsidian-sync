/**
 * Conflict merging (DESIGN.md §6.6).
 *
 * - Text: conservative three-way merge (diff3). Non-overlapping hunks merge;
 *   any overlap means "no clean merge" and the caller makes a sibling copy.
 *   Lines are compared without their line ending, so a side that re-saved
 *   the file with the other convention (CRLF on Windows, LF elsewhere) has
 *   not changed every line. The merge is written with one convention: the
 *   side that changed it, else the base's. A BOM is preserved verbatim.
 * - JSON (anything under $CONFIG ending in .json, and .canvas): key-level
 *   three-way merge. A key changed on one side only takes that side; the
 *   same key changed on both sides to different values is a conflict.
 */

import { diff3Merge } from "node-diff3";
import { fromUtf8, isValidUtf8, utf8 } from "./encoding";

export interface MergeResult {
  ok: boolean;
  merged?: Uint8Array;
}

export function mergeText(base: Uint8Array, local: Uint8Array, remote: Uint8Array): MergeResult {
  if (!isValidUtf8(base) || !isValidUtf8(local) || !isValidUtf8(remote)) return { ok: false };
  const [bs, ls, rs] = [fromUtf8(base), fromUtf8(local), fromUtf8(remote)];
  const lines = (s: string) => s.split("\n").map((x) => (x.endsWith("\r") ? x.slice(0, -1) : x));
  const regions = diff3Merge(lines(ls), lines(bs), lines(rs), { excludeFalseConflicts: true, stringSeparator: "\n" });
  const out: string[] = [];
  for (const reg of regions) {
    if (reg.ok) out.push(...reg.ok);
    else return { ok: false };
  }
  const [be, le, re] = [eol(bs), eol(ls), eol(rs)];
  const sep = le !== be ? le : re !== be ? re : be;
  return { ok: true, merged: utf8(out.join(sep)) };
}

/** The file's dominant line ending ("\r\n" or "\n"); LF for a file without one. */
function eol(s: string): string {
  const crlf = s.split("\r\n").length - 1;
  const lf = s.split("\n").length - 1 - crlf;
  return crlf > lf ? "\r\n" : "\n";
}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

function eq(a: Json, b: Json): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function isObj(v: Json): v is { [k: string]: Json } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function mergeJsonValue(base: Json | undefined, local: Json | undefined, remote: Json | undefined): { ok: boolean; value?: Json } {
  const same = (a: Json | undefined, b: Json | undefined) => (a === undefined ? b === undefined : b !== undefined && eq(a, b));
  if (same(base, local)) return { ok: true, value: remote }; // only remote changed (or nobody)
  if (same(base, remote)) return { ok: true, value: local }; // only local changed
  if (same(local, remote)) return { ok: true, value: local }; // both made the same change
  if (local !== undefined && remote !== undefined && isObj(local) && isObj(remote) && (base === undefined || isObj(base))) {
    const baseObj = base !== undefined && isObj(base) ? base : undefined;
    const out: { [k: string]: Json } = {};
    const keys = new Set([...Object.keys(local), ...Object.keys(remote), ...(baseObj ? Object.keys(baseObj) : [])]);
    for (const k of keys) {
      const m = mergeJsonValue(baseObj ? baseObj[k] : undefined, local[k], remote[k]);
      if (!m.ok) return { ok: false };
      if (m.value !== undefined) out[k] = m.value;
    }
    return { ok: true, value: out };
  }
  return { ok: false };
}

export function mergeJson(base: Uint8Array, local: Uint8Array, remote: Uint8Array): MergeResult {
  let b: Json, l: Json, r: Json;
  try {
    b = JSON.parse(fromUtf8(base));
    l = JSON.parse(fromUtf8(local));
    r = JSON.parse(fromUtf8(remote));
  } catch {
    return { ok: false };
  }
  const m = mergeJsonValue(b, l, r);
  if (!m.ok || m.value === undefined) return { ok: false };
  // Preserve the local file's indentation style if detectable.
  const txt = fromUtf8(local);
  const indent = /^\{\n(\s+)"/.exec(txt)?.[1] ?? (txt.includes("\n") ? 2 : 0);
  return { ok: true, merged: utf8(JSON.stringify(m.value, null, indent) + (txt.endsWith("\n") ? "\n" : "")) };
}
