/**
 * Conflict merging (DESIGN.md §6.6).
 *
 * - Text: conservative three-way merge (diff3). Non-overlapping hunks merge;
 *   any overlap means "no clean merge" and the caller makes a sibling copy.
 *   Line endings and a BOM are preserved verbatim because we split on "\n"
 *   and leave "\r" attached.
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
  const b = fromUtf8(base).split("\n");
  const l = fromUtf8(local).split("\n");
  const r = fromUtf8(remote).split("\n");
  const regions = diff3Merge(l, b, r, { excludeFalseConflicts: true, stringSeparator: "\n" });
  const out: string[] = [];
  for (const reg of regions) {
    if (reg.ok) out.push(...reg.ok);
    else return { ok: false };
  }
  return { ok: true, merged: utf8(out.join("\n")) };
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
