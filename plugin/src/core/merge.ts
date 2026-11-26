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

import { diffIndices } from "node-diff3";
import { fromUtf8, isValidUtf8, utf8 } from "./encoding";

export interface MergeResult {
  ok: boolean;
  merged?: Uint8Array;
}

interface Region {
  stable: boolean;
  bufferContent?: string[];
  aContent?: string[];
  bContent?: string[];
}

/**
 * node-diff3's diffIndices, after cutting the lines the two buffers share at
 * both ends. Its LCS scans a candidate list that grows with the file, so it
 * is quadratic: a 250,000-line note took 63 s to merge on a laptop and 166 s
 * on a CI runner, and a phone would stall for minutes, although each side
 * had changed one line. Edits are local, so the trimmed middle is small.
 */
function diffTrimmed(o: string[], x: string[]): ReturnType<typeof diffIndices<string>> {
  let head = 0;
  const max = Math.min(o.length, x.length);
  while (head < max && o[head] === x[head]) head++;
  let tail = 0;
  while (tail < max - head && o[o.length - 1 - tail] === x[x.length - 1 - tail]) tail++;
  const hunks = diffIndices(o.slice(head, o.length - tail), x.slice(head, x.length - tail));
  for (const h of hunks) {
    h.buffer1[0] += head;
    h.buffer2[0] += head;
  }
  return hunks;
}

/**
 * node-diff3's diff3MergeRegions (same regions, same boundaries) over
 * diffTrimmed. Only the stable regions and the two sides of an unstable one
 * are produced: the caller merges clean regions and refuses the rest.
 */
function mergeRegions(a: string[], o: string[], b: string[]): Region[] {
  type Hunk = { ab: "a" | "b"; oStart: number; oLength: number; abStart: number; abLength: number };
  const hunks: Hunk[] = [];
  for (const [ab, x] of [["a", a], ["b", b]] as const) {
    for (const h of diffTrimmed(o, x)) hunks.push({ ab, oStart: h.buffer1[0], oLength: h.buffer1[1], abStart: h.buffer2[0], abLength: h.buffer2[1] });
  }
  // Array.prototype.sort is stable, as the library's sort relies on: hunks of
  // `a` stay ahead of hunks of `b` that start at the same line.
  hunks.sort((x, y) => x.oStart - y.oStart);
  const results: Region[] = [];
  let curr = 0;
  const advanceTo = (end: number) => {
    if (end > curr) {
      results.push({ stable: true, bufferContent: o.slice(curr, end) });
      curr = end;
    }
  };
  let i = 0;
  while (i < hunks.length) {
    const first = hunks[i++];
    const regionStart = first.oStart;
    let regionEnd = first.oStart + first.oLength;
    const inRegion = [first];
    advanceTo(regionStart);
    while (i < hunks.length && hunks[i].oStart <= regionEnd) {
      regionEnd = Math.max(regionEnd, hunks[i].oStart + hunks[i].oLength);
      inRegion.push(hunks[i++]);
    }
    if (inRegion.length === 1) {
      if (first.abLength > 0) results.push({ stable: true, bufferContent: (first.ab === "a" ? a : b).slice(first.abStart, first.abStart + first.abLength) });
    } else {
      const bounds = { a: [a.length, -1, o.length, -1], b: [b.length, -1, o.length, -1] };
      for (const h of inRegion) {
        const bd = bounds[h.ab];
        bd[0] = Math.min(h.abStart, bd[0]);
        bd[1] = Math.max(h.abStart + h.abLength, bd[1]);
        bd[2] = Math.min(h.oStart, bd[2]);
        bd[3] = Math.max(h.oStart + h.oLength, bd[3]);
      }
      const aStart = bounds.a[0] + (regionStart - bounds.a[2]);
      const aEnd = bounds.a[1] + (regionEnd - bounds.a[3]);
      const bStart = bounds.b[0] + (regionStart - bounds.b[2]);
      const bEnd = bounds.b[1] + (regionEnd - bounds.b[3]);
      results.push({ stable: false, aContent: a.slice(aStart, aEnd), bContent: b.slice(bStart, bEnd) });
    }
    curr = regionEnd;
  }
  advanceTo(o.length);
  return results;
}

export function mergeText(base: Uint8Array, local: Uint8Array, remote: Uint8Array): MergeResult {
  if (!isValidUtf8(base) || !isValidUtf8(local) || !isValidUtf8(remote)) return { ok: false };
  const [bs, ls, rs] = [fromUtf8(base), fromUtf8(local), fromUtf8(remote)];
  const lines = (s: string) => s.split("\n").map((x) => (x.endsWith("\r") ? x.slice(0, -1) : x));
  // node-diff3's diff3Merge does this with push(...region): an unchanged
  // region of a large note is hundreds of thousands of lines, past the
  // engine's argument limit, so a merge of a big file threw. The same walk
  // over its regions, with loops, and with the diffs cut down to the lines
  // that changed (mergeRegions). A region both sides changed identically
  // is not a conflict (excludeFalseConflicts).
  const out: string[] = [];
  for (const r of mergeRegions(lines(ls), lines(bs), lines(rs))) {
    let take: string[];
    if (r.stable) take = r.bufferContent!;
    else if (r.aContent!.length === r.bContent!.length && r.aContent!.every((x, i) => x === r.bContent![i])) take = r.aContent!;
    else return { ok: false };
    for (const l of take) out.push(l);
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
