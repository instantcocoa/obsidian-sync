/**
 * Property tests for the three-way merge (DESIGN.md §6.6), the one cell the
 * evidence review listed as unproven: random edit histories through
 * `mergeText` and `mergeJson`, checking that every clean merge keeps what
 * both sides kept, carries what either side added or changed, and drops
 * what either side deleted on purpose; that the merge is deterministic and
 * symmetric in its two sides; that a side that did nothing yields the other
 * side exactly; and that arbitrary bytes never throw. Every line of base is a
 * unique token, so membership is unambiguous. Seeded: a failure prints the
 * seed and the three inputs.
 */
import { describe, expect, it } from "vitest";
import { mergeJson, mergeText } from "../src/core/merge";
import { fromUtf8, utf8 } from "../src/core/encoding";

/** xorshift32: small, fast, reproducible. */
function rng(seed: number): () => number {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x / 0x100000000;
  };
}

type Edit = { kind: "insert"; at: number; line: string } | { kind: "delete"; at: number } | { kind: "modify"; at: number; line: string };

/** Apply random edits to `base` (unique tokens); returns the result and what was added, removed, kept. */
function editSide(base: string[], r: () => number, tag: string, n: number): { lines: string[]; added: Set<string>; removed: Set<string>; touched: Set<number> } {
  const lines = [...base];
  const added = new Set<string>();
  const removed = new Set<string>();
  const touched = new Set<number>(); // base indexes this side touched (deleted or modified) or inserted next to
  let fresh = 0;
  // Map from current index to base index (or -1 for inserted lines) to track touches.
  let origin = base.map((_, i) => i);
  for (let k = 0; k < n; k++) {
    const kinds: Edit["kind"][] = ["insert", "delete", "modify"];
    const kind = kinds[Math.floor(r() * 3)];
    if (kind === "insert" || lines.length === 0) {
      const at = Math.floor(r() * (lines.length + 1));
      const line = `${tag}+${fresh++}`;
      lines.splice(at, 0, line);
      origin.splice(at, 0, -1);
      added.add(line);
      if (at > 0 && origin[at - 1] >= 0) touched.add(origin[at - 1]);
      if (at + 1 < origin.length && origin[at + 1] >= 0) touched.add(origin[at + 1]);
    } else {
      const at = Math.floor(r() * lines.length);
      const old = lines[at];
      if (kind === "delete") {
        lines.splice(at, 1);
        if (origin[at] >= 0) {
          removed.add(old);
          touched.add(origin[at]);
        } else added.delete(old);
        origin.splice(at, 1);
      } else {
        const line = `${tag}*${fresh++}`;
        if (origin[at] >= 0) {
          removed.add(old);
          touched.add(origin[at]);
        } else added.delete(old);
        lines[at] = line;
        origin[at] = -1;
        added.add(line);
      }
    }
  }
  return { lines, added, removed, touched };
}

const text = (lines: string[]) => utf8(lines.length ? lines.join("\n") + "\n" : "");
const linesOf = (b: Uint8Array) => {
  const t = fromUtf8(b).replace(/\n$/, "");
  return t === "" ? [] : t.split("\n");
};

describe("mergeText properties (seeded fuzz)", () => {
  const SEED = Number(process.env.MERGE_FUZZ_SEED ?? 20261107);
  const ROUNDS = Number(process.env.MERGE_FUZZ_ROUNDS ?? 3000);

  it(`${ROUNDS} random three-way histories: clean merges keep, carry and drop the right lines`, () => {
    const r = rng(SEED);
    let clean = 0;
    let conflicts = 0;
    for (let round = 0; round < ROUNDS; round++) {
      const n = 1 + Math.floor(r() * 30);
      const base = Array.from({ length: n }, (_, i) => `b${i}`);
      const L = editSide(base, r, "L", Math.floor(r() * 5));
      const R = editSide(base, r, "R", Math.floor(r() * 5));
      const ctx = () => `seed ${SEED} round ${round}\nbase=${JSON.stringify(base)}\nlocal=${JSON.stringify(L.lines)}\nremote=${JSON.stringify(R.lines)}`;
      const m = mergeText(text(base), text(L.lines), text(R.lines));
      // Determinism.
      const m2 = mergeText(text(base), text(L.lines), text(R.lines));
      expect(m2.ok, ctx()).toBe(m.ok);
      if (m.ok) expect(fromUtf8(m2.merged!), ctx()).toBe(fromUtf8(m.merged!));
      if (!m.ok) {
        conflicts++;
        // A conflict requires that both sides touched something; one idle side always merges cleanly.
        expect(L.touched.size + L.added.size > 0 && R.touched.size + R.added.size > 0, "conflict with an idle side: " + ctx()).toBe(true);
        continue;
      }
      clean++;
      const out = linesOf(m.merged!);
      const outSet = new Set(out);
      // Carried: every line either side added or wrote.
      for (const a of L.added) expect(outSet.has(a), `local addition ${a} lost: ${ctx()}\nmerged=${JSON.stringify(out)}`).toBe(true);
      for (const a of R.added) expect(outSet.has(a), `remote addition ${a} lost: ${ctx()}\nmerged=${JSON.stringify(out)}`).toBe(true);
      // Dropped: every line a side deleted or rewrote, when the other side left it alone.
      for (const d of L.removed) if (R.lines.includes(d)) expect(outSet.has(d), `local deletion of ${d} undone: ${ctx()}\nmerged=${JSON.stringify(out)}`).toBe(false);
      for (const d of R.removed) if (L.lines.includes(d)) expect(outSet.has(d), `remote deletion of ${d} undone: ${ctx()}\nmerged=${JSON.stringify(out)}`).toBe(false);
      // Kept: every base line both sides still have.
      for (const b of base) if (L.lines.includes(b) && R.lines.includes(b)) expect(outSet.has(b), `kept line ${b} lost: ${ctx()}\nmerged=${JSON.stringify(out)}`).toBe(true);
      // Nothing invented: every output line comes from one of the three inputs.
      for (const o of out) expect(base.includes(o) || L.lines.includes(o) || R.lines.includes(o), `invented line ${o}: ${ctx()}`).toBe(true);
      // Symmetry: swapping the sides merges to the same multiset of lines.
      const sw = mergeText(text(base), text(R.lines), text(L.lines));
      expect(sw.ok, "asymmetric: " + ctx()).toBe(true);
      expect([...linesOf(sw.merged!)].sort(), "asymmetric content: " + ctx()).toEqual([...out].sort());
    }
    // The generator produces both outcomes in quantity; a merge that always conflicted (or never) would prove nothing.
    expect(clean).toBeGreaterThan(ROUNDS / 4);
    expect(conflicts).toBeGreaterThan(ROUNDS / 20);
  });

  it("an idle side yields the other side exactly; identical sides yield themselves", () => {
    const r = rng(SEED ^ 0x5bd1e995);
    for (let round = 0; round < 500; round++) {
      const base = Array.from({ length: 1 + Math.floor(r() * 20) }, (_, i) => `b${i}`);
      const L = editSide(base, r, "L", 1 + Math.floor(r() * 6));
      const ctx = `seed ${SEED} round ${round} base=${JSON.stringify(base)} local=${JSON.stringify(L.lines)}`;
      const a = mergeText(text(base), text(L.lines), text(base));
      expect(a.ok, ctx).toBe(true);
      expect(linesOf(a.merged!), ctx).toEqual(L.lines);
      const b = mergeText(text(base), text(base), text(L.lines));
      expect(b.ok, ctx).toBe(true);
      expect(linesOf(b.merged!), ctx).toEqual(L.lines);
      const c = mergeText(text(base), text(L.lines), text(L.lines));
      expect(c.ok, ctx).toBe(true);
      expect(linesOf(c.merged!), ctx).toEqual(L.lines);
    }
  });

  it("arbitrary bytes never throw, and invalid UTF-8 is never merged", () => {
    const r = rng(SEED ^ 0x9e3779b9);
    for (let round = 0; round < 500; round++) {
      const buf = () => {
        const b = new Uint8Array(Math.floor(r() * 64));
        for (let i = 0; i < b.length; i++) b[i] = Math.floor(r() * 256);
        return b;
      };
      const [x, y, z] = [buf(), buf(), buf()];
      const m = mergeText(x, y, z);
      const valid = (b: Uint8Array) => {
        try {
          new TextDecoder("utf-8", { fatal: true }).decode(b);
          return true;
        } catch {
          return false;
        }
      };
      if (!(valid(x) && valid(y) && valid(z))) expect(m.ok).toBe(false);
      expect(() => mergeJson(x, y, z)).not.toThrow();
    }
  });
});

type J = null | boolean | number | string | J[] | { [k: string]: J };

function randomJson(r: () => number, depth: number): J {
  const t = r();
  if (depth <= 0 || t < 0.5) {
    const leaf = r();
    if (leaf < 0.25) return Math.floor(r() * 100);
    if (leaf < 0.5) return `s${Math.floor(r() * 100)}`;
    if (leaf < 0.7) return r() < 0.5;
    if (leaf < 0.8) return null;
    return Array.from({ length: Math.floor(r() * 3) }, () => Math.floor(r() * 10));
  }
  const o: { [k: string]: J } = {};
  const n = 1 + Math.floor(r() * 4);
  for (let i = 0; i < n; i++) o[`k${Math.floor(r() * 8)}`] = randomJson(r, depth - 1);
  return o;
}

/** All leaf paths of an object tree. */
function paths(v: J, prefix: string[] = []): string[][] {
  if (typeof v === "object" && v !== null && !Array.isArray(v)) {
    const out: string[][] = [];
    for (const k of Object.keys(v)) out.push(...paths(v[k], [...prefix, k]));
    return out.length ? out : [prefix];
  }
  return [prefix];
}
function get(v: J, p: string[]): J | undefined {
  let cur: J | undefined = v;
  for (const k of p) {
    if (typeof cur !== "object" || cur === null || Array.isArray(cur)) return undefined;
    cur = cur[k];
  }
  return cur;
}
function set(v: J, p: string[], val: J | undefined): J {
  if (p.length === 0) return val as J;
  const o = { ...(v as { [k: string]: J }) };
  if (p.length === 1) {
    if (val === undefined) delete o[p[0]];
    else o[p[0]] = val;
    return o;
  }
  o[p[0]] = set((o[p[0]] ?? {}) as J, p.slice(1), val);
  return o;
}

describe("mergeJson properties (seeded fuzz)", () => {
  const SEED = Number(process.env.MERGE_FUZZ_SEED ?? 20261107);

  it("disjoint key edits on the two sides all survive; the same key changed differently conflicts; the same change agrees", () => {
    const r = rng(SEED ^ 0x7f4a7c15);
    let clean = 0;
    for (let round = 0; round < 1500; round++) {
      const base = randomJson(r, 3);
      if (typeof base !== "object" || base === null || Array.isArray(base)) continue;
      const ps = paths(base);
      if (ps.length < 2) continue;
      // Pick disjoint paths for each side (no path a prefix of the other).
      const pick = (avoid: string[][]) => {
        for (let t = 0; t < 10; t++) {
          const p = ps[Math.floor(r() * ps.length)];
          if (!avoid.some((q) => q.join("/").startsWith(p.join("/")) || p.join("/").startsWith(q.join("/")))) return p;
        }
        return null;
      };
      const lp = pick([]);
      const rp = lp ? pick([lp]) : null;
      if (!lp || !rp) continue;
      const lv: J = `L${round}`;
      const rv: J | undefined = r() < 0.3 ? undefined : `R${round}`; // sometimes a deletion
      const local = set(base, lp, lv);
      const remote = set(base, rp, rv);
      const enc = (v: J) => utf8(JSON.stringify(v, null, 2) + "\n");
      const ctx = `seed ${SEED} round ${round}\nbase=${JSON.stringify(base)}\nlocal=${JSON.stringify(local)}\nremote=${JSON.stringify(remote)}`;
      const m = mergeJson(enc(base), enc(local), enc(remote));
      expect(m.ok, ctx).toBe(true);
      const out = JSON.parse(fromUtf8(m.merged!)) as J;
      expect(get(out, lp), "local edit lost: " + ctx).toEqual(lv);
      expect(get(out, rp), "remote edit lost: " + ctx).toEqual(rv);
      // Every untouched leaf is kept.
      for (const p of ps) {
        const touched = (q: string[]) => p.join("/").startsWith(q.join("/")) || q.join("/").startsWith(p.join("/"));
        if (!touched(lp) && !touched(rp)) expect(get(out, p), `untouched ${p.join(".")} changed: ${ctx}`).toEqual(get(base, p));
      }
      // Symmetric.
      const sw = mergeJson(enc(base), enc(remote), enc(local));
      expect(sw.ok, ctx).toBe(true);
      expect(JSON.parse(fromUtf8(sw.merged!)), ctx).toEqual(out);
      // Same key, different values: a conflict. Same key, same value: agreement.
      const c1 = mergeJson(enc(base), enc(set(base, lp, "X")), enc(set(base, lp, "Y")));
      expect(c1.ok, "conflict not detected: " + ctx).toBe(false);
      const c2 = mergeJson(enc(base), enc(set(base, lp, "X")), enc(set(base, lp, "X")));
      expect(c2.ok, "agreement rejected: " + ctx).toBe(true);
      expect(get(JSON.parse(fromUtf8(c2.merged!)) as J, lp), ctx).toEqual("X");
      clean++;
    }
    expect(clean).toBeGreaterThan(300);
  });
});
