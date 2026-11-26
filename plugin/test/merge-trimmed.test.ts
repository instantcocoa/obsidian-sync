/**
 * Found in CI (2026-11-25): review14 F6, a three-way merge of a 250,000-line
 * note where each side changed one line, took 63 s on a laptop and 166 s on a
 * runner, because node-diff3's LCS is quadratic in the file. mergeText now
 * diffs only the lines between the first and last difference of each pair.
 * The old call is kept here as the reference: the results must be identical.
 */
import { describe, expect, it } from "vitest";
import { diff3MergeRegions } from "node-diff3";
import { mergeText } from "../src/core/merge";
import { fromUtf8, utf8 } from "../src/core/encoding";

/** mergeText as it was before: the library's regions over whole files. */
function reference(base: string, local: string, remote: string): string | null {
  const lines = (s: string) => s.split("\n").map((x) => (x.endsWith("\r") ? x.slice(0, -1) : x));
  const out: string[] = [];
  for (const r of diff3MergeRegions(lines(local), lines(base), lines(remote))) {
    let take: string[];
    if (r.stable) take = r.bufferContent;
    else if (r.aContent.length === r.bContent.length && r.aContent.every((x, i) => x === r.bContent[i])) take = r.aContent;
    else return null;
    for (const l of take) out.push(l);
  }
  return out.join("\n");
}

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32);
}

function scenario(r: () => number, gen: () => string) {
  const base = Array.from({ length: Math.floor(r() * 24) }, gen);
  const edit = (src: string[]) => {
    const out = src.slice();
    for (let k = Math.floor(r() * 4); k > 0; k--) {
      const at = Math.floor(r() * (out.length + 1));
      const roll = r();
      if (roll < 0.34) out.splice(at, 0, gen());
      else if (roll < 0.67) out.splice(at, Math.floor(r() * 3));
      else if (at < out.length) out[at] = gen();
    }
    return out;
  };
  return { base: base.join("\n"), local: edit(base).join("\n"), remote: edit(base).join("\n") };
}

describe("mergeText over trimmed diffs", () => {
  it("agrees with the library's diff3MergeRegions on random edits of a note whose lines differ", () => {
    const r = rng(7);
    let id = 0;
    let merged = 0;
    let refused = 0;
    for (let n = 0; n < 4000; n++) {
      const { base, local, remote } = scenario(r, () => `u${id++}`);
      const want = reference(base, local, remote);
      const got = mergeText(utf8(base), utf8(local), utf8(remote));
      const why = JSON.stringify({ base, local, remote });
      if (want === null) {
        expect(got.ok, why).toBe(false);
        refused++;
      } else {
        expect(got.ok, why).toBe(true);
        expect(fromUtf8(got.merged!), why).toBe(want);
        merged++;
      }
    }
    expect(merged).toBeGreaterThan(500);
    expect(refused).toBeGreaterThan(500);
  });

  it("with many repeated lines, where the alignment of an edit is ambiguous, a one-sided or identical change still merges to exactly that side", () => {
    // Where the same line occurs many times the library and the trimmed diff
    // may place an insertion or deletion at different copies (about 3 % of
    // cases differ, in both directions, in a random sample); either is a
    // valid alignment. What must hold regardless:
    const r = rng(11);
    for (let n = 0; n < 3000; n++) {
      const alphabet = 1 + Math.floor(r() * 4);
      const { base, local, remote } = scenario(r, () => `l${Math.floor(r() * alphabet)}`);
      const why = JSON.stringify({ base, local, remote });
      const [b, l, rm] = [utf8(base), utf8(local), utf8(remote)];
      const onlyRemote = mergeText(b, b, rm);
      expect(onlyRemote.ok, why).toBe(true);
      expect(fromUtf8(onlyRemote.merged!), why).toBe(remote);
      const onlyLocal = mergeText(b, l, b);
      expect(onlyLocal.ok, why).toBe(true);
      expect(fromUtf8(onlyLocal.merged!), why).toBe(local);
      const same = mergeText(b, l, l);
      expect(same.ok, why).toBe(true);
      expect(fromUtf8(same.merged!), why).toBe(local);
    }
  });

  it("merges a 250,000-line note edited at both ends in seconds, not minutes", () => {
    const lines = 250_000;
    const base = Array.from({ length: lines }, (_, i) => `line ${i} lorem ipsum dolor sit amet`);
    const ea = base.slice();
    ea[5] = "edited on laptop";
    const eb = base.slice();
    eb[lines - 5] = "edited on phone";
    const enc = (a: string[]) => utf8(a.join("\n") + "\n");
    const t0 = Date.now();
    const m = mergeText(enc(base), enc(eb), enc(ea));
    const took = Date.now() - t0;
    expect(m.ok).toBe(true);
    const want = base.slice();
    want[5] = "edited on laptop";
    want[lines - 5] = "edited on phone";
    expect(Buffer.compare(Buffer.from(m.merged!), Buffer.from(enc(want)))).toBe(0);
    expect(took, `took ${took} ms`).toBeLessThan(5000);
  }, 60_000);
});
