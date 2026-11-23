/** The helpers behind the conflict review dialog: naming round trip and the line comparison. */
import { describe, expect, it } from "vitest";
import { conflictOrigin, conflictPath, lineDiff } from "../src/core/paths";

describe("conflict copies: origin and comparison", () => {
  it("conflictOrigin inverts conflictPath, ordinals, folders, dotted names and no extension included", () => {
    const when = new Date(2026, 10, 23, 14, 5);
    for (const p of ["a.md", "notes/deep/a b.md", "archive.tar.gz", "Makefile", "x/y.z/file", ".obsidian/app.json"]) {
      for (const n of [1, 2, 17]) {
        const sib = conflictPath(p, "Eric's phone", when, n);
        expect(conflictOrigin(sib)).toEqual({ original: p, device: "Eric's phone", when: "2026-11-23 14:05" });
      }
    }
    // A conflict on a conflict copy points at the copy it came from.
    const first = conflictPath("a.md", "laptop", when);
    expect(conflictOrigin(conflictPath(first, "phone", when))!.original).toBe(first);
    for (const p of ["a.md", "a (conflict).md", "a (conflict laptop).md", "notes/(conflict laptop 2026-11-23 1405).md x"]) expect(conflictOrigin(p)).toBeNull();
  });

  it("lineDiff reports what each side has that the other lacks, counting duplicates, ignoring line endings", () => {
    expect(lineDiff("a\nb\nc\n", "a\nb\nc\n")).toEqual({ onlyA: [], onlyB: [] });
    expect(lineDiff("a\r\nb\r\n", "a\nb\n")).toEqual({ onlyA: [], onlyB: [] });
    expect(lineDiff("title\nmine\nshared\n", "title\ntheirs\nshared\nextra\n")).toEqual({ onlyA: ["mine"], onlyB: ["theirs", "extra"] });
    expect(lineDiff("x\nx\ny", "x\ny")).toEqual({ onlyA: ["x"], onlyB: [] });
    expect(lineDiff("b\na", "a\nb")).toEqual({ onlyA: [], onlyB: [] });
  });
});
