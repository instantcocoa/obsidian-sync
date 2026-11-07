/**
 * Property the sixth review asked a human to check on a real NTFS volume,
 * made a test that runs on every CI platform instead: `fold()` must be at
 * least as aggressive as the volume this test runs on. For every pair of
 * spellings below, if the file system treats them as one entry, `foldClash`
 * must say so too; otherwise an exclusion or clash check could be sidestepped
 * by the spelling the volume folds but we do not. The reverse (we fold, the
 * volume does not) only over-excludes, which is safe, and is reported rather
 * than failed so the log shows what each volume does.
 */
import { describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fold, foldClash } from "../src/core/paths";

const PAIRS: [string, string, string][] = [
  ["obsync", "Obsync", "ASCII case"],
  ["obsync", "obſync", "U+017F long s"],
  ["kelvin", "Kelvin", "U+212A Kelvin sign"],
  ["strasse", "straße", "U+00DF sharp s"],
  ["istanbul", "İstanbul", "U+0130 dotted capital I"],
  ["café", "café", "NFC vs NFD"],
  ["ﬁle", "file", "U+FB01 fi ligature"],
  ["angstrom", "ångstrom".replace("å", "Å"), "U+212B Angstrom sign vs a"],
  ["fullwidth", "ｆullwidth", "U+FF46 fullwidth f"],
];

function volumeFolds(real: string, alias: string): boolean {
  const d = mkdtempSync(join(tmpdir(), "obsync-fold-"));
  try {
    mkdirSync(join(d, real));
    writeFileSync(join(d, real, "marker"), "x");
    return existsSync(join(d, alias, "marker"));
  } catch {
    return false;
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

describe(`fold() is at least as aggressive as this volume (${process.platform})`, () => {
  const report: string[] = [];
  for (const [a, b, what] of PAIRS) {
    it(`${what}: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`, () => {
      const vol = volumeFolds(a, b);
      const ours = foldClash(a, b) || a.normalize("NFC") === b.normalize("NFC");
      report.push(`${what}: volume=${vol} fold=${ours} (${fold(a)} / ${fold(b)})`);
      if (vol) expect(ours, `the volume treats ${a} and ${b} as one entry but fold() does not`).toBe(true);
    });
  }
  it("prints what this volume does", () => {
    console.info(`fold probe on ${process.platform}:\n  ` + report.join("\n  "));
  });
});
