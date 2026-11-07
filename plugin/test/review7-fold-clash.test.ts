/**
 * Seventh review (2026-11-07): the sixth round's fold-clash refusal
 * (node-fs.ts `refuseFoldClash`, obsidian-fs.ts `refuseCaseClash` via
 * `spelledAs`) reuses `fold()` — NFKC, both case directions, combining marks
 * stripped — which was designed for `aliasesConfigDir`, where over-matching
 * is harmless. For a write refusal over-matching is not harmless: every pair
 * of names `fold()` equates but the volume keeps apart is a legitimate file
 * that can never arrive on a Mac or Windows device.
 *
 * Measured on this machine's APFS volume (see `distinctOnVolume`):
 *   café.md / cafe.md     DISTINCT   fold() says clash  → refused (wrong)
 *   Ärger.md / Arger.md   DISTINCT   fold() says clash  → refused (wrong)
 *   straße.md / strasse.md SAME      fold() says clash  → refused (right)
 *   ﬁle.md / file.md       SAME      fold() says clash  → refused (right)
 *
 * A second, more common casualty: the refusal now walks every parent
 * folder. A case-only *folder* rename (Notes → notes) reaches other devices
 * as delete + put per file; the delete leaves the empty folder behind under
 * its old spelling, and every put under the new spelling is then refused.
 *
 * Both tests fail on HEAD (16dba52) on a case-insensitive volume and skip
 * themselves on a case-sensitive one.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync, promises as fsp } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink } from "../src/core/admin";
import { foldClash } from "../src/core/paths";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

/** Does the temp volume answer for "note" when only "Note" exists? */
function volumeIgnoresCase(): boolean {
  const d = mkdtempSync(join(tmpdir(), "obsync-r7-"));
  try {
    mkdirSync(join(d, "Note"));
    return existsSync(join(d, "note"));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

/** Can `a` and `b` coexist as two files in one folder on this volume? */
function distinctOnVolume(a: string, b: string): boolean {
  const d = mkdtempSync(join(tmpdir(), "obsync-r7-"));
  try {
    writeFileSync(join(d, a), "A");
    writeFileSync(join(d, b), "B");
    return readdirSync(d).length === 2;
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

async function pair(): Promise<[Device, Device]> {
  const sa = await createVault(srv.url, ADMIN, "linux");
  const link = await createInviteLink(sa);
  const sb = await joinWithLink(link, "mac");
  const a = await new Device("linux", sa).start();
  const b = await new Device("mac", sb).start();
  return [a, b];
}

describe("the fold-clash refusal refuses names the volume keeps apart", () => {
  it("two notes differing only by an accent both exist on this volume, but the second never arrives", async () => {
    if (!volumeIgnoresCase()) return;
    // The volume's own verdict: these are two files.
    expect(distinctOnVolume("café.md", "cafe.md")).toBe(true);
    expect(distinctOnVolume("Ärger.md", "Arger.md")).toBe(true);
    // fold()'s verdict: the same name. This is the disagreement under test.
    expect(foldClash("café.md", "cafe.md")).toBe(true);

    const [a, b] = await pair();
    try {
      // User's editor on A, not the plugin's fs (which would refuse too).
      await a.rawWrite("notes/café.md", utf8("with accent\n"));
      await a.rawWrite("notes/cafe.md", utf8("without\n"));
      await a.rawWrite("notes/Ärger.md", utf8("umlaut\n"));
      await a.rawWrite("notes/Arger.md", utf8("plain\n"));
      await a.sync();
      await b.sync();
      await b.sync();
      const files = await b.files();
      expect(files, b.logs.filter((l) => /already exists/.test(l)).join("\n")).toEqual(expect.arrayContaining(["notes/café.md", "notes/cafe.md", "notes/Ärger.md", "notes/Arger.md"]));
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });

  it("a case-only folder rename on one device leaves every file in the folder refused on the other", async () => {
    if (!volumeIgnoresCase()) return;
    const [a, b] = await pair();
    try {
      await a.rawWrite("Notes/a.md", utf8("one\n"));
      await a.rawWrite("Notes/b.md", utf8("two\n"));
      await a.sync();
      await b.sync();
      expect(await b.read("Notes/a.md")).toBe("one\n");

      // The rename as it reaches the wire from any device: the old names are
      // deleted (the folder they were in stays behind, as Obsidian leaves
      // empty folders alone), then the files appear under the new spelling.
      await fsp.rm(join(a.dir, "Notes"), { recursive: true, force: true });
      await a.sync(); // deletes
      await b.sync();
      expect(await b.exists("Notes/a.md")).toBe(false);
      expect(existsSync(join(b.dir, "Notes"))).toBe(true); // the empty folder lingers, as on a real device

      await a.rawWrite("notes/a.md", utf8("one\n"));
      await a.rawWrite("notes/b.md", utf8("two\n"));
      await a.sync(); // puts under the new spelling
      await b.sync();
      await b.sync();
      const files = await b.files();
      expect(files, b.logs.filter((l) => /already exists/.test(l)).join("\n")).toEqual(expect.arrayContaining(["notes/a.md", "notes/b.md"]));
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });
});
