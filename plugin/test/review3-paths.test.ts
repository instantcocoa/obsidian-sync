/**
 * Regression tests from the third adversarial review (2026-11-07; guide
 * area D, client-side path safety). A vault member holds K_e and can post
 * any op; the receiving device's validation is the only thing between that
 * op and its disk. Each was written as a proof that failed against the code
 * of the day and now pins the fix: a logical path that spells the config
 * directory literally, or in any spelling a case-insensitive volume folds
 * to it, is refused before any `$CONFIG` rule is consulted.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";
import { DEFAULT_EXCLUSIONS, aliasesConfigDir, compileExclusions, isSafeLogicalPath, logicalAliasesConfigDir } from "../src/core/paths";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

/** Does this machine's temp volume treat `alias` as the same directory as `.obsidian`? */
function volumeAliases(alias: string): boolean {
  const d = mkdtempSync(join(tmpdir(), "obsync-fold-"));
  try {
    mkdirSync(join(d, ".obsidian"));
    writeFileSync(join(d, ".obsidian", "marker"), "x");
    return existsSync(join(d, alias, "marker"));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

/** Craft an op the way a malicious member would: valid ciphertext, honest path_id for `path`. */
async function evilPut(s: Session, path: string, content: string): Promise<void> {
  const { vc, client, identity } = s;
  const payload = utf8(content);
  const bid = await vc.blobId(payload);
  await client.putBlob(identity.vaultId, bid, await vc.encryptBlob(bid, payload));
  const pid = await vc.pathId(path);
  const r = await client.postOps(identity.vaultId, [
    {
      op_id: Math.random().toString(16).slice(2).padEnd(24, "0"),
      path_id: pid,
      blob_id: bid,
      meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: payload.length }),
      meta_epoch: vc.keyring.current,
      base_seq: 0,
    },
  ]);
  expect(r.results[0].seq ?? 0).toBeGreaterThan(0);
}

async function pair(victimOpts: ConstructorParameters<typeof Device>[2] = {}): Promise<[Device, Device]> {
  const sa = await createVault(srv.url, ADMIN, "attacker");
  const link = await createInviteLink(sa);
  const sb = await joinWithLink(link, "victim");
  const a = await new Device("attacker", sa).start();
  const b = await new Device("victim", sb, victimOpts).start();
  return [a, b];
}

describe("the literal config-dir name is not mapped to $CONFIG and so bypasses every $CONFIG rule", () => {
  it("unit: '.obsidian/…' passes isSafeLogicalPath and aliasesConfigDir and matches no $CONFIG exclusion", () => {
    const p = ".obsidian/plugins/obsync/main.js";
    expect(isSafeLogicalPath(p)).toBe(true);
    expect(aliasesConfigDir(p, ".obsidian")).toBe(false);
    // Default exclusions protect "$CONFIG/plugins/obsync/" but not the same directory spelled literally.
    expect(compileExclusions(DEFAULT_EXCLUSIONS)("$CONFIG/plugins/obsync/main.js")).toBe(true);
    // The literal spelling is refused by the applier before any exclusion is consulted.
    expect(logicalAliasesConfigDir(p, ".obsidian")).toBe(true);
    expect(logicalAliasesConfigDir("$CONFIG/plugins/obsync/main.js", ".obsidian")).toBe(false);
    expect(logicalAliasesConfigDir(".obſidian/x", ".obsidian")).toBe(true);
  });

  it("e2e: a member overwrites the victim's obsync plugin although $CONFIG/plugins/obsync/ is excluded", async () => {
    const [a, b] = await pair();
    await a.write("note.md", "hello\n");
    await a.sync();
    await b.sync();
    await evilPut(a.session, ".obsidian/plugins/obsync/main.js", "// pwned\n");
    const refused: string[] = [];
    b.engine["hooks"].onSkipped = (p: string) => refused.push(p);
    await b.sync();
    expect(existsSync(join(b.dir, ".obsidian/plugins/obsync/main.js"))).toBe(false);
    expect(refused).toEqual([".obsidian/plugins/obsync/main.js"]);
    await a.cleanup();
    await b.cleanup();
  });

  it("e2e: with 'sync config folder' off (/$CONFIG/ excluded) a member still writes into the victim's config dir", async () => {
    const [a, b] = await pair({ exclusions: [...DEFAULT_EXCLUSIONS, "/$CONFIG/"] });
    await a.write("note.md", "hello\n");
    await a.sync();
    await b.sync();
    // The honest spelling is excluded on B, as the setting promises...
    await evilPut(a.session, "$CONFIG/community-plugins.json", '["honest-spelling"]');
    // ...the literal spelling is not.
    await evilPut(a.session, ".obsidian/community-plugins.json", '["evil-plugin"]');
    await b.sync();
    expect(existsSync(join(b.dir, ".obsidian/community-plugins.json"))).toBe(false);
    await a.cleanup();
    await b.cleanup();
  });
});

describe("aliasesConfigDir's fold() misses case-insensitive volumes' real folding", () => {
  // U+017F LATIN SMALL LETTER LONG S: toLowerCase() leaves it alone, but
  // Unicode case folding (and APFS/NTFS) map it to "s".
  const alias = ".obſidian";

  it("unit: on this volume '.obſidian' IS '.obsidian' but aliasesConfigDir says no", () => {
    if (!volumeAliases(alias)) return; // case-sensitive volume: not reachable here
    expect(aliasesConfigDir(alias + "/plugins/evil/main.js", ".obsidian")).toBe(true);
  });

  it("e2e: a member plants a plugin in the victim's real config dir through the alias", async () => {
    if (!volumeAliases(alias)) return;
    const [a, b] = await pair();
    await a.write("note.md", "hello\n");
    await a.sync();
    await b.sync();
    await evilPut(a.session, alias + "/plugins/evil/main.js", "// evil\n");
    await b.sync();
    expect(existsSync(join(b.dir, ".obsidian/plugins/evil/main.js"))).toBe(false);
    await a.cleanup();
    await b.cleanup();
  });
});
