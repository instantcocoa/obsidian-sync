/** Throwaway round-two verification probe (delete after review). */
import { afterAll, beforeAll, describe, it } from "vitest";
import { promises as fsp } from "node:fs";
import { join, resolve } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink } from "../src/core/admin";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const exists = (p: string) => fsp.stat(p).then(() => true, () => false);
const read = (p: string) => fsp.readFile(p, "utf8").catch(() => null);

/** Post an op from device `a` for `metaPath` (keyed by `idPath`); optionally store an undecryptable blob under the real id. */
async function craft(a: Device, idPath: string, metaPath: string, content: string, opts: { garbageBlob?: boolean } = {}) {
  const s = a.session;
  const v = s.identity.vaultId;
  const bytes = utf8(content);
  const bid = await s.vc.blobId(bytes);
  let ct = await s.vc.encryptBlob(bid, bytes);
  if (opts.garbageBlob) {
    ct = new Uint8Array(ct.length);
    ct[0] = 1;
    ct[1] = s.vc.keyring.current;
  }
  await s.client.putBlob(v, bid, ct, { replace: true });
  const pid = await s.vc.pathId(idPath);
  const meta = { path: metaPath, mtime: Date.now(), size: bytes.length };
  const res = await s.client.postOps(v, [{ op_id: "p3-" + Math.random().toString(16).slice(2), path_id: pid, blob_id: bid, meta_enc: await s.vc.encryptMeta(pid, meta), meta_epoch: s.vc.keyring.current, base_seq: 0 }]);
  return res.results[0];
}

async function trySync(d: Device): Promise<string> {
  try {
    await d.sync();
    return "ok";
  } catch (e) {
    return String((e as Error).message).slice(0, 90);
  }
}

async function pair(): Promise<[Device, Device]> {
  const sa = await createVault(srv.url, ADMIN, "author");
  const sb = await joinWithLink(await createInviteLink(sa), "other");
  return [await new Device("author", sa).start(), await new Device("other", sb).start()];
}

describe("probe3", () => {
  it("(5) path aliases", async () => {
    const [a, b] = await pair(); // b has DEFAULT_EXCLUSIONS incl. /$CONFIG/plugins/obsync/ and /$CONFIG/workspace.json
    const cases: Record<string, string> = {
      caseFirstSeg: ".Obsidian/plugins/x/main.js",
      trailingDot: ".obsidian./plugins/x/main.js",
      trailingSpace: ".obsidian /plugins/x/main.js",
      shortName: "OBSIDI~1/plugins/x/main.js",
      reserved: "notes/con.md",
      nfd: "notes/café.md",
      deeperCase_selfExclusion: "$CONFIG/plugins/Obsync/pwn.js",
      deeperCase_userExclusion: "$CONFIG/Workspace.json",
      longComponent: "notes/" + "x".repeat(300) + ".md",
      unicodeCase: ".OBSİDIAN/plugins/x/main.js",
    };
    for (const [k, p] of Object.entries(cases)) await craft(a, p, p, k);
    await a.write("after.md", "after\n");
    const sa = await trySync(a);
    const sb = await trySync(b);
    const out: Record<string, unknown> = { authorSync: sa, victimSync: sb, cursor: b.engine.state.cursor };
    for (const [k, p] of Object.entries(cases)) out[k] = await exists(join(b.dir, p.replace(/^\$CONFIG/, ".obsidian").normalize("NFC")));
    out.nfdAsNFD = await exists(join(b.dir, cases.nfd));
    out.afterArrived = await exists(join(b.dir, "after.md"));
    out.refused = b.logs.filter((l) => /unsafe or mismatched/.test(l)).length;
    out.skipped = b.logs.filter((l) => /could not be applied/.test(l)).length;
    console.log("PROBE3 PATHS", JSON.stringify(out, null, 1));
    await a.cleanup();
    await b.cleanup();
  }, 120_000);

  it("(4) garbage blob + long path: skip, keep moving, heal with reupload; and the push/conflict path", async () => {
    const [a, b] = await pair();
    await a.write("p.md", "good content\n");
    await craft(a, "p.md", "p.md", "good content\n", { garbageBlob: true }); // author's own file, server copy is garbage
    await craft(a, "notes/" + "y".repeat(300) + ".md", "notes/" + "y".repeat(300) + ".md", "long");
    await a.write("flow.md", "flows\n");
    const r1 = { authorSync: await trySync(a), victimSync: await trySync(b), cursor1: b.engine.state.cursor, flowArrived: await exists(join(b.dir, "flow.md")), pOnVictim: await read(join(b.dir, "p.md")), skipped: b.logs.filter((l) => /could not be applied/.test(l)).length };
    // Victim now edits the poisoned path locally before any repair: does push wedge?
    await b.write("p.md", "victim edit\n");
    await b.write("flow2.md", "flows2\n");
    const r2 = { victimSyncAfterLocalEdit: await trySync(b), victimSyncAgain: await trySync(b), flow2OnAuthor: (await trySync(a), await exists(join(a.dir, "flow2.md"))), victimDirty: b.engine.getStatus().pending };
    // Repair from the author.
    let heal = "ok";
    try {
      await a.engine.reupload("p.md");
    } catch (e) {
      heal = String((e as Error).message).slice(0, 90);
    }
    const r3 = { reupload: heal, authorSync: await trySync(a), victimSync: await trySync(b), pOnVictim: await read(join(b.dir, "p.md")), pOnAuthor: await read(join(a.dir, "p.md")), conflicts: b.conflicts.length, cursorAdvanced: b.engine.state.cursor > r1.cursor1 };
    console.log("PROBE3 SKIP", JSON.stringify({ r1, r2, r3 }, null, 1));
    await a.cleanup();
    await b.cleanup();
  }, 120_000);
});
