/**
 * Seventh review (2026-11-07): the sixth round taught `settle()` to refuse a
 * conflict head whose authenticated metadata names another blob than the
 * row (or another path). The applier already refused such an op, so the
 * refusal itself is consistent. What it does afterwards is not: the local
 * file is dropped from `dirty` without adopting the head's seq as its base,
 * so the next scan marks it dirty again, the push carries the same stale
 * base_seq, the server answers with the same head, and `settle()` refuses
 * it again. The honest edit never reaches the server; every other device
 * keeps the attacker's row as the path's head.
 *
 * Before the sixth round the inconsistent head was resolved against (the
 * attacker's bytes were written and the honest copy became a sibling) and
 * the sibling's push healed the path. Both behaviours are wrong; the right
 * one is "an inconsistent head loses": take its seq as the base and push
 * the honest bytes over it, which is exactly what the manual repair
 * (`reupload`) does.
 *
 * Precondition: one member with the keys (or a stolen invite) posts one op.
 * Both tests fail on HEAD (16dba52).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const opId = () => Math.random().toString(16).slice(2).padEnd(24, "0");

/** A member posts an op for `path` whose row names blob X while its authenticated metadata names blob Y. */
async function inconsistentPut(s: Session, path: string, baseSeq: number): Promise<string> {
  const { vc, client, identity } = s;
  const x = utf8("attacker bytes for " + path);
  const bidX = await vc.blobId(x);
  await client.putBlob(identity.vaultId, bidX, await vc.encryptBlob(bidX, x));
  const bidY = await vc.blobId(utf8("some other blob"));
  const pid = await vc.pathId(path);
  const r = await client.postOps(identity.vaultId, [
    { op_id: opId(), path_id: pid, blob_id: bidX, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: x.length, blob: bidY }), meta_epoch: vc.keyring.current, base_seq: baseSeq },
  ]);
  expect(r.results[0].seq ?? 0).toBeGreaterThan(0);
  return bidX;
}

async function headBlob(s: Session, path: string): Promise<string | null | undefined> {
  const pid = await s.vc.pathId(path);
  const snap = await s.client.snapshot(s.identity.vaultId, { since: 0, limit: 500 });
  return snap.ops.find((o) => o.path_id === pid)?.blob_id;
}

async function trio(): Promise<[Device, Device, Device]> {
  const sa = await createVault(srv.url, ADMIN, "honest");
  const sb = await joinWithLink(await createInviteLink(sa), "attacker");
  const sc = await joinWithLink(await createInviteLink(sa), "bystander");
  return [await new Device("honest", sa).start(), await new Device("attacker", sb).start(), await new Device("bystander", sc).start()];
}

describe("an inconsistent head freezes the path for every honest writer", () => {
  it("a note the honest device already had: its edit is pushed, refused, re-marked dirty, refused… and never lands", async () => {
    const [a, b, c] = await trio();
    try {
      await a.rawWrite("shared.md", utf8("v1\n"));
      await a.sync();
      await b.sync();
      await c.sync();
      const base = (b.engine.state.files["shared.md"] ?? { seq: 0 }).seq;
      const bad = await inconsistentPut(b.session, "shared.md", base);

      // Honest edit on A, then as many sync rounds as a patient user would give it.
      await a.rawWrite("shared.md", utf8("v2 honest edit\n"));
      for (let i = 0; i < 4; i++) await a.sync();
      const want = await a.session.vc.blobId(utf8("v2 honest edit\n"));
      expect(await headBlob(a.session, "shared.md"), a.logs.filter((l) => /inconsistent/.test(l)).slice(0, 2).join("\n")).toBe(want);

      // And the bystander ends up with the honest edit, not stuck on v1 behind a skipped op.
      await c.sync();
      await c.sync();
      expect(await c.read("shared.md")).toBe("v2 honest edit\n");
      expect(bad).not.toBe(want);
    } finally {
      await a.cleanup();
      await b.cleanup();
      await c.cleanup();
    }
  });

  it("a note the honest device never saw: creating it locally is frozen the same way", async () => {
    const [a, b, c] = await trio();
    try {
      await a.sync();
      await b.sync();
      await inconsistentPut(b.session, "new-note.md", 0);
      await a.sync(); // A pulls the op, skips it (correct), records nothing for the path
      await a.rawWrite("new-note.md", utf8("mine\n"));
      for (let i = 0; i < 4; i++) await a.sync();
      expect(await headBlob(a.session, "new-note.md"), a.logs.filter((l) => /inconsistent/.test(l)).slice(0, 2).join("\n")).toBe(await a.session.vc.blobId(utf8("mine\n")));
    } finally {
      await a.cleanup();
      await b.cleanup();
      await c.cleanup();
    }
  });
});
