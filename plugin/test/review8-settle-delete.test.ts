/**
 * Eighth review (2026-11-07): the seventh round made `settle()` rebase on
 * an inconsistent conflict head as if it were a tombstone and re-mark the
 * path dirty, so the next push supersedes the bad row. That is right for a
 * local *edit*. For a local *delete* (`p.bytes` undefined) the same move is a
 * no-op: the state becomes `{hash: null, seq: head.seq}` with no file on
 * disk, `prepareLocalOp` answers "nothing to delete", `dirty` is cleared,
 * and the member's inconsistent row stays the server's head. Every other
 * device skipped that row and still shows the file; the deleting device does
 * not. The vault no longer converges, and a device joining later gets the
 * file back from the last good op.
 *
 * Precondition: one member (or a stolen invite) posts one inconsistent op.
 * Fails on HEAD (93275e9).
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
async function inconsistentPut(s: Session, path: string, baseSeq: number): Promise<number> {
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
  return r.results[0].seq!;
}

async function head(s: Session, path: string): Promise<{ seq: number; blob_id: string | null } | undefined> {
  const pid = await s.vc.pathId(path);
  const snap = await s.client.snapshot(s.identity.vaultId, { since: 0, limit: 500 });
  const o = snap.ops.find((o) => o.path_id === pid);
  return o && { seq: o.seq, blob_id: o.blob_id };
}

describe("an inconsistent head swallows an honest delete", () => {
  it("the deleting device gives up, the bad row stays head, the bystander keeps the file", async () => {
    const sa = await createVault(srv.url, ADMIN, "honest");
    const sb = await joinWithLink(await createInviteLink(sa), "attacker");
    const sc = await joinWithLink(await createInviteLink(sa), "bystander");
    const a = await new Device("honest", sa).start();
    const b = await new Device("attacker", sb).start();
    const c = await new Device("bystander", sc).start();
    try {
      await a.rawWrite("shared.md", utf8("v1\n"));
      await a.sync();
      await b.sync();
      await c.sync();
      const base = b.engine.state.files["shared.md"].seq;
      const badSeq = await inconsistentPut(b.session, "shared.md", base);

      // The honest user deletes the note and syncs as often as a patient user would.
      await a.remove("shared.md");
      for (let i = 0; i < 4; i++) await a.sync();

      // The delete must have superseded the inconsistent row (a tombstone newer than it)...
      const h = await head(a.session, "shared.md");
      expect(h, a.logs.filter((l) => /inconsistent/.test(l)).slice(0, 2).join("\n")).toBeDefined();
      expect(h!.seq, `head is still the attacker's row (seq ${badSeq})`).toBeGreaterThan(badSeq);
      expect(h!.blob_id).toBeNull();

      // ...so that the bystander converges on "gone", not on v1 behind a skipped op.
      await c.sync();
      await c.sync();
      expect(await c.exists("shared.md")).toBe(false);
    } finally {
      await a.cleanup();
      await b.cleanup();
      await c.cleanup();
    }
  });
});
