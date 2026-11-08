/**
 * Ninth review (2026-11-07): the eighth round's `settle()` fix for an
 * inconsistent conflict head rebases a local *delete* with
 * `hash = r.conflict.blob_id`, so the next scan "finds the file gone" and
 * pushes the delete against the bad head. That only works while the bad
 * head is a *put*. When the member's inconsistent row is itself a tombstone
 * (`blob_id null`, metadata naming a blob or another path), the rebase sets
 * `hash: null` again, `prepareLocalOp` answers "nothing to delete", `dirty`
 * is cleared, and the bad row stays head: the same "delete it on this
 * device only" that review 8 finding 1 described, through the half of the
 * case the fix did not cover. Fails on HEAD (5a88779).
 *
 * The second test is soundness for the half it did cover (passes): a bad
 * *put* head, the file recreated with new content before the next scan, is
 * pushed on top of the head.
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

/** A member posts a tombstone whose authenticated metadata names a blob: inconsistent, skipped by every applier. */
async function inconsistentTombstone(s: Session, path: string, baseSeq: number): Promise<number> {
  const { vc, client, identity } = s;
  const bidY = await vc.blobId(utf8("some other blob"));
  const pid = await vc.pathId(path);
  const r = await client.postOps(identity.vaultId, [
    { op_id: opId(), path_id: pid, blob_id: null, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: 0, blob: bidY }), meta_epoch: vc.keyring.current, base_seq: baseSeq },
  ]);
  expect(r.results[0].seq ?? 0, JSON.stringify(r.results[0])).toBeGreaterThan(0);
  return r.results[0].seq!;
}

/** A member posts a put whose row names blob X while its metadata names blob Y. */
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
  const o = snap.ops.filter((o) => o.path_id === pid).at(-1);
  return o && { seq: o.seq, blob_id: o.blob_id };
}

describe("an inconsistent *tombstone* head still swallows an honest delete", () => {
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
      const badSeq = await inconsistentTombstone(b.session, "shared.md", base);

      await a.remove("shared.md");
      for (let i = 0; i < 4; i++) await a.sync();

      const h = await head(a.session, "shared.md");
      expect(h).toBeDefined();
      expect(h!.seq, `head is still the attacker's row (seq ${badSeq}); logs: ${a.logs.filter((l) => /inconsistent/.test(l)).slice(0, 2).join(" | ")}`).toBeGreaterThan(badSeq);
      expect(h!.blob_id).toBeNull();

      await c.sync();
      await c.sync();
      expect(await c.exists("shared.md")).toBe(false);
    } finally {
      await a.cleanup();
      await b.cleanup();
      await c.cleanup();
    }
  });

  it("(soundness) bad put head, file recreated with new content before the next scan: the new content is pushed on top", async () => {
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
      const badSeq = await inconsistentPut(b.session, "shared.md", b.engine.state.files["shared.md"].seq);

      // The user deletes the note; the push meets the bad head; before the
      // next round the user has recreated it (undo) with new content.
      await a.remove("shared.md");
      await a.engine.scan();
      const origPost = a.session.client.postOps.bind(a.session.client);
      let recreated = false;
      a.session.client.postOps = async (v, ops) => {
        const r = await origPost(v, ops);
        if (!recreated) {
          recreated = true;
          await a.rawWrite("shared.md", utf8("v2\n"));
        }
        return r;
      };
      for (let i = 0; i < 3; i++) await a.sync();

      const h = await head(a.session, "shared.md");
      expect(h!.seq).toBeGreaterThan(badSeq);
      expect(h!.blob_id).toBe(await sa.vc.blobId(utf8("v2\n")));
      await c.sync();
      expect(await c.read("shared.md")).toBe("v2\n");
    } finally {
      await a.cleanup();
      await b.cleanup();
      await c.cleanup();
    }
  });
});
