/**
 * Ninth review (2026-11-07): applyBatch's shared-blob refcount (`uses`) is
 * built from the ops that will *fetch* (not excluded, not already in state
 * under that path) but decremented by *every* op that carries the blob id.
 * An op skipped from the count (the path already holds that blob, or is
 * excluded) that sorts before a counted one drops the cache entry one op
 * early, and the last counted op downloads the blob again. Bandwidth only
 * (one extra download per such batch); the window bound is briefly exceeded
 * by the dropped in-flight prefetch, which keeps downloading unreferenced.
 * LOW. Fails on HEAD (5a88779): 2 downloads where 1 is expected.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const opId = () => Math.random().toString(16).slice(2).padEnd(24, "0");

async function putExisting(s: Session, path: string, blobId: string, size: number, baseSeq: number): Promise<void> {
  const pid = await s.vc.pathId(path);
  const r = await s.client.postOps(s.identity.vaultId, [
    { op_id: opId(), path_id: pid, blob_id: blobId, meta_enc: await s.vc.encryptMeta(pid, { path, mtime: Date.now(), size, blob: blobId }), meta_epoch: s.vc.keyring.current, base_seq: baseSeq },
  ]);
  expect(r.results[0].seq ?? 0, JSON.stringify(r.results[0])).toBeGreaterThan(0);
}

describe("applyBatch refcount: an op that is not counted still decrements", () => {
  it("one blob, already synced under copies/0.bin, new under five more names: downloaded twice", async () => {
    const sa = await createVault(srv.url, ADMIN, "desktop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("desktop", sa).start();
    const b = await new Device("phone", sb).start();
    try {
      const bytes = new Uint8Array(64 * 1024);
      crypto.getRandomValues(bytes);
      await a.rawWrite("copies/0.bin", bytes);
      await a.sync();
      await b.sync();
      const X = await sa.vc.blobId(bytes);
      expect(b.engine.state.files["copies/0.bin"].hash).toBe(X);

      // One batch from the desktop: copies/0.bin restored after a delete
      // (same bytes, so the phone already holds X for that path) and five
      // new copies of the same attachment.
      const seq0 = a.engine.state.files["copies/0.bin"].seq;
      await putExisting(sa, "copies/0.bin", X, bytes.length, seq0);
      for (let i = 1; i <= 5; i++) await putExisting(sa, `copies/${i}.bin`, X, bytes.length, 0);

      let fetches = 0;
      const client = b.session.client;
      const origGet = client.getBlob.bind(client);
      client.getBlob = async (v, id, sig) => {
        fetches++;
        return origGet(v, id, sig);
      };
      await b.sync();
      expect((await b.files()).filter((f) => f.startsWith("copies/")).length).toBe(6);
      expect(fetches, `${fetches} downloads of one blob in one batch`).toBe(1);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });
});
