/**
 * Thirteenth review (2026-11-07): decodeOp's new onSkipped for an unreadable
 * row (round 12 finding 1 and 3 fixed). The report is right; its cost is per
 * row and uncapped: every garbage row is a 12-second Notice in main.ts.
 *
 *  A. Fails on HEAD (af13604): N garbage rows under N distinct path_ids (each
 *     stays a head for ever, so every fresh device and every "Rebuild local
 *     sync state" pulls them all again) → N notices in one pull, titled
 *     "(op N)". A member can post 1 000 rows per request. Low: the cursor
 *     advances and nothing is wedged; the user gets a wall of notices on
 *     every device, and again on every rebuild and every new device. (The
 *     same is true of the older per-row reports: unsafe path, mismatched
 *     blob; pre-existing.) The per-row keybox refresh I expected is NOT
 *     reachable: the server refuses a header epoch that differs from
 *     meta_epoch (soundness assertion kept).
 *
 * Fix: coalesce onSkipped notices per sync in main.ts (one Notice naming the
 * count and the first few paths, the rest in the log), or in the engine
 * collect decodeOp's rejections per batch and report once.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";
import { utf8, u32le } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const opId = () => Math.random().toString(16).slice(2).padEnd(24, "0");

async function garbageRows(s: Session, n: number): Promise<void> {
  const bytes = utf8("x\n");
  const id = await s.vc.blobId(bytes);
  await s.client.putBlob(s.identity.vaultId, id, await s.vc.encryptBlob(id, bytes));
  const ops = [];
  for (let i = 0; i < n; i++) {
    // A valid epoch header over noise (the server now refuses a header that
    // does not match meta_epoch, so the "no key for epoch" retry is no longer
    // reachable from a member; "authentication failed" is).
    const noise = crypto.getRandomValues(new Uint8Array(96));
    noise.set(u32le(s.vc.keyring.current), 0);
    ops.push({ op_id: opId(), path_id: await s.vc.pathId(`junk/${i}.md`), blob_id: id, meta_enc: noise, meta_epoch: s.vc.keyring.current, base_seq: 0 });
  }
  const r = await s.client.postOps(s.identity.vaultId, ops);
  for (const x of r.results) expect(x.seq ?? 0, JSON.stringify(x)).toBeGreaterThan(0);
}

describe("decodeOp: one notice per unreadable row, uncapped", () => {
  it("A. 200 garbage rows under 200 paths: one pull raises 200 separate 12-second notices", async () => {
    const sa = await createVault(srv.url, ADMIN, "member");
    await garbageRows(sa, 200);
    const link = await createInviteLink(sa);
    const urls: string[] = [];
    const counting: typeof fetch = (u, init) => {
      urls.push(String(u));
      return fetch(u, init);
    };
    const sb = await joinWithLink(link, "mac", counting);
    const skipped: [string, string][] = [];
    const mac = await new Device("mac", sb, { hooks: { onSkipped: (p, why) => skipped.push([p, why]) } }).start();
    try {
      urls.length = 0;
      await mac.sync();
      const keybox = urls.filter((u) => /\/keybox/.test(u)).length;
      expect(skipped.length, "unreadable rows reported").toBeGreaterThan(0);
      // Server-side defence (store.validateOp) means a member cannot make a device refresh its keys per row any more: soundness.
      expect(keybox, `${keybox} keybox fetches for one pull of 200 garbage rows`).toBeLessThanOrEqual(1);
      expect(skipped.length, `${skipped.length} separate notices for one pull`).toBeLessThanOrEqual(1);
    } finally {
      await mac.cleanup();
    }
  }, 60_000);
});
