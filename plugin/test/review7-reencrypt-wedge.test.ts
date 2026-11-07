/**
 * Seventh review (2026-11-07): `reencrypt()` (admin.ts) decrypts every blob
 * below the target epoch with no bound and no isolation. The applier's rule
 * "one bad op is skipped and reported" has no counterpart here: the first
 * blob that fails `decryptBlob` (wrong plaintext under a real id, a damaged
 * ciphertext, or a deflate bomb — this path passes no `maxPlain`, so the
 * bound is the full 1 GiB) throws out of the loop. The rotation itself has
 * already happened, so each retry mints another epoch, and `min_epoch` never
 * reaches the current one: old-epoch keys are never pruned from any keyring,
 * the blobs after the bad one in the listing stay under the retired key, and
 * every "Remove device" / "Rotate keys" ends in an error.
 *
 * Precondition: one member uploads one blob (server cannot check a blob's
 * plaintext against its id). The honest applier skips the op fine; only the
 * rotating device is wedged. Fails on HEAD (16dba52).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, removeDevice, type Session } from "../src/core/admin";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const opId = () => Math.random().toString(16).slice(2).padEnd(24, "0");

/** A member uploads, under id X, a valid ciphertext of bytes that do not hash to X, and an op that keeps it live. */
async function plantBadBlob(s: Session, path: string): Promise<void> {
  const { vc, client, identity } = s;
  const claimed = await vc.blobId(utf8("what the id says"));
  const actual = utf8("what the blob holds");
  await client.putBlob(identity.vaultId, claimed, await vc.encryptBlob(claimed, actual));
  const pid = await vc.pathId(path);
  const r = await client.postOps(identity.vaultId, [
    { op_id: opId(), path_id: pid, blob_id: claimed, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: actual.length, blob: claimed }), meta_epoch: vc.keyring.current, base_seq: 0 },
  ]);
  expect(r.results[0].seq ?? 0).toBeGreaterThan(0);
}

describe("re-encryption has no failure isolation", () => {
  it("one undecryptable blob from a member: every rotation afterwards errors and min_epoch never advances", async () => {
    const sa = await createVault(srv.url, ADMIN, "owner");
    const sb = await joinWithLink(await createInviteLink(sa), "member");
    const a = await new Device("owner", sa).start();
    const b = await new Device("member", sb).start();
    try {
      for (let i = 0; i < 5; i++) await a.rawWrite(`notes/${i}.md`, utf8(`note ${i}\n`));
      await a.sync();
      await b.sync();
      await plantBadBlob(b.session, "junk.md");

      // The applier side is fine: A skips the op and keeps syncing.
      await a.sync();
      expect(a.logs.some((l) => /blob_id mismatch/.test(l))).toBe(true);

      // The owner rotates (what "Remove device" and "Rotate keys" do), and retries once as a user would.
      const errors: string[] = [];
      for (let i = 0; i < 2; i++) {
        try {
          await removeDevice(a.session, "");
        } catch (e) {
          errors.push(String((e as Error).message));
        }
      }
      const info = await a.session.client.vault(a.session.identity.vaultId);
      expect(errors, `epoch ${info.epoch}, min_epoch ${info.min_epoch}`).toEqual([]);
      expect(info.min_epoch).toBe(info.epoch);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });
});
