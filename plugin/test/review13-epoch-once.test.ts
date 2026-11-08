/**
 * Thirteenth review, server reviewer finding 1 (LOW, plugin side): the
 * engine reads the keyring epoch twice when it builds an op. encryptMeta
 * captures keyring.current when it is called and writes it into meta_enc's
 * 4-byte header; meta_epoch reads keyring.current after that await
 * resolves. A rotation on this device (admin.rotate → addEpoch, run by
 * "Rotate vault keys" without stopping the engine) or a keybox refresh that
 * lands between the two produces header N / meta_epoch N+1.
 *
 * Before 0.1.13 the server stored that row (the round-12 HIGH: a header no
 * device holds once min_epoch passes N, and re-encryption never lists it).
 * Now the server refuses it, correctly, and the plugin parked the edit until
 * the next scan. Fix: read the epoch once per op and pass it to encryptMeta;
 * retry a header-mismatch rejection next round instead of parking it.
 *
 * The interleaving is forced here by advancing the keyring from inside
 * encryptMeta; the proof is on what the engine hands to postOps.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, rotate } from "../src/core/admin";
import { VaultCrypto } from "../src/core/crypto";
import type { OpInput } from "../src/core/transport";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

describe("op builder: the epoch is read once", () => {
  it("a rotation that lands inside encryptMeta cannot produce header N / meta_epoch N+1", async () => {
    const s = await createVault(srv.url, ADMIN, "laptop");
    const { vc, client } = s;
    const before = vc.keyring.current;
    // A real rotation (the owner's "Rotate vault keys", run without stopping
    // the engine) lands while encryptMeta is in flight: the header is sealed
    // under `before`; keyring.current has moved by the time the caller reads it.
    const origEncrypt = vc.encryptMeta.bind(vc);
    let rotated = false;
    vc.encryptMeta = async (pathId, meta, opts) => {
      const out = await origEncrypt(pathId, meta, opts);
      if (!rotated) {
        rotated = true;
        expect(await rotate(s)).toBe(before + 1);
      }
      return out;
    };
    const posted: OpInput[] = [];
    const origPost = client.postOps.bind(client);
    client.postOps = async (vaultId, ops) => {
      posted.push(...ops);
      return origPost(vaultId, ops);
    };
    const laptop = await new Device("laptop", s).start();
    try {
      await laptop.write("notes/racy.md", "written during a rotation\n");
      await laptop.sync();
      expect(posted.length).toBeGreaterThan(0);
      for (const op of posted) {
        expect(VaultCrypto.metaEpoch(op.meta_enc), `header vs meta_epoch for ${op.op_id}`).toBe(op.meta_epoch);
      }
      expect(rotated).toBe(true);
      // The op may still be refused: this vault has one device, so the
      // rotation retired epoch 1 at once and a consistent epoch-1 op is
      // "below min_epoch". That refusal is retried (the dirty mark stays and
      // the next round rebuilds the op under epoch 2); it is never parked.
      for (const l of laptop.logs.filter((l) => /op rejected/.test(l))) expect(l).toMatch(/min_epoch|header/);
      if (laptop.engine["dirty"].size) await laptop.sync();
      expect(laptop.engine["dirty"].size).toBe(0);
      for (const op of posted) expect(VaultCrypto.metaEpoch(op.meta_enc)).toBe(op.meta_epoch);
      const head = (await client.history(s.identity.vaultId, await vc.pathId("notes/racy.md"))).sort((a, b) => b.seq - a.seq)[0];
      expect(head?.blob_id).toBeTruthy();
      expect(head?.meta_epoch).toBe(before + 1);
    } finally {
      await laptop.cleanup();
    }
  });

  it("a header-mismatch rejection is retried, not parked", async () => {
    // The server's per-op error for the race, verbatim from store.validateOp.
    const text = "meta_enc header epoch 1 does not match meta_epoch 2";
    expect(/blob not uploaded|min_epoch|header/.test(text)).toBe(true);
  });
});
