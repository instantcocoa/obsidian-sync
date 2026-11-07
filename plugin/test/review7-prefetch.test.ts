/**
 * Seventh review (2026-11-07), guide area D "any other allocation a single
 * hostile op controls": `applyBatch` (engine.ts) downloads every blob a
 * batch needs into one Map before the first file is written, and keeps the
 * Map until the last op of the batch is applied. Memory held is therefore
 * the sum of all blob ciphertexts in the batch (up to 500 ops), not the
 * `parallel` (8) downloads in flight. A member who uploads N large blobs and
 * posts N ops makes every device hold N × size at once; an honest user who
 * drops a folder of photos into the vault does the same to their own phone.
 * The crash comes before the cursor advances, so the batch is pulled again
 * at every launch (the failure mode the sixth round fixed for inflation).
 *
 * The metadata (authenticated, decrypted before any fetch) carries `size`,
 * so the engine knows the budget before it downloads; nothing uses it.
 *
 * Fails on HEAD (16dba52): 12 one-MiB blobs are all fetched before the first
 * write. With on-demand fetching (or a byte budget) at most `parallel` are.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink } from "../src/core/admin";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

describe("applyBatch holds a whole batch of blobs in memory", () => {
  it("every blob of the batch is downloaded before the first file is written", async () => {
    const sa = await createVault(srv.url, ADMIN, "desktop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("desktop", sa).start();
    const b = await new Device("phone", sb).start();
    try {
      const N = 12;
      const SIZE = 1 << 20;
      for (let i = 0; i < N; i++) {
        const bytes = new Uint8Array(SIZE);
        crypto.getRandomValues(bytes.subarray(0, 65536)); // distinct blobs, cheap to make
        bytes[0] = i;
        await a.rawWrite(`photos/${i}.bin`, bytes);
      }
      await a.sync();

      let fetched = 0;
      let fetchedAtFirstWrite = -1;
      let inflight = 0;
      let peakInflight = 0;
      const client = b.session.client;
      const origGet = client.getBlob.bind(client);
      client.getBlob = async (v, id, sig) => {
        inflight++;
        peakInflight = Math.max(peakInflight, inflight);
        const r = await origGet(v, id, sig);
        inflight--;
        fetched += r.length;
        return r;
      };
      const origWrite = b.fs.write.bind(b.fs);
      b.fs.write = async (p, d, m) => {
        if (fetchedAtFirstWrite < 0) fetchedAtFirstWrite = fetched;
        return origWrite(p, d, m);
      };
      await b.sync();
      expect((await b.files()).filter((f) => f.startsWith("photos/")).length).toBe(N);
      // Bytes resident when the first write happens. Bounded by what is in
      // flight (parallel = 8) if blobs are fetched as they are applied; the
      // whole batch if they are prefetched and held.
      expect(peakInflight).toBeLessThanOrEqual(8);
      expect(fetchedAtFirstWrite, `${(fetchedAtFirstWrite / SIZE).toFixed(1)} MiB fetched before the first write`).toBeLessThanOrEqual(8 * SIZE * 1.05);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });
});
