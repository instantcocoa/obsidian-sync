/**
 * Found in the field (2026-11-25): a note saved again while its previous
 * save was being pushed never reached the server. `prepareLocalOp` reads
 * the file, the push goes out, the editor autosaves, the watcher's
 * `markDirty` is a no-op because the path is still in `dirty`, and
 * `settle()` then clears the flag and records the stat of the bytes it
 * pushed. Nothing looks at the file again until the next full scan
 * (startup), so the status reads "synced" with the newer bytes only on disk.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device } from "./harness";
import { createVault } from "../src/core/admin";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

describe("a save that lands while the previous one is being pushed", () => {
  it("is pushed too, not dropped by settle", async () => {
    const s = await createVault(await srv.createLink(), "mac");
    const a = await new Device("mac", s).start();
    try {
      await a.rawWrite("note.md", utf8("first save\n"));
      const later = utf8("first save\nsecond save, two seconds later\n");
      // The second save arrives while the op for the first is on the wire.
      const post = s.client.postOps.bind(s.client);
      let once = false;
      s.client.postOps = async (v, ops) => {
        if (!once) {
          once = true;
          await a.rawWrite("note.md", later);
          a.engine.noteChange("note.md");
        }
        return post(v, ops);
      };
      // One sync, and no second scan: a rescan would find the file and hide the bug.
      await a.sync();
      await a.engine.sync();
      const pid = await s.vc.pathId("note.md");
      const snap = await s.client.snapshot(s.identity.vaultId, { since: 0, limit: 500 });
      const head = snap.ops.filter((o) => o.path_id === pid).sort((x, y) => y.seq - x.seq)[0];
      expect(head.blob_id).toBe(await s.vc.blobId(later));
    } finally {
      await a.cleanup();
    }
  });
});
