/**
 * Ninth review (2026-11-07): the eighth round inverted reencrypt()'s
 * isolation test to "rethrow only HttpError/NetworkError; everything else is
 * a blob no key holder can read: carry a placeholder". That classification
 * is wrong for one CryptoError that says nothing about the blob:
 *
 *  A. `inflate` throws CryptoError("compressed blob but no
 *     DecompressionStream") on a platform without the API (Safari/WebKit
 *     before 16.4, so iOS 15.x and 16.0-16.3 WebViews). It is a property of
 *     the *device running the rotation*, not of the blob, and every other
 *     device reads the blob fine. A vault where any device has "compress"
 *     on, rotated (or a device removed) from such an iPhone, replaces every
 *     compressed blob on the server with a placeholder. The applier on that
 *     same device merely skips those blobs; the rotation destroys them.
 *     Fails on HEAD (5a88779).
 *
 *  A2 (soundness, passes). A body-read failure in `getBlob` (a connection
 *     dropped after the 200 header: a bare TypeError, not NetworkError) is
 *     thrown from the fetch, outside the placeholder catch, so it aborts
 *     the run and replaces nothing. Recorded so nobody re-derives it.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, removeDevice } from "../src/core/admin";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const text = "# Notes\n" + "the same line, again and again, compresses well\n".repeat(400);

describe("reencrypt() turns a device-side failure into a placeholder", () => {
  it("A. 'Rotate keys' on a device without DecompressionStream replaces every compressed blob", async () => {
    const sa = await createVault(srv.url, ADMIN, "mac");
    const sb = await joinWithLink(await createInviteLink(sa), "old-iphone");
    const a = await new Device("mac", sa, { compress: true }).start();
    const b = await new Device("old-iphone", sb).start();
    try {
      await a.rawWrite("notes.md", utf8(text));
      await a.sync();
      await b.sync();
      expect(await b.read("notes.md")).toBe(text);
      const v = sa.identity.vaultId;
      const id = await sa.vc.blobId(utf8(text));
      expect((await sa.vc.decryptBlobInfo(id, await sa.client.getBlob(v, id))).compressed).toBe(true);

      // The phone's WebView has no DecompressionStream. Its owner runs "Rotate keys".
      vi.stubGlobal("DecompressionStream", undefined);
      let outcome: string;
      try {
        const r = await removeDevice(sb, "");
        outcome = `completed; skipped=${JSON.stringify(r.skipped)}`;
      } catch (e) {
        outcome = `aborted: ${(e as Error).message}`; // acceptable: nothing is replaced
      } finally {
        vi.unstubAllGlobals();
      }

      // The mac learns the new epoch (if one was minted) and reads the server's copy.
      await a.sync();
      const after = await sa.client.getBlob(v, id);
      let plain: string | null = null;
      try {
        plain = new TextDecoder().decode(await sa.vc.decryptBlob(id, after));
      } catch (e) {
        plain = `<unreadable: ${(e as Error).message}>`;
      }
      expect(plain === text ? "the note" : plain, `rotation ${outcome}; the server's only copy of notes.md must still be the note`).toBe("the note");
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });

  it("A2 (soundness). a body-read TypeError from getBlob aborts the run and replaces nothing", async () => {
    const sa = await createVault(srv.url, ADMIN, "mac");
    const a = await new Device("mac", sa).start();
    try {
      await a.rawWrite("n.md", utf8("hello\n"));
      await a.sync();
      const client = sa.client;
      const orig = client.getBlob.bind(client);
      let first = true;
      client.getBlob = async (v, id, s) => {
        if (first) {
          first = false;
          throw new TypeError("terminated"); // undici's error when the body stream is cut after the headers
        }
        return orig(v, id, s);
      };
      await expect(removeDevice(sa, "")).rejects.toThrow(/terminated/);
      const id = await sa.vc.blobId(utf8("hello\n"));
      expect(new TextDecoder().decode(await sa.vc.decryptBlob(id, await orig(sa.identity.vaultId, id)))).toBe("hello\n");
    } finally {
      await a.cleanup();
    }
  });
});
