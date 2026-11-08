/**
 * Tenth review (2026-11-08): `inflate()`'s new catch wraps every non-CryptoError
 * from `pipe()` as CryptoError kind "defect" ("the decompressor rejected the
 * body"). Two things inside that try are not about the body:
 *
 *  C. `new DecompressionStream("deflate-raw")` itself. A runtime can have the
 *     class and not the format: Chromium 80-102 (Android WebViews not updated
 *     since mid-2022, which Obsidian on Android 7-9 still runs in) and Firefox
 *     113 and older throw TypeError from the constructor for "deflate-raw"
 *     (Node does the same for an unknown format, see the probe below). The
 *     round-9 guard checks only `typeof DecompressionStream`, so on such a
 *     device the error is wrapped as a defect, and "Rotate keys" replaces
 *     every compressed blob in the vault with a placeholder: the exact
 *     outcome round 9 fixed for the no-DecompressionStream case, one API
 *     level down. End-to-end against the server. Fails on HEAD (167804c).
 *
 *  D. An allocation failure while the chunks are collected (RangeError from
 *     the engine, not from the data). Unit test on `inflate` with a stream
 *     that raises RangeError the way V8 does when a chunk's buffer cannot be
 *     allocated; the OOM itself is simulated, the classification is what is
 *     under test. Fails on HEAD: kind is "defect".
 *
 *  Soundness (pass): a genuinely malformed deflate body is a defect; a
 *  runtime with no DecompressionStream at all is environment.
 *
 * Fix: construct the stream outside the try (an unsupported format is
 * "environment", like the missing class), and inside the catch wrap only the
 * decompressor's own data error (Node: `code` Z_DATA_ERROR / name TypeError
 * from zlib; Chromium: TypeError) as a defect; a RangeError or anything else
 * is environment. Belt: `reencrypt()` can probe `deflate(new Uint8Array(1))`
 * + `inflate` once at the start and refuse to run on a runtime that cannot
 * round-trip.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, removeDevice } from "../src/core/admin";
import { CryptoError, deflate, inflate } from "../src/core/crypto";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const text = "# Notes\n" + "the same line, again and again, compresses well\n".repeat(400);

/** A DecompressionStream that exists but knows only "deflate" and "gzip" (Chromium < 103, Firefox <= 113). */
class OldDecompressionStream {
  readable: ReadableStream;
  writable: WritableStream;
  constructor(format: string) {
    if (format !== "deflate" && format !== "gzip") {
      throw new TypeError(`Failed to construct 'DecompressionStream': The provided value '${format}' is not a valid enum value of type CompressionFormat.`);
    }
    const t = new TransformStream();
    this.readable = t.readable;
    this.writable = t.writable;
  }
}

describe("inflate() classifies failures that are about this runtime as defects of the blob", () => {
  it("probe: Node's own DecompressionStream throws TypeError from the constructor for an unknown format", () => {
    expect(() => new DecompressionStream("bogus" as CompressionFormat)).toThrow(TypeError);
  });

  it("C. 'Rotate keys' on a runtime whose DecompressionStream lacks deflate-raw replaces every compressed blob", async () => {
    const sa = await createVault(srv.url, ADMIN, "mac");
    const sb = await joinWithLink(await createInviteLink(sa), "old-android");
    const a = await new Device("mac", sa, { compress: true }).start();
    const b = await new Device("old-android", sb).start();
    try {
      await a.rawWrite("notes.md", utf8(text));
      await a.sync();
      await b.sync();
      expect(await b.read("notes.md")).toBe(text);
      const v = sa.identity.vaultId;
      const id = await sa.vc.blobId(utf8(text));
      expect((await sa.vc.decryptBlobInfo(id, await sa.client.getBlob(v, id))).compressed).toBe(true);

      vi.stubGlobal("DecompressionStream", OldDecompressionStream);
      let outcome: string;
      try {
        const r = await removeDevice(sb, "");
        outcome = `completed; skipped=${JSON.stringify(r.skipped)}`;
      } catch (e) {
        outcome = `aborted: ${(e as Error).message}`; // acceptable: nothing is replaced
      } finally {
        vi.unstubAllGlobals();
      }

      await a.sync();
      const after = await sa.client.getBlob(v, id);
      let plain: string;
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

  it("D. a RangeError raised while collecting the output (allocation failure) is not a defect of the blob", async () => {
    const body = (await deflate(utf8(text)))!;
    class OomDecompressionStream {
      readable: ReadableStream;
      writable: WritableStream;
      constructor(_format: string) {
        const t = new TransformStream<Uint8Array, Uint8Array>({
          transform() {
            // What V8 raises when the chunk's ArrayBuffer cannot be allocated.
            throw new RangeError("Array buffer allocation failed");
          },
        });
        this.readable = t.readable;
        this.writable = t.writable;
      }
    }
    vi.stubGlobal("DecompressionStream", OomDecompressionStream);
    try {
      const err = await inflate(body).then(
        () => null,
        (e: unknown) => e,
      );
      expect(err).toBeInstanceOf(CryptoError);
      expect((err as CryptoError).kind, `"${(err as Error).message}" says nothing about the bytes; re-encryption must not replace them on it`).toBe("environment");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("soundness: a malformed deflate body is a defect; no DecompressionStream at all is environment", async () => {
    const bad = await inflate(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9])).then(
      () => null,
      (e: unknown) => e as CryptoError,
    );
    expect(bad).toBeInstanceOf(CryptoError);
    expect(bad!.kind).toBe("defect");
    vi.stubGlobal("DecompressionStream", undefined);
    try {
      const none = await inflate(new Uint8Array([1])).then(
        () => null,
        (e: unknown) => e as CryptoError,
      );
      expect(none!.kind).toBe("environment");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
