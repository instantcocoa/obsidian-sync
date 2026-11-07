/**
 * Sixth review (2026-11-07), guide area A/D. Before the fix,
 * `VaultCrypto.decryptBlob` inflated a deflate-flagged body to completion,
 * buffered every chunk, and only then HMAC'd the result to check the blob
 * id; the engine checked `meta.size` after that. Nothing bounded the
 * inflated size. deflate-raw compresses zeros about 1000:1 and the server
 * accepts blobs up to MaxBlobSize (1 GiB by default), so one member (or one
 * stolen invite link) could post an op whose blob inflates to tens of
 * gigabytes; every device that pulled it allocated until the WebView or
 * Electron renderer died, and because the crash came before the cursor
 * advanced, the same batch was pulled again at the next start. Skip-and-
 * report never got to run.
 *
 * Now: the engine passes the authenticated `meta.size` as the bound, the
 * decompressor is cancelled one chunk past it, and without a caller bound
 * the cap is MAX_PLAIN (the default server's largest blob). The proof keeps
 * the bomb small (64 MiB from ~64 KiB of ciphertext) and counts what the
 * decompressor emitted.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";
import { VaultCrypto, newKeyring, CryptoError, MAX_PLAIN } from "../src/core/crypto";
import { utf8 } from "../src/core/encoding";

const MiB = 1 << 20;

/** Counts bytes the decompressor emits, across every DecompressionStream created while installed. */
function countInflated(): { inflated: () => number; restore: () => void } {
  const RealDS = globalThis.DecompressionStream;
  let n = 0;
  globalThis.DecompressionStream = class extends RealDS {
    constructor(format: CompressionFormat) {
      super(format);
      const counted = this.readable.pipeThrough(
        new TransformStream<Uint8Array, Uint8Array>({
          transform(chunk, ctl) {
            n += chunk.byteLength;
            ctl.enqueue(chunk);
          },
        }),
      );
      Object.defineProperty(this, "readable", { value: counted });
    }
  } as typeof DecompressionStream;
  return { inflated: () => n, restore: () => void (globalThis.DecompressionStream = RealDS) };
}

describe("decryptBlob bounds the inflated size", () => {
  let counter: ReturnType<typeof countInflated> | null = null;
  afterEach(() => counter?.restore());

  it("stops a 64 MiB bomb one chunk past the size the metadata admits, before any HMAC", async () => {
    const vc = new VaultCrypto(newKeyring());
    // The attacker's op names an honest-looking tiny file...
    const claimedId = await vc.blobId(new Uint8Array([0x78]));
    // ...and uploads, under that id, a valid ciphertext of 64 MiB of zeros, compressed.
    const bomb = await vc.encryptBlob(claimedId, new Uint8Array(64 * MiB), { compress: true });
    expect(bomb.length).toBeLessThan(256 * 1024);

    counter = countInflated();
    await expect(vc.decryptBlob(claimedId, bomb, { maxPlain: 1 })).rejects.toBeInstanceOf(CryptoError);
    // A bounded decoder stops a chunk or so past the largest size the op could honestly claim.
    expect(counter.inflated()).toBeLessThan(1 * MiB);
  });

  it("without a caller bound the cap is MAX_PLAIN, and an honest compressed blob still round-trips", async () => {
    const vc = new VaultCrypto(newKeyring());
    expect(MAX_PLAIN).toBe(1 << 30);
    const text = utf8("hello ".repeat(10_000));
    const id = await vc.blobId(text);
    const enc = await vc.encryptBlob(id, text, { compress: true });
    expect(await vc.decryptBlob(id, enc)).toEqual(text);
    expect(await vc.decryptBlob(id, enc, { maxPlain: text.length })).toEqual(text);
    // Exactly one byte too strict a bound is refused: the bound is the metadata's authenticated size, not a guess.
    await expect(vc.decryptBlob(id, enc, { maxPlain: text.length - 1 })).rejects.toBeInstanceOf(CryptoError);
  });
});

describe("through the engine: a bomb op is skipped and reported, and sync carries on past it", () => {
  let srv: TestServer;
  let counter: ReturnType<typeof countInflated> | null = null;
  beforeAll(async () => {
    srv = await TestServer.start();
  });
  afterAll(async () => {
    counter?.restore();
    await srv.stop();
  });

  it("the victim inflates under 1 MiB, reports the file, keeps its cursor moving", async () => {
    const sa = await createVault(srv.url, ADMIN, "attacker");
    const sb = await joinWithLink(await createInviteLink(sa), "victim");
    const skipped: string[] = [];
    const a = await new Device("attacker", sa).start();
    const b = await new Device("victim", sb, { hooks: { onSkipped: (p) => skipped.push(p) } }).start();
    await a.write("before.md", "x\n");
    await a.sync();
    await b.sync();

    // The bomb: metadata for a one-byte file, blob body 64 MiB of zeros under that file's id.
    const s: Session = a.session;
    const path = "innocent.md";
    const claimed = new Uint8Array([0x78]);
    const bid = await s.vc.blobId(claimed);
    await s.client.putBlob(s.identity.vaultId, bid, await s.vc.encryptBlob(bid, new Uint8Array(64 * MiB), { compress: true }));
    const pid = await s.vc.pathId(path);
    const r = await s.client.postOps(s.identity.vaultId, [
      { op_id: "b0".repeat(12), path_id: pid, blob_id: bid, meta_enc: await s.vc.encryptMeta(pid, { path, mtime: Date.now(), size: 1, blob: bid }), meta_epoch: s.vc.keyring.current, base_seq: 0 },
    ]);
    expect(r.results[0].seq ?? 0).toBeGreaterThan(0);

    counter = countInflated();
    await b.sync();
    expect(counter.inflated()).toBeLessThan(1 * MiB);
    expect(skipped).toEqual([path]);
    expect(await b.exists(path)).toBe(false);

    // The cursor moved past the bomb: later changes arrive, and the bomb is not pulled again.
    // (The attacker's own engine pulls and skips the bomb too on its sync; count only the victim's.)
    await a.write("after.md", "y\n");
    await a.sync();
    const before = counter.inflated();
    await b.sync();
    expect(await b.read("after.md")).toBe("y\n");
    expect(counter.inflated()).toBe(before);
    await a.cleanup();
    await b.cleanup();
  });
});
