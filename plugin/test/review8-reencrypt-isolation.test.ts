/**
 * Eighth review (2026-11-07): the seventh round gave `reencrypt()` failure
 * isolation for one error class only: a `CryptoError` whose message does
 * not mention "epoch" becomes a placeholder. Three things a member can plant
 * still throw out of the loop, so every rotation afterwards errors at the
 * same row, `min_epoch` never advances, retired keys are never pruned, and
 * blobs listed after the bad one stay under the retired epoch (readable by a
 * removed device's key for as long as the database lives):
 *
 *  1. A blob under an epoch nobody holds any more. The server accepts any
 *     header epoch in [1, vault.epoch] (not >= min_epoch), so a member who
 *     kept the epoch-1 key posts one blob under it after a completed
 *     rotation. Every honest keyring pruned epoch 1; `decryptBlob` throws
 *     "no key for epoch 1"; `/epoch/` matches; `reencrypt` rethrows. The
 *     applier is fine (refreshKeys, fail, skip). `removeDevice(s, "")` then
 *     resumes this very loop at every "Rotate keys".
 *  2. A compressed blob whose body is not a deflate stream: valid GCM, flag
 *     bit 1 set, random bytes. `inflate` throws the runtime's error (a
 *     TypeError in Node), not a `CryptoError`; rethrown.
 *  3. An op whose metadata is valid GCM over something that is not JSON:
 *     `JSON.parse` throws a SyntaxError, not a `CryptoError`; rethrown.
 *
 * Each case fails on HEAD (93275e9) with the thrown error repeated on the
 * retry and `min_epoch < epoch`.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, removeDevice, type Session } from "../src/core/admin";
import { VaultCrypto, type Keyring } from "../src/core/crypto";
import { concat, fromHex, u32le, utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const subtle = crypto.subtle;
const B = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;
const opId = () => Math.random().toString(16).slice(2).padEnd(24, "0");

// The blob and metadata key schedule, as crypto.ts derives it (replicated here
// because the test needs ciphertexts encryptBlob/encryptMeta cannot produce).
async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<CryptoKey> {
  const k = await subtle.importKey("raw", B(ikm), "HKDF", false, ["deriveBits"]);
  const raw = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: B(salt), info: B(utf8(info)) }, k, 256);
  return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
}
async function gcm(key: CryptoKey, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: B(nonce), additionalData: B(aad) }, key, B(pt)));
}
/** A blob ciphertext with an arbitrary body (flags byte included) under `epoch`. */
async function rawBlob(kr: Keyring, epoch: number, blobId: string, bodyFull: Uint8Array): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await hkdf(kr.epochs.get(epoch)!, salt, "obsync/blob/v1");
  const ct = await gcm(key, nonce, concat(utf8("blob"), fromHex(blobId), u32le(epoch)), bodyFull);
  return concat(new Uint8Array([1]), u32le(epoch), salt, nonce, ct);
}
/** A metadata ciphertext over arbitrary plaintext under `epoch`. */
async function rawMeta(kr: Keyring, epoch: number, pathId: string, pt: Uint8Array): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await hkdf(kr.epochs.get(epoch)!, new Uint8Array(0), "obsync/meta/v1");
  return concat(u32le(epoch), nonce, await gcm(key, nonce, concat(utf8("meta"), fromHex(pathId), u32le(epoch)), pt));
}

async function post(s: Session, path: string, blobId: string, metaEnc: Uint8Array, metaEpoch: number): Promise<void> {
  const pid = await s.vc.pathId(path);
  const r = await s.client.postOps(s.identity.vaultId, [{ op_id: opId(), path_id: pid, blob_id: blobId, meta_enc: metaEnc, meta_epoch: metaEpoch, base_seq: 0 }]);
  expect(r.results[0].seq ?? 0, JSON.stringify(r.results[0])).toBeGreaterThan(0);
}

async function rotateTwice(s: Session): Promise<{ errors: string[]; epoch: number; min_epoch: number }> {
  const errors: string[] = [];
  for (let i = 0; i < 2; i++) {
    try {
      await removeDevice(s, "");
    } catch (e) {
      errors.push(`${(e as Error).name}: ${(e as Error).message}`);
    }
  }
  const info = await s.client.vault(s.identity.vaultId);
  return { errors, epoch: info.epoch, min_epoch: info.min_epoch };
}

async function pair(): Promise<[Device, Device]> {
  const sa = await createVault(srv.url, ADMIN, "owner");
  const sb = await joinWithLink(await createInviteLink(sa), "member");
  const a = await new Device("owner", sa).start();
  const b = await new Device("member", sb).start();
  for (let i = 0; i < 3; i++) await a.rawWrite(`notes/${i}.md`, utf8(`note ${i}\n`));
  await a.sync();
  await b.sync();
  return [a, b];
}

describe("re-encryption still has unisolated failures a member can plant", () => {
  it("1. a blob under an epoch every honest keyring has pruned: 'no key for epoch' wedges every rotation", async () => {
    const [a, b] = await pair();
    try {
      // The member remembers the epoch-1 key (a modified client never prunes).
      const kr1: Keyring = { kId: b.session.vc.keyring.kId, epochs: new Map([[1, b.session.vc.keyring.epochs.get(1)!]]), current: 1 };
      const old = new VaultCrypto(kr1);

      // The owner rotates once, completely: epoch 2, min_epoch 2, epoch 1 pruned everywhere.
      await removeDevice(a.session, "");
      await a.sync();
      await b.sync();
      let info = await a.session.client.vault(a.session.identity.vaultId);
      expect([info.epoch, info.min_epoch]).toEqual([2, 2]);
      expect(a.session.vc.keyring.epochs.has(1)).toBe(false);
      // The server's GC prunes keybox rows below min_epoch (the routine
      // every deployment runs on an interval): from here no honest device
      // can fetch the epoch-1 key again.
      await srv.gc();

      // The member tries to plant one blob under epoch 1. The server (since
      // 0.1.7) refuses any header epoch below min_epoch: no live device holds
      // that key, and the blob would drag min_epoch back for everyone.
      const bytes = utf8("planted under a retired epoch\n");
      const id = await old.blobId(bytes);
      await expect(b.session.client.putBlob(b.session.identity.vaultId, id, await old.encryptBlob(id, bytes, { epoch: 1 }))).rejects.toThrow(/epoch 1 outside \[2,2\]/);
      // Metadata under a retired epoch is refused the same way.
      const pid = await b.session.vc.pathId("planted.md");
      const r0 = await b.session.client.postOps(b.session.identity.vaultId, [
        { op_id: "ab".repeat(12), path_id: pid, blob_id: null, meta_enc: await old.encryptMeta(pid, { path: "planted.md", mtime: 1, size: 0, blob: null }, { epoch: 1 }), meta_epoch: 1, base_seq: 0 },
      ]);
      expect(r0.results[0].error).toMatch(/below the vault's min_epoch/);
      info = await a.session.client.vault(a.session.identity.vaultId);
      expect(info.min_epoch).toBe(2);
      await a.sync();

      // The owner's "Rotate keys" (which now resumes the unfinished re-encryption) and its retry.
      const r = await rotateTwice(a.session);
      expect(r.errors, `epoch ${r.epoch}, min_epoch ${r.min_epoch}`).toEqual([]);
      expect(r.min_epoch).toBe(r.epoch);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });

  it("1b. planted as insurance before a removal: everything written after it stays under the epoch the removed device holds", async () => {
    const [a, b] = await pair();
    try {
      const kr1: Keyring = { kId: b.session.vc.keyring.kId, epochs: new Map([[1, b.session.vc.keyring.epochs.get(1)!]]), current: 1 };
      const old = new VaultCrypto(kr1);
      await removeDevice(a.session, ""); // epoch 2, complete
      await a.sync();
      await b.sync();
      await srv.gc();
      // The member tries to plant the insurance blob now, while still welcome: refused at the door.
      const bytes = utf8("insurance\n");
      const id = await old.blobId(bytes);
      await expect(b.session.client.putBlob(b.session.identity.vaultId, id, await old.encryptBlob(id, bytes, { epoch: 1 }))).rejects.toThrow(/epoch 1 outside/);

      // Life goes on: the owner writes five more notes under epoch 2.
      const later: string[] = [];
      for (let i = 0; i < 5; i++) {
        const t = utf8(`written after the plant ${i}\n`);
        later.push(await a.session.vc.blobId(t));
        await a.rawWrite(`later/${i}.md`, t);
      }
      await a.sync();

      // The owner removes the member and retries once. The member's device is locked out (good)...
      const errors: string[] = [];
      for (let i = 0; i < 2; i++) {
        try {
          await removeDevice(a.session, i === 0 ? b.session.identity.deviceId : "");
        } catch (e) {
          errors.push(`${(e as Error).name}: ${(e as Error).message}`);
        }
      }
      const info = await a.session.client.vault(a.session.identity.vaultId);
      // Two rotations: the removal (epoch 3) and a plain "Rotate keys" (epoch 4; nothing left to resume).
      expect(info.epoch).toBe(4);
      expect(info.min_epoch).toBe(4);
      // ...and the five later notes must no longer be under epoch 2, the key the removed member still holds.
      const stillOld = await a.session.client.blobsBelowEpoch(a.session.identity.vaultId, info.epoch, 500);
      expect(later.filter((x) => stillOld.includes(x)), `${errors.join(" | ")}; min_epoch ${info.min_epoch}`).toEqual([]);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });

  it("2. a 'compressed' blob whose body is not deflate: the runtime's error is not a CryptoError and is rethrown", async () => {
    const [a, b] = await pair();
    try {
      const kr = b.session.vc.keyring;
      const id = await b.session.vc.blobId(utf8("claimed content"));
      const body = concat(new Uint8Array([1]), crypto.getRandomValues(new Uint8Array(64))); // flags = compressed, garbage body
      await b.session.client.putBlob(b.session.identity.vaultId, id, await rawBlob(kr, kr.current, id, body));
      const pid = await b.session.vc.pathId("garbage.md");
      await post(b.session, "garbage.md", id, await b.session.vc.encryptMeta(pid, { path: "garbage.md", mtime: Date.now(), size: 15, blob: id }), kr.current);

      await a.sync(); // the applier skips it
      expect(a.logs.some((l) => /garbage\.md could not be applied/.test(l))).toBe(true);

      const r = await rotateTwice(a.session);
      expect(r.errors, `epoch ${r.epoch}, min_epoch ${r.min_epoch}`).toEqual([]);
      expect(r.min_epoch).toBe(r.epoch);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });

  it("3. an op whose metadata decrypts to non-JSON: SyntaxError is rethrown", async () => {
    const [a, b] = await pair();
    try {
      const kr = b.session.vc.keyring;
      const bytes = utf8("real content\n");
      const id = await b.session.vc.blobId(bytes);
      await b.session.client.putBlob(b.session.identity.vaultId, id, await b.session.vc.encryptBlob(id, bytes));
      const pid = await b.session.vc.pathId("nonjson.md");
      await post(b.session, "nonjson.md", id, await rawMeta(kr, kr.current, pid, utf8("this is not json")), kr.current);

      await a.sync(); // the applier skips it
      expect(a.logs.some((l) => /cannot decrypt metadata/.test(l))).toBe(true);

      const r = await rotateTwice(a.session);
      expect(r.errors, `epoch ${r.epoch}, min_epoch ${r.min_epoch}`).toEqual([]);
      expect(r.min_epoch).toBe(r.epoch);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });
});
