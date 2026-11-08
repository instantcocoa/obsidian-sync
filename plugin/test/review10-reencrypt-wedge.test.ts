/**
 * Tenth review (2026-11-08): the ninth round's `CryptoError.kind` whitelist in
 * `reencrypt()` ("placeholder only for kind defect, or SyntaxError for
 * metadata; anything else aborts") is right in spirit and has the edge the
 * brief predicted: two shapes of member-authored garbage reach a *non*
 * CryptoError inside the decrypt path, so the whitelist reads them as "about
 * this device" and aborts the rotation. The rows stay below the epoch, every
 * later "Rotate keys" / "Remove device" hits them again: the rotation is
 * wedged for good by one blob or one op, which is exactly what rounds 7 to 9
 * were closing.
 *
 *  A. A blob whose authenticated body is the single byte 0x02 (flags
 *     "padded", no length field). `decryptBlobInfo` takes the branch
 *     `readU32le(bodyFull, 1)`, which builds a 4-byte DataView over a 1-byte
 *     buffer: RangeError, not CryptoError. Any member can produce it (the
 *     body is AEAD-sealed under the real epoch key with the real AAD; the
 *     test seals it with WebCrypto and first proves the sealing is right by
 *     decrypting a well-formed body through the real `decryptBlob`). The
 *     applier is unaffected (no op names the blob, and applyBatch's catch is
 *     generic); only the rotation dies. Fails on HEAD (167804c).
 *
 *  B. An op whose metadata is the JSON literal `null`. `decryptMeta` parses
 *     it and then reads `m.path` on null: TypeError, neither CryptoError nor
 *     SyntaxError. The applier skips the op (generic catch); the ops loop of
 *     `reencrypt()` rethrows it. Fails on HEAD.
 *
 * Both say the same thing: the whitelist must be "defect = anything that is
 * not transport and not an environment-kind CryptoError", or decryptBlobInfo
 * and decryptMeta must guard their shape checks (body too short for the
 * padded length field; parsed JSON not an object) and throw CryptoError
 * "defect". The second is the smaller change and keeps the whitelist.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, removeDevice, type Session } from "../src/core/admin";
import { BLOB_VERSION, type FileMeta } from "../src/core/crypto";
import { concat, fromHex, randomBytes, u32le, utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const opId = () => Math.random().toString(16).slice(2).padEnd(24, "0");

/**
 * What a member's own code can produce: a blob sealed under the real epoch
 * key, with the real header and AAD, whose body is whatever they choose.
 * Mirrors VaultCrypto.encryptBlob's framing exactly (BLOB_VERSION, epoch,
 * salt, nonce, AES-GCM over bodyFull with AAD "blob" || id || epoch).
 */
async function sealBody(s: Session, id: string, bodyFull: Uint8Array): Promise<Uint8Array> {
  const epoch = s.vc.keyring.current;
  const ek = s.vc.keyring.epochs.get(epoch)!;
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const base = await crypto.subtle.importKey("raw", ek as Uint8Array<ArrayBuffer>, "HKDF", false, ["deriveBits"]);
  const raw = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt as Uint8Array<ArrayBuffer>, info: utf8("obsync/blob/v1") as Uint8Array<ArrayBuffer> }, base, 256));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const aad = concat(utf8("blob"), fromHex(id), u32le(epoch));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as Uint8Array<ArrayBuffer>, additionalData: aad as Uint8Array<ArrayBuffer> }, key, bodyFull as Uint8Array<ArrayBuffer>));
  return concat(new Uint8Array([BLOB_VERSION]), u32le(epoch), salt, nonce, ct);
}

/** Run the rotation twice (the second resumes an unfinished re-encryption) and say how it went. */
async function rotateTwice(s: Session): Promise<{ outcome: string; skipped: string[] }> {
  const skipped: string[] = [];
  let outcome = "";
  for (let i = 0; i < 2; i++) {
    try {
      const r = await removeDevice(s, "");
      skipped.push(...r.skipped);
      outcome += `attempt ${i + 1}: completed (resumed=${r.resumed}, skipped=${JSON.stringify(r.skipped)}); `;
    } catch (e) {
      outcome += `attempt ${i + 1}: aborted: ${(e as Error).constructor.name}: ${(e as Error).message}; `;
    }
  }
  return { outcome, skipped };
}

describe("reencrypt(): member garbage that is not a CryptoError wedges the rotation", () => {
  it("A. a blob whose body is a lone 'padded' flag byte makes every rotation abort with a RangeError", async () => {
    const sa = await createVault(srv.url, ADMIN, "mac");
    const sb = await joinWithLink(await createInviteLink(sa), "member");
    const a = await new Device("mac", sa).start();
    try {
      await a.rawWrite("note.md", utf8("honest\n"));
      await a.sync();
      const v = sa.identity.vaultId;

      // The sealing is the real framing: a well-formed body round-trips through the real decryptBlob.
      const okId = await sb.vc.blobId(utf8("probe\n"));
      const okBlob = await sealBody(sb, okId, concat(new Uint8Array([0]), utf8("probe\n")));
      expect(new TextDecoder().decode(await sb.vc.decryptBlob(okId, okBlob))).toBe("probe\n");

      // The member's blob: flags = 2 (padded), and nothing after the flag byte.
      const badId = "ab".repeat(32);
      await sb.client.putBlob(v, badId, await sealBody(sb, badId, new Uint8Array([2])));

      // The applier on the honest device is untouched by it (no op names it).
      await a.sync();
      expect(await a.read("note.md")).toBe("honest\n");

      const { outcome } = await rotateTwice(sa);
      const info = await sa.client.vault(v);
      expect(info.min_epoch, `rotation must retire the old epoch, carrying the member's blob as a placeholder: ${outcome}`).toBe(info.epoch);

      // And the honest note is still readable from the server under the new epoch.
      await a.sync();
      const id = await sa.vc.blobId(utf8("honest\n"));
      expect(new TextDecoder().decode(await sa.vc.decryptBlob(id, await sa.client.getBlob(v, id)))).toBe("honest\n");
    } finally {
      await a.cleanup();
    }
  });

  it("B. an op whose metadata is the JSON literal null makes every rotation abort with a TypeError", async () => {
    const sa = await createVault(srv.url, ADMIN, "mac");
    const sb = await joinWithLink(await createInviteLink(sa), "member");
    const a = await new Device("mac", sa).start();
    try {
      await a.rawWrite("note.md", utf8("honest\n"));
      await a.sync();
      const v = sa.identity.vaultId;

      // A real blob, and an op whose authenticated metadata decrypts to `null`.
      const bytes = utf8("whatever\n");
      const id = await sb.vc.blobId(bytes);
      await sb.client.putBlob(v, id, await sb.vc.encryptBlob(id, bytes));
      const pid = await sb.vc.pathId("member.md");
      const r = await sb.client.postOps(v, [
        { op_id: opId(), path_id: pid, blob_id: id, meta_enc: await sb.vc.encryptMeta(pid, null as unknown as FileMeta), meta_epoch: sb.vc.keyring.current, base_seq: 0 },
      ]);
      expect(r.results[0].seq ?? 0, JSON.stringify(r.results[0])).toBeGreaterThan(0);

      // The honest device skips the op and carries on.
      await a.sync();
      expect(await a.files()).toEqual(["note.md"]);
      expect(a.logs.some((l) => /cannot decrypt metadata/.test(l)), a.logs.join("\n")).toBe(true);

      const { outcome } = await rotateTwice(sa);
      const info = await sa.client.vault(v);
      expect(info.min_epoch, `rotation must retire the old epoch, carrying the member's op as a placeholder: ${outcome}`).toBe(info.epoch);
    } finally {
      await a.cleanup();
    }
  });
});
