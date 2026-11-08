/**
 * Eleventh review (2026-11-08): soundness checks, all expected to PASS on
 * HEAD (a4f34a0). The brief asked for every non-CryptoError that can still
 * escape `decryptBlobInfo`, `decryptMeta` and `inflate` after the round-10
 * shape guards. Each shape below is one a member (a key holder) can author
 * under the real epoch key with the real framing; each must surface as a
 * CryptoError (so `reencrypt()` makes a placeholder of it instead of
 * aborting every rotation, round 10 finding 1). None escaped: no finding.
 *
 * Shapes: ciphertext shorter than a GCM tag; a tag-only ciphertext (0-byte
 * body after authentication); padded flag with a length past the body;
 * padded flag with length 0 and compressed bit set (inflate of 0 bytes);
 * compressed bit over random bytes; metadata that is invalid UTF-8, a bare
 * number, an array, an object without `path`, a 100 000-deep nested array,
 * and a path holding a lone surrogate escape (accepted: it is a string).
 */
import { describe, expect, it } from "vitest";
import { CryptoError, VaultCrypto, newKeyring, BLOB_VERSION } from "../src/core/crypto";
import { concat, fromHex, randomBytes, u32le, utf8 } from "../src/core/encoding";

const vc = new VaultCrypto(newKeyring());
const B = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;

async function sealBlobBody(id: string, bodyFull: Uint8Array): Promise<Uint8Array> {
  const epoch = vc.keyring.current;
  const ek = vc.keyring.epochs.get(epoch)!;
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const base = await crypto.subtle.importKey("raw", B(ek), "HKDF", false, ["deriveBits"]);
  const raw = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: B(salt), info: B(utf8("obsync/blob/v1")) }, base, 256));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const aad = concat(utf8("blob"), fromHex(id), u32le(epoch));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: B(nonce), additionalData: B(aad) }, key, B(bodyFull)));
  return concat(new Uint8Array([BLOB_VERSION]), u32le(epoch), salt, nonce, ct);
}

async function sealMeta(pathId: string, json: Uint8Array): Promise<Uint8Array> {
  const epoch = vc.keyring.current;
  const ek = vc.keyring.epochs.get(epoch)!;
  const nonce = randomBytes(12);
  const base = await crypto.subtle.importKey("raw", B(ek), "HKDF", false, ["deriveBits"]);
  const raw = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: B(utf8("obsync/meta/v1")) }, base, 256));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const aad = concat(utf8("meta"), fromHex(pathId), u32le(epoch));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: B(nonce), additionalData: B(aad) }, key, B(json)));
  return concat(u32le(epoch), nonce, ct);
}

async function kind(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CryptoError ? `CryptoError/${e.kind}` : `${(e as Error).constructor.name}: ${(e as Error).message}`;
  }
}

describe("(soundness) member-authored shapes never escape decryption as anything but a CryptoError", () => {
  const id = "ab".repeat(32);

  it("blob: framing sanity (a well-formed body round-trips)", async () => {
    const pt = utf8("probe\n");
    const okId = await vc.blobId(pt);
    expect(await vc.decryptBlob(okId, await sealBlobBody(okId, concat(new Uint8Array([0]), pt)))).toEqual(pt);
  });

  it("blob: ciphertext shorter than a tag, tag-only ciphertext, empty authenticated body", async () => {
    const good = await sealBlobBody(id, new Uint8Array([0, 1]));
    // header (33) + 15 bytes: passes the `< BLOB_HEADER_LEN + 16` guard? No: 48 < 49, rejected as a header. 49 bytes = header + 16 = a tag-only ciphertext.
    expect(await kind(vc.decryptBlob(id, good.subarray(0, 48)))).toBe("CryptoError/defect");
    expect(await kind(vc.decryptBlob(id, good.subarray(0, 49)))).toBe("CryptoError/defect");
    expect(await kind(vc.decryptBlob(id, await sealBlobBody(id, new Uint8Array(0))))).toBe("CryptoError/defect");
  });

  it("blob: padded flag with an oversized length, length 0 with the compressed bit, compressed bit over random bytes", async () => {
    expect(await kind(vc.decryptBlob(id, await sealBlobBody(id, concat(new Uint8Array([2]), u32le(0xffffffff), new Uint8Array(8)))))).toBe("CryptoError/defect");
    expect(await kind(vc.decryptBlob(id, await sealBlobBody(id, concat(new Uint8Array([3]), u32le(0), new Uint8Array(4091)))))).toBe("CryptoError/defect");
    expect(await kind(vc.decryptBlob(id, await sealBlobBody(id, concat(new Uint8Array([1]), randomBytes(64)))))).toBe("CryptoError/defect");
    expect(await kind(vc.decryptBlob(id, await sealBlobBody(id, new Uint8Array([1]))))).toBe("CryptoError/defect");
  });

  it("meta: invalid UTF-8, a number, an array, no path, 100 000-deep nesting; a lone surrogate in the path is a string and is accepted", async () => {
    const pid = "cd".repeat(32);
    const shapes: [string, Uint8Array][] = [
      ["invalid utf-8", new Uint8Array([0xff, 0xfe, 0xfd])],
      ["number", utf8("42")],
      ["array", utf8('["a.md"]')],
      ["no path", utf8('{"mtime":1,"size":1}')],
      ["path not a string", utf8('{"path":{"a":1}}')],
      ["deep nesting", utf8("[".repeat(100_000) + "]".repeat(100_000))],
      ["empty", new Uint8Array(0)],
    ];
    for (const [name, json] of shapes) expect(await kind(vc.decryptMeta(pid, await sealMeta(pid, json))), name).toBe("CryptoError/defect");
    const m = await vc.decryptMeta(pid, await sealMeta(pid, utf8('{"path":"a\\udc00.md","mtime":"x","size":-5,"blob":7}')));
    expect(typeof m.path).toBe("string");
    expect(m.mtime).toBe(0);
    expect(m.size).toBe(0);
    // metaKey must not cache a rejected derivation when the epoch key is missing.
    expect(await kind(vc.decryptMeta(pid, concat(u32le(99), new Uint8Array(12), new Uint8Array(16))))).toBe("CryptoError/environment");
  });
});
