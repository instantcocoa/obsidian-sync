import { describe, expect, it } from "vitest";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import {
  VaultCrypto,
  newKeyring,
  keyringFromJSON,
  keyringToJSON,
  generateKeypair,
  wrapEpochKey,
  unwrapEpochKey,
  encryptInviteKeybox,
  decryptInviteKeybox,
  buildInviteLink,
  parseInviteLink,
  createRecovery,
  openRecovery,
  CryptoError,
  type Rng,
} from "../src/core/crypto";
import { fromHex, hex, utf8, fromUtf8, b64url } from "../src/core/encoding";

/** Deterministic "randomness" for vectors: counter bytes. */
function seqRng(start = 0): Rng {
  let c = start;
  return (n) => {
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = (c++ & 0xff);
    return b;
  };
}

const fixedKeyring = () =>
  keyringFromJSON({
    k_id: "00".repeat(31) + "01",
    epochs: { "1": "11".repeat(32), "2": "22".repeat(32) },
    current: 2,
  });

describe("identifiers", () => {
  it("are deterministic, keyed, and NFC-normalised", async () => {
    const a = new VaultCrypto(fixedKeyring());
    const b = new VaultCrypto(newKeyring());
    const id1 = await a.blobId(utf8("hello"));
    expect(id1).toMatch(/^[0-9a-f]{64}$/);
    expect(await a.blobId(utf8("hello"))).toBe(id1);
    expect(await b.blobId(utf8("hello"))).not.toBe(id1);
    // é as composed vs decomposed
    expect(await a.pathId("café.md")).toBe(await a.pathId("café.md"));
    expect(await a.pathId("a.md")).not.toBe(await a.pathId("b.md"));
  });
});

describe("blobs", () => {
  it("round-trip, bind id and epoch, and detect tampering", async () => {
    const vc = new VaultCrypto(fixedKeyring());
    const pt = utf8("# Note\n\nsome content ".repeat(50));
    const id = await vc.blobId(pt);
    const blob = await vc.encryptBlob(id, pt);
    expect(blob[0]).toBe(1);
    expect(VaultCrypto.blobEpoch(blob)).toBe(2);
    expect(await vc.decryptBlob(id, blob)).toEqual(pt);
    // Wrong id → AEAD fails.
    await expect(vc.decryptBlob("ab".repeat(32), blob)).rejects.toBeInstanceOf(CryptoError);
    // Flip a byte.
    const bad = new Uint8Array(blob);
    bad[bad.length - 1] ^= 1;
    await expect(vc.decryptBlob(id, bad)).rejects.toBeInstanceOf(CryptoError);
    // Explicit older epoch still decrypts (needed during re-encryption).
    const old = await vc.encryptBlob(id, pt, { epoch: 1 });
    expect(VaultCrypto.blobEpoch(old)).toBe(1);
    expect(await vc.decryptBlob(id, old)).toEqual(pt);
    // Missing epoch key.
    const pruned = new VaultCrypto(fixedKeyring());
    pruned.pruneBelow(2);
    await expect(pruned.decryptBlob(id, old)).rejects.toThrow(/epoch 1/);
  });

  it("compress and pad flags", async () => {
    const vc = new VaultCrypto(fixedKeyring());
    const pt = utf8("abc ".repeat(2000));
    const id = await vc.blobId(pt);
    const plain = await vc.encryptBlob(id, pt);
    const comp = await vc.encryptBlob(id, pt, { compress: true });
    expect(comp.length).toBeLessThan(plain.length / 4);
    expect(await vc.decryptBlob(id, comp)).toEqual(pt);
    const padded = await vc.encryptBlob(id, pt, { pad: true });
    expect((padded.length - 33 - 16) % 4096).toBe(0);
    expect(await vc.decryptBlob(id, padded)).toEqual(pt);
    const both = await vc.encryptBlob(id, pt, { pad: true, compress: true });
    expect(both.length).toBe(33 + 16 + 4096);
    expect(await vc.decryptBlob(id, both)).toEqual(pt);
    // Incompressible data is stored raw even when compress is requested.
    const rnd = crypto.getRandomValues(new Uint8Array(5000));
    const rid = await vc.blobId(rnd);
    const rblob = await vc.encryptBlob(rid, rnd, { compress: true });
    expect(rblob.length).toBe(33 + 1 + 5000 + 16);
    expect(await vc.decryptBlob(rid, rblob)).toEqual(rnd);
    // Empty file.
    const eid = await vc.blobId(new Uint8Array(0));
    expect(await vc.decryptBlob(eid, await vc.encryptBlob(eid, new Uint8Array(0)))).toEqual(new Uint8Array(0));
  });
});

describe("metadata and names", () => {
  it("round-trip and are bound to path_id", async () => {
    const vc = new VaultCrypto(fixedKeyring());
    const pid = await vc.pathId("$CONFIG/app.json");
    const meta = { path: "$CONFIG/app.json", mtime: 1700000000000, size: 42 };
    const enc = await vc.encryptMeta(pid, meta);
    expect(VaultCrypto.metaEpoch(enc)).toBe(2);
    expect(await vc.decryptMeta(pid, enc)).toEqual(meta);
    await expect(vc.decryptMeta(await vc.pathId("other"), enc)).rejects.toBeInstanceOf(CryptoError);
    const name = await vc.encryptName("Eric's laptop");
    expect(await vc.decryptName(name)).toBe("Eric's laptop");
  });
});

describe("keybox wrap / invites / recovery", () => {
  it("wraps an epoch key to a device and only that device can unwrap", async () => {
    const a = await generateKeypair();
    const b = await generateKeypair();
    const k = crypto.getRandomValues(new Uint8Array(32));
    const kid = crypto.getRandomValues(new Uint8Array(32));
    const w = await wrapEpochKey(a.pub, "vault1", 3, "devA", k, kid);
    const u = await unwrapEpochKey(a.privJwk, "vault1", 3, "devA", w);
    expect(u.epochKey).toEqual(k);
    expect(u.kId).toEqual(kid);
    await expect(unwrapEpochKey(b.privJwk, "vault1", 3, "devA", w)).rejects.toBeInstanceOf(CryptoError);
    await expect(unwrapEpochKey(a.privJwk, "vault1", 4, "devA", w)).rejects.toBeInstanceOf(CryptoError);
    await expect(unwrapEpochKey(a.privJwk, "vault1", 3, "devB", w)).rejects.toBeInstanceOf(CryptoError);
  });

  it("invite keybox and link round-trip", async () => {
    const kr = fixedKeyring();
    const I = crypto.getRandomValues(new Uint8Array(32));
    const enc = await encryptInviteKeybox(I, kr);
    const back = await decryptInviteKeybox(I, enc);
    expect(keyringToJSON(back)).toEqual(keyringToJSON(kr));
    const link = buildInviteLink("https://sync.example.com/", "in_abc-DEF_123", I);
    const p = parseInviteLink(link);
    expect(p.server).toBe("https://sync.example.com");
    expect(p.token).toBe("in_abc-DEF_123");
    expect(p.inviteKey).toEqual(I);
    expect(() => parseInviteLink("https://nope")).toThrow();
  });

  it("recovery passphrase wraps the private key and yields a stable auth token", async () => {
    const rec = await createRecovery("correct horse battery staple");
    expect(rec.authToken).toMatch(/^rc_[A-Za-z0-9_-]{43}$/);
    const opened = await openRecovery("correct horse battery staple", rec.recoveryEnc);
    expect(opened.authToken).toBe(rec.authToken);
    // The recovered private key can unwrap a key wrapped to the recovery pub.
    const k = crypto.getRandomValues(new Uint8Array(32));
    const w = await wrapEpochKey(rec.pub, "v", 1, "rec", k, k);
    expect((await unwrapEpochKey(opened.privJwk, "v", 1, "rec", w)).epochKey).toEqual(k);
    await expect(openRecovery("wrong", rec.recoveryEnc)).rejects.toThrow(/wrong passphrase/);
  }, 30_000);
});

describe("test vectors", () => {
  // Pins the wire formats. Regenerate deliberately with UPDATE_VECTORS=1 when
  // a format changes; a second implementation must reproduce these bytes.
  it("match test/vectors.json", async () => {
    const vc = new VaultCrypto(fixedKeyring());
    const pt = utf8("hello obsync\n");
    const blobId = await vc.blobId(pt);
    const pathId = await vc.pathId("notes/hello.md");
    const vectors = {
      k_id: keyringToJSON(fixedKeyring()).k_id,
      epochs: keyringToJSON(fixedKeyring()).epochs,
      plaintext: fromUtf8(pt),
      blob_id: blobId,
      path_id: pathId,
      blob_epoch2_seq_rng: hex(await vc.encryptBlob(blobId, pt, { rng: seqRng(0) })),
      blob_epoch1_padded_seq_rng: hex(await vc.encryptBlob(blobId, pt, { rng: seqRng(0), epoch: 1, pad: true })),
      meta_enc_seq_rng: hex(await vc.encryptMeta(pathId, { path: "notes/hello.md", mtime: 1700000000000, size: 13 }, { rng: seqRng(7) })),
      name_enc_seq_rng: hex(await vc.encryptName("laptop", { rng: seqRng(9) })),
      invite_keybox_I_zero_seq_rng: hex(await encryptInviteKeybox(new Uint8Array(32), fixedKeyring(), seqRng(3))),
    };
    const file = new URL("./vectors.json", import.meta.url).pathname;
    if (process.env.UPDATE_VECTORS || !existsSync(file)) {
      writeFileSync(file, JSON.stringify(vectors, null, 2) + "\n");
    }
    const expected = JSON.parse(readFileSync(file, "utf8"));
    expect(vectors).toEqual(expected);
    // And every vector decrypts.
    expect(await vc.decryptBlob(blobId, fromHex(expected.blob_epoch2_seq_rng))).toEqual(pt);
    expect(await vc.decryptBlob(blobId, fromHex(expected.blob_epoch1_padded_seq_rng))).toEqual(pt);
    expect((await vc.decryptMeta(pathId, fromHex(expected.meta_enc_seq_rng))).size).toBe(13);
    expect(await vc.decryptName(fromHex(expected.name_enc_seq_rng))).toBe("laptop");
    expect(b64url(new Uint8Array(3))).toBe("AAAA");
  });
});
