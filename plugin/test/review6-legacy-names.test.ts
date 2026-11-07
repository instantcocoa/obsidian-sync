/**
 * Sixth review (2026-11-07), guide area A (rotation). Since the third
 * review, `rotate()` wraps the new epoch key only to devices whose name row
 * authenticates under their own id, and revokes the rest as "unproven". A
 * name row used to be written once, at enrolment, and only rewritten when
 * the user renamed the device. Two generations of honest rows do not verify:
 *
 *   - rows written by 0.1.0 (name key, epoch field 0, AAD "name" with no
 *     device id): `verifyName` demands the device id in the AAD;
 *   - rows written before e9c7316 (under K_meta,e with the epoch in the
 *     header): they verify only while that epoch's key is still held, and
 *     `pruneBelow` drops it once min_epoch passes.
 *
 * Before the fix nothing migrated such a row, so the next "Remove device" or
 * "Rotate keys" from any other device silently revoked every such honest
 * device. Accepting the old formats as proof is not the answer: a row
 * without the device id in its AAD is one the server could copy onto a
 * planted device, which is exactly what the id binding prevents. Instead:
 *
 *   1. every device rewrites its own row at start when it does not verify
 *      (`ensureOwnName`), so legacy rows vanish as devices upgrade;
 *   2. `decryptName` still shows the name a 0.1.0 row carries (for the
 *      roster) while `verifyName`, what rotation trusts, keeps refusing it;
 *   3. `rotate()` asks before revoking unproven devices, naming them, and a
 *      "no" cancels the rotation with nothing posted.
 */
import { describe, expect, it } from "vitest";
import { VaultCrypto, generateKeypair, newKeyring, type Keyring } from "../src/core/crypto";
import { ensureOwnName, rotate, RotationCancelled, type Session } from "../src/core/admin";
import { b64, concat, fromB64, u32le, utf8 } from "../src/core/encoding";

const subtle = crypto.subtle;
const B = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;
const ME = "a".repeat(32);
const OTHER = "b".repeat(32);

async function hkdfAes(ikm: Uint8Array, info: string): Promise<CryptoKey> {
  const k = await subtle.importKey("raw", B(ikm), "HKDF", false, ["deriveBits"]);
  const raw = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: B(utf8(info)) }, k, 256);
  return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
}

/** A name row exactly as 0.1.0 wrote it: K_name, epoch field 0, AAD "name" (no device id). */
async function nameRow_0_1_0(kr: Keyring, name: string): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: B(utf8("name")) }, await hkdfAes(kr.kId, "obsync/name/v1"), B(utf8(name))));
  return concat(u32le(0), nonce, ct);
}

/** A name row as versions before e9c7316 wrote it: K_meta,e with the epoch in the header, AAD "name". */
async function nameRow_pre_e9c7316(kr: Keyring, epoch: number, name: string): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: B(utf8("name")) }, await hkdfAes(kr.epochs.get(epoch)!, "obsync/meta/v1"), B(utf8(name))));
  return concat(u32le(epoch), nonce, ct);
}

type Row = { id: string; name_enc: string | null; pub_kex: string; recovery: boolean; created_at: number; last_seen: number; revoked_at: number | null };

/** A session over an in-memory roster; records what rotate() and setDeviceName post. */
async function fakeSession(vc: VaultCrypto, self: string, rows: Row[]): Promise<{ s: Session; posted: () => { revoke: string[]; recipients: string[]; rotated: boolean }; roster: Row[] }> {
  let revoke: string[] = [];
  let recipients: string[] = [];
  let rotated = false;
  const identity = { server: "http://x", vaultId: "v".repeat(32), deviceId: self, deviceToken: "dv_x", deviceName: "owner", pub: "", privJwk: {}, keyring: { k_id: "", epochs: {}, current: 1 } };
  const client = {
    vault: async () => ({ vault_id: identity.vaultId, epoch: vc.keyring.current, min_epoch: vc.keyring.current, seq: 1 }),
    devices: async () => rows,
    setDeviceName: async (_v: string, enc: Uint8Array) => {
      rows.find((r) => r.id === self)!.name_enc = b64(enc);
    },
    rotate: async (_v: string, _e: number, rev: string[], wrapped: { recipient_id: string }[]) => {
      rotated = true;
      revoke = rev;
      recipients = wrapped.map((r) => r.recipient_id);
      return {};
    },
  };
  return { s: { identity, client, vc } as unknown as Session, posted: () => ({ revoke, recipients, rotated }), roster: rows };
}

async function roster(vc: VaultCrypto, otherNameEnc: Uint8Array | null): Promise<Row[]> {
  const pub = b64((await generateKeypair()).pub);
  return [
    { id: ME, name_enc: b64(await vc.encryptName("owner", ME)), pub_kex: pub, recovery: false, created_at: 1, last_seen: 1, revoked_at: null },
    { id: OTHER, name_enc: otherNameEnc ? b64(otherNameEnc) : null, pub_kex: pub, recovery: false, created_at: 2, last_seen: 2, revoked_at: null },
  ];
}

describe("legacy name rows: readable, not proof, and rewritten by their owner", () => {
  it("a 0.1.0 row shows its name in the roster but does not verify as proof of keys", async () => {
    const kr = newKeyring();
    const vc = new VaultCrypto(kr);
    const row = await nameRow_0_1_0(kr, "laptop");
    expect(await vc.decryptName(row, OTHER)).toBe("laptop");
    expect(await vc.legacyName(row)).toBe("laptop");
    // Without the device id in the AAD the server could copy this row onto a planted device: never proof.
    expect(await vc.verifyName(row, OTHER)).toBeNull();
    // And a current row is proof only for its own id.
    const mine = await vc.encryptName("laptop", OTHER);
    expect(await vc.verifyName(mine, OTHER)).toBe("laptop");
    expect(await vc.verifyName(mine, ME)).toBeNull();
    expect(await vc.legacyName(mine)).toBeNull();
  });

  it("the device with a 0.1.0 row rewrites it at start; after that a rotation from another device includes it", async () => {
    const kr = newKeyring();
    const vc = new VaultCrypto(kr);
    const rows = await roster(vc, await nameRow_0_1_0(kr, "laptop"));
    // Seen from the laptop (OTHER): its own row does not verify, so it rewrites it. Idempotent afterwards.
    const laptop = await fakeSession(vc, OTHER, rows);
    laptop.s.identity.deviceName = "laptop";
    expect(await ensureOwnName(laptop.s)).toBe(true);
    expect(await ensureOwnName(laptop.s)).toBe(false);
    expect(await vc.verifyName(fromB64(rows[1].name_enc!), OTHER)).toBe("laptop");
    // The owner (ME) rotates: nobody is unproven, both get epoch 2.
    const owner = await fakeSession(vc, ME, rows);
    const asked: string[][] = [];
    await rotate(owner.s, [], (ids) => (asked.push(ids), true));
    expect(asked).toEqual([]);
    expect(owner.posted().revoke).toEqual([]);
    expect(owner.posted().recipients.sort()).toEqual([ME, OTHER]);
  });

  it("a row from before the name key is rewritten before its epoch is pruned, so the proof outlives the epoch", async () => {
    const kr = newKeyring();
    const vc = new VaultCrypto(kr);
    const rows = await roster(vc, await nameRow_pre_e9c7316(kr, 1, "phone"));
    // Readable while epoch 1 is held, but not proof (no id in its AAD).
    expect(await vc.decryptName(fromB64(rows[1].name_enc!), OTHER)).toBe("phone");
    expect(await vc.verifyName(fromB64(rows[1].name_enc!), OTHER)).toBeNull();
    const phone = await fakeSession(vc, OTHER, rows);
    phone.s.identity.deviceName = "phone";
    expect(await ensureOwnName(phone.s)).toBe(true);
    // Rotation to epoch 2 and re-encryption completing: min_epoch = 2, epoch 1 is dropped.
    vc.addEpoch(2, crypto.getRandomValues(new Uint8Array(32)));
    vc.pruneBelow(2);
    expect(await vc.verifyName(fromB64(rows[1].name_enc!), OTHER)).toBe("phone");
  });

  it("a rotation that would revoke unproven devices asks first, names them, and a 'no' posts nothing", async () => {
    const kr = newKeyring();
    const vc = new VaultCrypto(kr);
    const rows = await roster(vc, await nameRow_0_1_0(kr, "laptop"));
    const owner = await fakeSession(vc, ME, rows);
    let asked: { ids: string[]; names: string[] } | null = null;
    await expect(
      rotate(owner.s, [], (ids, names) => {
        asked = { ids, names };
        return false;
      }),
    ).rejects.toBeInstanceOf(RotationCancelled);
    expect(asked).toEqual({ ids: [OTHER], names: ["laptop"] });
    expect(owner.posted().rotated).toBe(false);
    expect(vc.keyring.current).toBe(1);
    // A "yes" proceeds as before: the unproven device is revoked and handed nothing.
    await rotate(owner.s, [], () => true);
    expect(owner.posted().revoke).toEqual([OTHER]);
    expect(owner.posted().recipients).toEqual([ME]);
    // An unnamed planted device is reported as such.
    const vc2 = new VaultCrypto(newKeyring());
    const planted = await fakeSession(vc2, ME, await roster(vc2, null));
    let names: string[] = [];
    await rotate(planted.s, [], (_ids, n) => ((names = n), true));
    expect(names).toEqual(["(unnamed)"]);
  });

  it("a device whose pub_kex does not import is treated as unproven, not as a rotation failure (seventh review)", async () => {
    const kr = newKeyring();
    const vc = new VaultCrypto(kr);
    const rows = await roster(vc, await vc.encryptName("laptop", OTHER));
    rows[1].pub_kex = b64(new Uint8Array(65).fill(0xff)); // 65 bytes, not a point on the curve
    const owner = await fakeSession(vc, ME, rows);
    let asked: { ids: string[]; names: string[] } | null = null;
    await rotate(owner.s, [], (ids, names) => ((asked = { ids, names }), true));
    expect(asked).toEqual({ ids: [OTHER], names: ["laptop [unusable key]"] });
    expect(owner.posted().revoke).toEqual([OTHER]);
    expect(owner.posted().recipients).toEqual([ME]);
  });
});
