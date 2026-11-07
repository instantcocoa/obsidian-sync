/**
 * Seventh review (2026-11-07): `ensureOwnName` (admin.ts) runs detached at
 * every start (main.ts, `void ensureOwnName(...)`). It reads the roster,
 * decides the row is legacy, encrypts `identity.deviceName` and PATCHes it.
 * A rename the user performs in that window (settings → Rename this device)
 * PATCHes too; if the rename's request lands first, `ensureOwnName`'s
 * request overwrites it with the old name, and the next start sees a
 * current-format row and leaves it: the roster shows the old name on every
 * other device until the user renames again. One request's latency wide, on
 * the first start after an upgrade from 0.1.0 only. Fails on HEAD (16dba52).
 */
import { describe, expect, it } from "vitest";
import { VaultCrypto, newKeyring, type Keyring } from "../src/core/crypto";
import { ensureOwnName, renameOwnDevice, type Session } from "../src/core/admin";
import { b64, concat, fromB64, u32le, utf8 } from "../src/core/encoding";

const subtle = crypto.subtle;
const B = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;
const ME = "a".repeat(32);

async function nameKey(kr: Keyring): Promise<CryptoKey> {
  const k = await subtle.importKey("raw", B(kr.kId), "HKDF", false, ["deriveBits"]);
  const raw = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: B(utf8("obsync/name/v1")) }, k, 256);
  return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
}

/** A name row exactly as 0.1.0 wrote it: K_name, epoch field 0, AAD "name" (no device id). */
async function nameRow_0_1_0(kr: Keyring, name: string): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: B(utf8("name")) }, await nameKey(kr), B(utf8(name))));
  return concat(u32le(0), nonce, ct);
}

describe("ensureOwnName races a rename", () => {
  it("a rename that lands while the start-up rewrite is in flight is undone by it", async () => {
    const kr = newKeyring();
    const vc = new VaultCrypto(kr);
    const row = { id: ME, name_enc: b64(await nameRow_0_1_0(kr, "old")), pub_kex: "", recovery: false, created_at: 1, last_seen: 1, revoked_at: null };
    const landed: string[] = [];
    let holdFirstPatch!: () => void;
    const gate = new Promise<void>((r) => (holdFirstPatch = r));
    let patches = 0;
    const client = {
      devices: async () => [{ ...row }],
      setDeviceName: async (_v: string, enc: Uint8Array) => {
        // The first PATCH (ensureOwnName's) is slow on the wire; the rename's goes straight through.
        if (patches++ === 0) await gate;
        row.name_enc = b64(enc);
        landed.push(await vc.verifyName(enc, ME).then((n) => n ?? "?"));
      },
    };
    const identity = { server: "http://x", vaultId: "v".repeat(32), deviceId: ME, deviceToken: "dv_x", deviceName: "old", pub: "", privJwk: {}, keyring: { k_id: "", epochs: {}, current: 1 } };
    const s = { identity, client, vc } as unknown as Session;

    const startup = ensureOwnName(s);
    await new Promise((r) => setTimeout(r, 20)); // ensureOwnName has read the roster and is encrypting / sending "old"
    // main.ts renameDevice() goes through renameOwnDevice, which waits for the
    // start-up rewrite instead of being undone by it.
    const rename = renameOwnDevice(s, "new");
    holdFirstPatch();
    await startup;
    await rename;

    expect(landed).toEqual(["old", "new"]);
    expect(identity.deviceName).toBe("new");
    expect(await vc.verifyName(fromB64(row.name_enc), ME)).toBe("new");
  });
});
