/**
 * Eighth review (2026-11-07): smaller edges of the seventh round's fixes.
 *
 *  A. applyBatch's bounded window drops a blob's cache entry when *its* op
 *     is done; a blob shared by several ops in one batch (the same bytes
 *     under several names: templates, copies, empty files) is fetched once
 *     per op instead of once. 0.1.5's Set fetched it once. Fails on HEAD.
 *  B. ensureOwnName's in-flight guard is keyed by the Session object, and
 *     main.ts opens a new Session at every (re)start. A rewrite still on the
 *     wire from the previous Session is not awaited by a rename on the new
 *     one and lands after it, putting the old name back: the race the
 *     seventh round closed, one restart wide. Fails on HEAD.
 *  C. reencrypt() re-encrypts with neither compression nor padding, so a
 *     rotation strips both from every blob: a 1 MiB compressible file that
 *     was a few KiB on the server is 1 MiB afterwards, and the length
 *     hiding that `pad` bought is gone. Pre-existing, not from this round;
 *     recorded because the round rewrote this loop. Fails on HEAD.
 *  D. Soundness, not a finding: the pre-decrypt bound
 *     `ct.length > meta.size + PAD_BLOCK + 256` admits every honest
 *     ciphertext (padded, compressed, both, neither) for sizes around every
 *     padding boundary. Passes on HEAD; here so nobody has to re-derive it.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, ensureOwnName, renameOwnDevice, removeDevice, type Session } from "../src/core/admin";
import { VaultCrypto, newKeyring, PAD_BLOCK, type Keyring } from "../src/core/crypto";
import { b64, concat, fromB64, u32le, utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

describe("A. one blob under many names is fetched once per name", () => {
  it("20 identical files cost 20 downloads of the same blob (0.1.5: one)", async () => {
    const sa = await createVault(srv.url, ADMIN, "desktop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("desktop", sa).start();
    const b = await new Device("phone", sb).start();
    try {
      const N = 20;
      const bytes = new Uint8Array(256 * 1024);
      crypto.getRandomValues(bytes.subarray(0, 65536));
      for (let i = 0; i < N; i++) await a.rawWrite(`copies/${i}.bin`, bytes);
      await a.sync();
      expect(a.uploads).toBe(1);

      let fetches = 0;
      const client = b.session.client;
      const origGet = client.getBlob.bind(client);
      client.getBlob = async (v, id, sig) => {
        fetches++;
        return origGet(v, id, sig);
      };
      await b.sync();
      expect((await b.files()).filter((f) => f.startsWith("copies/")).length).toBe(N);
      expect(fetches, `${fetches} downloads of one blob`).toBeLessThanOrEqual(2);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });
});

const subtle = crypto.subtle;
const B = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;
const ME = "a".repeat(32);
async function nameKey(kr: Keyring): Promise<CryptoKey> {
  const k = await subtle.importKey("raw", B(kr.kId), "HKDF", false, ["deriveBits"]);
  const raw = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: B(utf8("obsync/name/v1")) }, k, 256);
  return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
}
/** A name row exactly as 0.1.0 wrote it. */
async function nameRow_0_1_0(kr: Keyring, name: string): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: B(utf8("name")) }, await nameKey(kr), B(utf8(name))));
  return concat(u32le(0), nonce, ct);
}

describe("B. the in-flight name rewrite is keyed by Session; a restart opens a new one", () => {
  it("a rename on the new Session does not wait for the old Session's rewrite, which lands last", async () => {
    const kr = newKeyring();
    const vc = new VaultCrypto(kr);
    const row = { id: ME, name_enc: b64(await nameRow_0_1_0(kr, "old")), pub_kex: "", recovery: false, created_at: 1, last_seen: 1, revoked_at: null };
    const landed: string[] = [];
    let releaseFirst!: () => void;
    const gate = new Promise<void>((r) => (releaseFirst = r));
    let patches = 0;
    const client = {
      devices: async () => [{ ...row }],
      setDeviceName: async (_v: string, enc: Uint8Array) => {
        if (patches++ === 0) await gate; // the first start's PATCH is slow on the wire
        row.name_enc = b64(enc);
        landed.push((await vc.verifyName(enc, ME)) ?? "?");
      },
    };
    const identity = { server: "http://x", vaultId: "v".repeat(32), deviceId: ME, deviceToken: "dv_x", deviceName: "old", pub: "", privJwk: {}, keyring: { k_id: "", epochs: {}, current: 1 } };
    // main.ts: startEngine() → this.session = openSession(identity); void ensureOwnName(this.session).
    const s1 = { identity, client, vc } as unknown as Session;
    const startup1 = ensureOwnName(s1);
    await new Promise((r) => setTimeout(r, 20)); // roster read, "old" being sent
    // restartEngine() (a settings change, a reconnect): a fresh Session object over the same identity and client.
    const s2 = { identity, client, vc } as unknown as Session;
    const startup2 = ensureOwnName(s2); // the row still reads as legacy: this one rewrites too, and lands at once (patch #2)
    await startup2;
    // The user renames on the current Session. It must wait for every rewrite still in
    // flight for this device, s1's included, so the slow "old" cannot land after "new".
    const rename = renameOwnDevice(s2, "new");
    releaseFirst();
    await startup1;
    await rename;

    expect(landed).toEqual(["old", "old", "new"]);
    expect(await vc.verifyName(fromB64(row.name_enc), ME)).toBe("new");
  });
});

describe("C. re-encryption strips compression and padding", () => {
  it("a few-KiB compressed, padded blob is 1 MiB after a rotation", async () => {
    const sa = await createVault(srv.url, ADMIN, "owner");
    const a = await new Device("owner", sa, { compress: true, pad: true }).start();
    try {
      const bytes = new Uint8Array(1 << 20); // all zeros: compresses ~1000:1
      await a.rawWrite("zeros.bin", bytes);
      await a.sync();
      const id = await sa.vc.blobId(bytes);
      const before = (await sa.client.getBlob(sa.identity.vaultId, id)).length;
      expect(before).toBeLessThan(64 * 1024);

      await removeDevice(sa, "");
      const after = (await sa.client.getBlob(sa.identity.vaultId, id)).length;
      expect(after, `before ${before} bytes, after ${after}`).toBeLessThan(64 * 1024);
      expect(after % PAD_BLOCK === 0 || after - 33 - 16 >= PAD_BLOCK, "padding kept").toBe(true);
    } finally {
      await a.cleanup();
    }
  });
});

describe("D. (soundness) the pre-decrypt ciphertext bound admits every honest blob", () => {
  it("ct.length <= size + PAD_BLOCK + 256 around every padding boundary, all four option combinations", async () => {
    const vc = new VaultCrypto(newKeyring());
    const sizes = [0, 1, 2, 3, 4, 5, 4090, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 8186, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 65536, 65537];
    for (const size of sizes) {
      for (const content of ["random", "zeros"] as const) {
        const pt = new Uint8Array(size);
        if (content === "random") for (let off = 0; off < size; off += 65536) crypto.getRandomValues(pt.subarray(off, Math.min(size, off + 65536)));
        const id = await vc.blobId(pt);
        for (const compress of [false, true]) {
          for (const pad of [false, true]) {
            const ct = await vc.encryptBlob(id, pt, { compress, pad });
            expect(ct.length, `size ${size} ${content} compress=${compress} pad=${pad}: ct ${ct.length}`).toBeLessThanOrEqual(size + PAD_BLOCK + 256);
          }
        }
      }
    }
  });
});
