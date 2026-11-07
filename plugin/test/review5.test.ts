/**
 * Regression tests from the fifth review (2026-11-07), which checked the
 * fourth round's own plugin changes. Real Go server, real Engines. Each was
 * a failing proof at the time and now pins the fix: a recovery passphrase
 * set before the KDF change still opens the vault, an unused restore
 * acceptance is spent rather than kept, an accepted device stays correct
 * after a restart, and a lost state file cannot hide a device that joined.
 *
 *   cd server && go build -o obsync ./cmd/obsync
 *   cd ../plugin && OBSYNC_SERVER_BIN=$PWD/../server/obsync npx vitest run test/review5.test.ts
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { rmSync } from "node:fs";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, joinWithPassphrase, rotate } from "../src/core/admin";
import { generateKeypair, recoveryAuthToken, wrapEpochKey, RECOVERY_ITERATIONS } from "../src/core/crypto";
import { Client } from "../src/core/transport";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

// ---------- a 0.1.2 client's recovery derivation, byte for byte ----------
// crypto.ts at tags 0.1.1 and 0.1.2: PBKDF2-SHA-256 x PBKDF2_ITERATIONS
// (600 000) -> 32 B seed -> HKDF("obsync/recovery/{wrap,auth}/v1"). The
// server stores salt + hash(auth token); recovery_enc carries version byte 1.
const subtle = globalThis.crypto.subtle;
const utf8 = (s: string) => new TextEncoder().encode(s);
const buf = (u: Uint8Array) => u as unknown as BufferSource;
async function hkdf012(ikm: Uint8Array, info: string): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", buf(ikm), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: buf(new Uint8Array(0)), info: buf(utf8(info)) }, k, 256));
}
async function kdf012(passphrase: string, salt: Uint8Array): Promise<{ wrapKey: Uint8Array; auth: Uint8Array }> {
  const base = await subtle.importKey("raw", buf(utf8(passphrase.normalize("NFC"))), "PBKDF2", false, ["deriveBits"]);
  const seed = new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: buf(salt), iterations: 600_000 }, base, 256));
  return { wrapKey: await hkdf012(seed, "obsync/recovery/wrap/v1"), auth: await hkdf012(seed, "obsync/recovery/auth/v1") };
}
async function createRecovery012(passphrase: string) {
  const kp = await generateKeypair();
  const priv = await subtle.importKey("jwk", kp.privJwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", priv));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const { wrapKey, auth } = await kdf012(passphrase, salt);
  const key = await subtle.importKey("raw", buf(wrapKey), "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: buf(nonce), additionalData: buf(utf8("recovery")) }, key, buf(pkcs8)));
  const recoveryEnc = new Uint8Array(1 + 16 + 12 + ct.length);
  recoveryEnc.set([1], 0);
  recoveryEnc.set(salt, 1);
  recoveryEnc.set(nonce, 17);
  recoveryEnc.set(ct, 29);
  return { recoveryEnc, salt, pub: kp.pub, authToken: recoveryAuthToken(auth) };
}

describe("recovery passphrase across the KDF change (aca5ce1: 600k -> 2M iterations)", () => {
  /**
   * Nothing records which iteration count a recovery identity was
   * made with: recovery_enc keeps version byte 1, GET /recovery hands out
   * only the salt, and the auth token is derived from the same PBKDF2
   * output. A passphrase set by 0.1.1/0.1.2 therefore derives a different
   * auth token on 0.1.3 and the server answers 401: "wrong recovery
   * passphrase", for a passphrase that is right. The recovery path is the
   * one you use when every device is gone, so nobody notices until then.
   */
  it("a passphrase set by a 0.1.2 client still opens the vault for a 0.1.3 client", async () => {
    expect(RECOVERY_ITERATIONS).not.toBe(600_000); // the change under test
    const pass = "correct horse battery staple";
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const v = sa.identity.vaultId;
    const rec = await createRecovery012(pass);
    const { device_id } = await sa.client.setRecovery(v, rec.pub, rec.recoveryEnc, rec.salt, rec.authToken);
    const rows = [];
    for (const [epoch, key] of sa.vc.keyring.epochs) rows.push({ epoch, recipient_id: device_id, wrapped: await wrapEpochKey(rec.pub, v, epoch, device_id, key, sa.vc.keyring.kId) });
    await sa.client.putKeybox(v, rows, { authority: true });

    // The material is sound: a 0.1.2 client (old derivation) gets through the door.
    const kp = await generateKeypair();
    await expect(Client.recoveryJoin(srv.url, v, rec.authToken, kp.pub, new Uint8Array(0))).resolves.toBeTruthy();

    // The 0.1.3 client, same passphrase.
    await expect(
      joinWithPassphrase(srv.url, v, pass, "phone"),
      "the recovery passphrase set on 0.1.2 is refused by 0.1.3: the iteration count changed and nothing stored says which one applies",
    ).resolves.toBeTruthy();
  }, 120_000);
});

describe("restore acceptance (engine.ts restoreAccepted)", () => {
  /**
   * acceptServerRestore() sets a flag that only the next regression
   * clears. If no regression follows (the person ran the command early, by
   * mistake, or the server moved on), the flag outlives the pause for the
   * rest of the session, and a later regression, the one a lying server
   * would produce, is adopted with no notice at all.
   */
  it("an acceptance with no regression pending is spent, not kept for the next one", async () => {
    const own = await TestServer.start();
    const sa = await createVault(own.url, ADMIN, "laptop");
    const regressions: string[] = [];
    const a = await new Device("laptop", sa, { hooks: { onEpochRegressed: (f, t) => regressions.push(`${f}->${t}`) } }).start();
    await a.write("note.md", "epoch 1\n");
    await a.sync();
    const backup = await own.backup();
    await rotate(sa);
    await a.write("note.md", "epoch 2\n");
    await a.sync();
    expect(sa.vc.keyring.current).toBe(2);

    a.engine.acceptServerRestore(); // nothing is paused; the command was run anyway
    await a.sync(); // a normal sync: the acceptance had nothing to accept
    expect(regressions).toEqual([]);

    await own.restoreFrom(backup); // now the server says epoch 1
    let paused = false;
    try {
      await a.sync();
    } catch {
      paused = true;
    }
    expect(
      paused || regressions.length > 0,
      `the regression 2->1 was adopted silently (keyring.current=${sa.vc.keyring.current}, notices=${regressions.length}): the earlier acceptance was still armed`,
    ).toBe(true);
    await a.cleanup();
    await own.stop();
  }, 120_000);

  /** Holds (confirmation). After acceptance the device restarts into the restored epoch and keeps syncing. */
  it("a device that accepted a restore is still correct after a restart", async () => {
    const own = await TestServer.start();
    const sa = await createVault(own.url, ADMIN, "laptop");
    const a = await new Device("laptop", sa).start();
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const b = await new Device("phone", sb).start();
    await a.write("k.md", "epoch 1\n");
    await a.sync();
    await b.sync();
    const backup = await own.backup();
    await rotate(sa);
    await a.write("k.md", "epoch 2\n");
    await a.sync();
    await b.sync();
    await own.restoreFrom(backup);
    for (const d of [a, b]) {
      await expect(d.sync()).rejects.toThrow(/went backwards/);
      d.engine.acceptServerRestore();
    }
    for (let i = 0; i < 6; i++) {
      await a.sync();
      await b.sync();
    }
    expect(sa.vc.keyring.current).toBe(1);
    await a.restart();
    await a.write("after.md", "written after the restart\n");
    await expect(a.sync()).resolves.toBeUndefined();
    expect(a.engine.getStatus().phase).toBe("idle");
    await b.sync();
    expect(await b.read("after.md")).toBe("written after the restart\n");
    expect(await b.read("k.md")).toBe("epoch 2\n");
    await Promise.all([a.cleanup(), b.cleanup()]);
    await own.stop();
  }, 120_000);
});

describe("roster watch (engine.ts watchRoster)", () => {
  /**
   * The list of known devices lives in state.json, which the engine
   * treats as a cache: loadState() starts empty when the file is unreadable
   * (a reload racing the previous instance's flush, documented in
   * engine.ts), and "Rebuild local sync state" throws it away on purpose.
   * The next look is then a "first look" and announces nothing, so every
   * device that joined meanwhile is absorbed as if it had always been there.
   */
  it("a device that joined while this device's state.json was lost is still announced", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const seen: { id: string; name: string }[][] = [];
    const a = await new Device("laptop", sa, { hooks: { onNewDevices: (ds) => seen.push(ds) } }).start();
    await a.write("note.md", "hello\n");
    await a.sync();
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const b = await new Device("phone", sb).start();
    await b.sync();
    await a.sync();
    expect(seen.flat().map((d) => d.name)).toEqual(["phone"]); // the alert works in the ordinary case

    await a.engine.flushState();
    rmSync(await a.stateFile(), { force: true }); // what the documented reload race, or Rebuild, leaves behind
    await a.restart({ crash: true });

    const leaked = await joinWithLink(await createInviteLink(sa), "stranger"); // a leaked link, redeemed meanwhile
    const c = await new Device("stranger", leaked).start();
    await c.sync();
    await a.sync();
    expect(seen.flat().map((d) => d.name), "the stranger joined while state.json was gone and was never announced: the first look after a state loss suppresses everything").toContain("stranger");
    await Promise.all([a.cleanup(), b.cleanup(), c.cleanup()]);
  });
});
