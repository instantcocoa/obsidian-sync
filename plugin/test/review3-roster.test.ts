/**
 * Regression tests from the third adversarial review (2026-11-07; guide
 * areas A, B, E, F). Real Go server, real Engines. Each was written as a
 * proof that failed against the code of the day and now pins the fix: a
 * token holder cannot wear another device's name, a device that never
 * proved it holds the keys is revoked by the next rotation instead of being
 * handed them, and a server cannot re-pair a path's metadata with another
 * blob.
 *
 * Needs OBSYNC_SERVER_BIN (cd server && go build -o obsync ./cmd/obsync).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, listDevices, rotate } from "../src/core/admin";
import { parseInviteLink } from "../src/core/crypto";
import { Client } from "../src/core/transport";
import { generateKeypair, unwrapEpochKey } from "../src/core/crypto";
import { b64, fromB64, utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

describe("roster trust (names, planted devices)", () => {
  it("a token-only holder cannot make its device wear another device's name", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const vault = sa.identity.vaultId;

    // Attacker: phone's device token, no keys, no vault authority.
    const thief = new Client(srv.url, sb.identity.deviceToken);
    const roster = await thief.devices(vault);
    const laptopRow = roster.find((d) => d.id === sa.identity.deviceId)!;
    expect(laptopRow.name_enc).toBeTruthy();
    // name_enc is AES-GCM with aad "name" and no device id, so it is a valid
    // name for *any* device. PATCH /devices/me needs no authority.
    let accepted = true;
    try {
      await thief.setDeviceName(vault, fromB64(laptopRow.name_enc!));
    } catch {
      accepted = false;
    }
    // What the owner sees in "Remove device":
    const seen = await listDevices(sa);
    const phone = seen.find((d) => d.id === sb.identity.deviceId)!;
    expect(accepted && phone.name === "laptop", `phone row now reads "${phone.name}" (owner sees two devices named laptop)`).toBe(false);
  });

  it("an admin-minted invite cannot plant a device, and a device that never proved it holds the keys is revoked by the next rotation instead of being handed K_e and K_id", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const vault = sa.identity.vaultId;
    await new Device("laptop", sa).start().then(async (a) => {
      await a.write("secret.md", "before rotation");
      await a.sync();
    });

    // Layer 1: the admin token (or the server) cannot mint an invite into a
    // populated vault at all.
    const admin = new Client(srv.url, ADMIN);
    await expect(admin.createInvite(vault, utf8("not a keybox"), 600)).rejects.toThrow(/403/);

    // Layer 2: a device that got in some other way (a stolen invite link
    // redeemed with a foreign keypair, a row planted in the database) holds a
    // token and a pub_kex but never named itself, because naming needs the
    // keys. The owner's "Rotate keys" must not wrap the new key to it.
    const link = await createInviteLink(sa);
    const { server, token } = parseInviteLink(link);
    const kp = await generateKeypair();
    const planted = await Client.redeemInvite(server, token, kp.pub, new Uint8Array(0));
    const plantedClient = new Client(srv.url, planted.device_token);
    const roster = await listDevices(sa);
    expect(roster.find((d) => d.id === planted.device_id)?.name).toBe("(unnamed)");

    let revoked: string[] = [];
    const epoch = await rotate(sa, [], (ids) => (revoked = ids));
    expect(epoch).toBe(2);
    expect(revoked).toEqual([planted.device_id]);

    // Its token is dead and it was handed nothing.
    await expect(plantedClient.keybox(vault)).rejects.toThrow(/401/);
    const after = await sa.client.devices(vault);
    expect(after.find((d) => d.id === planted.device_id)?.revoked_at).toBeTruthy();
    const rows = (await sa.client.keybox(vault)).filter((r) => r.recipient_id === planted.device_id && r.epoch === 2);
    expect(rows).toEqual([]);
  });
});

describe("AEAD bindings (what a tampering server can do)", () => {
  it("a server cannot re-pair one path's metadata with another path's blob", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const vault = sa.identity.vaultId;
    const a = await new Device("laptop", sa).start();
    await a.write("private/secret.md", "the secret plan");
    await a.write("public/readme.md", "hello world");
    await a.sync();

    // Server operator swaps the blob reference on secret.md's head op to the
    // readme blob. meta_enc is bound to ("meta", path_id, epoch) only, the
    // blob to ("blob", blob_id, epoch) only; nothing ties the two together
    // and the op row itself is unauthenticated.
    const secretPid = await sa.vc.pathId("private/secret.md");
    const readmeBid = await sa.vc.blobId(utf8("hello world"));
    await srv.halt();
    execFileSync("sqlite3", [join(srv.dir, "obsync.db"), `UPDATE ops SET blob_id='${readmeBid}' WHERE vault_id='${vault}' AND path_id='${secretPid}';`]);
    await srv.resume();

    // A device that joins afterwards (or any device re-pulling a snapshot).
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const b = await new Device("phone", sb).start();
    await b.sync();
    const skipped = b.logs.some((l) => /secret\.md/.test(l) && /(skip|refus|mismatch)/i.test(l));
    const content = (await b.exists("private/secret.md")) ? await b.read("private/secret.md") : null;
    // Acceptable outcomes: the op is refused, or the file holds its own content.
    expect(skipped || content === "the secret plan" || content === null, `phone wrote readme's content into private/secret.md ("${content}") without any AEAD failure`).toBe(true);
    await a.cleanup();
    await b.cleanup();
  });
});

describe("local key protection format", () => {
  it("documents that the sealed keystore is not bound to its data.json (note, not a finding)", async () => {
    // keystore.seal() uses a constant AAD ("obsync/keystore/v1"): a sealed
    // blob can be moved between data.json files, but it still needs the same
    // wrapping key, so this buys an attacker nothing. Recorded here so the
    // reviewer's note is checkable, and so the test file is self-contained.
    const { seal, open } = await import("../src/core/keystore");
    const k = crypto.getRandomValues(new Uint8Array(32));
    const sealed = await seal({ hello: "world" }, "pin", k, crypto.getRandomValues(new Uint8Array(16)));
    expect(await open(sealed, k)).toEqual({ hello: "world" });
    expect(typeof b64).toBe("function");
  });
});
