/**
 * Create links (DESIGN.md §5.9): the first device of a new vault redeems a
 * one-time link minted by the operator instead of pasting an admin token.
 * Real Go server, real CLI (`obsync vault create` as a second process).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device } from "./harness";
import { createVault, createInviteLink, joinWithLink, listDevices } from "../src/core/admin";
import { Client } from "../src/core/transport";
import { parseCreateLink, generateKeypair } from "../src/core/crypto";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

describe("create links", () => {
  it("the CLI's link creates a vault whose first device holds the keys, writes, names itself and invites; the link then dies", async () => {
    const link = await srv.createLink();
    expect(parseCreateLink(link).server).toBe(srv.url);
    const sa = await createVault(link, "laptop");
    expect(sa.identity.vaultId).toMatch(/^[0-9a-f]{32}$/);
    expect(sa.identity.deviceToken).toMatch(/^dv_/);
    // The first device registered vault authority and its name in finishEnrol.
    expect((await sa.client.vault(sa.identity.vaultId)).has_auth).toBe(true);
    const roster = await listDevices(sa);
    expect(roster.map((d) => d.name)).toEqual(["laptop"]);
    const a = await new Device("laptop", sa).start();
    await a.write("notes/hello.md", "# hello\n");
    await a.sync();
    // Second device via a normal invite; it sees the note.
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const b = await new Device("phone", sb).start();
    await b.sync();
    expect(await b.read("notes/hello.md")).toBe("# hello\n");
    // One-time: the same link cannot make a second vault.
    await expect(createVault(link, "again")).rejects.toThrow(/already used or has expired/);
  });

  it("a create link is not a key to anything that exists", async () => {
    const sa = await createVault(await srv.createLink(), "owner");
    const vault = sa.identity.vaultId;
    const link = await srv.createLink();
    const { server, token } = parseCreateLink(link);
    const holder = new Client(server, token);
    // Not a device token: every vault route refuses it.
    await expect(holder.vault(vault)).rejects.toThrow(/401/);
    await expect(holder.snapshot(vault)).rejects.toThrow(/401/);
    // Not an invite: it cannot be redeemed as one.
    await expect(Client.redeemInvite(server, token, (await generateKeypair()).pub, new Uint8Array(0))).rejects.toThrow(/already used or has expired/);
    // Not vault authority: with a stolen device token and the link as the authority header, writes still fail.
    const thief = new Client(server, sa.identity.deviceToken, { vaultAuth: async () => token });
    await expect(thief.createInvite(vault, utf8("x"), 60)).rejects.toThrow(/401/);
    // And the owner's vault still has exactly one device.
    expect((await listDevices(sa)).length).toBe(1);
    // The link itself still works for what it is for.
    const other = await createVault(link, "someone else");
    expect(other.identity.vaultId).not.toBe(vault);
  });

  it("a malformed or foreign link is refused before anything is sent", async () => {
    await expect(createVault("obsync://join#x,y,z", "d")).rejects.toThrow(/not an obsync create link/);
    await expect(createVault("obsync://create#https%3A%2F%2Fowner.example%40evil.example,cr_abc", "d")).rejects.toThrow(/plain http\(s\) address/);
    await expect(createVault(`obsync://create#${encodeURIComponent(srv.url)},cr_nonsense`, "d")).rejects.toThrow(/already used or has expired/);
  });
});
