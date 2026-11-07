/**
 * Regression tests from the fourth (hardening) review, 2026-11-07. Real Go
 * server, real Engines. Each was written as a proof that failed against the
 * code of the day and now pins the fix: an epoch regression keeps the newer
 * keys and reaches the user, and the invite-link join asks before plain http.
 *
 * Needs OBSYNC_SERVER_BIN (cd server && go build -o obsync ./cmd/obsync).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, rotate } from "../src/core/admin";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

describe("epoch authority", () => {
  /**
   * DESIGN §6.8 lets the server say "the epoch is 1 again" and the device
   * then makes K_1 current and DELETES K_2. That is the restore-from-backup
   * story, but the feed is not authenticated: a server that lies (or that a
   * removed member has a hand in) makes every honest device encrypt all new
   * content under a key the removed member still holds, and nothing reaches
   * the user: `log("warn")` is console-only in Obsidian. A regression should
   * at least stop sync with an error the user must acknowledge.
   */
  it("a server-reported epoch regression is adopted silently and the newer key is thrown away", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const a = await new Device("laptop", sa).start();
    await a.write("note.md", "under epoch 1");
    await a.sync();
    const backup = await srv.backup(); // what a hostile server would "restore": the pre-rotation state

    await rotate(sa); // epoch 2: the owner removed someone (or just rotated)
    expect(sa.vc.keyring.current).toBe(2);
    await a.write("note.md", "under epoch 2");
    await a.sync();

    await srv.restoreFrom(backup); // the server now claims epoch 1 and offers only the epoch-1 keybox
    let status = "ok";
    try {
      await a.sync();
    } catch (e) {
      status = String((e as Error).message);
    }
    const warned = a.logs.some((l) => /epoch went backwards/.test(l));
    const keptK2 = sa.vc.keyring.epochs.has(2);
    expect(
      keptK2 || status !== "ok",
      `device went back to epoch ${sa.vc.keyring.current}, K_2 kept: ${keptK2}, sync status: ${status}, only a console warning: ${warned}. New content is now written under the old key with no user-visible error.`,
    ).toBe(true);
    await a.cleanup();
  });
});

describe("plain http gate", () => {
  /**
   * docs/SECURITY-REVIEW-GUIDE.md: "The plugin asks for confirmation before
   * using http to a non-localhost host." settings.ts does so for the
   * passphrase join and for vault creation (`plainHttpOk`), but the invite
   * link path, the one setup flow every second device uses, hands the
   * link's server URL straight to joinWithLink. An `obsync://join#http://…`
   * link therefore sends the new device token in the clear without a word.
   */
  it("the invite-link join path confirms before using plain http like the other two entry points do", () => {
    const src = readFileSync(join(__dirname, "../src/obsidian/settings.ts"), "utf8");
    const start = src.indexOf("Join with invite link");
    const end = src.indexOf("Join with recovery passphrase");
    expect(start).toBeGreaterThan(0);
    const joinBlock = src.slice(start, end);
    expect(joinBlock).toContain("joinWithLink(");
    expect(joinBlock, "the invite-link Join handler calls joinWithLink without plainHttpOk; the passphrase and create flows both gate on it").toContain("plainHttpOk");
  });
});
