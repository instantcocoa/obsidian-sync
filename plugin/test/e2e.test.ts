/**
 * End-to-end: real Go server, real files on disk, two or more Engines.
 * Covers the scenarios in DESIGN.md §6–8: bootstrap, propagation, rename
 * dedup, concurrent edits (merge and sibling), deletes, exclusions, config
 * dir mapping, state loss, interrupted writes, rotation, recovery, restore.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { promises as fsp } from "node:fs";
import { join } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, listDevices, removeDevice, setRecoveryPassphrase, joinWithPassphrase, reencrypt } from "../src/core/admin";
import { DEFAULT_EXCLUSIONS } from "../src/core/paths";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

async function pair(): Promise<[Device, Device]> {
  const sa = await createVault(srv.url, ADMIN, "laptop");
  const link = await createInviteLink(sa);
  const sb = await joinWithLink(link, "phone");
  const a = await new Device("laptop", sa).start();
  const b = await new Device("phone", sb).start();
  return [a, b];
}

describe("two devices", () => {
  it("bootstraps, propagates, preserves bytes and mtimes, renames for free", async () => {
    const [a, b] = await pair();
    const png = new Uint8Array(70000).map((_, i) => (i * 7919) & 0xff);
    const mt = 1_700_000_000_000;
    await a.write("notes/hello.md", "# Hello\n\nworld\n", mt);
    await a.write("attachments/pic.png", png, mt + 1000);
    await a.write(".obsidian/app.json", '{"theme":"obsidian"}\n', mt + 2000);
    await a.write(".obsidian/plugins/dataview/data.json", '{"a":1}', mt + 3000);
    await a.write(".obsidian/workspace.json", '{"should":"not sync"}'); // excluded by default
    await a.sync();
    expect(a.uploads).toBe(4);
    await b.sync();
    expect(await b.files()).toEqual([".obsidian/app.json", ".obsidian/plugins/dataview/data.json", "attachments/pic.png", "notes/hello.md"]);
    expect(await b.read("notes/hello.md")).toBe("# Hello\n\nworld\n");
    expect(await b.readBytes("attachments/pic.png")).toEqual(png);
    expect((await b.fs.stat("notes/hello.md"))!.mtime).toBe(mt);
    expect(await b.exists(".obsidian/workspace.json")).toBe(false);

    // Edit on B flows back.
    await b.write("notes/hello.md", "# Hello\n\nworld, edited on phone\n");
    await b.sync();
    await a.sync();
    expect(await a.read("notes/hello.md")).toBe("# Hello\n\nworld, edited on phone\n");

    // Rename the big attachment on A: delete + put, zero blob uploads.
    const before = a.uploads;
    await a.write("attachments/renamed.png", png, mt + 1000);
    await a.remove("attachments/pic.png");
    await a.sync();
    expect(a.uploads).toBe(before);
    await b.sync();
    expect(await b.exists("attachments/pic.png")).toBe(false);
    expect(await b.readBytes("attachments/renamed.png")).toEqual(png);

    // Nothing to do → no network writes.
    const [u, p] = [a.uploads, a.posts];
    await a.sync();
    await b.sync();
    expect([a.uploads, a.posts]).toEqual([u, p]);
    await a.cleanup();
    await b.cleanup();
  });

  it("merges non-overlapping concurrent edits and makes siblings for overlapping ones", async () => {
    const [a, b] = await pair();
    await a.write("doc.md", "line1\nline2\nline3\nline4\n");
    await a.sync();
    await b.sync();
    // Non-overlapping: A edits top, B edits bottom.
    await a.write("doc.md", "LINE1\nline2\nline3\nline4\n");
    await b.write("doc.md", "line1\nline2\nline3\nLINE4\n");
    await a.sync();
    await b.sync(); // B: push conflicts → merge → push merged
    await a.sync(); // A receives the merge
    expect(await a.read("doc.md")).toBe("LINE1\nline2\nline3\nLINE4\n");
    expect(await b.read("doc.md")).toBe("LINE1\nline2\nline3\nLINE4\n");
    expect(a.conflicts.length + b.conflicts.length).toBe(0);

    // Overlapping: both change line2.
    await a.write("doc.md", "LINE1\nA2\nline3\nLINE4\n");
    await b.write("doc.md", "LINE1\nB2\nline3\nLINE4\n");
    await a.sync();
    await b.sync();
    await a.sync();
    expect(b.conflicts.length).toBe(1);
    const [, sibling] = b.conflicts[0];
    expect(sibling).toMatch(/^doc \(conflict phone \d{4}-\d{2}-\d{2} \d{4}\)\.md$/);
    expect(await b.read("doc.md")).toBe("LINE1\nA2\nline3\nLINE4\n"); // head wins at the path
    expect(await b.read(sibling)).toBe("LINE1\nB2\nline3\nLINE4\n"); // local kept beside it
    expect(await a.read(sibling)).toBe("LINE1\nB2\nline3\nLINE4\n"); // and synced to A
    expect(a.engine.conflictFiles()).toEqual([sibling]);

    // JSON config merge at key level.
    await a.write(".obsidian/app.json", '{\n  "a": 1,\n  "b": 2\n}\n');
    await a.sync();
    await b.sync();
    await a.write(".obsidian/app.json", '{\n  "a": 10,\n  "b": 2\n}\n');
    await b.write(".obsidian/app.json", '{\n  "a": 1,\n  "b": 20,\n  "c": 3\n}\n');
    await a.sync();
    await b.sync();
    await a.sync();
    expect(JSON.parse(await a.read(".obsidian/app.json"))).toEqual({ a: 10, b: 20, c: 3 });
    await a.cleanup();
    await b.cleanup();
  });

  it("deletes propagate; a local edit survives a stale remote delete", async () => {
    const [a, b] = await pair();
    await a.write("x.md", "x");
    await a.write("y.md", "y");
    await a.sync();
    await b.sync();
    await a.remove("x.md");
    await a.sync();
    await b.sync();
    expect(await b.exists("x.md")).toBe(false);
    // A deletes y while B edits y → B's edit wins and comes back to A.
    await a.remove("y.md");
    await b.write("y.md", "y edited");
    await a.sync();
    await b.sync();
    await a.sync();
    expect(await a.read("y.md")).toBe("y edited");
    expect(await b.read("y.md")).toBe("y edited");
    // B deletes while A edits: A's push conflicts with the tombstone → A keeps its edit.
    await b.remove("y.md");
    await b.sync();
    await a.write("y.md", "y edited again");
    await a.sync();
    await b.sync();
    expect(await b.read("y.md")).toBe("y edited again");
    await a.cleanup();
    await b.cleanup();
  });

  it("mass-deletion guard holds large deletions until confirmed", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    let asked: string[] = [];
    const a = await new Device("laptop", sa, { massDelete: { min: 3, fraction: 0.2 }, hooks: { confirmMassDelete: async (p) => ((asked = p), false) } }).start();
    for (let i = 0; i < 10; i++) await a.write(`n${i}.md`, String(i));
    await a.sync();
    for (let i = 0; i < 5; i++) await a.remove(`n${i}.md`);
    const posts = a.posts;
    await a.sync();
    expect(asked.length).toBe(5);
    expect(a.posts).toBe(posts); // nothing pushed
    expect(a.engine.heldDeletes.length).toBe(5);
    a.engine.applyHeldDeletes();
    await a.engine.sync();
    expect(a.posts).toBe(posts + 5);
    await a.cleanup();
  });

  it("maps the config dir per device and honours per-device exclusions", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("laptop", sa).start();
    // B uses a differently named config dir and excludes a heavy plugin and a private folder.
    const b = await new Device("phone", sb, { configDir: ".obsidian-phone", exclusions: [...DEFAULT_EXCLUSIONS, "/$CONFIG/plugins/heavy/", "Private/"] }).start();
    await a.write(".obsidian/app.json", "{}");
    await a.write(".obsidian/plugins/heavy/main.js", "big");
    await a.write("Private/secret.md", "s");
    await a.write("notes/ok.md", "ok");
    await a.sync();
    await b.sync();
    expect(await b.files()).toEqual([".obsidian-phone/app.json", "notes/ok.md"]);
    // Un-excluding later fetches the head without a server change.
    await b.engine.setExclusions(DEFAULT_EXCLUSIONS);
    await b.engine.rebuildState();
    await b.sync();
    expect(await b.files()).toEqual([".obsidian-phone/app.json", ".obsidian-phone/plugins/heavy/main.js", "Private/secret.md", "notes/ok.md"]);
    await a.cleanup();
    await b.cleanup();
  });

  it("a joining device adopts the vault's config files instead of making conflict copies", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const a = await new Device("laptop", sa).start();
    await a.write(".obsidian/app.json", '{"theme":"dark","from":"A"}');
    await a.write(".obsidian/community-plugins.json", '["obsync","dataview"]');
    await a.write("notes/shared.md", "from A\n");
    await a.sync();
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const b = await new Device("phone", sb).start();
    // Obsidian wrote defaults on B before the plugin joined, and the user also copied a note over by hand.
    await b.write(".obsidian/app.json", '{"legacyEditor":false,"safeMode":false}');
    await b.write(".obsidian/community-plugins.json", '["obsync"]');
    await b.write("notes/shared.md", "copied by hand, differs\n");
    await b.sync();
    expect(await b.read(".obsidian/app.json")).toBe('{"theme":"dark","from":"A"}');
    expect(await b.read(".obsidian/community-plugins.json")).toBe('["obsync","dataview"]');
    // A user file that differs with no shared base is preserved as a sibling, never discarded.
    expect(await b.read("notes/shared.md")).toBe("from A\n");
    expect(b.conflicts.length).toBe(1);
    expect(b.conflicts[0][1]).toMatch(/^notes\/shared \(conflict phone /);
    const files = await b.files();
    expect(files.filter((f) => f.includes("(conflict")).length).toBe(1); // only the note, no config siblings
    await a.sync();
    expect(await a.read(b.conflicts[0][1])).toBe("copied by hand, differs\n");
    await a.cleanup();
    await b.cleanup();
  });

  it("survives state loss and interrupted writes without spurious uploads", async () => {
    const [a, b] = await pair();
    for (let i = 0; i < 20; i++) await a.write(`n/${i}.md`, `note ${i}\n`);
    await a.sync();
    await b.sync();
    // Lose B's state (simulating a crash so the engine cannot write it back first).
    await b.engine.flushState();
    await fsp.rm(await b.stateFile());
    await b.restart({ crash: true });
    const [u, p] = [b.uploads, b.posts];
    await b.sync();
    expect([b.uploads, b.posts]).toEqual([u, p]);
    expect((await b.files()).length).toBe(20);
    // Interrupted write: inflight record says blob X is being written, disk has garbage.
    await a.write("n/0.md", "note 0 v2\n");
    await a.sync();
    await b.engine.flushState();
    const st = JSON.parse(await fsp.readFile(await b.stateFile(), "utf8"));
    st.inflight["n/0.md"] = { blob: "ff".repeat(32), seq: 99, size: 1, mtime: 1 };
    await fsp.writeFile(await b.stateFile(), JSON.stringify(st));
    await b.rawWrite("n/0.md", new TextEncoder().encode("partial garbage"));
    await b.restart({ crash: true });
    await b.sync();
    expect(await b.read("n/0.md")).toBe("note 0 v2\n");
    expect(b.uploads).toBe(u); // garbage was never uploaded
    await a.cleanup();
    await b.cleanup();
  });

  it("rotation locks out a removed device; new and recovered devices read everything", async () => {
    const [a, b] = await pair();
    await a.write("secret.md", "before rotation\n");
    await a.sync();
    await b.sync();
    await setRecoveryPassphrase(a.session, "correct horse battery staple");
    const roster = await listDevices(a.session);
    expect(roster.map((d) => d.name).sort()).toEqual(["(recovery passphrase)", "laptop", "phone"]);
    const phone = roster.find((d) => d.name === "phone")!;
    let progress = 0;
    await removeDevice(a.session, phone.id, () => progress++);
    expect(progress).toBeGreaterThan(0);
    const info = await a.session.client.vault(a.session.identity.vaultId);
    expect(info.epoch).toBe(2);
    expect(info.min_epoch).toBe(2); // everything re-encrypted
    expect(a.session.identity.keyring.epochs["1"]).toBeUndefined(); // old key pruned
    // B is locked out.
    await expect(b.sync()).rejects.toThrow(/401|forbidden|removed/i);
    // A keeps working under epoch 2.
    await a.write("after.md", "after rotation\n");
    await a.sync();
    // New device via invite reads old (re-encrypted) and new data.
    const sc = await joinWithLink(await createInviteLink(a.session), "tablet");
    const c = await new Device("tablet", sc).start();
    await c.sync();
    expect(await c.read("secret.md")).toBe("before rotation\n");
    expect(await c.read("after.md")).toBe("after rotation\n");
    // Recovery join with only the passphrase.
    const sd = await joinWithPassphrase(srv.url, a.session.identity.vaultId, "correct horse battery staple", "desktop2");
    const d = await new Device("desktop2", sd).start();
    await d.sync();
    expect(await d.read("secret.md")).toBe("before rotation\n");
    await expect(joinWithPassphrase(srv.url, a.session.identity.vaultId, "wrong", "x")).rejects.toThrow(/passphrase/);
    // A second rotation reaches C and D through the keybox without a restart.
    await removeDevice(a.session, (await listDevices(a.session)).find((x) => x.name === "tablet")!.id);
    await a.write("epoch3.md", "e3\n");
    await a.sync();
    await d.sync();
    expect(await d.read("epoch3.md")).toBe("e3\n");
    await expect(c.sync()).rejects.toThrow();
    await Promise.all([a.cleanup(), b.cleanup(), c.cleanup(), d.cleanup()]);
  }, 120_000);

  it("restores the vault to a point in time", async () => {
    const [a, b] = await pair();
    await a.write("r.md", "v1\n");
    await a.sync();
    await new Promise((r) => setTimeout(r, 20));
    const t = Date.now();
    await new Promise((r) => setTimeout(r, 20));
    await a.write("r.md", "v2\n");
    await a.write("new.md", "n\n");
    await a.sync();
    await b.sync();
    const res = await a.session.client.restore(a.session.identity.vaultId, t);
    expect(res.emitted).toBe(1); // r.md back to v1; new.md did not exist at t and is untouched
    await a.sync();
    await b.sync();
    expect(await a.read("r.md")).toBe("v1\n");
    expect(await b.read("r.md")).toBe("v1\n");
    expect(await b.exists("new.md")).toBe(true);
    await a.cleanup();
    await b.cleanup();
  });
});
