/**
 * Every conflict shape and recovery path, one scenario each, against the
 * real server with real files (DESIGN.md §6.6, §6.8, §8). The matrix in
 * docs/CONFLICT-RECOVERY-MATRIX.md maps each row here.
 *
 * The invariant under test everywhere: nothing a user wrote is ever lost.
 * After the devices converge, every version that was current on some
 * device when it synced is either the file itself, a conflict sibling, or
 * an ancestor the server's history still holds.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { promises as fsp } from "node:fs";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, listDevices, removeDevice } from "../src/core/admin";
import { NetworkError } from "../src/core/transport";
import { CONFLICT_RE } from "../src/core/paths";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

async function pair(s: TestServer = srv): Promise<[Device, Device]> {
  const sa = await createVault(s.url, ADMIN, "laptop");
  const sb = await joinWithLink(await createInviteLink(sa), "phone");
  return [await new Device("laptop", sa).start(), await new Device("phone", sb).start()];
}
async function trio(): Promise<[Device, Device, Device]> {
  const sa = await createVault(srv.url, ADMIN, "laptop");
  const sb = await joinWithLink(await createInviteLink(sa), "phone");
  const sc = await joinWithLink(await createInviteLink(sa), "tablet");
  return [await new Device("laptop", sa).start(), await new Device("phone", sb).start(), await new Device("tablet", sc).start()];
}

/** Sync every device until two consecutive rounds change nothing on any of them. */
async function converge(devs: Device[], maxRounds = 8): Promise<void> {
  let quiet = 0;
  for (let i = 0; i < maxRounds && quiet < 2; i++) {
    const before = devs.map((d) => d.posts + d.uploads);
    for (const d of devs) await d.sync();
    quiet = devs.every((d, k) => d.posts + d.uploads === before[k]) ? quiet + 1 : 0;
  }
  expect(quiet, "devices kept producing ops instead of converging").toBeGreaterThanOrEqual(2);
}

/** Full file map of a device: path → utf8 text (or hex for binary). */
async function contents(d: Device): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const f of await d.files()) out[f] = Buffer.from(await d.readBytes(f)).toString("latin1");
  return out;
}

async function expectIdentical(devs: Device[]): Promise<Record<string, string>> {
  const maps = await Promise.all(devs.map(contents));
  for (let i = 1; i < maps.length; i++) expect(maps[i], `${devs[i].name} differs from ${devs[0].name}`).toEqual(maps[0]);
  return maps[0];
}

const siblingsOf = (files: string[], stem: string) => files.filter((f) => f.startsWith(stem) && CONFLICT_RE.test(f)).sort();

describe("conflict shapes", () => {
  it("1 create/create: same path, different bytes, no shared base -> one sibling, both versions kept", async () => {
    const [a, b] = await pair();
    await a.write("new.md", "from laptop\n");
    await b.write("new.md", "from phone\n");
    await a.sync();
    await b.sync();
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m["new.md"]).toBe("from laptop\n");
    const sibs = siblingsOf(Object.keys(m), "new (conflict phone");
    expect(sibs).toHaveLength(1);
    expect(m[sibs[0]]).toBe("from phone\n");
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("2 create/create with identical bytes converges without a sibling or a second upload", async () => {
    const [a, b] = await pair();
    await a.write("same.md", "identical\n");
    await b.write("same.md", "identical\n");
    await a.sync();
    const u = b.uploads;
    await b.sync();
    expect(b.uploads).toBe(u); // the blob was already there
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(Object.keys(m)).toEqual(["same.md"]);
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("3 delete/delete and edit-to-identical converge with no ops wasted", async () => {
    const [a, b] = await pair();
    await a.write("gone.md", "x\n");
    await a.write("both.md", "v1\n");
    await a.sync();
    await b.sync();
    await a.remove("gone.md");
    await b.remove("gone.md");
    await a.write("both.md", "v2\n");
    await b.write("both.md", "v2\n");
    await a.sync();
    await b.sync();
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m).toEqual({ "both.md": "v2\n" });
    expect(a.conflicts.length + b.conflicts.length).toBe(0);
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("4 three devices editing the same line: every version survives, all three converge", async () => {
    const [a, b, c] = await trio();
    await a.write("shared.md", "line1\nline2\nline3\n");
    await a.sync();
    await b.sync();
    await c.sync();
    await a.write("shared.md", "line1\nA\nline3\n");
    await b.write("shared.md", "line1\nB\nline3\n");
    await c.write("shared.md", "line1\nC\nline3\n");
    await converge([a, b, c]);
    const m = await expectIdentical([a, b, c]);
    const texts = Object.values(m).sort();
    expect(texts).toEqual(["line1\nA\nline3\n", "line1\nB\nline3\n", "line1\nC\nline3\n"]);
    expect(m["shared.md"]).toBe("line1\nA\nline3\n");
    expect(siblingsOf(Object.keys(m), "shared (conflict")).toHaveLength(2);
    await Promise.all([a.cleanup(), b.cleanup(), c.cleanup()]);
  });

  it("5 three devices, non-overlapping edits of one file all merge cleanly", async () => {
    const [a, b, c] = await trio();
    await a.write("merge.md", "top\n\nmiddle\n\nbottom\n");
    await converge([a, b, c]);
    await a.write("merge.md", "TOP\n\nmiddle\n\nbottom\n");
    await b.write("merge.md", "top\n\nMIDDLE\n\nbottom\n");
    await c.write("merge.md", "top\n\nmiddle\n\nBOTTOM\n");
    await converge([a, b, c]);
    const m = await expectIdentical([a, b, c]);
    expect(m).toEqual({ "merge.md": "TOP\n\nMIDDLE\n\nBOTTOM\n" });
    await Promise.all([a.cleanup(), b.cleanup(), c.cleanup()]);
  });

  it("6 binary concurrent edit makes a sibling with exact bytes (no merge attempt)", async () => {
    const [a, b] = await pair();
    const v1 = new Uint8Array(3 * 1024 * 1024).map((_, i) => (i * 31) & 0xff);
    await a.write("img.bin", v1);
    await converge([a, b]);
    const va = new Uint8Array(v1);
    va[1000] ^= 0xff;
    const vb = new Uint8Array(v1);
    vb[2_000_000] ^= 0xff;
    await a.write("img.bin", va);
    await b.write("img.bin", vb);
    await converge([a, b]);
    const files = await b.files();
    const sib = siblingsOf(files, "img (conflict phone");
    expect(sib).toHaveLength(1);
    const same = (x: Uint8Array, y: Uint8Array) => Buffer.compare(Buffer.from(x), Buffer.from(y)) === 0;
    expect(same(await b.readBytes("img.bin"), va)).toBe(true);
    expect(same(await b.readBytes(sib[0]), vb)).toBe(true);
    expect(same(await a.readBytes(sib[0]), vb)).toBe(true);
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("7 two conflicts on one file within the same minute keep two siblings (no overwrite)", async () => {
    const [a, b] = await pair();
    await a.write("hot.md", "base\n");
    await converge([a, b]);
    // Round one: overlapping edit.
    await a.write("hot.md", "A1\n");
    await b.write("hot.md", "B1\n");
    await a.sync();
    await b.sync();
    // Round two, same minute: B edits again, A edits again.
    await a.write("hot.md", "A2\n");
    await b.write("hot.md", "B2\n");
    await a.sync();
    await b.sync();
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m["hot.md"]).toBe("A2\n");
    const sibs = siblingsOf(Object.keys(m), "hot (conflict phone");
    expect(sibs).toHaveLength(2);
    expect(sibs.map((s) => m[s]).sort()).toEqual(["B1\n", "B2\n"]);
    expect(sibs.some((s) => / 2\)\.md$/.test(s))).toBe(true);
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("8 a conflict on a conflict sibling resolves like any other file", async () => {
    const [a, b] = await pair();
    await a.write("n.md", "base\n");
    await converge([a, b]);
    await a.write("n.md", "A\n");
    await b.write("n.md", "B\n");
    await converge([a, b]);
    const sib = siblingsOf(await a.files(), "n (conflict phone")[0];
    await a.write(sib, "A edits the copy\n");
    await b.write(sib, "B edits the copy\n");
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m[sib]).toBe("A edits the copy\n");
    const nested = Object.keys(m).filter((f) => f !== sib && f.startsWith("n (conflict phone") && CONFLICT_RE.test(f));
    expect(nested).toHaveLength(1);
    expect(m[nested[0]]).toBe("B edits the copy\n");
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("9 CRLF text: non-overlapping edits merge and keep CRLF; overlapping ones make a sibling", async () => {
    const [a, b] = await pair();
    await a.write("win.md", "one\r\ntwo\r\nthree\r\nfour\r\n");
    await converge([a, b]);
    await a.write("win.md", "ONE\r\ntwo\r\nthree\r\nfour\r\n");
    await b.write("win.md", "one\r\ntwo\r\nthree\r\nFOUR\r\n");
    await converge([a, b]);
    let m = await expectIdentical([a, b]);
    expect(m).toEqual({ "win.md": "ONE\r\ntwo\r\nthree\r\nFOUR\r\n" });
    await a.write("win.md", "ONE\r\nA\r\nthree\r\nFOUR\r\n");
    await b.write("win.md", "ONE\r\nB\r\nthree\r\nFOUR\r\n");
    await converge([a, b]);
    m = await expectIdentical([a, b]);
    expect(m["win.md"]).toBe("ONE\r\nA\r\nthree\r\nFOUR\r\n");
    expect(siblingsOf(Object.keys(m), "win (conflict phone")).toHaveLength(1);
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("10 empty files: empty/empty converges, empty vs content makes a sibling", async () => {
    const [a, b] = await pair();
    await a.write("e.md", "");
    await b.write("e.md", "");
    await a.write("f.md", "");
    await b.write("f.md", "content\n");
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m["e.md"]).toBe("");
    expect(m["f.md"]).toBe("");
    const sib = siblingsOf(Object.keys(m), "f (conflict phone");
    expect(sib).toHaveLength(1);
    expect(m[sib[0]]).toBe("content\n");
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("11 rename on one device vs edit on the other keeps both files (edit survives the delete)", async () => {
    const [a, b] = await pair();
    await a.write("old.md", "v1\n");
    await converge([a, b]);
    await a.write("new.md", "v1\n");
    await a.remove("old.md");
    await b.write("old.md", "v2 on phone\n");
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m).toEqual({ "new.md": "v1\n", "old.md": "v2 on phone\n" });
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("12 folder deleted on one device while the other edits inside it: the edited file survives", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("laptop", sa, { massDelete: { min: 1000, fraction: 1 } }).start();
    const b = await new Device("phone", sb).start();
    for (let i = 0; i < 5; i++) await a.write(`proj/${i}.md`, `${i}\n`);
    await converge([a, b]);
    for (let i = 0; i < 5; i++) await a.remove(`proj/${i}.md`);
    await b.write("proj/3.md", "edited on phone\n");
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m).toEqual({ "proj/3.md": "edited on phone\n" });
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("13 config JSON: same key changed both ways makes a sibling under the config dir, nothing lost", async () => {
    const [a, b] = await pair();
    await a.write(".obsidian/app.json", '{"theme":"light","x":1}\n');
    await converge([a, b]);
    await a.write(".obsidian/app.json", '{"theme":"dark","x":1}\n');
    await b.write(".obsidian/app.json", '{"theme":"solar","x":1}\n');
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(JSON.parse(m[".obsidian/app.json"])).toEqual({ theme: "dark", x: 1 });
    const sib = siblingsOf(Object.keys(m), ".obsidian/app (conflict phone");
    expect(sib).toHaveLength(1);
    expect(JSON.parse(m[sib[0]])).toEqual({ theme: "solar", x: 1 });
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("14 ten rapid alternating edits of one file converge with every unsynced version kept", async () => {
    const [a, b] = await pair();
    await a.write("r.md", "0\n");
    await converge([a, b]);
    const written: string[] = [];
    for (let i = 1; i <= 5; i++) {
      await a.write("r.md", `A${i}\n`);
      await b.write("r.md", `B${i}\n`);
      written.push(`A${i}\n`, `B${i}\n`);
      await a.sync();
      await b.sync();
    }
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    // Every B version that lost a race is a sibling; every A version is in history or the head.
    const texts = new Set(Object.values(m));
    for (let i = 1; i <= 5; i++) expect(texts.has(`B${i}\n`), `B${i} lost`).toBe(true);
    const pid = await a.session.vc.pathId("r.md");
    const hist = new Set((await a.session.client.history(a.session.identity.vaultId, pid)).map((o) => o.blob_id));
    for (let i = 1; i <= 5; i++) expect(hist.has(await a.session.vc.blobId(utf8(`A${i}\n`))), `A${i} not in history`).toBe(true);
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("15 a file with no text extension never merges, even when the bytes are text", async () => {
    const [a, b] = await pair();
    await a.write("data.pdf", "a\nb\nc\n");
    await converge([a, b]);
    await a.write("data.pdf", "A\nb\nc\n");
    await b.write("data.pdf", "a\nb\nC\n");
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m["data.pdf"]).toBe("A\nb\nc\n");
    expect(siblingsOf(Object.keys(m), "data (conflict phone")).toHaveLength(1);
    await Promise.all([a.cleanup(), b.cleanup()]);
  });
});

describe("recovery paths", () => {
  it("16 server restart mid-session: both devices carry on, no duplicate ops", async () => {
    const [a, b] = await pair();
    await a.write("s.md", "1\n");
    await converge([a, b]);
    await srv.restart();
    await a.write("s.md", "2\n");
    await b.write("t.md", "t\n");
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m).toEqual({ "s.md": "2\n", "t.md": "t\n" });
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("17 editing while the server is down: offline, not error; everything lands when it returns", async () => {
    const [a, b] = await pair();
    await a.write("o.md", "v1\n");
    await converge([a, b]);
    await srv.halt();
    await a.write("o.md", "v2 offline\n");
    await a.write("p.md", "new offline\n");
    await expect(a.sync()).rejects.toThrow(/offline/);
    expect(a.engine.getStatus().phase).toBe("offline");
    await srv.resume();
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m).toEqual({ "o.md": "v2 offline\n", "p.md": "new offline\n" });
    expect(a.engine.getStatus().phase).toBe("idle");
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("18 crash between blob upload and op post: no re-upload, op posted after restart", async () => {
    const [a, b] = await pair();
    await a.write("c.md", "crash me\n");
    const client = a.session.client;
    const orig = client.postOps.bind(client);
    let armed = true;
    client.postOps = async (v, ops) => {
      if (armed) {
        armed = false;
        throw new NetworkError(srv.url, new Error("connection reset"));
      }
      return orig(v, ops);
    };
    await expect(a.sync()).rejects.toThrow(/offline/);
    expect(a.uploads).toBe(1);
    await a.restart({ crash: true });
    await a.sync();
    expect(a.uploads).toBe(1); // blob was already on the server
    await converge([a, b]);
    expect(await expectIdentical([a, b])).toEqual({ "c.md": "crash me\n" });
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("19 disk error while applying a conflict: the batch is skipped and the next sync heals it", async () => {
    const [a, b] = await pair();
    await a.write("d.md", "base\n");
    await converge([a, b]);
    await a.write("d.md", "A\n");
    await b.write("d.md", "B\n");
    await a.sync();
    const ow = b.fs.write.bind(b.fs);
    let fail = true;
    b.fs.write = async (p, d, m) => {
      if (fail && p === "d.md") {
        fail = false;
        throw new Error("EIO: disk error");
      }
      return ow(p, d, m);
    };
    await b.sync(); // skips d.md, reports, moves on
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m["d.md"]).toBe("A\n");
    const sibs = siblingsOf(Object.keys(m), "d (conflict phone");
    expect(sibs).toHaveLength(1); // identical bytes reused, not duplicated
    expect(m[sibs[0]]).toBe("B\n");
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("20 both devices lose their state at once: no uploads, no siblings, everything intact", async () => {
    const [a, b] = await pair();
    for (let i = 0; i < 10; i++) await a.write(`k/${i}.md`, `k${i}\n`);
    await converge([a, b]);
    for (const d of [a, b]) {
      await d.engine.flushState();
      await fsp.rm(await d.stateFile());
      await d.restart({ crash: true });
    }
    const [ua, ub] = [a.uploads, b.uploads];
    await converge([a, b]);
    expect([a.uploads, b.uploads]).toEqual([ua, ub]);
    expect(a.conflicts.length + b.conflicts.length).toBe(0);
    expect(Object.keys(await expectIdentical([a, b]))).toHaveLength(10);
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("21 server restored from an older backup: devices push back what it forgot, nothing is lost", async () => {
    const own = await TestServer.start();
    const [a, b] = await pair(own);
    await a.write("f1.md", "v1\n");
    await a.write("f2.md", "keep\n");
    await a.write("f3.md", "to delete\n");
    await converge([a, b]);
    const backup = await own.backup();
    await a.write("f1.md", "v2 after backup\n");
    await a.write("f4.md", "created after backup\n");
    await a.remove("f3.md");
    await converge([a, b]);
    await b.write("f5.md", "phone after backup\n");
    await converge([a, b]);
    // Disaster: the operator restores last night's backup.
    await own.restoreFrom(backup);
    const info = await a.session.client.vault(a.session.identity.vaultId);
    expect(info.seq).toBeLessThan(a.engine.state.cursor);
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m).toEqual({ "f1.md": "v2 after backup\n", "f2.md": "keep\n", "f4.md": "created after backup\n", "f5.md": "phone after backup\n" });
    expect(a.conflicts.length + b.conflicts.length).toBe(0);
    expect(a.logs.some((l) => /restored server/.test(l))).toBe(true);
    // A brand-new device sees the repaired vault.
    const sc = await joinWithLink(await createInviteLink(a.session), "tablet");
    const c = await new Device("tablet", sc).start();
    await c.sync();
    expect(await contents(c)).toEqual(m);
    await Promise.all([a.cleanup(), b.cleanup(), c.cleanup()]);
    await own.stop();
  }, 60_000);

  it("22 server restored from backup while another device already moved on: its newer edit wins", async () => {
    const own = await TestServer.start();
    const [a, b] = await pair(own);
    await a.write("g.md", "v1\n");
    await converge([a, b]);
    const backup = await own.backup();
    await a.write("g.md", "v2\n");
    await converge([a, b]); // b holds v2 as its synced version
    await own.restoreFrom(backup); // server back to v1
    await a.write("g.md", "v3 after restore\n");
    await a.sync(); // A reconciles (its v2 was lost, the head v1 is older) and pushes v3 on top of v1
    await converge([a, b]); // B's v2 was lost too, but the head v3 is newer than B's sync: a concurrent edit, so v2 becomes a sibling
    const m = await expectIdentical([a, b]);
    // The post-restore write wins at the path; the other device's lost version is kept beside it.
    expect(m["g.md"]).toBe("v3 after restore\n");
    const sib = siblingsOf(Object.keys(m), "g (conflict phone");
    expect(sib).toHaveLength(1);
    expect(m[sib[0]]).toBe("v2\n");
    await Promise.all([a.cleanup(), b.cleanup()]);
    await own.stop();
  }, 60_000);

  it("23 a blob missing on the server is reported, skipped, and healed by a re-upload", async () => {
    const own = await TestServer.start();
    const [a, b] = await pair(own);
    await a.write("m.md", "missing soon\n");
    await a.sync();
    const id = await a.session.vc.blobId(utf8("missing soon\n"));
    await own.dropBlob(a.session.identity.vaultId, id);
    const skipped: string[] = [];
    b.engine["hooks"].onSkipped = (p: string) => skipped.push(p);
    await b.sync();
    expect(skipped).toEqual(["m.md"]);
    expect(b.engine.getStatus().phase).toBe("idle");
    await a.engine.reupload("m.md");
    await converge([a, b]);
    expect(await expectIdentical([a, b])).toEqual({ "m.md": "missing soon\n" });
    await Promise.all([a.cleanup(), b.cleanup()]);
    await own.stop();
  });

  it("24 key rotation while a device is offline with pending edits: it catches up and its edits land", async () => {
    const [a, b, c] = await trio();
    await a.write("rot.md", "v1\n");
    await converge([a, b, c]);
    await b.write("rot.md", "phone edit while offline\n");
    await b.write("rot2.md", "phone new while offline\n");
    const tablet = (await listDevices(a.session)).find((d) => d.name === "tablet")!;
    await removeDevice(a.session, tablet.id);
    await a.write("after.md", "epoch 2\n");
    await a.sync();
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m).toEqual({ "after.md": "epoch 2\n", "rot.md": "phone edit while offline\n", "rot2.md": "phone new while offline\n" });
    await expect(c.sync()).rejects.toThrow();
    await Promise.all([a.cleanup(), b.cleanup(), c.cleanup()]);
  });

  it("25 a removed device keeps its files and its unsynced edits on disk", async () => {
    const [a, b] = await pair();
    await a.write("keep.md", "v1\n");
    await converge([a, b]);
    await b.write("keep.md", "phone's last words\n");
    await b.write("unsynced.md", "never pushed\n");
    const phone = (await listDevices(a.session)).find((d) => d.name === "phone")!;
    await removeDevice(a.session, phone.id);
    await expect(b.sync()).rejects.toThrow(/removed|401/i);
    await expect(b.sync()).rejects.toThrow();
    expect(await contents(b)).toEqual({ "keep.md": "phone's last words\n", "unsynced.md": "never pushed\n" });
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("26 a device that left and rejoins over the same files: identical files adopt, a differing note gets a sibling", async () => {
    const [a, b] = await pair();
    await a.write("same.md", "same\n");
    await a.write("diff.md", "vault version\n");
    await a.write(".obsidian/app.json", '{"vault":true}');
    await converge([a, b]);
    // B leaves: engine stops, state is thrown away, files stay.
    await b.engine.stop();
    await fsp.rm(await b.stateFile());
    await b.write("diff.md", "edited while away\n");
    await b.write(".obsidian/app.json", '{"local":true}');
    await a.write("diff.md", "vault moved on\n");
    await a.sync();
    const sb2 = await joinWithLink(await createInviteLink(a.session), "phone");
    const b2 = await new Device("phone", sb2).start(b.dir);
    await converge([a, b2]);
    const m = await expectIdentical([a, b2]);
    expect(m["same.md"]).toBe("same\n");
    expect(m["diff.md"]).toBe("vault moved on\n");
    expect(m[".obsidian/app.json"]).toBe('{"vault":true}');
    const sib = siblingsOf(Object.keys(m), "diff (conflict phone");
    expect(sib).toHaveLength(1);
    expect(m[sib[0]]).toBe("edited while away\n");
    expect(Object.keys(m).filter((f) => f.startsWith(".obsidian/") && CONFLICT_RE.test(f))).toEqual([]);
    await Promise.all([a.cleanup(), b2.cleanup()]);
  });

  it("27 restore to a point in time, then keep editing on both sides: converges", async () => {
    const [a, b] = await pair();
    await a.write("pit.md", "v1\n");
    await converge([a, b]);
    await new Promise((r) => setTimeout(r, 20));
    const t = Date.now();
    await new Promise((r) => setTimeout(r, 20));
    await a.write("pit.md", "v2\n");
    await converge([a, b]);
    await a.session.client.restore(a.session.identity.vaultId, t);
    await a.write("pit.md", "v2 plus A\n"); // A edits on top of v2 before pulling the restore
    await b.sync(); // B takes v1
    await b.write("pit.md", "v1 plus B\n");
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(Object.values(m).sort()).toEqual(["v1 plus B\n", "v2 plus A\n"]);
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("28 garbage collection while a device is far behind: it still ends on the right content", async () => {
    const own = await TestServer.start();
    const [a, b] = await pair(own);
    await a.write("gc.md", "v1\n");
    await converge([a, b]);
    for (let i = 2; i <= 6; i++) {
      await a.write("gc.md", `v${i}\n`);
      await a.sync();
    }
    await own.gc("0s"); // superseded blobs v1..v5 are gone
    await converge([a, b]);
    expect(await expectIdentical([a, b])).toEqual({ "gc.md": "v6\n" });
    expect(b.engine.getStatus().phase).toBe("idle");
    await Promise.all([a.cleanup(), b.cleanup()]);
    await own.stop();
  });

  it("29 replayed ops (cursor rewound) are no-ops: no siblings, no uploads", async () => {
    const [a, b] = await pair();
    for (let i = 0; i < 5; i++) await a.write(`rp/${i}.md`, `${i}\n`);
    await converge([a, b]);
    await b.write("rp/2.md", "local edit\n");
    b.engine.state.cursor = 0; // force a full replay from the snapshot
    const u = b.uploads;
    await b.sync();
    await converge([a, b]);
    expect(b.uploads).toBe(u + 1); // only the real edit
    expect(b.conflicts).toEqual([]);
    const m = await expectIdentical([a, b]);
    expect(m["rp/2.md"]).toBe("local edit\n");
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("30 odd mtimes (zero, far future) sync once and stay quiet", async () => {
    const [a, b] = await pair();
    await a.write("zero.md", "z\n", 0);
    await a.write("future.md", "f\n", Date.now() + 10 * 365 * 24 * 3600 * 1000);
    await converge([a, b]);
    const [pa, pb] = [a.posts, b.posts];
    await a.sync();
    await b.sync();
    await a.sync();
    expect([a.posts, b.posts]).toEqual([pa, pb]);
    expect(await expectIdentical([a, b])).toEqual({ "future.md": "f\n", "zero.md": "z\n" });
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("31 a file name in NFD on one device: one file per side, edits flow both ways, no loop", async () => {
    const [a, b] = await pair();
    const nfd = "café.md";
    const nfc = "café.md";
    await a.write(nfd, "v1\n");
    await converge([a, b]);
    const fa = await a.files();
    const fb = await b.files();
    expect(fb).toEqual([nfc]);
    expect(fa.map((f) => f.normalize("NFC"))).toEqual([nfc]);
    await b.write(nfc, "v2 from phone\n");
    await converge([a, b]);
    const [pa, pb] = [a.posts, b.posts];
    await a.sync();
    await b.sync();
    expect([a.posts, b.posts]).toEqual([pa, pb]);
    const onA = await a.files();
    expect(onA.map((f) => f.normalize("NFC"))).toEqual([nfc]);
    expect(await a.read(onA[0])).toBe("v2 from phone\n");
    await Promise.all([a.cleanup(), b.cleanup()]);
  });
});

describe("extreme scenarios", () => {
  const text = (m: Record<string, string>, f: string) => m[f];

  it("32 thirty conflicts on one file inside one minute: thirty numbered siblings, every version kept", async () => {
    const [a, b] = await pair();
    await a.write("storm.md", "0\n");
    await converge([a, b]);
    const phoneVersions: string[] = [];
    for (let i = 1; i <= 30; i++) {
      await a.write("storm.md", `A${i}\n`);
      await b.write("storm.md", `B${i}\n`);
      phoneVersions.push(`B${i}\n`);
      await a.sync();
      await b.sync();
    }
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    const sibs = siblingsOf(Object.keys(m), "storm (conflict phone");
    expect(sibs).toHaveLength(30);
    expect(sibs.map((s) => text(m, s)).sort()).toEqual([...phoneVersions].sort());
    await Promise.all([a.cleanup(), b.cleanup()]);
  }, 120_000);

  it("33 rotation storm: four rotations while a device is offline with edits; it catches up through all of them", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const a = await new Device("laptop", sa).start();
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const b = await new Device("phone", sb).start();
    await a.write("r.md", "v1\n");
    await converge([a, b]);
    await b.write("r.md", "phone edit during the storm\n");
    await b.write("r2.md", "phone new during the storm\n");
    for (let i = 0; i < 4; i++) {
      const t = await new Device(`temp${i}`, await joinWithLink(await createInviteLink(sa), `temp${i}`)).start();
      await t.sync();
      await a.write(`epoch${i + 2}.md`, `written in epoch ${i + 2}\n`);
      await a.sync();
      await removeDevice(sa, (await listDevices(sa)).find((d) => d.name === `temp${i}`)!.id);
      await t.cleanup();
    }
    const info = await sa.client.vault(sa.identity.vaultId);
    expect([info.epoch, info.min_epoch]).toEqual([5, 5]);
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m["r.md"]).toBe("phone edit during the storm\n");
    expect(m["r2.md"]).toBe("phone new during the storm\n");
    for (let e = 2; e <= 5; e++) expect(m[`epoch${e}.md`]).toBe(`written in epoch ${e}\n`);
    await Promise.all([a.cleanup(), b.cleanup()]);
  }, 120_000);

  it("34 server restored to a backup taken before a key rotation: devices re-adopt the old epoch and repair", async () => {
    const own = await TestServer.start();
    const sa = await createVault(own.url, ADMIN, "laptop");
    const a = await new Device("laptop", sa).start();
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const b = await new Device("phone", sb).start();
    await a.write("k.md", "epoch 1 content\n");
    await converge([a, b]);
    const backup = await own.backup();
    const t = await new Device("temp", await joinWithLink(await createInviteLink(sa), "temp")).start();
    await t.sync();
    await removeDevice(sa, (await listDevices(sa)).find((d) => d.name === "temp")!.id);
    await t.cleanup();
    await a.write("k.md", "epoch 2 content\n");
    await a.write("k2.md", "new in epoch 2\n");
    await converge([a, b]);
    expect((await sa.client.vault(sa.identity.vaultId)).epoch).toBe(2);
    await own.restoreFrom(backup);
    expect((await sa.client.vault(sa.identity.vaultId)).epoch).toBe(1);
    await converge([a, b], 12);
    const m = await expectIdentical([a, b]);
    expect(m).toEqual({ "k.md": "epoch 2 content\n", "k2.md": "new in epoch 2\n" });
    for (const d of [a, b]) expect(d.engine.getStatus().phase).toBe("idle");
    const c = await new Device("tablet", await joinWithLink(await createInviteLink(sa), "tablet")).start();
    await c.sync();
    expect(await contents(c)).toEqual(m);
    await Promise.all([a.cleanup(), b.cleanup(), c.cleanup()]);
    await own.stop();
  }, 120_000);

  it("35 large vault: 3000 files synced, then 100 deleted on one side and 100 edited on the other", async () => {
    const sa = await createVault(srv.url, ADMIN, "laptop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("laptop", sa).start();
    const b = await new Device("phone", sb, { massDelete: { min: 1000, fraction: 1 } }).start();
    const t0 = Date.now();
    for (let i = 0; i < 3000; i++) await a.write(`v/${i % 30}/f${i}.md`, `file ${i}\n`);
    await a.sync();
    await b.sync();
    const t1 = Date.now();
    expect((await b.files()).length).toBe(3000);
    for (let i = 0; i < 100; i++) await b.remove(`v/${i % 30}/f${i}.md`);
    for (let i = 50; i < 150; i++) await a.write(`v/${i % 30}/f${i}.md`, `file ${i} edited\n`);
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(Object.keys(m)).toHaveLength(2950); // 0..49 gone; 50..99 deleted on one side but edited on the other survive
    expect(m["v/20/f50.md"]).toBe("file 50 edited\n");
    expect(m["v/0/f0.md"]).toBeUndefined();
    console.log(`35: 3000 files, first sync ${t1 - t0} ms, reconciliation ${Date.now() - t1} ms`);
    await Promise.all([a.cleanup(), b.cleanup()]);
  }, 300_000);

  it("36 a 48 MB file edited concurrently: head and sibling both bit-exact", async () => {
    const own = await TestServer.start();
    const [a, b] = await pair(own);
    const big = new Uint8Array(48 * 1024 * 1024);
    for (let i = 0; i < big.length; i += 4096) big[i] = (i / 4096) & 0xff;
    await a.write("big.bin", big);
    await converge([a, b]);
    const va = new Uint8Array(big);
    va[12345] ^= 1;
    const vb = new Uint8Array(big);
    vb[40_000_000] ^= 1;
    await a.write("big.bin", va);
    await b.write("big.bin", vb);
    await converge([a, b]);
    const sib = siblingsOf(await b.files(), "big (conflict phone");
    expect(sib).toHaveLength(1);
    const same = (x: Uint8Array, y: Uint8Array) => Buffer.compare(Buffer.from(x), Buffer.from(y)) === 0;
    expect(same(await b.readBytes("big.bin"), va)).toBe(true);
    expect(same(await a.readBytes(sib[0]), vb)).toBe(true);
    await Promise.all([a.cleanup(), b.cleanup()]);
    await own.stop();
  }, 300_000);

  it("37 twenty levels deep with a 196-character name: syncs and conflicts like any file", async () => {
    const [a, b] = await pair();
    const dir = Array.from({ length: 20 }, (_, i) => `level${i}`).join("/");
    const p = `${dir}/${"n".repeat(196)}.md`;
    await a.write(p, "deep\n");
    await converge([a, b]);
    await a.write(p, "deep A\n");
    await b.write(p, "deep B\n");
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(m[p]).toBe("deep A\n");
    const sib = Object.keys(m).filter((f) => f !== p && f.startsWith(`${dir}/`) && CONFLICT_RE.test(f));
    expect(sib).toHaveLength(1);
    expect(m[sib[0]]).toBe("deep B\n");
    await Promise.all([a.cleanup(), b.cleanup()]);
  });

  it("38 deleted and recreated on one side while the other edits the old content: both kept", async () => {
    const [a, b] = await pair();
    await a.write("re.md", "original\n");
    await converge([a, b]);
    await a.remove("re.md");
    await a.sync();
    await a.write("re.md", "brand new\n");
    await b.write("re.md", "original, edited on phone\n");
    await converge([a, b]);
    const m = await expectIdentical([a, b]);
    expect(Object.values(m).sort()).toEqual(["brand new\n", "original, edited on phone\n"]);
    await Promise.all([a.cleanup(), b.cleanup()]);
  });
});
