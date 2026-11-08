/**
 * Twelfth review (2026-11-08): the eleventh round's reworked deferral
 * (engine.ts: deferOp / retryDeferred / decodeOp, 0.1.12), read as a hurried
 * fix with an edge. As in review11-deferred.test.ts the parent-folder refusal
 * is injected through the device's `fs.write` and `fs.aliasRefusal` with the
 * exact text NodeFS and ObsidianFS produce, so the engine is tested, not the
 * file layer.
 *
 *  A. The retry fetches the path's "head" as the max-seq row of
 *     `client.history`, but the server's History is `ORDER BY seq LIMIT 5000`
 *     ascending (store.go, maxListLimit): for a path with more than 5000
 *     versions the newest rows are the ones cut off, and the "head" the retry
 *     applies is version 5000. The device records that seq for the path, its
 *     cursor is already past the real head, and the stale content stays
 *     (logged as "applied") until someone edits the file again. Any member
 *     can give a path 5001 versions. Fails on HEAD (1256db0).
 *
 *  B. "Every drop is reported": not when the head's metadata does not
 *     decrypt. `decodeOp` only logs for a non-epoch CryptoError and returns
 *     null; retryDeferred then deletes the entry "(decodeOp reported why)",
 *     and no onSkipped is called. A member who posts one row with garbage
 *     meta_enc for the parked path makes the file vanish from this device
 *     without a word. Fails on HEAD.
 *
 *  C. The day budget restarts whenever the path is edited elsewhere:
 *     applyBatch deletes the entry before applying the newer op, so the
 *     re-defer finds no `cur` and takes `since = Date.now()` (and tries = 1,
 *     and a fresh first notice). A note another device touches daily is
 *     parked for ever and re-announced each time. Fails on HEAD (low).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";
import { Engine } from "../src/core/engine";
import { CryptoError } from "../src/core/crypto";
import { utf8, u32le } from "../src/core/encoding";
import { promises as fsp } from "node:fs";
import { join } from "node:path";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const opId = () => Math.random().toString(16).slice(2).padEnd(24, "0");

/** A consistent put of `path` from a case-sensitive device, on top of head `base` (0 for a new path). Returns the seq. */
async function put(s: Session, path: string, text: string, base = 0): Promise<number> {
  const { vc, client, identity } = s;
  const bytes = utf8(text);
  const id = await vc.blobId(bytes);
  await client.putBlob(identity.vaultId, id, await vc.encryptBlob(id, bytes));
  const pid = await vc.pathId(path);
  const r = await client.postOps(identity.vaultId, [
    { op_id: opId(), path_id: pid, blob_id: id, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: bytes.length, blob: id }), meta_epoch: vc.keyring.current, base_seq: base },
  ]);
  expect(r.results[0].seq ?? 0, JSON.stringify(r.results[0])).toBeGreaterThan(0);
  return r.results[0].seq!;
}

/**
 * `n` more versions of `path` on top of head `base`, in batches of 1000 (the
 * server's per-post limit); every version but the last carries the same
 * bytes, the last carries `finalText`. Heads are updated inside the server's
 * loop, so a batch can chain base_seqs it predicts. Returns the head seq.
 */
async function manyVersions(s: Session, path: string, base: number, n: number, finalText: string): Promise<number> {
  const { vc, client, identity } = s;
  const pid = await vc.pathId(path);
  const same = utf8("same\n");
  const sameId = await vc.blobId(same);
  await client.putBlob(identity.vaultId, sameId, await vc.encryptBlob(sameId, same));
  const fin = utf8(finalText);
  const finId = await vc.blobId(fin);
  await client.putBlob(identity.vaultId, finId, await vc.encryptBlob(finId, fin));
  let head = base;
  for (let done = 0; done < n; ) {
    const batch = Math.min(1000, n - done);
    const ops = [];
    for (let i = 0; i < batch; i++) {
      const last = done + i === n - 1;
      const bytes = last ? fin : same;
      const id = last ? finId : sameId;
      ops.push({ op_id: opId(), path_id: pid, blob_id: id, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: bytes.length, blob: id }), meta_epoch: vc.keyring.current, base_seq: head + i });
    }
    const r = await client.postOps(identity.vaultId, ops);
    for (const [i, res] of r.results.entries()) expect(res.seq ?? 0, `op ${done + i}: ${JSON.stringify(res)}`).toBe(head + i + 1);
    head += batch;
    done += batch;
  }
  return head;
}

const ALIAS = (folder: string) => new Error(`"${folder}" resolves to a folder spelled differently on this volume; refusing to write through it`);

function refuseNotes(mac: Device): { on: boolean; refused: number } {
  const orig = mac.fs.write.bind(mac.fs);
  const origProbe = mac.fs.aliasRefusal?.bind(mac.fs);
  const ctl = { on: true, refused: 0 };
  mac.fs.write = async (p, d, m) => {
    if (ctl.on && p.startsWith("notes/")) {
      ctl.refused++;
      throw ALIAS("notes");
    }
    return orig(p, d, m);
  };
  mac.fs.aliasRefusal = async (p) => (ctl.on && p.startsWith("notes/") ? ALIAS("notes").message : (await origProbe?.(p)) ?? null);
  return ctl;
}

type Stuck = { sa: Session; sb: Session; mac: Device; ctl: { on: boolean; refused: number }; skipped: [string, string][]; seq: number };

async function fixFolder(s: Stuck): Promise<void> {
  s.ctl.on = false;
  await fsp.rename(join(s.mac.dir, "Notes"), join(s.mac.dir, "notes"));
}

/** A Mac whose `Notes/` holds something sync never removes, while Linux writes `notes/x0.md`: the put is deferred. */
async function stuck(): Promise<Stuck> {
  const sa = await createVault(srv.url, ADMIN, "linux");
  const sb = await joinWithLink(await createInviteLink(sa), "mac");
  const skipped: [string, string][] = [];
  const mac = await new Device("mac", sb, { hooks: { onSkipped: (p, why) => skipped.push([p, why]) } }).start();
  await mac.rawWrite("Notes/keep.md", utf8("keep\n"));
  await mac.sync();
  const ctl = refuseNotes(mac);
  const seq = await put(sa, "notes/x0.md", "x0\n");
  await mac.sync();
  expect(await mac.files()).toEqual(["Notes/keep.md"]);
  expect(Object.keys(mac.engine.state.deferred ?? {})).toEqual(["notes/x0.md"]);
  expect(skipped.length, "reported once").toBe(1);
  return { sa, sb, mac, ctl, skipped, seq };
}

describe("A. the retry's 'head' is the max of history, and history is the OLDEST 5000 rows", () => {
  it("a path with 5001 versions: once the folder is fixed, the device gets version 5000 and records it as current", async () => {
    const s = await stuck();
    try {
      // The other device keeps editing the note (or a hostile member posts
      // 5000 rows for it: every member may). The Mac pulls them all while
      // its folder is still misspelled; each page's last op is re-deferred.
      const head = await manyVersions(s.sa, "notes/x0.md", s.seq, 5000, "the real head\n");
      await s.mac.sync();
      expect(s.mac.engine.state.deferred?.["notes/x0.md"]?.seq, "parked at the head after the pull").toBe(head);
      expect(s.mac.engine.state.cursor).toBe(head);
      // The user does what the notice asked.
      await fixFolder(s);
      await s.mac.sync();
      const got = await s.mac.read("notes/x0.md");
      const rec = s.mac.engine.state.files["notes/x0.md"];
      expect(got, `the device applied seq ${rec?.seq} (head is ${head}); its cursor ${s.mac.engine.state.cursor} is past the head, so this content is now permanent until the next edit; logs: ${s.mac.logs.filter((l) => /deferred/.test(l)).join(" | ")}`).toBe("the real head\n");
      expect(rec?.seq).toBe(head);
      // And it does not heal by itself: the cursor is past the real head.
      await s.mac.sync();
      expect(await s.mac.read("notes/x0.md")).toBe("the real head\n");
    } finally {
      await s.mac.cleanup();
    }
  }, 120_000);
});

/**
 * A row any member can post: `meta_enc` the server cannot read and no device
 * can decrypt. "valid-epoch" carries the current epoch in the 4-byte header
 * (decryptMeta: "authentication failed"); "random-epoch" carries whatever the
 * random bytes say (decryptMeta: "no key for epoch <n>").
 */
async function garbageRow(s: Session, path: string, header: "valid-epoch" | "random-epoch", base: number): Promise<number> {
  const pid = await s.vc.pathId(path);
  const bytes = utf8("x0\n");
  const id = await s.vc.blobId(bytes);
  await s.client.putBlob(s.identity.vaultId, id, await s.vc.encryptBlob(id, bytes));
  const noise = crypto.getRandomValues(new Uint8Array(96));
  if (header === "valid-epoch") noise.set(u32le(s.vc.keyring.current), 0);
  const r = await s.client.postOps(s.identity.vaultId, [{ op_id: opId(), path_id: pid, blob_id: id, meta_enc: noise, meta_epoch: s.vc.keyring.current, base_seq: base }]);
  expect(r.results[0].seq ?? 0, JSON.stringify(r.results[0])).toBeGreaterThan(0);
  return r.results[0].seq!;
}

describe("B0. a row whose meta_enc header names an epoch nobody has", () => {
  it("is refused by the server, and a device that meets one anyway skips it and keeps syncing; a fresh device joins fine", async () => {
    const sa = await createVault(srv.url, ADMIN, "linux");
    const sb = await joinWithLink(await createInviteLink(sa), "mac");
    const skipped: [string, string][] = [];
    const mac = await new Device("mac", sb, { hooks: { onSkipped: (p, why) => skipped.push([p, why]) } }).start();
    try {
      await put(sa, "plain/before.md", "before\n");
      await mac.sync();
      expect(await mac.files()).toEqual(["plain/before.md"]);
      // Layer 1, the server: the 4-byte epoch header of meta_enc is the one
      // plaintext field it can read, and it must agree with meta_epoch.
      const pid = await sa.vc.pathId("plain/poison.md");
      const noise = crypto.getRandomValues(new Uint8Array(96));
      const r = await sa.client.postOps(sa.identity.vaultId, [{ op_id: opId(), path_id: pid, blob_id: null, meta_enc: noise, meta_epoch: sa.vc.keyring.current, base_seq: 0 }]);
      expect(r.results[0].seq ?? 0).toBe(0);
      expect(r.results[0].error).toMatch(/header epoch .* does not match meta_epoch/);
      // Layer 2, the client: should such a row ever reach a device (an older
      // server, a restored database), the pull must skip and report it, not
      // stop at it for good. Simulated by making this device's keyring lack
      // the epoch for that one path.
      await put(sa, "plain/poison.md", "poison\n");
      await put(sa, "plain/after.md", "after\n"); // honest work that follows it
      const realDecrypt = sb.vc.decryptMeta.bind(sb.vc);
      sb.vc.decryptMeta = async (pathId, enc) => {
        if (pathId === pid) throw new CryptoError("no key for epoch 4242", "environment");
        return realDecrypt(pathId, enc);
      };
      const outcomes: string[] = [];
      for (let i = 0; i < 3; i++) {
        try {
          await mac.sync();
          outcomes.push("ok");
        } catch (e) {
          outcomes.push(String((e as Error).message));
        }
      }
      expect(outcomes, `three syncs after the row: ${JSON.stringify(outcomes)}; cursor ${mac.engine.state.cursor}`).toEqual(["ok", "ok", "ok"]);
      expect(await mac.files(), "the honest op behind it must arrive").toContain("plain/after.md");
      expect(await mac.files(), "the unreadable row is skipped").not.toContain("plain/poison.md");
      expect(skipped.some(([, why]) => /names a key no device has|cannot be read/.test(why)), `reported: ${JSON.stringify(skipped)}`).toBe(true);
      const sc = await joinWithLink(await createInviteLink(sa), "pad");
      const pad = await new Device("pad", sc).start();
      try {
        await pad.sync();
        expect(await pad.files()).toContain("plain/after.md");
        expect(await pad.files()).toContain("plain/poison.md"); // readable with a full keyring
      } finally {
        await pad.cleanup();
      }
    } finally {
      await mac.cleanup();
    }
  });
});

describe("B1. a drop caused by an undecryptable head is not reported", () => {
  it("one garbage row (valid epoch header) for the parked path: the entry is deleted, the user hears nothing, the file never arrives", async () => {
    const s = await stuck();
    try {
      // Any member can post a row whose meta_enc is noise; it becomes the path's head.
      await garbageRow(s.sa, "notes/x0.md", "valid-epoch", s.seq);
      await s.mac.sync(); // pull: "cannot decrypt metadata ... skipping" (logged only); the entry survives
      expect(s.mac.engine.state.deferred?.["notes/x0.md"]).toBeDefined();
      const before = s.skipped.length;
      await fixFolder(s);
      await s.mac.sync();
      await s.mac.sync();
      const arrived = (await s.mac.files()).includes("notes/x0.md");
      const parked = !!s.mac.engine.state.deferred?.["notes/x0.md"];
      expect(arrived || parked || s.skipped.length > before, `the parked op was dropped (deferred: ${JSON.stringify(s.mac.engine.state.deferred)}) with no notice; notices: ${JSON.stringify(s.skipped)}; logs: ${s.mac.logs.filter((l) => /decrypt|deferred|dropping/.test(l)).join(" | ")}`).toBe(true);
    } finally {
      await s.mac.cleanup();
    }
  });
});

describe("C. the day budget restarts on every edit of the parked path elsewhere", () => {
  it("an entry parked for 23 h is re-parked as new (since = now, tries = 1, a fresh first notice) when the other device edits the note", async () => {
    const s = await stuck();
    try {
      const entry = s.mac.engine.state.deferred!["notes/x0.md"];
      const since = Date.now() - 23 * 3_600_000;
      entry.since = since;
      entry.tries = 40;
      await put(s.sa, "notes/x0.md", "x0 again\n", s.seq);
      await s.mac.sync(); // the newer op supersedes the entry and is refused in turn
      const re = s.mac.engine.state.deferred?.["notes/x0.md"];
      expect(re, "still parked").toBeDefined();
      expect(re!.since, `the budget was restarted (since moved from ${since} to ${re!.since}; tries ${re!.tries}; notices ${s.skipped.length})`).toBeLessThanOrEqual(since);
      expect(s.skipped.length, "no second 'first notice' for the same folder").toBe(1);
      // One more hour and it must be dropped, as the first notice's promise ("for a day") says.
      re!.since = Date.now() - Engine.DEFERRED_MAX_AGE - 1;
      await s.mac.sync();
      expect(s.mac.engine.state.deferred).toBeUndefined();
    } finally {
      await s.mac.cleanup();
    }
  });
});
