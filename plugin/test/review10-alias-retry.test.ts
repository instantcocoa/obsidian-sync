/**
 * Tenth review (2026-11-08): the ninth round's fixes for a case-only folder
 * rename reaching a Mac: `isOsJunk` makes a twin folder holding only Finder's
 * files "empty" for `alignParentSpelling`, and a parent-folder refusal is
 * retried through the busy path. Both have the edge the brief predicted.
 *
 *  E. The "empty" test is one level deep. A folder with a SUBFOLDER is never
 *     empty after the deletes land: `fs.remove` deletes files, not the
 *     folders they were in, so `Notes/Sub/` stays behind (with or without a
 *     .DS_Store inside) and `Notes/` holds `Sub`. The rename `Notes/` ->
 *     `notes/` done on Linux therefore still strands the Mac: every delete
 *     lands, no put does, the notes are gone from this device. Round 9's
 *     proof used a flat folder; this is the same scenario one level deeper,
 *     the common shape of a real vault folder. Fails on HEAD (167804c).
 *
 *  F. The retry has no end and no bound. A twin folder that will never empty
 *     (a case-twin folder genuinely created on a case-sensitive device while
 *     this Mac's folder has content) is refused, recorded in `inflight`,
 *     and `retryBusy` rewinds the cursor to that op on EVERY sync, so each
 *     cycle re-downloads and re-decodes the whole changes feed from that
 *     seq onwards, for ever, growing with the vault; and the one notice the
 *     user sees says "the file is in use by another program". Fails on HEAD
 *     on both counts (two tests).
 *
 * Needs a case-insensitive temp volume (this Mac); skipped elsewhere.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";
import { utf8 } from "../src/core/encoding";

function volumeIgnoresCase(): boolean {
  const d = mkdtempSync(join(tmpdir(), "obsync-r10-"));
  try {
    mkdirSync(join(d, "Note"));
    return existsSync(join(d, "note"));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const opId = () => Math.random().toString(16).slice(2).padEnd(24, "0");

/** What a case-sensitive device's push looks like: a consistent put of `path`. */
async function put(s: Session, path: string, text: string): Promise<number> {
  const { vc, client, identity } = s;
  const bytes = utf8(text);
  const id = await vc.blobId(bytes);
  await client.putBlob(identity.vaultId, id, await vc.encryptBlob(id, bytes));
  const pid = await vc.pathId(path);
  const r = await client.postOps(identity.vaultId, [
    { op_id: opId(), path_id: pid, blob_id: id, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: bytes.length, blob: id }), meta_epoch: vc.keyring.current, base_seq: 0 },
  ]);
  expect(r.results[0].seq ?? 0, JSON.stringify(r.results[0])).toBeGreaterThan(0);
  return r.results[0].seq!;
}

async function del(s: Session, path: string, baseSeq: number): Promise<void> {
  const { vc, client, identity } = s;
  const pid = await vc.pathId(path);
  const r = await client.postOps(identity.vaultId, [
    { op_id: opId(), path_id: pid, blob_id: null, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: 0, blob: null }), meta_epoch: vc.keyring.current, base_seq: baseSeq },
  ]);
  expect(r.results[0].seq ?? 0, JSON.stringify(r.results[0])).toBeGreaterThan(0);
}

const ci = volumeIgnoresCase();

describe.skipIf(!ci)("E. a case-only rename of a folder that has a subfolder strands the Mac", () => {
  for (const junk of [false, true]) {
    it(`Notes/Sub/a.md -> notes/Sub/a.md renamed on Linux${junk ? ", Finder's .DS_Store in both folders" : ", no junk at all"}: the Mac ends with neither spelling`, async () => {
      const sa = await createVault(srv.url, ADMIN, "linux");
      const sb = await joinWithLink(await createInviteLink(sa), "mac");
      const mac = await new Device("mac", sb).start();
      try {
        await mac.rawWrite("Notes/Sub/a.md", utf8("a\n"));
        if (junk) {
          await mac.rawWrite("Notes/.DS_Store", new Uint8Array(32));
          await mac.rawWrite("Notes/Sub/.DS_Store", new Uint8Array(32));
        }
        await mac.sync();
        expect(mac.uploads).toBe(1);
        const seqA = mac.engine.state.files["Notes/Sub/a.md"].seq;

        // The Linux device renames the top folder: a delete, then a put under the new spelling.
        await del(sa, "Notes/Sub/a.md", seqA);
        await put(sa, "notes/Sub/a.md", "a\n");

        await mac.sync();
        await mac.sync();
        await mac.sync();
        const files = (await mac.files()).filter((f) => !/DS_Store/.test(f));
        expect(files, mac.logs.filter((l) => /refus|skip|retry/.test(l)).join("\n")).toEqual(["notes/Sub/a.md"]);
      } finally {
        await mac.cleanup();
      }
    });
  }
});

describe.skipIf(!ci)("F. a twin folder that never empties: the retry is unbounded and misdescribed", () => {
  async function stuckMac() {
    const sa = await createVault(srv.url, ADMIN, "linux");
    const sb = await joinWithLink(await createInviteLink(sa), "mac");
    const skipped: [string, string][] = [];
    const fetched: number[] = []; // ops returned by each changes() call
    const mac = await new Device("mac", sb, { hooks: { onSkipped: (p, why) => skipped.push([p, why]) } }).start();
    const client = sb.client;
    const origChanges = client.changes.bind(client);
    client.changes = async (v, since, o) => {
      const f = await origChanges(v, since, o);
      fetched.push(f.ops.length);
      return f;
    };
    await mac.rawWrite("Notes/keep.md", utf8("keep\n"));
    await mac.sync();
    // Linux has a *different* folder spelled `notes/` with its own file: a
    // legitimate pair of folders there, one folder here.
    await put(sa, "notes/x.md", "x\n");
    await mac.sync();
    expect(await mac.files()).toEqual(["Notes/keep.md"]);
    return { sa, mac, skipped, fetched };
  }

  it("F1. the notice names the folder spelling, not a program holding the file", async () => {
    const { mac, skipped } = await stuckMac();
    try {
      expect(skipped.length).toBeGreaterThan(0);
      const why = skipped.map(([, w]) => w).join(" | ");
      expect(why, "the user is told a program holds the file; nothing does").toMatch(/spell|folder|case/i);
      expect(why).not.toMatch(/in use by another program/);
    } finally {
      await mac.cleanup();
    }
  });

  it("F2. after the vault moves on, a sync with nothing new must not re-download the feed from the stuck op", async () => {
    const { sa, mac, fetched } = await stuckMac();
    try {
      for (let i = 0; i < 30; i++) await put(sa, `other/${i}.md`, `${i}\n`);
      await mac.sync(); // applies the 30 new ops
      expect((await mac.files()).length).toBe(31);
      fetched.length = 0;
      await mac.sync(); // nothing new on the server
      await mac.sync();
      const refetched = fetched.reduce((a, b) => a + b, 0);
      expect(refetched, `two idle syncs re-fetched ${refetched} ops (${JSON.stringify(fetched)}); the cursor is rewound to the refused op every cycle`).toBe(0);
    } finally {
      await mac.cleanup();
    }
  });
});
