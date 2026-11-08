/**
 * Thirteenth review (2026-11-07): the twelfth round's settle() fix, read as a
 * hurried fix with an edge. settle() now treats a conflict head whose
 * metadata does not decrypt like an inconsistent one: "our version will
 * replace it", rebased as a tombstone at the head's seq. The rebase records
 * `files[P].seq = head.seq` without this device ever having pulled the ops
 * beneath that head. Every honest op between our last pull and the garbage
 * head is then "already seen" (`applyRemoteOnce` returns on e.seq >= op.seq)
 * and our bytes supersede it with no sibling, no merge, no notice to its
 * author.
 *
 * Who can arrange that? Any member: posting a row with noise in meta_enc
 * needs only the vault authority token members hold. A bot that shadows
 * every op it sees on the live feed with a garbage row for the same path_id
 * turns every concurrent edit that lands while another device is uploading
 * its blobs (the window between that device's pull and its postOps) into a
 * silent loss of the other author's version. Without the garbage row the
 * same race ends in a sibling copy (control below).
 *
 *  A. Fails on HEAD (af13604): device A's push conflicts with a garbage head
 *     above B's honest version; A rebases, B's version is never applied
 *     anywhere on A, A's bytes become the vault's head, a fresh device sees
 *     only A's version.
 *  B. Control, passes on HEAD: no garbage row, same race, B's version is
 *     kept as A's conflict sibling.
 *
 * Fix: rebase on a bad (inconsistent or unreadable) head only when it is at
 * or below our cursor (`r.conflict.seq <= this.state.cursor`: every honest
 * op beneath it has been through applyBatch); otherwise mark the path dirty
 * and sync again (pull first, then push) so the conflict is seen against the
 * honest ops first.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";
import { utf8, u32le } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

const opId = () => Math.random().toString(16).slice(2).padEnd(24, "0");

/** An honest put of `path` from session `s` on top of head `base`. Returns the seq. */
async function put(s: Session, path: string, text: string, base: number): Promise<number> {
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

/** A row any member can post: a valid epoch header over noise. No device can read it; the server accepts it. */
async function garbageRow(s: Session, path: string, base: number): Promise<number> {
  const pid = await s.vc.pathId(path);
  const bytes = utf8("noise\n");
  const id = await s.vc.blobId(bytes);
  await s.client.putBlob(s.identity.vaultId, id, await s.vc.encryptBlob(id, bytes));
  const noise = crypto.getRandomValues(new Uint8Array(96));
  noise.set(u32le(s.vc.keyring.current), 0);
  const r = await s.client.postOps(s.identity.vaultId, [{ op_id: opId(), path_id: pid, blob_id: id, meta_enc: noise, meta_epoch: s.vc.keyring.current, base_seq: base }]);
  expect(r.results[0].seq ?? 0, JSON.stringify(r.results[0])).toBeGreaterThan(0);
  return r.results[0].seq!;
}

const PATH = "notes/n.bin"; // not a text path: no three-way merge, so the honest outcome is a sibling copy

/**
 * A (a Device) and B (an honest session) share a vault with M (a member).
 * A has synced version 1 and edited the file. While A is pushing (between
 * its pull and its postOps, i.e. during its blob upload), B posts an honest
 * version 2 and, if `hostile`, M shadows it with a garbage row. Returns what
 * A ended up with after it settled and synced once more.
 */
async function race(hostile: boolean) {
  const sa = await createVault(srv.url, ADMIN, "linux"); // B
  const sm = await joinWithLink(await createInviteLink(sa), "member"); // M
  const sb = await joinWithLink(await createInviteLink(sa), "mac"); // A
  const skipped: [string, string][] = [];
  const a = await new Device("mac", sb, { hooks: { onSkipped: (p, why) => skipped.push([p, why]) } }).start();
  try {
    await a.write(PATH, "base\n");
    await a.sync();
    const s0 = a.engine.state.files[PATH]!.seq;
    expect(s0).toBeGreaterThan(0);

    await a.write(PATH, "from A\n");
    // The window: A has pulled (nothing new) and is uploading; B's version
    // and M's shadow land before A's ops are posted.
    const orig = sb.client.postOps.bind(sb.client);
    let injected = 0;
    sb.client.postOps = async (v, ops) => {
      if (injected++ === 0) {
        const s1 = await put(sa, PATH, "from B\n", s0);
        if (hostile) await garbageRow(sm, PATH, s1);
      }
      return orig(v, ops);
    };
    await a.sync(); // conflict against the head; settle() decides
    sb.client.postOps = orig;
    await a.sync(); // the cycle after: pull the rows beneath, push whatever is dirty
    await a.sync();

    const files = await a.files();
    const contents = Object.fromEntries(await Promise.all(files.map(async (f) => [f, await a.read(f)])));
    // What a device joining now sees: the vault's truth after A settled.
    const sc = await joinWithLink(await createInviteLink(sa), "fresh");
    const fresh = await new Device("fresh", sc).start();
    try {
      await fresh.sync();
      const freshFiles = await fresh.files();
      const freshContents = Object.fromEntries(await Promise.all(freshFiles.map(async (f) => [f, await fresh.read(f)])));
      return { contents, freshContents, skipped, logs: a.logs, conflicts: a.conflicts };
    } finally {
      await fresh.cleanup();
    }
  } finally {
    await a.cleanup();
  }
}

describe("settle(): an unreadable conflict head makes our version supersede honest ops we never pulled", () => {
  it("B. control: no garbage row; the concurrent edit ends in a sibling copy and both versions survive", async () => {
    const r = await race(false);
    const all = Object.values(r.contents).join("|");
    expect(all, `A's files: ${JSON.stringify(r.contents)}`).toContain("from B\n");
    expect(all).toContain("from A\n");
    expect(Object.values(r.freshContents).join("|")).toContain("from B\n");
    expect(r.conflicts.length, "one sibling").toBe(1);
  }, 60_000);

  it("A. a member shadows B's version with a garbage row: A's bytes replace B's, B's version is nowhere, nobody is told it was theirs", async () => {
    const r = await race(true);
    const onA = Object.values(r.contents).join("|");
    const everywhere = Object.values(r.freshContents).join("|");
    expect(
      onA,
      `B's honest version is gone from A (files ${JSON.stringify(r.contents)}); a fresh device sees ${JSON.stringify(r.freshContents)}; A was told: ${JSON.stringify(r.skipped)}; logs: ${r.logs.filter((l) => /conflict|supersede|replace|already/.test(l)).join(" | ")}`,
    ).toContain("from B\n");
    expect(everywhere, "the vault still holds B's version under some name").toContain("from B\n");
  }, 60_000);
});
