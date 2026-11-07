/**
 * Eighth review (2026-11-07): the seventh round replaced the fold-table
 * clash refusal with a probe of the volume, and dropped the refusal for
 * *parent folders* altogether ("write through it; the volume will anyway"),
 * keeping only `alignParentSpelling` (rename an empty, differently cased
 * folder) and `refuseAliasClash` (the final segment). The final-segment
 * probe reads the parent folder through the requested spelling, so a file
 * spelled exactly the same inside a differently spelled parent passes it:
 * "notes/A.md" resolves to "Notes/A.md" on APFS, `readdir("notes")` lists
 * "A.md", the name matches, and the write replaces Notes/A.md's bytes.
 *
 * Two distinct files on a case-sensitive device (Linux, a CLI vault, or a
 * member's op) are therefore one file on every Mac and Windows device, and
 * the second to arrive overwrites the first. The scanner then sees
 * Notes/A.md changed and pushes the twin's content as an edit of Notes/A.md,
 * so the honest content is replaced on the case-sensitive device too. 0.1.5
 * refused the write (skip and report; the Mac keeps the first, Linux keeps
 * both). Same probe in ObsidianFS (`exactName` lists the parent under the
 * requested spelling; Obsidian's adapter echoes that spelling back), by code
 * reading only.
 *
 * Needs a case-insensitive volume for the temp dir (macOS, Windows); skipped
 * elsewhere. Fails on HEAD (93275e9).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";
import { utf8 } from "../src/core/encoding";

function volumeIgnoresCase(): boolean {
  const d = mkdtempSync(join(tmpdir(), "obsync-r8-"));
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
async function put(s: Session, path: string, text: string): Promise<void> {
  const { vc, client, identity } = s;
  const bytes = utf8(text);
  const id = await vc.blobId(bytes);
  await client.putBlob(identity.vaultId, id, await vc.encryptBlob(id, bytes));
  const pid = await vc.pathId(path);
  const r = await client.postOps(identity.vaultId, [
    { op_id: opId(), path_id: pid, blob_id: id, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: bytes.length, blob: id }), meta_epoch: vc.keyring.current, base_seq: 0 },
  ]);
  expect(r.results[0].seq ?? 0).toBeGreaterThan(0);
}

async function headBlob(s: Session, path: string): Promise<string | null | undefined> {
  const pid = await s.vc.pathId(path);
  const snap = await s.client.snapshot(s.identity.vaultId, { since: 0, limit: 500 });
  return snap.ops.filter((o) => o.path_id === pid).at(-1)?.blob_id;
}

describe.skipIf(!volumeIgnoresCase())("a case-twin parent folder from a case-sensitive device overwrites the honest file", () => {
  it("Notes/A.md is replaced by notes/A.md's bytes on the Mac, then pushed back as an edit of Notes/A.md", async () => {
    const sa = await createVault(srv.url, ADMIN, "linux");
    const sb = await joinWithLink(await createInviteLink(sa), "mac");
    const mac = await new Device("mac", sb).start();
    try {
      // The Linux device has both folders, each with an A.md (distinct files there).
      await put(sa, "Notes/A.md", "honest notes\n");
      await put(sa, "notes/A.md", "other folder\n");
      const honest = await sa.vc.blobId(utf8("honest notes\n"));

      await mac.sync();
      // 0.1.5: the second write was refused and reported; the Mac keeps the first.
      expect(await mac.read("Notes/A.md"), mac.logs.filter((l) => /refus|skip/.test(l)).join("\n")).toBe("honest notes\n");

      // And nothing of the Mac's goes back as an "edit" of the honest file.
      await mac.sync();
      await mac.sync();
      expect(await headBlob(sa, "Notes/A.md"), "Notes/A.md on the server now holds notes/A.md's content").toBe(honest);
    } finally {
      await mac.cleanup();
    }
  });
});
