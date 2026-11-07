/**
 * Sixth review (2026-11-07): the smaller findings, each pinned here against
 * the behaviour that fixed it (each test failed on 8319950, the state the
 * review examined).
 *
 *   1. meta_enc leaked the path length byte for byte (area A, metadata):
 *      now padded to a 256-byte multiple.
 *   2. The invite link's server field was shown to the user raw; a userinfo
 *      prefix made an attacker's server read as the owner's, and any URL
 *      scheme was accepted (area A, invite handling / obsidian:// handler):
 *      now only a plain http(s) address parses.
 *   3. `isSafeLogicalPath` admitted ":" so an NTFS alternate data stream
 *      suffix ("::$DATA") passed validation and escaped every non-directory
 *      exclusion (area D): now the Windows-forbidden characters are rejected
 *      up front (Obsidian refuses them in names everywhere anyway).
 *   4. `reencrypt()` overwrote `meta.blob` with the op row's blob_id
 *      unconditionally, so a re-pointed op (which the applier refuses) was
 *      laundered into an authenticated one by the next re-encryption (area
 *      A; malicious-server item): now an existing binding is kept.
 */
import { describe, expect, it } from "vitest";
import { VaultCrypto, newKeyring, parseInviteLink, buildInviteLink, META_PAD } from "../src/core/crypto";
import { reencrypt, type Session } from "../src/core/admin";
import { DEFAULT_EXCLUSIONS, compileExclusions, isSafeLogicalPath } from "../src/core/paths";
import { b64 } from "../src/core/encoding";

describe("1. meta_enc length no longer reveals the path length", () => {
  it("paths of different lengths give ciphertexts of one length, and the metadata still parses", async () => {
    const vc = new VaultCrypto(newKeyring());
    const bid = await vc.blobId(new Uint8Array([1]));
    const lens: number[] = [];
    for (const path of ["a.md", "ab.md", "abc.md", "notes/2026/some long meeting title here.md"]) {
      const pid = await vc.pathId(path);
      const enc = await vc.encryptMeta(pid, { path, mtime: 1_700_000_000_000, size: 1, blob: bid });
      lens.push(enc.length);
      expect(await vc.decryptMeta(pid, enc)).toMatchObject({ path, mtime: 1_700_000_000_000, size: 1, blob: bid });
    }
    expect(new Set(lens).size).toBe(1);
    // 4 header + 12 nonce + 16 tag + a padded JSON body.
    expect((lens[0] - 32) % META_PAD).toBe(0);
    // A path long enough to cross a boundary lands on the next multiple, never in between.
    const long = "n/".repeat(100) + "x.md";
    const pidL = await vc.pathId(long);
    expect(((await vc.encryptMeta(pidL, { path: long, mtime: 1, size: 1, blob: bid })).length - 32) % META_PAD).toBe(0);
  });
});

describe("2. invite link server field", () => {
  it("a userinfo prefix that would show the owner's host while the request goes elsewhere is refused", () => {
    const link = buildInviteLink("https://sync.owner.example@evil.example", "tok", new Uint8Array(32));
    expect(() => parseInviteLink(link)).toThrow(/plain http/);
  });

  it("non-http schemes, queries and fragments are refused; plain origins and paths are accepted", () => {
    for (const s of ["ftp://x.example", "file:///tmp", "javascript:alert(1)//", "https://x.example/?a=b", "https://x.example/#f", "not a url"]) {
      expect(() => parseInviteLink(buildInviteLink(s, "tok", new Uint8Array(32))), s).toThrow();
    }
    for (const s of ["https://sync.example", "https://sync.example:8443", "http://127.0.0.1:8080", "https://sync.example/obsync/"]) {
      expect(parseInviteLink(buildInviteLink(s, "tok", new Uint8Array(32))).server).toBe(s.replace(/\/+$/, ""));
    }
  });
});

describe("3. Windows-forbidden characters in paths", () => {
  it("'::$DATA' and other stream or wildcard spellings fail validation before any exclusion is consulted", () => {
    const excluded = compileExclusions(DEFAULT_EXCLUSIONS);
    expect(excluded("$CONFIG/workspace.json")).toBe(true);
    for (const p of ["$CONFIG/workspace.json::$DATA", "note.md:Zone.Identifier", "a<b.md", "a>b.md", 'a"b.md', "a|b.md", "a?b.md", "a*b.md"]) {
      expect(isSafeLogicalPath(p), p).toBe(false);
    }
    expect(isSafeLogicalPath("notes/plain name (1).md")).toBe(true);
  });
});

describe("4. reencrypt() keeps the metadata's own blob binding", () => {
  it("an op the applier refuses (meta.blob ≠ row blob_id) comes out of re-encryption still refused", async () => {
    const vc = new VaultCrypto(newKeyring());
    const honestBlob = await vc.blobId(new Uint8Array([1]));
    const plantedBlob = await vc.blobId(new Uint8Array([2]));
    const path = "secret.md";
    const pid = await vc.pathId(path);
    const metaEnc = await vc.encryptMeta(pid, { path, mtime: 1, size: 1, blob: honestBlob }, { epoch: 1 });
    vc.addEpoch(2, crypto.getRandomValues(new Uint8Array(32)));
    const patched: Uint8Array[] = [];
    const client = {
      vault: async () => ({ epoch: 2, min_epoch: 1 }),
      blobsBelowEpoch: async () => [],
      opsBelowMetaEpoch: async () => (patched.length ? [] : [7]),
      changes: async () => ({ epoch: 2, min_epoch: 1, cursor: 7, more: false, ops: [{ seq: 7, op_id: "o", device_id: "d", path_id: pid, blob_id: plantedBlob, meta_enc: b64(metaEnc), meta_epoch: 1, base_seq: 0, created_at: 1 }] }),
      patchMeta: async (_v: string, _seq: number, enc: Uint8Array) => {
        patched.push(enc);
      },
    };
    const s = { identity: { vaultId: "v" }, client, vc } as unknown as Session;
    await reencrypt(s);
    expect(patched.length).toBe(1);
    const after = await vc.decryptMeta(pid, patched[0]);
    expect(after.blob).toBe(honestBlob);
  });

  it("a row from before the binding existed gains it", async () => {
    const vc = new VaultCrypto(newKeyring());
    const blob = await vc.blobId(new Uint8Array([1]));
    const path = "old.md";
    const pid = await vc.pathId(path);
    const metaEnc = await vc.encryptMeta(pid, { path, mtime: 1, size: 1 }, { epoch: 1 });
    vc.addEpoch(2, crypto.getRandomValues(new Uint8Array(32)));
    const patched: Uint8Array[] = [];
    const client = {
      vault: async () => ({ epoch: 2, min_epoch: 1 }),
      blobsBelowEpoch: async () => [],
      opsBelowMetaEpoch: async () => (patched.length ? [] : [3]),
      changes: async () => ({ epoch: 2, min_epoch: 1, cursor: 3, more: false, ops: [{ seq: 3, op_id: "o", device_id: "d", path_id: pid, blob_id: blob, meta_enc: b64(metaEnc), meta_epoch: 1, base_seq: 0, created_at: 1 }] }),
      patchMeta: async (_v: string, _seq: number, enc: Uint8Array) => {
        patched.push(enc);
      },
    };
    await reencrypt({ identity: { vaultId: "v" }, client, vc } as unknown as Session);
    expect((await vc.decryptMeta(pid, patched[0])).blob).toBe(blob);
  });
});
