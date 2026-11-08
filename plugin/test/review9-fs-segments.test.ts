/**
 * Ninth review (2026-11-07): NodeFS after the eighth round probes every
 * path segment (`refuseAliasClash`) and renames an *empty* differently
 * spelled parent first (`alignParentSpelling`).
 *
 *  1. A folder is rarely empty on a Mac: Finder leaves `.DS_Store` in every
 *     folder it has shown, and `.DS_Store` is excluded from sync (so no
 *     device ever deletes it). A case-only folder rename done on another
 *     device arrives as deletes under the old spelling and puts under the
 *     new one. The deletes land, the folder keeps only `.DS_Store`, so it
 *     is not renamed, and every put under the new spelling is refused as
 *     "resolves to an entry spelled differently". The Mac is left with the
 *     folder's files gone (0.1.6 wrote them under the old spelling; 0.1.7
 *     writes nothing), and nothing retries them. Fails on HEAD (5a88779).
 *     Needs a case-insensitive volume for the temp dir; skipped elsewhere.
 *
 *  2. Measurement, not a finding: 500 writes of depth-5 paths and 300
 *     writes into a flat folder of 2,000 files, 0.1.7 NodeFS against the
 *     0.1.6 copy in .cache/agent-review9/node-fs-016.ts. Numbers printed.
 *
 *  3. Soundness (passes): round-7/8 scenarios re-run — café/cafe stay two
 *     files, a case-only rename with an emptied folder is realigned, a write
 *     whose parent does not exist yet, a deep new path, and a populated twin
 *     folder is refused (by design, as 0.1.5 did).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, promises as fsp } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TestServer, Device, ADMIN } from "./harness";
import { NodeFS } from "../src/core/node-fs";
import { NodeFS as NodeFS016 } from "../.cache/agent-review9/node-fs-016";
import { createVault, createInviteLink, joinWithLink, type Session } from "../src/core/admin";
import { utf8 } from "../src/core/encoding";

function volumeIgnoresCase(): boolean {
  const d = mkdtempSync(join(tmpdir(), "obsync-r9-"));
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

async function put(s: Session, path: string, text: string): Promise<void> {
  const { vc, client, identity } = s;
  const bytes = utf8(text);
  const id = await vc.blobId(bytes);
  await client.putBlob(identity.vaultId, id, await vc.encryptBlob(id, bytes));
  const pid = await vc.pathId(path);
  const r = await client.postOps(identity.vaultId, [
    { op_id: opId(), path_id: pid, blob_id: id, meta_enc: await vc.encryptMeta(pid, { path, mtime: Date.now(), size: bytes.length, blob: id }), meta_epoch: vc.keyring.current, base_seq: 0 },
  ]);
  expect(r.results[0].seq ?? 0, JSON.stringify(r.results[0])).toBeGreaterThan(0);
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

describe.skipIf(!ci)("1. a .DS_Store left behind blocks the case-only folder rename, and the puts are refused", () => {
  it("Notes/ -> notes/ renamed on Linux: the Mac ends with neither spelling", async () => {
    const sa = await createVault(srv.url, ADMIN, "linux");
    const sb = await joinWithLink(await createInviteLink(sa), "mac");
    const mac = await new Device("mac", sb).start();
    try {
      await mac.rawWrite("Notes/a.md", utf8("a\n"));
      await mac.rawWrite("Notes/b.md", utf8("b\n"));
      await mac.rawWrite("Notes/.DS_Store", new Uint8Array(32)); // Finder's; excluded from sync by default
      await mac.sync();
      expect(mac.uploads).toBe(2);
      const seqA = mac.engine.state.files["Notes/a.md"].seq;
      const seqB = mac.engine.state.files["Notes/b.md"].seq;

      // The Linux device renames the folder: its push is two deletes, then two puts.
      await del(sa, "Notes/a.md", seqA);
      await del(sa, "Notes/b.md", seqB);
      await put(sa, "notes/a.md", "a\n");
      await put(sa, "notes/b.md", "b\n");

      await mac.sync();
      await mac.sync();
      const files = (await mac.files()).filter((f) => !/DS_Store/.test(f));
      expect(files, mac.logs.filter((l) => /refus|skip/.test(l)).join("\n")).toEqual(["notes/a.md", "notes/b.md"]);
    } finally {
      await mac.cleanup();
    }
  });
});

describe("2. measurement: per-write cost of the per-segment probes", () => {
  const bytes = utf8("x".repeat(200));
  async function time(label: string, mk: (root: string) => { write: (p: string, d: Uint8Array, m: number) => Promise<void> }, paths: string[], pre: string[] = []): Promise<number> {
    const root = mkdtempSync(join(tmpdir(), "obsync-r9-perf-"));
    try {
      const fs = mk(root);
      for (const p of pre) await fs.write(p, bytes, Date.now());
      const t0 = performance.now();
      for (const p of paths) await fs.write(p, bytes, Date.now());
      const ms = performance.now() - t0;
      console.log(`${label}: ${paths.length} writes in ${ms.toFixed(0)} ms (${(ms / paths.length).toFixed(2)} ms/write)`);
      return ms;
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
  it("500 depth-5 writes and 300 writes into a 2,000-file folder, 0.1.7 vs 0.1.6", async () => {
    const deep = Array.from({ length: 500 }, (_, i) => `a${i % 5}/b${i % 7}/c${i % 3}/d${i % 2}/${i}.md`);
    const flatPre = Array.from({ length: 2000 }, (_, i) => `flat/pre-${i}.md`);
    const flat = Array.from({ length: 300 }, (_, i) => `flat/new-${i}.md`);
    const d7 = await time("0.1.7 deep", (r) => new NodeFS(r), deep);
    const d6 = await time("0.1.6 deep", (r) => new NodeFS016(r), deep);
    const f7 = await time("0.1.7 flat/2000", (r) => new NodeFS(r), flat, flatPre);
    const f6 = await time("0.1.6 flat/2000", (r) => new NodeFS016(r), flat, flatPre);
    const summary = [
      `0.1.7 deep: ${d7.toFixed(0)} ms (${(d7 / 500).toFixed(2)} ms/write); 0.1.6 deep: ${d6.toFixed(0)} ms (${(d6 / 500).toFixed(2)} ms/write)`,
      `0.1.7 flat/2000: ${f7.toFixed(0)} ms (${(f7 / 300).toFixed(2)} ms/write); 0.1.6 flat/2000: ${f6.toFixed(0)} ms (${(f6 / 300).toFixed(2)} ms/write)`,
      `ratio 0.1.7/0.1.6: deep ${(d7 / d6).toFixed(2)}x, flat ${(f7 / f6).toFixed(2)}x (volume ${ci ? "case-insensitive" : "case-sensitive"}, ${process.platform} ${process.arch}, node ${process.version})`,
    ].join("\n");
    console.log(summary);
    appendFileSync(join(__dirname, "../.cache/agent-review9/timings.txt"), `${new Date().toISOString()}\n${summary}\n\n`);
    expect(d7).toBeGreaterThan(0);
  });
});

describe.skipIf(!ci)("3. soundness of the per-segment probe on a case-insensitive volume", () => {
  let root: string;
  let fs: NodeFS;
  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "obsync-r9-fs-"));
    fs = new NodeFS(root);
  });
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("café.md and cafe.md stay two files", async () => {
    await fs.write("café.md", utf8("accent\n"), Date.now());
    await fs.write("cafe.md", utf8("plain\n"), Date.now());
    expect(new TextDecoder().decode(await fs.read("café.md"))).toBe("accent\n");
    expect(new TextDecoder().decode(await fs.read("cafe.md"))).toBe("plain\n");
  });

  it("a case-only folder rename with an emptied old folder is realigned", async () => {
    await fs.write("Folder/x.md", utf8("x\n"), Date.now());
    await fs.remove("Folder/x.md");
    await fs.write("folder/x.md", utf8("x2\n"), Date.now());
    expect(await fsp.readdir(root)).toContain("folder");
    expect(await fsp.readdir(root)).not.toContain("Folder");
  });

  it("a write whose parents do not exist yet, five deep", async () => {
    await fs.write("p1/p2/p3/p4/leaf.md", utf8("deep\n"), Date.now());
    expect(await fs.stat("p1/p2/p3/p4/leaf.md")).not.toBeNull();
  });

  it("a populated twin folder is refused (by design) and the first folder's file is untouched", async () => {
    await fs.write("Docs/A.md", utf8("honest\n"), Date.now());
    await expect(fs.write("docs/A.md", utf8("other\n"), Date.now())).rejects.toThrow(/spelled differently/);
    expect(new TextDecoder().decode(await fs.read("Docs/A.md"))).toBe("honest\n");
  });
});
