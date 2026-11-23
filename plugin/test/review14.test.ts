/**
 * Fourteenth review (1.0.2): resource bounds on chunked content, crash-loop
 * protection, merges of chunked text, and where conflict copies come from.
 * Each attack is built the way the reviewer built it (plugin/.cache/
 * agent-secreview-102 on the owner's machine), against the real server.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { promises as fsp } from "node:fs";
import { TestServer, Device } from "./harness";
import { createVault, createInviteLink, joinWithLink } from "../src/core/admin";
import { CHUNK_MAX } from "../src/core/chunks";
import type { FileMeta } from "../src/core/crypto";
import { conflictPath } from "../src/core/paths";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

function noise(n: number, seed: number): Uint8Array {
  const out = new Uint8Array(n);
  let x = seed >>> 0 || 1;
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

type S = Awaited<ReturnType<typeof createVault>>;
function meter(s: S) {
  const m = { gets: 0, ctBytes: 0, plainBytes: 0, largestHashed: 0 };
  const g = s.client.getBlob.bind(s.client);
  s.client.getBlob = async (...a: Parameters<typeof g>) => {
    const r = await g(...a);
    m.gets++;
    m.ctBytes += r.length;
    return r;
  };
  const d = s.vc.decryptBlob.bind(s.vc);
  s.vc.decryptBlob = async (...a: Parameters<typeof d>) => {
    const r = await d(...a);
    m.plainBytes += r.length;
    return r;
  };
  const h = s.vc.blobId.bind(s.vc);
  s.vc.blobId = async (x: Uint8Array) => {
    m.largestHashed = Math.max(m.largestHashed, x.length);
    return h(x);
  };
  return m;
}

async function forge(s: S, path: string, size: number, chunks: string[]): Promise<void> {
  const vault = s.identity.vaultId;
  const pathId = await s.vc.pathId(path);
  const blob = "ab".repeat(32);
  const meta: FileMeta = { path, mtime: Date.now(), size, blob };
  const epoch = s.vc.keyring.current;
  const r = await s.client.postOps(vault, [{ op_id: "forged-" + Math.random(), path_id: pathId, blob_id: blob, chunks, meta_enc: await s.vc.encryptMeta(pathId, meta, { epoch }), meta_epoch: epoch, base_seq: 0 }]);
  expect(r.results[0].error ?? "").toBe("");
}

async function pair(): Promise<[S, S, Device, Device]> {
  const sa = await createVault(await srv.createLink(), "laptop");
  const sb = await joinWithLink(await createInviteLink(sa), "phone");
  return [sa, sb, await new Device("laptop", sa).start(), await new Device("phone", sb).start()];
}

describe("review 14: chunked content is bounded before it is fetched or allocated", () => {
  it("F4: one chunk listed past MAX_PLAIN is refused with nothing fetched, allocated or hashed", async () => {
    const [sa, sb, a, b] = await pair();
    const zeros = new Uint8Array(CHUNK_MAX);
    const c = await sa.vc.blobId(zeros);
    await sa.client.putBlob(sa.identity.vaultId, c, await sa.vc.encryptBlob(c, zeros, { compress: true }));
    await forge(sa, "bomb.bin", 300 * CHUNK_MAX, Array(300).fill(c));
    const m = meter(sb);
    await b.engine.sync();
    expect(m.gets).toBe(0);
    expect(m.largestHashed).toBe(0);
    expect(await b.exists("bomb.bin")).toBe(false);
    await a.cleanup();
    await b.cleanup();
  });

  it("F1: a list longer than the claimed size allows is refused with no download; a list of oversized chunks stops at the first", async () => {
    const [sa, sb, a, b] = await pair();
    const vault = sa.identity.vaultId;
    const ids: string[] = [];
    for (let i = 0; i < 24; i++) {
      const part = new Uint8Array(CHUNK_MAX);
      part[0] = i + 1;
      const id = await sa.vc.blobId(part);
      await sa.client.putBlob(vault, id, await sa.vc.encryptBlob(id, part, { compress: true }));
      ids.push(id);
    }
    const m = meter(sb);
    await forge(sa, "evil.bin", 2 * 1024 * 1024, ids);
    await b.engine.sync();
    expect(m.gets).toBe(0);
    // Within the count bound, but each chunk is bigger than the whole claimed file.
    await forge(sa, "evil2.bin", 2 * 1024 * 1024, ids.slice(0, 8));
    await b.engine.sync();
    expect(m.plainBytes).toBe(0); // the first chunk is refused while inflating, before it is held
    expect(m.gets).toBeLessThanOrEqual(4); // at most the prefetch window
    expect(await b.exists("evil.bin")).toBe(false);
    expect(await b.exists("evil2.bin")).toBe(false);
    await a.cleanup();
    await b.cleanup();
  });

  it("F2: a server padding an honest op's chunk list costs the reader nothing and writes nothing", async () => {
    const [sa, sb, a, b] = await pair();
    for (let i = 0; i < 3; i++) await a.write(`video${i}.bin`, noise(6 * 1024 * 1024, 100 + i));
    await a.write("t.bin", noise(1_500_000, 7));
    await a.sync();
    await b.sync();
    const vault = sa.identity.vaultId;
    const all = new Set<string>();
    for (let i = 0; i < 3; i++) for (const o of await sa.client.history(vault, await sa.vc.pathId(`video${i}.bin`))) for (const c of o.chunks ?? []) all.add(c);
    await a.write("t.bin", noise(1_500_000, 8));
    await a.sync();
    const feed = sb.client.changes.bind(sb.client);
    sb.client.changes = (async (...args: Parameters<typeof feed>) => {
      const r = await feed(...args);
      for (const o of r.ops) if (o.chunks?.length) o.chunks = [...o.chunks, ...all];
      return r;
    }) as typeof feed;
    const m = meter(sb);
    await b.engine.sync();
    expect(m.ctBytes).toBe(0);
    expect(Buffer.compare(await b.readBytes("t.bin"), noise(1_500_000, 7))).toBe(0);
    sb.client.changes = feed;
    await a.cleanup();
    await b.cleanup();
  });

  it("crash loop: an op that stopped the app twice while being written is skipped and reported; once is retried", async () => {
    const skipped: string[] = [];
    const sa = await createVault(await srv.createLink(), "laptop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("laptop", sa).start();
    const b = await new Device("phone", sb, { hooks: { onSkipped: (p) => void skipped.push(p) } }).start();
    const big = noise(3 * 1024 * 1024, 31);
    await a.write("big.bin", big);
    await a.write("other.md", "fine\n");
    await a.sync();
    const op = (await sb.client.history(sb.identity.vaultId, await sb.vc.pathId("big.bin")))[0];
    const crashOnce = async (tries: number) => {
      await b.engine.flushState();
      const f = await b.stateFile();
      const st = JSON.parse(await fsp.readFile(f, "utf8"));
      st.applying = { seq: op.seq, tries };
      await fsp.writeFile(f, JSON.stringify(st));
      await b.restart({ crash: true });
    };
    await crashOnce(1); // died once: tried again
    await b.sync();
    expect(Buffer.compare(await b.readBytes("big.bin"), big)).toBe(0);
    expect(skipped).toEqual([]);

    // Second device, died twice on the same op: skipped, the rest of the vault still arrives.
    const sc = await joinWithLink(await createInviteLink(sa), "tablet");
    const c = await new Device("tablet", sc, { hooks: { onSkipped: (p) => void skipped.push(p) } }).start();
    await c.engine.flushState();
    const f = await c.stateFile();
    const st = JSON.parse(await fsp.readFile(f, "utf8"));
    st.applying = { seq: op.seq, tries: 2 };
    await fsp.writeFile(f, JSON.stringify(st));
    await c.restart({ crash: true });
    await c.sync();
    expect(await c.exists("big.bin")).toBe(false);
    expect(await c.read("other.md")).toBe("fine\n");
    expect(skipped).toEqual(["big.bin"]);
    // A later version of the file is applied normally.
    const big2 = noise(3 * 1024 * 1024, 32);
    await a.write("big.bin", big2);
    await a.sync();
    await c.sync();
    expect(Buffer.compare(await c.readBytes("big.bin"), big2)).toBe(0);
    for (const d of [a, b, c]) await d.cleanup();
  }, 120_000);
});

describe("review 14: merges and conflict provenance", () => {
  it("F6: disjoint concurrent edits of a note stored as chunks merge", async () => {
    const [, , a, b] = await pair();
    const lines = 250_000;
    const base = Array.from({ length: lines }, (_, i) => `line ${i} lorem ipsum dolor sit amet`);
    await a.write("big.md", base.join("\n") + "\n");
    await a.sync();
    await b.sync();
    expect((await b.fs.stat("big.md"))!.size).toBeGreaterThan(4 * 1024 * 1024);
    const ea = base.slice();
    ea[5] = "edited on laptop";
    const eb = base.slice();
    eb[lines - 5] = "edited on phone";
    await a.write("big.md", ea.join("\n") + "\n");
    await b.write("big.md", eb.join("\n") + "\n");
    await a.sync();
    await b.sync();
    await a.sync();
    const merged = base.slice();
    merged[5] = "edited on laptop";
    merged[lines - 5] = "edited on phone";
    expect((await b.files()).filter((p) => p.includes("(conflict"))).toEqual([]);
    expect(await b.read("big.md")).toBe(merged.join("\n") + "\n");
    expect(await a.read("big.md")).toBe(merged.join("\n") + "\n");
    await a.cleanup();
    await b.cleanup();
  }, 120_000);

  it("(b): the review dialog learns who wrote a copy from the sync record, not its name, and which targets are safe to replace", async () => {
    const sa = await createVault(await srv.createLink(), "laptop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("laptop", sa).start();
    const b = await new Device("phone", sb, { exclusions: ["/.obsidian/workspace.json", "/private.md"] }).start();
    const bin = noise(10_000, 1);
    await a.write("pic.bin", bin);
    await a.sync();
    await b.sync();
    await a.write("pic.bin", noise(10_000, 2));
    await b.write("pic.bin", noise(10_000, 3));
    await a.sync();
    await b.sync(); // b keeps its own bytes as a copy
    await a.sync();
    const sib = (await b.files()).find((p) => p.includes("(conflict"))!;
    expect(b.engine.conflictInfo(sib)).toMatchObject({ own: true, target: "pic.bin", targetSynced: true });
    expect(a.engine.conflictInfo(sib)).toMatchObject({ own: false, by: sb.identity.deviceId, targetSynced: true });

    // A look-alike made on the laptop, naming the phone as its author.
    const fake = conflictPath("note.md", "phone", new Date());
    await a.write("note.md", "real\n");
    await a.write(fake, "planted\n");
    await a.write("private (conflict phone 2026-01-01 1200).md", "planted\n");
    await a.sync();
    await b.write("private.md", "local only\n");
    await b.sync();
    expect(b.engine.conflictInfo(fake)).toMatchObject({ own: false, by: sa.identity.deviceId, target: "note.md", targetSynced: true });
    expect(b.engine.conflictInfo("private (conflict phone 2026-01-01 1200).md")).toMatchObject({ target: "private.md", targetSynced: false });
    await a.cleanup();
    await b.cleanup();
  });
});
