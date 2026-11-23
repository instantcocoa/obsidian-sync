/**
 * Large files as content-defined chunks (1.0): only changed chunks travel,
 * equal chunks are stored once, and nothing is written unless the
 * reassembled content matches the authenticated size and content id.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device } from "./harness";
import { createVault, createInviteLink, joinWithLink, listDevices, removeDevice } from "../src/core/admin";
import { CHUNK_MAX, CHUNK_MIN, CHUNK_THRESHOLD, cutPoints, gearTable, split } from "../src/core/chunks";

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
const table = gearTable(noise(1024, 7));
const same = (a: Uint8Array, b: Uint8Array) => Buffer.compare(a, b) === 0;

describe("chunker", () => {
  it("covers the input exactly, within the size bounds, deterministically", () => {
    const data = noise(20 * 1024 * 1024, 1);
    const cuts = cutPoints(data, table);
    expect(cuts[cuts.length - 1]).toBe(data.length);
    let prev = 0;
    for (const [i, c] of cuts.entries()) {
      const len = c - prev;
      expect(len).toBeLessThanOrEqual(CHUNK_MAX);
      if (i < cuts.length - 1) expect(len).toBeGreaterThan(CHUNK_MIN);
      prev = c;
    }
    expect(cuts.length).toBeGreaterThan(8);
    expect(cuts.length).toBeLessThan(60);
    expect(cutPoints(data, table)).toEqual(cuts);
    expect(same(Buffer.concat(split(data, table)), data)).toBe(true);
  });

  it("an insertion near the front moves few boundaries; a different key moves all of them", () => {
    const data = noise(16 * 1024 * 1024, 2);
    const edited = new Uint8Array(data.length + 1000);
    edited.set(data.subarray(0, 500_000));
    edited.set(noise(1000, 3), 500_000);
    edited.set(data.subarray(500_000), 501_000);
    const key = (parts: Uint8Array[]) => new Set(parts.map((p) => `${p.length}:${p[0]}:${p[p.length - 1]}:${p[p.length >> 1]}`));
    const a = key(split(data, table));
    const b = key(split(edited, table));
    const shared = [...a].filter((k) => b.has(k)).length;
    expect(shared).toBeGreaterThanOrEqual(a.size - 2);
    const other = cutPoints(data, gearTable(noise(1024, 99)));
    expect(other.filter((c) => cutPoints(data, table).includes(c)).length).toBeLessThanOrEqual(1); // only the end
  });

  it("small inputs are one chunk", () => {
    expect(cutPoints(noise(1000, 4), table)).toEqual([1000]);
    expect(cutPoints(new Uint8Array(0), table)).toEqual([]);
  });
});

describe("large files through the real server", () => {
  it("a 12 MiB file travels as chunks, an edit uploads and downloads only what changed, history and rename work", async () => {
    const sa = await createVault(await srv.createLink(), "laptop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("laptop", sa).start();
    const b = await new Device("phone", sb).start();
    const count = (s: typeof sa) => {
      const c = { put: 0, putBytes: 0, get: 0, getBytes: 0 };
      const put = s.client.putBlob.bind(s.client);
      s.client.putBlob = async (v: string, id: string, d: Uint8Array, o?: never) => {
        c.put++;
        c.putBytes += d.length;
        return put(v, id, d, o);
      };
      const get = s.client.getBlob.bind(s.client);
      s.client.getBlob = async (v: string, id: string) => {
        const r = await get(v, id);
        c.get++;
        c.getBytes += r.length;
        return r;
      };
      return c;
    };
    const ca = count(sa);
    const cb = count(sb);

    const big = noise(12 * 1024 * 1024, 5);
    await a.write("video.bin", big, 1_700_000_000_000);
    await a.write("small.md", "one blob as before\n");
    await a.sync();
    const chunks = split(big, gearTable(await sa.vc.cdcSeed())).length;
    expect(chunks).toBeGreaterThan(4);
    expect(ca.put).toBe(chunks + 1);
    await b.sync();
    expect(cb.get).toBe(chunks + 1);
    expect(same(await b.readBytes("video.bin"), big)).toBe(true);
    expect((await b.fs.stat("video.bin"))!.mtime).toBe(1_700_000_000_000);

    // Change 100 bytes in the middle: one or two chunks, not twelve megabytes.
    const edited = big.slice();
    edited.set(noise(100, 6), 6_000_000);
    ca.put = ca.putBytes = cb.get = cb.getBytes = 0;
    await a.write("video.bin", edited);
    await a.sync();
    expect(ca.put).toBeLessThanOrEqual(2);
    expect(ca.putBytes).toBeLessThan(CHUNK_MAX * 2 + 4096);
    await b.sync();
    expect(cb.get).toBeLessThanOrEqual(2);
    expect(cb.getBytes).toBeLessThan(CHUNK_MAX * 2 + 4096);
    expect(same(await b.readBytes("video.bin"), edited)).toBe(true);

    // The first version is still whole in history.
    const ops = await sb.client.history(sb.identity.vaultId, await sb.vc.pathId("video.bin"));
    const first = ops.sort((x, y) => x.seq - y.seq)[0];
    expect(first.chunks!.length).toBe(chunks);
    expect(same(await b.engine.versionBytes(first), big)).toBe(true);

    // Rename on A: nothing uploaded, nothing downloaded.
    ca.put = cb.get = 0;
    await a.write("renamed.bin", edited);
    await a.remove("video.bin");
    await a.sync();
    await b.sync();
    expect(ca.put).toBe(0);
    expect(cb.get).toBe(0);
    expect(same(await b.readBytes("renamed.bin"), edited)).toBe(true);
    expect(await b.exists("video.bin")).toBe(false);

    // A third device joining gets the current files only.
    const sc = await joinWithLink(await createInviteLink(sa), "tablet");
    const c = await new Device("tablet", sc).start();
    await c.sync();
    expect(same(await c.readBytes("renamed.bin"), edited)).toBe(true);
    expect(await c.read("small.md")).toBe("one blob as before\n");

    // Concurrent edits of a large binary: a sibling with exact bytes, as for any binary.
    const ea = edited.slice();
    ea.set(noise(50, 8), 1_000_000);
    const eb = edited.slice();
    eb.set(noise(50, 9), 9_000_000);
    await a.write("renamed.bin", ea);
    await b.write("renamed.bin", eb);
    await a.sync();
    await b.sync();
    await a.sync();
    expect(same(await a.readBytes("renamed.bin"), ea)).toBe(true);
    expect(same(await b.readBytes("renamed.bin"), ea)).toBe(true);
    const sib = (await b.files()).find((p) => p.includes("(conflict"))!;
    expect(same(await b.readBytes(sib), eb)).toBe(true);
    expect(same(await a.readBytes(sib), eb)).toBe(true);

    // GC keeps every chunk a live version needs.
    await srv.gc("0s");
    const sd = await joinWithLink(await createInviteLink(sa), "fresh");
    const d = await new Device("fresh", sd).start();
    await d.sync();
    expect(same(await d.readBytes("renamed.bin"), ea)).toBe(true);
    expect(same(await d.readBytes(sib), eb)).toBe(true);
    for (const x of [a, b, c, d]) await x.cleanup();
  }, 240_000);

  it("key rotation re-encrypts chunks, restore-to-time brings a chunked version back, GC then keeps it", async () => {
    const sa = await createVault(await srv.createLink(), "laptop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("laptop", sa).start();
    const b = await new Device("phone", sb).start();
    const v1 = noise(6 * 1024 * 1024, 21);
    await a.write("big.bin", v1);
    await a.sync();
    await b.sync();
    await new Promise((r) => setTimeout(r, 30));
    const t = Date.now();
    await new Promise((r) => setTimeout(r, 30));
    const v2 = noise(6 * 1024 * 1024, 22); // unrelated content: no chunk shared with v1
    await a.write("big.bin", v2);
    await a.sync();

    // Remove the phone: keys rotate and every blob, chunks included, is re-encrypted.
    const phone = (await listDevices(sa)).find((d) => d.name === "phone")!;
    await removeDevice(a.session, phone.id);
    await a.sync();
    const sc = await joinWithLink(await createInviteLink(a.session), "tablet");
    const c = await new Device("tablet", sc).start();
    await c.sync();
    expect(same(await c.readBytes("big.bin"), v2)).toBe(true);

    // Rewind the vault to before the second version.
    const res = await a.session.client.restore(a.session.identity.vaultId, t);
    expect(res.emitted).toBe(1);
    expect(res.skipped_path_ids).toEqual([]);
    await a.sync();
    await c.sync();
    expect(same(await a.readBytes("big.bin"), v1)).toBe(true);
    expect(same(await c.readBytes("big.bin"), v1)).toBe(true);

    // A sweep with no retention drops v2's chunks and keeps v1's.
    await srv.gc("0s");
    const sd = await joinWithLink(await createInviteLink(a.session), "fresh");
    const d = await new Device("fresh", sd).start();
    await d.sync();
    expect(same(await d.readBytes("big.bin"), v1)).toBe(true);
    for (const x of [a, c, d]) await x.cleanup();
  }, 240_000);

  it("a chunk list the server tampered with is refused, nothing is written", async () => {
    const sa = await createVault(await srv.createLink(), "laptop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("laptop", sa).start();
    const b = await new Device("phone", sb).start();
    const big = noise(5 * 1024 * 1024, 11);
    await a.write("big.bin", big);
    await a.sync();
    for (const mangle of [(c: string[]) => c.slice().reverse(), (c: string[]) => c.slice(1), (c: string[]) => [...c, c[0]]]) {
      const snap = sb.client.snapshot.bind(sb.client);
      const feed = sb.client.changes.bind(sb.client);
      const fix = <T extends { ops: { chunks?: string[] }[] }>(r: T): T => {
        for (const o of r.ops) if (o.chunks?.length) o.chunks = mangle(o.chunks);
        return r;
      };
      sb.client.snapshot = (async (...args: Parameters<typeof snap>) => fix(await snap(...args))) as typeof snap;
      sb.client.changes = (async (...args: Parameters<typeof feed>) => fix(await feed(...args))) as typeof feed;
      await b.engine.rebuildState();
      await b.engine.sync();
      expect(await b.exists("big.bin")).toBe(false);
      sb.client.snapshot = snap;
      sb.client.changes = feed;
    }
    await b.engine.rebuildState();
    await b.sync();
    expect(same(await b.readBytes("big.bin"), big)).toBe(true);
    expect(CHUNK_THRESHOLD).toBe(1024 * 1024);
    await a.cleanup();
    await b.cleanup();
  }, 120_000);
});
