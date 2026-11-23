/**
 * Sixteenth review (1.0.4): the crash guard for any large version, a per-device
 * size ceiling, edits to skipped files, and history pages without chunk lists.
 * Same kill model as review15.test.ts.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { TestServer, Device } from "./harness";
import { createVault, createInviteLink, joinWithLink, openSession, type Session } from "../src/core/admin";
import { Engine, type EngineHooks } from "../src/core/engine";
import type { FileMeta } from "../src/core/crypto";

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
function text(n: number, seed: number): string {
  const b = noise(n, seed);
  let s = "";
  for (let i = 0; i < n; i++) s += i % 60 === 59 ? "\n" : String.fromCharCode(97 + (b[i] % 26));
  return s;
}

type Eng = { state: { applying?: { seq: number; tries: number; path?: string }; files: Record<string, { skip?: number }>; ceiling?: number }; store: unknown; stopped: boolean; dirty: Set<string> };

/**
 * One launch of the victim. `shouldDie` is consulted on every blob GET and
 * every fs.write; returning true kills the process at that point.
 */
async function launch(
  identity: Session["identity"],
  dir: string | undefined,
  shouldDie: (ev: { kind: "get" | "write"; id: string; eng: Eng }) => boolean,
  hooks: EngineHooks = {},
): Promise<{ dev: Device; outcome: "done" | "killed"; persisted: Record<string, unknown> | null }> {
  const dev = await new Device("victim", openSession(identity), { hooks }).start(dir);
  const eng = dev.engine as unknown as Eng;
  let die!: (p: Record<string, unknown> | null) => void;
  const death = new Promise<Record<string, unknown> | null>((r) => (die = r));
  const kill = async (): Promise<never> => {
    const f = await dev.stateFile();
    const raw = existsSync(f) ? readFileSync(f, "utf8") : null;
    eng.store = { save: async () => undefined, load: async () => raw };
    eng.stopped = true;
    if (raw !== null) writeFileSync(f, raw); // what the disk holds at the instant of death
    die(raw ? JSON.parse(raw) : null);
    return new Promise<never>(() => undefined);
  };
  const c = dev.session.client;
  const get = c.getBlob.bind(c);
  c.getBlob = async (v: string, id: string, s?: AbortSignal) => {
    if (shouldDie({ kind: "get", id, eng })) return kill();
    return get(v, id, s);
  };
  const w = dev.fs.write.bind(dev.fs);
  dev.fs.write = async (p: string, d: Uint8Array, m: number) => {
    if (shouldDie({ kind: "write", id: p, eng })) return kill();
    return w(p, d, m);
  };
  const r = await Promise.race([dev.sync().then(() => "done" as const), death.then(() => "killed" as const)]);
  const persisted = r === "killed" ? await death : null;
  return { dev, outcome: r, persisted };
}

async function killsUntilDone(identity: Session["identity"], dir: string | undefined, die: (ev: { kind: string; id: string }) => boolean, max: number, hooks: EngineHooks = {}) {
  let kills = 0;
  let dev!: Device;
  for (let i = 0; i < max; i++) {
    const r = await launch(identity, dir, die, hooks);
    dir = r.dev.dir;
    dev = r.dev;
    if (r.outcome === "done") return { kills, dir, done: true, dev };
    kills++;
  }
  return { kills, dir, done: false, dev };
}

describe("review 16: every large version is guarded, and many cost two crashes in all", () => {
  it("R1: a single-blob version that inflates large is guarded like a chunked one", async () => {
    const sa = await createVault(await srv.createLink(), "attacker");
    const sb = await joinWithLink(await createInviteLink(sa), "victim");
    const vault = sa.identity.vaultId;
    const SIZE = 8 * 1024 * 1024;
    const zeros = new Uint8Array(SIZE);
    const id = await sa.vc.blobId(zeros);
    await sa.client.putBlob(vault, id, await sa.vc.encryptBlob(id, zeros, { compress: true }));
    const pathId = await sa.vc.pathId("bomb.bin");
    const epoch = sa.vc.keyring.current;
    const meta: FileMeta = { path: "bomb.bin", mtime: Date.now(), size: SIZE, blob: id };
    await sa.client.postOps(vault, [{ op_id: `bomb-${Date.now()}`, path_id: pathId, blob_id: id, meta_enc: await sa.vc.encryptMeta(pathId, meta, { epoch }), meta_epoch: epoch, base_seq: 0 }]);
    const r = await killsUntilDone(sb.identity, undefined, (ev) => ev.kind === "get" && ev.id === id, 6);
    expect(r.done).toBe(true);
    expect(r.kills).toBe(2);
    expect(await r.dev.exists("bomb.bin")).toBe(false);
  }, 120_000);

  it("R4: many oversized versions, and re-posts of them, cost a device two crashes in all", async () => {
    const floor = Engine.CEILING_FLOOR;
    (Engine as unknown as { CEILING_FLOOR: number }).CEILING_FLOOR = 1024 * 1024; // the test files stand in for 64 MiB+ ones
    try {
      const sa = await createVault(await srv.createLink(), "attacker");
      const a = await new Device("attacker", sa).start();
      const N = 10;
      for (let i = 0; i < N; i++) await a.write(`big/b${i}.bin`, noise(1024 * 1024 + 4096, i + 1));
      await a.write("note.md", "fine\n");
      await a.sync();
      const vault = sa.identity.vaultId;
      const bombChunks = new Set<string>();
      for (let i = 0; i < N; i++) {
        const pid = await sa.vc.pathId(`big/b${i}.bin`);
        for (const o of await sa.client.history(vault, pid)) for (const c of (await sa.client.getOp(vault, o.seq))?.chunks ?? []) bombChunks.add(c);
      }
      expect(bombChunks.size).toBeGreaterThan(N);
      const die = (ev: { kind: string; id: string }) => ev.kind === "get" && bombChunks.has(ev.id);
      const sb = await joinWithLink(await createInviteLink(sa), "phone");
      const r = await killsUntilDone(sb.identity, undefined, die, 2 * N + 4);
      expect(r.done).toBe(true);
      expect(r.kills).toBe(2);
      expect(await r.dev.read("note.md")).toBe("fine\n");
      // A re-post of one of them under a new seq costs nothing more.
      const pid = await sa.vc.pathId("big/b0.bin");
      const head = (await sa.client.getOp(vault, (await sa.client.history(vault, pid))[0].seq))!;
      await sa.client.postOps(vault, [{ op_id: `repost-${Date.now()}`, path_id: pid, blob_id: head.blob_id, chunks: head.chunks, meta_enc: Buffer.from(head.meta_enc, "base64"), meta_epoch: head.meta_epoch, base_seq: head.seq }]);
      await r.dev.engine.stop();
      const again = await killsUntilDone(sb.identity, r.dir, die, 4);
      expect(again.done).toBe(true);
      expect(again.kills).toBe(0);
    } finally {
      (Engine as unknown as { CEILING_FLOOR: number }).CEILING_FLOOR = floor;
    }
  }, 300_000);

  it("R2: edits to a file whose newest version was skipped are uploaded as a conflict copy, and said so", async () => {
    const sa = await createVault(await srv.createLink(), "attacker");
    const sb = await joinWithLink(await createInviteLink(sa), "victim");
    const a = await new Device("attacker", sa).start();
    await a.write("Daily.md", "today\n");
    await a.sync();
    const first = await launch(sb.identity, undefined, () => false);
    const dir = first.dev.dir;
    await first.dev.engine.stop();
    await a.write("Daily.md", text(1536 * 1024, 7));
    await a.sync();
    const vault = sa.identity.vaultId;
    const pid = await sa.vc.pathId("Daily.md");
    const bomb = (await sa.client.getOp(vault, (await sa.client.history(vault, pid))[0].seq))!;
    const chunkIds = new Set(bomb.chunks);
    const r = await killsUntilDone(sb.identity, dir, (ev) => ev.kind === "get" && chunkIds.has(ev.id), 4);
    expect(r.kills).toBe(2);
    await r.dev.engine.stop();
    const notices: string[] = [];
    const v = await new Device("victim", openSession(sb.identity), { hooks: { onSkipped: (p, why) => void notices.push(`${p}: ${why}`) } }).start(dir);
    await v.write("Daily.md", "today\nmy edit\n", Date.now() + 1000);
    await v.sync();
    await v.sync();
    expect(await v.read("Daily.md")).toBe("today\nmy edit\n");
    const copy = (await v.files()).find((p) => p.startsWith("Daily (conflict"))!;
    expect(copy).toBeDefined();
    expect(notices.some((n) => n.includes(copy))).toBe(true);
    await a.sync();
    expect(await a.read(copy)).toBe("today\nmy edit\n");
    await v.engine.stop();
  }, 300_000);

  it("R3: history pages leave chunk lists out, so junk with long lists cannot crowd out real versions", async () => {
    const so = await createVault(await srv.createLink(), "owner");
    const sm = await joinWithLink(await createInviteLink(so), "member");
    const o = await new Device("owner", so).start();
    for (let i = 0; i < 20; i++) {
      await o.write("Notes.md", `version ${i}\n`);
      await o.sync();
    }
    const vault = so.identity.vaultId;
    const pathId = await sm.vc.pathId("Notes.md");
    const c = await sm.vc.blobId(new Uint8Array([42]));
    await sm.client.putBlob(vault, c, await sm.vc.encryptBlob(c, new Uint8Array([42])));
    const epoch = sm.vc.keyring.current;
    const metaEnc = await sm.vc.encryptMeta(pathId, { path: "Notes.md", mtime: Date.now(), size: 1, blob: c }, { epoch });
    let base = Math.max(...(await so.client.history(vault, pathId)).map((x) => x.seq));
    for (let i = 0; i < 60; i++) {
      const r = await sm.client.postOps(vault, [{ op_id: `j${i}-${Date.now()}`, path_id: pathId, blob_id: c, chunks: Array(4096).fill(c), meta_enc: metaEnc, meta_epoch: epoch, base_seq: base }]);
      base = r.results[0].seq!;
    }
    let requests = 0;
    let bytes = 0;
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const res = await realFetch(input, init);
      if (String(input).includes("/history")) {
        requests++;
        bytes += (await res.clone().arrayBuffer()).byteLength;
      }
      return res;
    }) as typeof fetch;
    let after;
    try {
      after = await so.client.history(vault, pathId);
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(requests).toBe(1);
    expect(bytes).toBeLessThan(200_000);
    expect(after.filter((x) => x.blob_id !== c).length).toBe(20);
    expect(after.filter((x) => x.chunked).length).toBe(60);
    expect(after.every((x) => !x.chunks?.length)).toBe(true);
    // The full op, list included, is one request away.
    expect((await so.client.getOp(vault, after[0].seq))!.chunks!.length).toBe(4096);
  }, 300_000);
});
