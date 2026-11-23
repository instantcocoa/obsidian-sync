/**
 * Fifteenth review (1.0.3): the crash guard on every path, history paging,
 * and conflict-copy provenance. The kill model is the reviewer's: at the
 * chosen moment the engine is frozen and the next launch reads the state
 * file as it was on disk at that instant.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { TestServer, Device } from "./harness";
import { createVault, createInviteLink, joinWithLink, openSession, type Session } from "../src/core/admin";
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

type Eng = { state: { applying?: { seq: number; tries: number; path?: string }; files: Record<string, { skip?: number }> }; store: unknown; stopped: boolean };

/**
 * One launch of the victim. `shouldDie` is consulted on every blob GET and
 * every fs.write; returning true kills the process at that point.
 */
async function launch(
  identity: Session["identity"],
  dir: string | undefined,
  shouldDie: (ev: { kind: "get" | "write"; id: string; eng: Eng }) => boolean,
): Promise<{ dev: Device; outcome: "done" | "killed"; persisted: Record<string, unknown> | null }> {
  const dev = await new Device("victim", openSession(identity)).start(dir);
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

describe("review 15: the crash guard holds on every path", () => {
  it("N1: 51 oversized versions in one batch: each stops the app at most twice, then the device finishes syncing", async () => {
    const sa = await createVault(await srv.createLink(), "attacker");
    const sb = await joinWithLink(await createInviteLink(sa), "victim");
    const a = await new Device("attacker", sa).start();
    const N = 51;
    for (let i = 0; i < N; i++) await a.write(`big/b${i}.bin`, noise(1024 * 1024 + 4096, i + 1));
    await a.write("note.md", "still arrives\n");
    await a.sync();
    // Fetching any chunk of the oversized versions kills the app.
    const bombChunks = new Set<string>();
    for (let i = 0; i < N; i++) for (const o of await sa.client.history(sa.identity.vaultId, await sa.vc.pathId(`big/b${i}.bin`))) for (const c of (await sa.client.getOp(sa.identity.vaultId, o.seq))?.chunks ?? []) bombChunks.add(c);
    const die = (ev: { kind: string; id: string }) => ev.kind === "get" && bombChunks.has(ev.id);
    let dir: string | undefined;
    const triesBySeq = new Map<number, number>();
    let done: Device | null = null;
    for (let launchNo = 0; launchNo < 2 * N + 4; launchNo++) {
      const r = await launch(sb.identity, dir, die);
      dir = r.dev.dir;
      if (r.outcome === "done") {
        done = r.dev;
        break;
      }
      const ap = (r.persisted as { applying?: { seq: number; tries: number } }).applying;
      expect(ap).toBeDefined();
      if (!ap) break;
      triesBySeq.set(ap.seq, (triesBySeq.get(ap.seq) ?? 0) + 1);
    }
    expect(done).not.toBeNull();
    for (const n of triesBySeq.values()) expect(n).toBeLessThanOrEqual(2);
    expect(await done!.read("note.md")).toBe("still arrives\n");
    for (let i = 0; i < N; i++) expect(await done!.exists(`big/b${i}.bin`)).toBe(false);
  }, 300_000);

  it("N2: the merge path is guarded too: a local edit against an oversized head stops the app at most twice, the edit survives", async () => {
    const sa = await createVault(await srv.createLink(), "attacker");
    const sb = await joinWithLink(await createInviteLink(sa), "victim");
    const a = await new Device("attacker", sa).start();
    await a.write("Daily.md", "today\n");
    await a.sync();
    const first = await launch(sb.identity, undefined, () => false);
    expect(first.outcome).toBe("done");
    const dir = first.dev.dir;
    await first.dev.engine.flushState();
    await first.dev.engine.stop();
    await first.dev.write("Daily.md", "today\nmy unsynced line\n");
    await a.write("Daily.md", text(1536 * 1024, 7));
    await a.sync();
    const pid = await sa.vc.pathId("Daily.md");
    const head = (await sa.client.getOp(sa.identity.vaultId, (await sa.client.history(sa.identity.vaultId, pid)).reduce((x, y) => (y.seq > x.seq ? y : x)).seq))!;
    const chunkIds = new Set(head.chunks);
    const die = (ev: { kind: string; id: string }) => ev.kind === "get" && chunkIds.has(ev.id);
    let kills = 0;
    let last!: Device;
    for (let i = 0; i < 6; i++) {
      const r = await launch(sb.identity, dir, die);
      last = r.dev;
      if (r.outcome === "done") break;
      kills++;
    }
    expect(kills).toBeLessThanOrEqual(2);
    expect(await last.read("Daily.md")).toBe("today\nmy unsynced line\n");
  }, 120_000);

  it("N3: a death while writing the reassembled file is counted like any other", async () => {
    const sa = await createVault(await srv.createLink(), "attacker");
    const sb = await joinWithLink(await createInviteLink(sa), "victim");
    const a = await new Device("attacker", sa).start();
    await a.write("big.bin", noise(1536 * 1024, 99));
    await a.sync();
    const die = (ev: { kind: string; id: string }) => ev.kind === "write" && ev.id === "big.bin";
    let dir: string | undefined;
    let kills = 0;
    let outcome = "killed";
    for (let i = 0; i < 6 && outcome === "killed"; i++) {
      const r = await launch(sb.identity, dir, die);
      dir = r.dev.dir;
      outcome = r.outcome;
      if (outcome === "killed") {
        kills++;
        expect((r.persisted as { applying?: { path?: string } }).applying?.path).toBe("big.bin");
      }
    }
    expect(outcome).toBe("done");
    expect(kills).toBe(2);
  }, 120_000);
});

describe("review 15: history pages and conflict provenance", () => {
  it("N4: junk versions with long chunk lists no longer hide a file's history", async () => {
    const so = await createVault(await srv.createLink(), "owner");
    const sm = await joinWithLink(await createInviteLink(so), "member");
    const o = await new Device("owner", so).start();
    for (let i = 0; i < 20; i++) {
      await o.write("Notes.md", `version ${i}\n`);
      await o.sync();
    }
    const vault = so.identity.vaultId;
    const pathId = await sm.vc.pathId("Notes.md");
    const part = new Uint8Array([42]);
    const c = await sm.vc.blobId(part);
    await sm.client.putBlob(vault, c, await sm.vc.encryptBlob(c, part));
    const epoch = sm.vc.keyring.current;
    let base = Math.max(...(await so.client.history(vault, pathId)).map((x) => x.seq));
    for (let i = 0; i < 9; i++) {
      const meta: FileMeta = { path: "Notes.md", mtime: Date.now(), size: 1, blob: c };
      const r = await sm.client.postOps(vault, [
        { op_id: `h${i}-${Date.now()}`, path_id: pathId, blob_id: c, chunks: Array(4096).fill(c), meta_enc: await sm.vc.encryptMeta(pathId, meta, { epoch }), meta_epoch: epoch, base_seq: base },
      ]);
      base = r.results[0].seq!;
    }
    const after = await so.client.history(vault, pathId);
    expect(after.length).toBe(29);
    expect(after.filter((x) => x.blob_id !== c).length).toBe(20);
  });

  it("N5: another device's edit of this device's conflict copy is no longer reported as this device's own", async () => {
    const sv = await createVault(await srv.createLink(), "victim");
    const sm = await joinWithLink(await createInviteLink(sv), "member");
    const v = await new Device("victim", sv).start();
    const m = await new Device("member", sm).start();
    await v.write("note.md", "line one\n");
    await v.sync();
    await m.sync();
    await m.write("note.md", "member line\n");
    await m.sync();
    await v.write("note.md", "victim line\n");
    await v.sync();
    const sib = (await v.files()).find((p) => / \(conflict /.test(p))!;
    expect(v.engine.conflictInfo(sib).own).toBe(true);
    await v.sync();
    await m.sync();
    await m.write(sib, "attacker text, presented as yours\n");
    await m.sync();
    await v.sync();
    const info = v.engine.conflictInfo(sib);
    expect(info.own).toBe(false);
    expect(info.by).toBe(sm.identity.deviceId);
  });
});
