/**
 * Eleventh review (2026-11-08): the tenth round's `State.deferred` mechanism
 * (engine.ts: deferOp / retryDeferred / DEFERRED_TRIES, 0.1.11), read as a
 * hurried fix with an edge. The parent-folder refusal is injected through the
 * device's `fs.write` with the exact message NodeFS and ObsidianFS throw, so
 * these run on any volume (the round-10 proofs needed an APFS temp dir) and
 * test the engine, not the file layer.
 *
 *  A. Every retry re-downloads the blob, decrypts it and flushes state.json
 *     BEFORE discovering that the folder is still spelled differently: the
 *     refusal comes from `fs.write`, the last step of `writeRemote`. N
 *     deferred files cost N sequential downloads and N state flushes per
 *     sync cycle, ahead of the user's own pull and push, for 48 cycles.
 *     Fails on HEAD (a4f34a0).
 *
 *  B. The 48-try bound counts sync cycles, not time. A cycle runs at every
 *     poll, live hint and debounced local change, so a user who keeps editing
 *     other notes burns the budget in a minute or two; the first notice says
 *     "it will be retried once that folder is emptied or renamed", and when
 *     they then rename the folder nothing arrives. Fails on HEAD.
 *
 *  C. A key rotation between the defer and the retry (someone runs "Remove
 *     device", which re-encrypts and raises min_epoch) leaves the parked op
 *     with a `meta_enc` under the pruned epoch: `decryptMeta` throws "no key
 *     for epoch", the catch is not the alias one, and the op is dropped with
 *     a console line only: no notice, no refetch of the row the server now
 *     holds under the new epoch. Fails on HEAD (two assertions).
 *
 *  D. `retryDeferred`'s catch deletes `state.inflight[logical]` for ANY
 *     error, not only the alias refusal. A write that fails after touching
 *     the file (ObsidianFS's "write verification failed", seen on Android)
 *     loses the record that would have made the scanner treat the partial
 *     bytes as an interrupted write; they become a "local edit" instead, and
 *     the next push fans a 0-byte conflict sibling out to every device. The
 *     same failure through `applyBatch` heals cleanly (soundness check,
 *     passes). Fails on HEAD.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink, removeDevice, type Session } from "../src/core/admin";
import { Engine } from "../src/core/engine";
import { utf8 } from "../src/core/encoding";
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

/** The exact refusal NodeFS.refuseAliasClash / ObsidianFS.refuseCaseClash throw for a differently spelled parent FOLDER. */
const ALIAS = (folder: string) => new Error(`"${folder}" resolves to a folder spelled differently on this volume; refusing to write through it`);

/**
 * Make the device's volume "spell `notes/` differently": every write under it
 * is refused the way the real file layers refuse it, until `ctl.on` is false
 * (the user renamed or emptied the twin folder).
 */
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
  // The engine asks the volume first (VaultFS.aliasRefusal) before it
  // downloads anything for a parked op; the stub must answer the way the
  // write would, or on a case-sensitive volume the probe says "fine" and the
  // test measures the wrong thing.
  mac.fs.aliasRefusal = async (p) => (ctl.on && p.startsWith("notes/") ? ALIAS("notes").message : (await origProbe?.(p)) ?? null);
  return ctl;
}

type Stuck = { sa: Session; sb: Session; mac: Device; ctl: { on: boolean; refused: number }; skipped: [string, string][]; fetched: string[]; saves: () => number };

/**
 * The user does what the first notice asks: renames the twin folder to the
 * other devices' spelling. Done on disk as well as in the stub, because on a
 * case-insensitive volume (this Mac) the real NodeFS would otherwise keep
 * refusing the write through `Notes/`, and the test would pass for the wrong
 * reason on a fixed engine.
 */
async function fixFolder(s: Stuck): Promise<void> {
  s.ctl.on = false;
  await fsp.rename(join(s.mac.dir, "Notes"), join(s.mac.dir, "notes"));
}

/** A Mac whose `Notes/` holds something sync never removes, while Linux writes `notes/…`: the puts are deferred. */
async function stuck(n = 1): Promise<Stuck> {
  const sa = await createVault(srv.url, ADMIN, "linux");
  const sb = await joinWithLink(await createInviteLink(sa), "mac");
  const skipped: [string, string][] = [];
  const fetched: string[] = [];
  const mac = await new Device("mac", sb, { hooks: { onSkipped: (p, why) => skipped.push([p, why]) } }).start();
  const client = sb.client;
  const origGet = client.getBlob.bind(client);
  client.getBlob = async (v, id, sig) => {
    fetched.push(id);
    return origGet(v, id, sig);
  };
  const store = (mac.engine as unknown as { store: { save: (j: string) => Promise<void> } }).store;
  const origSave = store.save.bind(store);
  let saves = 0;
  store.save = async (j) => {
    saves++;
    return origSave(j);
  };
  await mac.rawWrite("Notes/keep.md", utf8("keep\n"));
  await mac.sync();
  const ctl = refuseNotes(mac);
  for (let i = 0; i < n; i++) await put(sa, `notes/x${i}.md`, `x${i}\n`);
  await mac.sync();
  expect(await mac.files()).toEqual(["Notes/keep.md"]);
  expect(Object.keys(mac.engine.state.deferred ?? {}).length, "the puts were deferred").toBe(n);
  expect(skipped.length, "reported once each").toBe(n);
  return { sa, sb, mac, ctl, skipped, fetched, saves: () => saves };
}

describe("A. a deferred op is downloaded, decrypted and state-flushed again on every cycle before the folder check", () => {
  it("ten deferred files, three idle syncs: thirty blob downloads and thirty state flushes for nothing", async () => {
    const s = await stuck(10);
    try {
      s.fetched.length = 0;
      const saves0 = s.saves();
      const t0 = Date.now();
      for (let i = 0; i < 3; i++) await s.mac.sync(); // nothing new on the server, the twin folder unchanged
      const refetched = s.fetched.length;
      const reflushed = s.saves() - saves0;
      expect(refetched, `three idle syncs re-downloaded ${refetched} blobs and wrote state.json ${reflushed} times (${Date.now() - t0} ms) although nothing about the folder changed; the refusal is only discovered inside fs.write, after the download`).toBe(0);
    } finally {
      await s.mac.cleanup();
    }
  });
});

describe("B. the retry budget is time, not sync cycles", () => {
  it("sixty quick syncs (a few minutes of editing other notes) do not exhaust it; renaming the folder afterwards brings the file; a day does", async () => {
    const s = await stuck(1);
    try {
      const t0 = Date.now();
      let cycles = 0;
      while (s.mac.engine.state.deferred && cycles < 60) {
        await s.mac.sync(); // a keystroke saved in another note, a poll, a live hint: each is one cycle
        cycles++;
      }
      expect(s.mac.engine.state.deferred, "sixty cycles must not spend the budget").toBeDefined();
      const elapsed = Date.now() - t0;
      // The user now does what the first notice asked: the twin folder is renamed to match.
      await fixFolder(s);
      await s.mac.sync();
      await s.mac.sync();
      expect(await s.mac.files(), `after ${cycles} idle sync cycles in ${elapsed} ms the op was dropped (notices: ${s.skipped.map(([, w]) => w).join(" | ")}); the file never arrives once the folder is fixed`).toContain("notes/x0.md");
      // And the budget that does end it is a day: an entry parked that long is dropped with a notice naming the fix.
      const t = await stuck(1);
      try {
        for (const e of Object.values(t.mac.engine.state.deferred ?? {})) e.since = Date.now() - Engine.DEFERRED_MAX_AGE - 1;
        await t.mac.sync();
        expect(t.mac.engine.state.deferred).toBeUndefined();
        expect(t.skipped.map(([, w]) => w).join(" | ")).toMatch(/Rebuild local sync state/);
      } finally {
        await t.mac.cleanup();
      }
    } finally {
      await s.mac.cleanup();
    }
  });
});

describe("C. a key rotation while an op is parked drops it silently", () => {
  async function rotated(): Promise<Stuck> {
    const s = await stuck(1);
    // Another device removes a third device / rotates: new epoch, everything
    // re-encrypted, min_epoch raised. The Mac adopts the epoch and prunes the
    // old key at its next pull.
    await removeDevice(s.sa, "");
    const info = await s.sa.client.vault(s.sa.identity.vaultId);
    expect(info.min_epoch).toBe(info.epoch);
    await s.mac.sync(); // retry (still refused), then the pull adopts epoch 2 and prunes epoch 1
    expect(s.mac.engine.vc.keyring.epochs.has(1), "the Mac pruned the retired epoch").toBe(false);
    await s.mac.sync(); // retry: the parked meta_enc is under epoch 1
    return s;
  }

  it("C1. the user renames the folder as asked; the file never arrives", async () => {
    const s = await rotated();
    try {
      await fixFolder(s);
      await s.mac.sync();
      await s.mac.sync();
      expect(await s.mac.files(), `logs: ${s.mac.logs.filter((l) => /deferred|dropping|epoch/.test(l)).join("\n")}`).toContain("notes/x0.md");
    } finally {
      await s.mac.cleanup();
    }
  });

  it("C2. if the parked op is dropped, the user hears about it", async () => {
    const s = await rotated();
    try {
      const dropped = s.mac.logs.some((l) => /dropping it/.test(l));
      expect(dropped || !!s.mac.engine.state.deferred, "either still parked or dropped").toBe(true);
      if (dropped) expect(s.skipped.length, `the op was dropped ("${s.mac.logs.find((l) => /dropping it/.test(l))}") but the only notice the user ever saw was the first one: ${JSON.stringify(s.skipped)}`).toBeGreaterThan(1);
    } finally {
      await s.mac.cleanup();
    }
  });
});

describe("D. a write that fails after touching the file: the deferred path forgets the inflight record, the batch path does not", () => {
  /** ObsidianFS.verifyWrite's failure: the adapter left a 0-byte file and the write threw. */
  function shortWriteOnce(mac: Device, path: string): { done: boolean } {
    const orig = mac.fs.write.bind(mac.fs);
    const st = { done: false };
    mac.fs.write = async (p, d, m) => {
      if (!st.done && p === path) {
        st.done = true;
        await mac.rawWrite(p, new Uint8Array(0));
        throw new Error(`write verification failed for ${p}: wrote ${d.length} bytes, the adapter reports 0`);
      }
      return orig(p, d, m);
    };
    return st;
  }

  it("D1. through retryDeferred: a 0-byte conflict sibling is created and pushed to every device", async () => {
    const s = await stuck(1);
    try {
      await fixFolder(s); // the folder is fixed...
      const sw = shortWriteOnce(s.mac, "notes/x0.md"); // ...and the first write into it is Android's short write
      await s.mac.sync();
      expect(sw.done).toBe(true);
      for (let i = 0; i < 3; i++) await s.mac.sync(); // scan sees the 0-byte file; the engine decides what it is
      const files = await s.mac.files();
      expect(await s.mac.read("notes/x0.md")).toBe("x0\n");
      expect(s.mac.conflicts, `files: ${JSON.stringify(files)}; a transient write failure on the retry became a conflict copy of 0 bytes (and ${s.mac.uploads} upload(s) carried it to the server)`).toEqual([]);
      expect(files.filter((f) => /conflict/.test(f))).toEqual([]);
    } finally {
      await s.mac.cleanup();
    }
  });

  it("D2. (soundness) through applyBatch: the inflight record survives and the partial bytes are overwritten, no sibling", async () => {
    const sa = await createVault(srv.url, ADMIN, "linux");
    const sb = await joinWithLink(await createInviteLink(sa), "mac");
    const mac = await new Device("mac", sb).start();
    try {
      await put(sa, "plain/y.md", "y\n");
      const sw = shortWriteOnce(mac, "plain/y.md");
      await mac.sync();
      expect(sw.done).toBe(true);
      for (let i = 0; i < 3; i++) await mac.sync();
      expect(await mac.read("plain/y.md")).toBe("y\n");
      expect(mac.conflicts).toEqual([]);
      expect(await mac.files()).toEqual(["plain/y.md"]);
    } finally {
      await mac.cleanup();
    }
  });
});
