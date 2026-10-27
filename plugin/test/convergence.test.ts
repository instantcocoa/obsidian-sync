/**
 * Randomised multi-device convergence (DESIGN.md §8). Three devices perform
 * random writes, edits and deletes, sync in random orders, go offline,
 * restart (cleanly or by crash), lose their state, and the server restarts
 * under them. After it all settles, the suite checks the two properties the
 * design promises:
 *
 *   1. Convergence: every device has byte-identical files.
 *   2. No silent loss: the last bytes any device wrote to any path (unless
 *      that device later deleted the path itself) are present in the final
 *      vault, either at the path or in a conflict sibling, or are an
 *      ancestor the server's history still holds.
 *
 * Seeds are fixed so a failure is reproducible; the action trace is printed
 * on failure. Add a seed to SEEDS to pin a new case.
 */
import { describe, expect, it } from "vitest";
import { promises as fsp } from "node:fs";
import { TestServer, Device, ADMIN } from "./harness";
import { createVault, createInviteLink, joinWithLink } from "../src/core/admin";
import { CONFLICT_RE } from "../src/core/paths";
import { utf8 } from "../src/core/encoding";

const SEEDS = [1, 2, 3, 4, 5, 6];
const ROUNDS = 28;

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const PATHS = ["a.md", "b.md", "notes/c.md", "notes/d.md", "deep/x/e.md", "f.txt", "bin.dat", "g.md"];
const stem = (p: string) => p.replace(/\.[^.]+$/, "");

describe("randomised multi-device convergence", () => {
  for (const seed of SEEDS) {
    it(`seed ${seed}: ${ROUNDS} rounds of random edits, syncs, restarts and outages converge without loss`, async () => {
      const r = rng(seed);
      const pick = <T>(xs: T[]): T => xs[Math.floor(r() * xs.length)];
      const chance = (p: number) => r() < p;
      const srv = await TestServer.start();
      const sa = await createVault(srv.url, ADMIN, "d0");
      const sb = await joinWithLink(await createInviteLink(sa), "d1");
      const sc = await joinWithLink(await createInviteLink(sa), "d2");
      const devs = [await new Device("d0", sa).start(), await new Device("d1", sb).start(), await new Device("d2", sc).start()];
      // What each device last wrote per path, and whether it deleted the path afterwards.
      const lastWrite = devs.map(() => new Map<string, Uint8Array>());
      const trace: string[] = [];
      let counter = 0;

      // A three-way merge folds a device's unsynced edit into the merged file,
      // which is what gets uploaded; from then on the merged bytes are what
      // that device "last wrote". Anything else that replaces an unsynced
      // write without a sibling is a loss and stays flagged.
      const seenLogs = devs.map(() => 0);
      const followMerges = async (d: Device) => {
        const i = devs.indexOf(d);
        for (; seenLogs[i] < d.logs.length; seenLogs[i]++) {
          const m = /^info: merged concurrent edits of (.+)$/.exec(d.logs[seenLogs[i]]);
          if (m && lastWrite[i].has(m[1]) && (await d.exists(m[1]))) {
            lastWrite[i].set(m[1], await d.readBytes(m[1]));
            trace.push(`  ${d.name} merged ${m[1]}`);
          }
        }
      };

      const textFor = async (d: Device, p: string): Promise<Uint8Array> => {
        // Mostly line-level edits of the current content so merges and overlaps both happen.
        let lines: string[] = [];
        if (await d.exists(p)) lines = (await d.read(p)).split("\n").filter((l) => l !== "");
        if (lines.length === 0 || chance(0.15)) lines = ["l1", "l2", "l3", "l4", "l5", "l6"];
        const i = Math.floor(r() * lines.length);
        lines[i] = `${d.name}-${++counter}`;
        if (chance(0.2)) lines.push(`${d.name}-${++counter}`);
        return utf8(lines.join("\n") + "\n");
      };

      try {
        for (let round = 0; round < ROUNDS; round++) {
          // Mutations.
          for (const [i, d] of devs.entries()) {
            const n = Math.floor(r() * 3);
            for (let k = 0; k < n; k++) {
              const p = pick(PATHS);
              if (chance(0.15) && (await d.exists(p))) {
                await d.remove(p);
                lastWrite[i].delete(p);
                trace.push(`${round} ${d.name} rm ${p}`);
              } else {
                const bytes = p.endsWith(".dat") ? new Uint8Array(64 + Math.floor(r() * 64)).map(() => Math.floor(r() * 256)) : await textFor(d, p);
                await d.write(p, bytes);
                lastWrite[i].set(p, bytes);
                trace.push(`${round} ${d.name} write ${p} (${bytes.length}b)`);
              }
            }
          }
          // Infrastructure events.
          if (chance(0.06)) {
            trace.push(`${round} server restart`);
            await srv.restart();
          }
          for (const [i, d] of devs.entries()) {
            if (chance(0.05)) {
              trace.push(`${round} ${d.name} restart`);
              await d.restart();
            } else if (chance(0.04)) {
              trace.push(`${round} ${d.name} crash`);
              await d.restart({ crash: true });
            } else if (chance(0.02)) {
              trace.push(`${round} ${d.name} state loss`);
              await d.engine.flushState();
              await fsp.rm(await d.stateFile(), { force: true });
              await d.restart({ crash: true });
            }
            void i;
          }
          // Syncs in random order; some devices stay offline this round.
          const order = [...devs].sort(() => r() - 0.5);
          for (const d of order) {
            if (chance(0.35)) continue;
            trace.push(`${round} ${d.name} sync`);
            await d.sync();
            await followMerges(d);
          }
        }
        for (const d of devs) await followMerges(d);
        // Settle.
        let quiet = 0;
        for (let i = 0; i < 12 && quiet < 2; i++) {
          const before = devs.map((d) => d.posts + d.uploads);
          for (const d of devs) await d.sync();
          quiet = devs.every((d, k) => d.posts + d.uploads === before[k]) ? quiet + 1 : 0;
        }
        expect(quiet, "did not converge").toBeGreaterThanOrEqual(2);
        for (const d of devs) expect(d.engine.getStatus().phase, `${d.name} status`).toBe("idle");

        // 1. Convergence.
        const maps = await Promise.all(
          devs.map(async (d) => {
            const m: Record<string, string> = {};
            for (const f of await d.files()) m[f] = Buffer.from(await d.readBytes(f)).toString("base64");
            return m;
          }),
        );
        for (let i = 1; i < devs.length; i++) expect(maps[i], `${devs[i].name} differs from d0`).toEqual(maps[0]);

        // 2. No silent loss.
        const vault = maps[0];
        const { vc, client, identity } = devs[0].session;
        const histories = new Map<string, Set<string>>();
        for (const [i, d] of devs.entries()) {
          for (const [p, bytes] of lastWrite[i]) {
            const b64 = Buffer.from(bytes).toString("base64");
            const inVault = Object.entries(vault).some(([f, c]) => c === b64 && (f === p || (f.startsWith(stem(p)) && CONFLICT_RE.test(f))));
            if (inVault) continue;
            if (!histories.has(p)) {
              const pid = await vc.pathId(p);
              histories.set(p, new Set((await client.history(identity.vaultId, pid)).map((o) => o.blob_id ?? "")));
            }
            const inHistory = histories.get(p)!.has(await vc.blobId(bytes));
            expect(inHistory, `${d.name}'s last write to ${p} is in neither the vault nor the history`).toBe(true);
          }
        }
        const siblings = Object.keys(vault).filter((f) => CONFLICT_RE.test(f)).length;
        trace.push(`end: ${Object.keys(vault).length} files, ${siblings} conflict siblings`);
      } catch (err) {
        console.log(`seed ${seed} trace:\n` + trace.join("\n"));
        for (const d of devs) console.log(`${d.name} logs:\n` + d.logs.filter((l) => /^(warn|error)/.test(l)).join("\n"));
        throw err;
      } finally {
        await Promise.all(devs.map((d) => d.cleanup()));
        await srv.stop();
      }
    }, 180_000);
  }
});
