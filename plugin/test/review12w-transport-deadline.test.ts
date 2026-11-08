/**
 * Twelfth review, whole-system pass (2026-11-08): the HTTP client and the
 * sync loop have no deadline of their own. `Client.request` (transport.ts)
 * hands `init.signal` to fetch when a caller supplies one, and no caller in
 * the engine does: `changes`, `snapshot`, `getBlob`, `postOps`, `putBlob`,
 * `keybox`, `devices` all run with no AbortSignal. Retries cover a request
 * that FAILS; nothing covers a request that never answers (a TCP connection
 * that went dark across a network switch on a phone, a proxy that holds the
 * request, a server that accepted the connection and stalled).
 *
 *  A. Transport: a fetch that never settles leaves the request pending for
 *     ever. Pinned so a fix (per-request deadline, longer for blob bodies)
 *     has a failing test to start from. Passes on HEAD as a statement of
 *     fact; the assertion is "still pending after N ms".
 *
 *  B. Engine: one stalled request wedges the loop. `sync()` coalesces every
 *     later call into the promise in flight (`this.syncing`), so once a pull
 *     hangs, every poll, live hint, resume and "Sync now" returns the same
 *     never-settling promise and the status stays "syncing" until Obsidian
 *     restarts. Nothing is lost (local edits stay dirty), but nothing moves
 *     either, and the user sees ↕ for ever with no error. Same shape as A:
 *     passes on HEAD, documents the behaviour.
 *
 * Both run without the Go server: the fake fetch is the whole network.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "../src/core/transport";
import { Engine } from "../src/core/engine";
import { NodeFS, FileStateStore } from "../src/core/node-fs";
import { VaultCrypto, newKeyring, generateKeypair } from "../src/core/crypto";
import { DEFAULT_EXCLUSIONS } from "../src/core/paths";

/** A network that accepts every request and never answers any of them. */
function blackHole(): { fetchImpl: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl = ((input: RequestInfo | URL) => {
    calls.push(String(input));
    return new Promise<Response>(() => {});
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const settled = async <T,>(p: Promise<T>, ms: number): Promise<"settled" | "pending"> => {
  const marker = Symbol("pending");
  const r = await Promise.race([p.then(() => "settled" as const, () => "settled" as const), new Promise<typeof marker>((res) => setTimeout(() => res(marker), ms))]);
  return r === marker ? "pending" : "settled";
};

describe("review 12 (whole system): no request deadline", () => {
  it("A. Client.request has no deadline: a fetch that never answers is waited on for ever", async () => {
    const { fetchImpl, calls } = blackHole();
    const c = new Client("http://127.0.0.1:1", "dv_test", { fetchImpl, maxRetries: 0 });
    const p = c.vault("v");
    p.catch(() => {});
    expect(await settled(p, 1500)).toBe("pending");
    expect(calls).toHaveLength(1);
    // The one caller-side escape hatch is `init.signal`; the engine never passes one.
    const src = await import("node:fs").then((m) => m.readFileSync(join(__dirname, "../src/core/engine.ts"), "utf8"));
    expect(src).not.toMatch(/AbortSignal\.timeout|signal:/);
  });

  describe("B. one stalled request wedges the sync loop for the rest of the session", () => {
    let dir = "";
    afterEach(() => dir && rmSync(dir, { recursive: true, force: true }));

    it("every later sync() coalesces into the hung one; status stays 'syncing'", async () => {
      dir = mkdtempSync(join(tmpdir(), "obsync-r12w-"));
      const { fetchImpl, calls } = blackHole();
      const kp = await generateKeypair();
      const vc = new VaultCrypto(newKeyring());
      const client = new Client("http://127.0.0.1:1", "dv_test", { fetchImpl, maxRetries: 0, vaultAuth: () => vc.authToken() });
      const fs = new NodeFS(dir, ".obsidian");
      const statuses: string[] = [];
      const engine = new Engine(fs, new FileStateStore(join(dir, ".obsidian/plugins/obsync/state.json")), client, vc, { vaultId: "v", deviceId: "d", deviceName: "d", privJwk: kp.privJwk, exclusions: DEFAULT_EXCLUSIONS, noLive: true, pollIntervalMs: 3_600_000, dotScanIntervalMs: 3_600_000 }, { onStatus: (s) => statuses.push(s.phase) });
      await (engine as unknown as { loadState: () => Promise<void> }).loadState();
      (engine as unknown as { stopped: boolean }).stopped = false;

      const first = engine.sync(); // cursor 0 → snapshot → hangs
      first.catch(() => {});
      await new Promise((r) => setTimeout(r, 100));
      expect(calls.filter((u) => u.includes("/snapshot"))).toHaveLength(1);

      // A user edit arrives and "Sync now" is pressed: both fold into the hung promise.
      await fs.write("note.md", new TextEncoder().encode("hello"), Date.now());
      engine.noteChange("note.md");
      // `sync()` is async, so each call returns a fresh wrapper around the
      // same `this.syncing`; what matters is that none of them starts work.
      const second = engine.sync();
      const third = engine.sync();
      second.catch(() => {});
      third.catch(() => {});
      expect(await settled(first, 1500)).toBe("pending");
      expect(await settled(second, 10)).toBe("pending");
      expect(await settled(third, 10)).toBe("pending");
      expect(calls).toHaveLength(1); // nothing else was ever sent: no push, no second pull
      expect(engine.getStatus().phase).toBe("syncing");
      expect(statuses.at(-1)).toBe("syncing");
      // The edit is not lost: it is dirty and will upload once the loop is free (a restart).
      expect(engine.getStatus().pending).toBe(1);
      (engine as unknown as { stopped: boolean }).stopped = true;
    });
  });
});
