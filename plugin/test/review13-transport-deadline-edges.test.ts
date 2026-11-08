/**
 * Thirteenth review (2026-11-07): edges of the twelfth round's per-request
 * deadline in transport.ts (Client.request).
 *
 *  A. The deadline covers the body too, which is right, but the body is read
 *     outside request(): `json()` and `getBlob()` call res.json() /
 *     res.arrayBuffer() after request() returned. A body that stalls past the
 *     deadline rejects there with the raw DOMException (TimeoutError), not a
 *     NetworkError: the engine's `offline` classification (TypeError |
 *     NetworkError | transient HttpError) calls it an "error", and the retry
 *     loop never sees it. Fails on HEAD (af13604). Low: nothing hangs.
 *
 *  B. `AbortSignal.timeout` is called before the try block, unguarded. Where
 *     it does not exist (WebKit before 16, i.e. iOS 15; the webkit test
 *     targets safari15) every request throws TypeError before fetch is even
 *     called, which the engine reads as "offline" for ever. Fails on HEAD
 *     under a simulated absence; unproven on a real iOS 15 device.
 *
 *  C. With a caller signal and no `AbortSignal.any` (WebKit before 17.4),
 *     the deadline is silently dropped: the bare caller signal is what fetch
 *     gets. No current caller in src passes a signal, so this is latent.
 *     Fails on HEAD under a simulated absence.
 *
 *  D, E. Soundness (pass on HEAD): a deadline that fires through
 *     AbortSignal.any is mapped to NetworkError; a caller's own abort is
 *     rethrown as the AbortError it is, not as the network.
 *
 * Fix for B and C in one: build the deadline from `new AbortController()` +
 * `setTimeout(() => ac.abort(new DOMException("timeout", "TimeoutError")))`
 * and forward the caller's abort by listener (clearing the timer when the
 * request settles). For A: wrap the body read in `json()` / `getBlob()` and
 * map TimeoutError/AbortError (caller not aborted) to NetworkError, or read
 * the body inside request().
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { Client, NetworkError } from "../src/core/transport";

type Req = (method: string, path: string, body?: unknown, init?: Record<string, unknown>) => Promise<Response>;
type Json = <T>(method: string, path: string, body?: unknown, init?: Record<string, unknown>) => Promise<T>;

let stall: Server;
let base: string;
beforeAll(async () => {
  // Headers and half a JSON body, then silence.
  stall = createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.write('{"ops": [');
    // never ends; the client's deadline must.
    req.on("close", () => res.destroy());
  });
  await new Promise<void>((r) => stall.listen(0, "127.0.0.1", () => r()));
  base = `http://127.0.0.1:${(stall.address() as { port: number }).port}`;
});
afterAll(async () => {
  stall.closeAllConnections?.();
  await new Promise<void>((r) => stall.close(() => r()));
});

describe("A. a body that stalls past the deadline", () => {
  it("rejects out of json() as a raw TimeoutError, not a NetworkError", async () => {
    const c = new Client(base, "tok", { maxRetries: 0 });
    const json = (c as unknown as { json: Json }).json.bind(c);
    const t0 = Date.now();
    const err = await Promise.race([json("GET", "/v1/vaults/v/history?path_id=x", undefined, { timeoutMs: 300 }), new Promise((r) => setTimeout(() => r(new Error("body read never settled")), 5000))]).then(
      () => new Error("resolved?"),
      (e: unknown) => e,
    );
    // The deadline did reach the body read (soundness: nothing hangs) ...
    expect(String((err as Error).message), `took ${Date.now() - t0} ms`).not.toMatch(/never settled/);
    // ... but what comes out is the bare DOMException, which the engine does not call "offline".
    expect(err, `got ${(err as Error).name}: ${(err as Error).message}`).toBeInstanceOf(NetworkError);
  }, 10_000);
});

describe("B. a platform without AbortSignal.timeout (WebKit < 16)", () => {
  it("every request throws before fetch is called; the engine would read it as offline for ever", async () => {
    const saved = AbortSignal.timeout;
    // @ts-expect-error simulate the older engine
    delete AbortSignal.timeout;
    let fetched = 0;
    try {
      const c = new Client("http://example.invalid", "tok", {
        maxRetries: 0,
        fetchImpl: async () => {
          fetched++;
          return new Response(JSON.stringify({ id: "v", epoch: 1 }), { status: 200 });
        },
      });
      const r = await c.vault("v").then(
        () => "ok",
        (e: unknown) => e,
      );
      expect(r, `fetch called ${fetched} time(s); result ${String(r)}`).toBe("ok");
    } finally {
      AbortSignal.timeout = saved;
    }
  });
});

describe("C. a caller signal on a platform without AbortSignal.any (WebKit < 17.4)", () => {
  it("drops the deadline: fetch gets the bare caller signal and a stalled request never ends", async () => {
    const saved = AbortSignal.any;
    // @ts-expect-error simulate the older engine
    delete AbortSignal.any;
    try {
      let seen: AbortSignal | undefined;
      const c = new Client("http://example.invalid", "tok", {
        maxRetries: 0,
        fetchImpl: (_u, init) =>
          new Promise<Response>((_res, rej) => {
            seen = init?.signal ?? undefined;
            seen?.addEventListener("abort", () => rej(seen!.reason));
          }),
      });
      const caller = new AbortController();
      const req = (c as unknown as { request: Req }).request.bind(c);
      const out = await Promise.race([req("GET", "/v1/vaults/v", undefined, { signal: caller.signal, timeoutMs: 200 }).then(() => "resolved", (e: unknown) => e), new Promise((r) => setTimeout(() => r("hung"), 1500))]);
      expect(seen, "fetch received a signal").toBeDefined();
      expect(seen === caller.signal, "the signal fetch got is the caller's own: no deadline on it").toBe(false);
      expect(out, "the deadline must still end the request").not.toBe("hung");
    } finally {
      AbortSignal.any = saved;
    }
  });
});

describe("soundness on HEAD", () => {
  it("D. a deadline firing through AbortSignal.any (caller signal present) is the network", async () => {
    const c = new Client("http://example.invalid", "tok", {
      maxRetries: 0,
      fetchImpl: (_u, init) =>
        new Promise<Response>((_res, rej) => {
          init?.signal?.addEventListener("abort", () => rej(init.signal!.reason));
        }),
    });
    const req = (c as unknown as { request: Req }).request.bind(c);
    const e = await req("GET", "/v1/vaults/v", undefined, { signal: new AbortController().signal, timeoutMs: 100 }).then(() => null, (e: unknown) => e);
    expect(e).toBeInstanceOf(NetworkError);
  });

  it("E. the caller's own abort is an AbortError, not the network, and is not retried", async () => {
    let calls = 0;
    const c = new Client("http://example.invalid", "tok", {
      maxRetries: 4,
      fetchImpl: (_u, init) =>
        new Promise<Response>((_res, rej) => {
          calls++;
          init?.signal?.addEventListener("abort", () => rej(init.signal!.reason));
        }),
    });
    const ac = new AbortController();
    const req = (c as unknown as { request: Req }).request.bind(c);
    const p = req("GET", "/v1/vaults/v", undefined, { signal: ac.signal, timeoutMs: 5000 }).then(() => null, (e: unknown) => e);
    setTimeout(() => ac.abort(), 50);
    const e = (await p) as { name?: string };
    expect(e).not.toBeInstanceOf(NetworkError);
    expect(e?.name).toBe("AbortError");
    expect(calls).toBe(1);
  });

  it("F. a timeout is retried with a fresh timer per attempt (maxRetries attempts + 1), then is the network", async () => {
    let calls = 0;
    const c = new Client("http://example.invalid", "tok", {
      maxRetries: 2,
      fetchImpl: (_u, init) =>
        new Promise<Response>((_res, rej) => {
          calls++;
          init?.signal?.addEventListener("abort", () => rej(init.signal!.reason));
        }),
    });
    const req = (c as unknown as { request: Req }).request.bind(c);
    const e = await req("GET", "/v1/vaults/v", undefined, { timeoutMs: 50 }).then(() => null, (e: unknown) => e);
    expect(e).toBeInstanceOf(NetworkError);
    expect(calls).toBe(3);
  }, 10_000);
});
