/**
 * Runs inside a real WebKit page (Playwright's WebKit build, the engine
 * Obsidian for iOS runs plugins in). Bundled by test/webkit.test.ts with
 * esbuild and injected into a page served by the obsync server itself, so
 * every fetch and WebSocket is same-origin. Exercises what the plugin's
 * core needs from the engine: WebCrypto (AES-GCM, HKDF, HMAC, ECDH P-256,
 * PBKDF2), CompressionStream, fetch with custom headers, and WebSocket
 * subprotocol auth, by running the crypto vectors and a two-engine sync
 * round trip. Reports through window.__obsync.
 */
import { Engine } from "../../src/core/engine";
import { createVault, createInviteLink, joinWithLink, openSession, type Session } from "../../src/core/admin";
import { VaultCrypto, keyringFromJSON } from "../../src/core/crypto";
import { DEFAULT_EXCLUSIONS } from "../../src/core/paths";
import { utf8, hex, fromHex } from "../../src/core/encoding";
import type { FileStat, StateStore, VaultFS } from "../../src/core/fs";
import vectors from "../vectors.json";

class MemFS implements VaultFS {
  readonly configDir = ".obsidian";
  files = new Map<string, { data: Uint8Array; mtime: number }>();
  async list(): Promise<FileStat[]> {
    return [...this.files].map(([path, f]) => ({ path, size: f.data.length, mtime: f.mtime }));
  }
  async stat(path: string): Promise<FileStat | null> {
    const f = this.files.get(path);
    return f ? { path, size: f.data.length, mtime: f.mtime } : null;
  }
  async read(path: string): Promise<Uint8Array> {
    const f = this.files.get(path);
    if (!f) throw new Error(`ENOENT ${path}`);
    return f.data;
  }
  async write(path: string, data: Uint8Array, mtime: number): Promise<void> {
    this.files.set(path, { data: new Uint8Array(data), mtime: Math.floor(mtime) });
  }
  async remove(path: string): Promise<void> {
    this.files.delete(path);
  }
  onChange(): () => void {
    return () => {};
  }
}

class MemStore implements StateStore {
  json: string | null = null;
  async load(): Promise<string | null> {
    return this.json;
  }
  async save(json: string): Promise<void> {
    this.json = json;
  }
}

function device(name: string, s: Session, fs: MemFS, noLive: boolean): Engine {
  const e = new Engine(fs, new MemStore(), s.client, s.vc, {
    vaultId: s.identity.vaultId,
    deviceId: s.identity.deviceId,
    deviceName: name,
    privJwk: s.identity.privJwk,
    exclusions: DEFAULT_EXCLUSIONS,
    noLive,
    pollIntervalMs: 3_600_000,
    dotScanIntervalMs: 3_600_000,
    debounceMs: 50,
  });
  return e;
}

async function syncOnce(e: Engine): Promise<void> {
  await (e as unknown as { loadState: () => Promise<void> }).loadState();
  (e as unknown as { stopped: boolean }).stopped = false;
  await e.scan();
  await e.sync();
  const st = e.getStatus();
  if (st.phase === "error" || st.phase === "offline") throw new Error(`sync ${st.phase}: ${st.message}`);
}

async function main(server: string, admin: string): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = { ua: navigator.userAgent, steps: [] as string[] };
  const steps = out.steps as string[];

  // 1. Crypto vectors: the same bytes test/crypto.test.ts pins, under WebKit's WebCrypto.
  const v = vectors as unknown as { k_id: string; epochs: Record<string, string>; plaintext: string; blob_id: string; path_id: string; blob_epoch2_seq_rng: string; meta_enc_seq_rng: string };
  const vc = new VaultCrypto(keyringFromJSON({ k_id: v.k_id, epochs: v.epochs, current: 2 }));
  const vpt = utf8(v.plaintext);
  if ((await vc.blobId(vpt)) !== v.blob_id) throw new Error("blob id vector mismatch");
  if ((await vc.pathId("notes/hello.md")) !== v.path_id) throw new Error("path id vector mismatch");
  if (new TextDecoder().decode(await vc.decryptBlob(v.blob_id, fromHex(v.blob_epoch2_seq_rng))) !== v.plaintext) throw new Error("pinned blob ciphertext did not decrypt");
  if ((await vc.decryptMeta(v.path_id, fromHex(v.meta_enc_seq_rng))).path !== "notes/hello.md") throw new Error("pinned meta ciphertext did not decrypt");
  const pid = v.path_id;
  const bid = await vc.blobId(utf8("round trip"));
  const ct = await vc.encryptBlob(bid, utf8("round trip"), { compress: true });
  const pt = await vc.decryptBlob(bid, ct);
  if (new TextDecoder().decode(pt) !== "round trip") throw new Error("blob round trip failed");
  const meta = await vc.decryptMeta(pid, await vc.encryptMeta(pid, { path: "notes/hello.md", mtime: 1, size: 10 }));
  if (meta.path !== "notes/hello.md") throw new Error("meta round trip failed");
  out.compression = typeof CompressionStream !== "undefined";
  steps.push("crypto ok");

  // 2. Two engines over in-memory vaults against the real server.
  const sa = await createVault(server, admin, "webkit-a");
  const sb = await joinWithLink(await createInviteLink(sa), "webkit-b");
  const fa = new MemFS();
  const fb = new MemFS();
  const a = device("webkit-a", sa, fa, true);
  const b = device("webkit-b", sb, fb, true);
  await fa.write("notes/hello.md", utf8("# from webkit a\n"), Date.now());
  await fa.write("bin.dat", new Uint8Array(70_000).map((_, i) => (i * 13) & 0xff), Date.now());
  await syncOnce(a);
  await syncOnce(b);
  if (new TextDecoder().decode(await fb.read("notes/hello.md")) !== "# from webkit a\n") throw new Error("a -> b failed");
  if ((await fb.read("bin.dat")).length !== 70_000) throw new Error("binary a -> b failed");
  await fb.write("notes/hello.md", utf8("# from webkit a\nedited on b\n"), Date.now());
  await fb.write("new.md", utf8("new on b\n"), Date.now());
  await syncOnce(b);
  await syncOnce(a);
  if (new TextDecoder().decode(await fa.read("new.md")) !== "new on b\n") throw new Error("b -> a failed");
  // Concurrent overlapping edit: a sibling, nothing lost.
  await fa.write("notes/hello.md", utf8("# A\nedited on b\n"), Date.now());
  await fb.write("notes/hello.md", utf8("# B\nedited on b\n"), Date.now());
  await syncOnce(a);
  await syncOnce(b);
  await syncOnce(a);
  const sib = [...fb.files.keys()].find((k) => / \(conflict webkit-b /.test(k));
  if (!sib) throw new Error("no conflict sibling");
  out.sibling = sib;
  steps.push("sync ok");

  // 3. Live channel: the WebSocket must open with the bearer carried in the subprotocol list.
  const ws = new WebSocket(sa.client.liveUrl(sa.identity.vaultId), sa.client.liveProtocols());
  out.ws = await new Promise<string>((res) => {
    const t = setTimeout(() => res("timeout"), 10_000);
    ws.onopen = () => {
      clearTimeout(t);
      res("open");
      ws.close();
    };
    ws.onerror = () => {
      clearTimeout(t);
      res("error");
    };
  });
  if (out.ws !== "open") throw new Error(`websocket ${out.ws}`);
  steps.push("websocket ok");

  // 4. The identity survives a JSON round trip the way data.json stores it.
  const again = openSession(JSON.parse(JSON.stringify(sa.identity)));
  if ((await again.vc.authToken()) !== (await sa.vc.authToken())) throw new Error("identity round trip changed the authority token");
  out.hexOk = hex(fromHex("00ff")) === "00ff";
  steps.push("identity ok");
  return out;
}

declare global {
  interface Window {
    __obsync?: Promise<Record<string, unknown>>;
  }
}
const params = new URLSearchParams(location.search);
window.__obsync = main(location.origin, params.get("admin") ?? "").catch((e) => ({ error: String((e as Error)?.stack ?? e) }));
