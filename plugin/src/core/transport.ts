/**
 * HTTP client for the obsync server (DESIGN.md §4.3). One method per route.
 *
 * Uses global fetch (Electron, Capacitor WebView, Node 18+). Obsidian's
 * desktop origin is app://obsidian.md, so the server answers CORS with a
 * wildcard; auth is a bearer header, never a cookie.
 *
 * Retries: only idempotent calls on transient failures (network error, 408,
 * 429, 5xx) with capped exponential backoff. Op posts are idempotent too
 * (op_id) and are retried as well.
 */

import { b64, fromB64 } from "./encoding";

export class HttpError extends Error {
  constructor(
    public status: number,
    public body: string,
    public path: string,
  ) {
    super(`HTTP ${status} ${path}: ${body.slice(0, 200)}`);
  }
  get transient(): boolean {
    return this.status === 408 || this.status === 429 || this.status >= 500;
  }
}

/** The server could not be reached at all (DNS, refused, TLS, offline). */
export class NetworkError extends Error {
  constructor(
    public base: string,
    public override cause: unknown,
  ) {
    super(`Could not reach ${base}. Check the address and that the server is running.`);
  }
}

export interface WireOp {
  seq: number;
  op_id: string;
  device_id: string;
  path_id: string;
  blob_id: string | null;
  meta_enc: string; // base64
  meta_epoch: number;
  base_seq: number;
  created_at: number;
}

export interface OpInput {
  op_id: string;
  path_id: string;
  blob_id: string | null;
  meta_enc: Uint8Array;
  meta_epoch: number;
  base_seq: number;
}

export interface OpResult {
  op_id: string;
  seq?: number;
  conflict?: WireOp;
  error?: string;
}

export interface Feed {
  epoch: number;
  min_epoch: number;
  cursor: number;
  ops: WireOp[];
  more: boolean;
}

export interface VaultInfo {
  vault_id: string;
  epoch: number;
  min_epoch: number;
  seq: number;
}

export interface WireDevice {
  id: string;
  name_enc: string | null;
  pub_kex: string | null;
  recovery: boolean;
  created_at: number;
  last_seen: number | null;
  revoked_at: number | null;
}

export interface KeyboxRow {
  epoch: number;
  recipient_id: string;
  wrapped: string; // base64
  author_id?: string;
}

export interface Redeemed {
  device_id: string;
  device_token: string;
  vault_id: string;
  epoch: number;
  keybox_enc: string;
}

export interface ClientOptions {
  /** Called for every request failure that will be retried. */
  onRetry?: (err: unknown, attempt: number) => void;
  maxRetries?: number;
  fetchImpl?: typeof fetch;
  /**
   * Supplies the vault authority token (VaultCrypto.authToken) for routes
   * that need it. Absent for admin-only or pre-enrolment clients.
   */
  vaultAuth?: () => Promise<string>;
}

export class Client {
  readonly base: string;
  private fetchImpl: typeof fetch;

  constructor(
    server: string,
    public token: string,
    private opts: ClientOptions = {},
  ) {
    this.base = server.replace(/\/+$/, "");
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => fetch(input, init));
  }

  // ---------- low level ----------

  private async request(
    method: string,
    path: string,
    body?: unknown,
    init: { raw?: boolean; headers?: Record<string, string>; retry?: boolean; signal?: AbortSignal; token?: string; authority?: boolean } = {},
  ): Promise<Response> {
    const headers: Record<string, string> = { ...(init.headers ?? {}) };
    const tok = init.token ?? this.token;
    if (tok) headers["Authorization"] = `Bearer ${tok}`;
    if (init.authority) {
      if (!this.opts.vaultAuth) throw new Error("this operation needs the vault keys");
      headers["X-Obsync-Vault-Auth"] = await this.opts.vaultAuth();
    }
    let payload: BodyInit | undefined;
    if (body instanceof Uint8Array) {
      headers["Content-Type"] = "application/octet-stream";
      payload = body as Uint8Array<ArrayBuffer>;
    } else if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
    const max = init.retry === false ? 0 : (this.opts.maxRetries ?? 4);
    for (let attempt = 0; ; attempt++) {
      try {
        const res = await this.fetchImpl(this.base + path, { method, headers, body: payload, signal: init.signal });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          const err = new HttpError(res.status, text, path);
          if (err.transient && attempt < max) throw err;
          throw Object.assign(err, { final: true });
        }
        return res;
      } catch (e) {
        if ((e as { final?: boolean }).final || attempt >= max || init.signal?.aborted) {
          // fetch reports every connection problem as a bare TypeError ("Failed to fetch").
          if (e instanceof TypeError) throw new NetworkError(this.base, e);
          throw e;
        }
        this.opts.onRetry?.(e, attempt);
        await new Promise((r) => setTimeout(r, Math.min(8000, 300 * 2 ** attempt) + Math.random() * 200));
      }
    }
  }

  private async json<T>(method: string, path: string, body?: unknown, init?: Parameters<Client["request"]>[3]): Promise<T> {
    const res = await this.request(method, path, body, init);
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  // ---------- admin / enrolment ----------

  /** Create a vault with the admin token. */
  static async createVault(server: string, adminToken: string, fetchImpl?: typeof fetch): Promise<VaultInfo> {
    const c = new Client(server, adminToken, { fetchImpl });
    try {
      return await c.json<VaultInfo>("POST", "/v1/vaults", undefined, { retry: false });
    } catch (e) {
      if (e instanceof HttpError && e.status === 401) throw new Error(`Admin token rejected by ${c.base}.`);
      throw e;
    }
  }

  async createInvite(vaultId: string, keyboxEnc: Uint8Array, ttlSeconds?: number): Promise<{ token: string; expires_at: number }> {
    // The admin token may mint the very first invite; devices need vault authority.
    return this.json("POST", `/v1/vaults/${vaultId}/invites`, { keybox_enc: b64(keyboxEnc), ttl_seconds: ttlSeconds ?? 0 }, { authority: Boolean(this.opts.vaultAuth) });
  }

  /** Register the vault authority hash (first enrolment); a 409 means it is already set. */
  async registerAuth(vaultId: string, auth: string): Promise<void> {
    await this.json("POST", `/v1/vaults/${vaultId}/auth`, { auth });
  }

  static async redeemInvite(server: string, token: string, pubKex: Uint8Array, nameEnc: Uint8Array, fetchImpl?: typeof fetch): Promise<Redeemed> {
    const c = new Client(server, "", { fetchImpl });
    try {
      return await c.json<Redeemed>("POST", `/v1/invites/${token}`, { pub_kex: b64(pubKex), name_enc: b64(nameEnc) }, { retry: false });
    } catch (e) {
      if (e instanceof HttpError && e.status === 401) throw new Error("This invite link was already used or has expired. Generate a new one on a connected device.");
      throw e;
    }
  }

  async vault(vaultId: string): Promise<VaultInfo> {
    return this.json("GET", `/v1/vaults/${vaultId}`);
  }

  async devices(vaultId: string): Promise<WireDevice[]> {
    return (await this.json<{ devices: WireDevice[] }>("GET", `/v1/vaults/${vaultId}/devices`)).devices ?? [];
  }

  async setDeviceName(vaultId: string, nameEnc: Uint8Array): Promise<void> {
    await this.json("PATCH", `/v1/vaults/${vaultId}/devices/me`, { name_enc: b64(nameEnc) });
  }

  async keybox(vaultId: string): Promise<KeyboxRow[]> {
    return (await this.json<{ keybox: KeyboxRow[] }>("GET", `/v1/vaults/${vaultId}/keybox`)).keybox ?? [];
  }

  async putKeybox(vaultId: string, rows: { epoch: number; recipient_id: string; wrapped: Uint8Array }[]): Promise<void> {
    await this.json("POST", `/v1/vaults/${vaultId}/keybox`, { keybox: rows.map((r) => ({ ...r, wrapped: b64(r.wrapped) })) });
  }

  async rotate(vaultId: string, epoch: number, revoke: string[], rows: { epoch: number; recipient_id: string; wrapped: Uint8Array }[], authNext: string): Promise<VaultInfo> {
    return this.json("POST", `/v1/vaults/${vaultId}/rotate`, { epoch, revoke, keybox: rows.map((r) => ({ ...r, wrapped: b64(r.wrapped) })), auth_next: authNext }, { retry: false, authority: true });
  }

  async setRecovery(vaultId: string, pubKex: Uint8Array, recoveryEnc: Uint8Array, salt: Uint8Array, auth: string): Promise<{ device_id: string }> {
    return this.json("PUT", `/v1/vaults/${vaultId}/recovery`, { pub_kex: b64(pubKex), recovery_enc: b64(recoveryEnc), salt: b64(salt), auth }, { authority: true });
  }

  static async getRecovery(server: string, vaultId: string, fetchImpl?: typeof fetch): Promise<{ device_id: string; pub_kex: string; salt: string }> {
    const c = new Client(server, "", { fetchImpl });
    try {
      return await c.json("GET", `/v1/vaults/${vaultId}/recovery`, undefined, { retry: false });
    } catch (e) {
      if (e instanceof HttpError && e.status === 404) throw new Error("No recovery passphrase is set for that vault id on this server.");
      throw e;
    }
  }

  static async recoveryJoin(
    server: string,
    vaultId: string,
    authToken: string,
    pubKex: Uint8Array,
    nameEnc: Uint8Array,
    fetchImpl?: typeof fetch,
  ): Promise<{ device_id: string; device_token: string; vault_id: string; epoch: number; keybox: KeyboxRow[]; recovery_enc: string }> {
    const c = new Client(server, authToken, { fetchImpl });
    return c.json("POST", `/v1/vaults/${vaultId}/recovery/join`, { pub_kex: b64(pubKex), name_enc: b64(nameEnc) }, { retry: false });
  }

  // ---------- feed ----------

  async snapshot(vaultId: string): Promise<Feed> {
    return this.json("GET", `/v1/vaults/${vaultId}/snapshot`);
  }

  async changes(vaultId: string, since: number, opts: { wait?: number; limit?: number; signal?: AbortSignal } = {}): Promise<Feed> {
    const q = new URLSearchParams({ since: String(since) });
    if (opts.wait) q.set("wait", String(opts.wait));
    if (opts.limit) q.set("limit", String(opts.limit));
    return this.json("GET", `/v1/vaults/${vaultId}/changes?${q}`, undefined, { signal: opts.signal });
  }

  /**
   * WebSocket endpoint and the subprotocol list that carries the token
   * (`new WebSocket(url, protocols)`). The token travels in the
   * Sec-WebSocket-Protocol header, never in the URL, so it stays out of
   * proxy and devtools logs.
   */
  liveUrl(vaultId: string): string {
    return `${this.base.replace(/^http/, "ws")}/v1/vaults/${vaultId}/live`;
  }

  liveProtocols(): string[] {
    return ["obsync-bearer", this.token];
  }

  // ---------- blobs ----------

  async missingBlobs(vaultId: string, ids: string[]): Promise<string[]> {
    if (ids.length === 0) return [];
    return (await this.json<{ missing: string[] }>("POST", `/v1/vaults/${vaultId}/blobs/missing`, ids)).missing ?? [];
  }

  /** `replace` is for re-encryption: replacing stored ciphertext needs vault authority. */
  async putBlob(vaultId: string, id: string, data: Uint8Array, opts: { replace?: boolean } = {}): Promise<void> {
    await this.request("PUT", `/v1/vaults/${vaultId}/blobs/${id}`, data, { authority: Boolean(opts.replace) });
  }

  async getBlob(vaultId: string, id: string, signal?: AbortSignal): Promise<Uint8Array> {
    const res = await this.request("GET", `/v1/vaults/${vaultId}/blobs/${id}`, undefined, { signal });
    return new Uint8Array(await res.arrayBuffer());
  }

  async blobsBelowEpoch(vaultId: string, epoch: number, limit = 500): Promise<string[]> {
    return (await this.json<{ blob_ids: string[] }>("GET", `/v1/vaults/${vaultId}/blobs?epoch_lt=${epoch}&limit=${limit}`)).blob_ids ?? [];
  }

  // ---------- ops ----------

  async postOps(vaultId: string, ops: OpInput[]): Promise<{ epoch: number; cursor: number; results: OpResult[] }> {
    return this.json("POST", `/v1/vaults/${vaultId}/ops`, ops.map((o) => ({ ...o, meta_enc: b64(o.meta_enc) })));
  }

  async opsBelowMetaEpoch(vaultId: string, epoch: number, limit = 500): Promise<number[]> {
    return (await this.json<{ seqs: number[] }>("GET", `/v1/vaults/${vaultId}/ops?meta_epoch_lt=${epoch}&limit=${limit}`)).seqs ?? [];
  }

  async getOp(vaultId: string, seq: number): Promise<WireOp | undefined> {
    // There is no single-op route; history by path is the lookup. Callers
    // that need an op by seq keep it from the feed. Provided for symmetry.
    const f = await this.changes(vaultId, seq - 1, { limit: 1 });
    return f.ops[0]?.seq === seq ? f.ops[0] : undefined;
  }

  async patchMeta(vaultId: string, seq: number, metaEnc: Uint8Array, metaEpoch: number): Promise<void> {
    await this.json("PATCH", `/v1/vaults/${vaultId}/ops/${seq}/meta`, { meta_enc: b64(metaEnc), meta_epoch: metaEpoch }, { authority: true });
  }

  async history(vaultId: string, pathId: string): Promise<WireOp[]> {
    return (await this.json<{ ops: WireOp[] }>("GET", `/v1/vaults/${vaultId}/history?path_id=${pathId}`)).ops ?? [];
  }

  async restore(vaultId: string, atMs: number): Promise<{ emitted: number; skipped_path_ids: string[]; cursor: number }> {
    return this.json("POST", `/v1/vaults/${vaultId}/restore`, { at: atMs }, { retry: false });
  }
}

export const decodeMeta = (op: WireOp): Uint8Array => fromB64(op.meta_enc);
