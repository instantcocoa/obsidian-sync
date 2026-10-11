/**
 * All cryptography for obsync. Every primitive is WebCrypto so this runs
 * unchanged in Electron, iOS WKWebView, Android WebView, and Node 20+.
 *
 * Formats are the ones in DESIGN.md §5. They are the contract between the
 * plugin and any future second implementation, so every byte is spelled out
 * here and pinned by test/vectors.json.
 *
 *   K_id       identity key, 32 bytes, never rotated
 *     K_blobid = HKDF(K_id, salt="", info="obsync/blob-id/v1")
 *     K_pathid = HKDF(K_id, salt="", info="obsync/path-id/v1")
 *   K_e        content key for epoch e, 32 bytes
 *     K_meta,e = HKDF(K_e, salt="", info="obsync/meta/v1")
 *     K_blob   = HKDF(K_e, salt=salt16, info="obsync/blob/v1")   per blob
 *
 *   blob_id  = HMAC-SHA-256(K_blobid, plaintext)                      (hex)
 *   path_id  = HMAC-SHA-256(K_pathid, NFC(path))                      (hex)
 *   blob     = 0x01 ‖ epoch u32LE ‖ salt16 ‖ nonce12
 *              ‖ AES-256-GCM(K_blob, body, aad = "blob" ‖ blob_id ‖ epoch u32LE)
 *     body   = flags u8 ‖ [len u32LE if padded] ‖ plaintext' ‖ [zero pad]
 *     flags  bit0: plaintext' is deflate-raw compressed; bit1: padded to 4 KiB
 *   meta_enc = epoch u32LE ‖ nonce12 ‖ AES-256-GCM(K_meta, JSON, aad = "meta" ‖ path_id ‖ epoch u32LE)
 *   name_enc = epoch u32LE ‖ nonce12 ‖ AES-256-GCM(K_meta, utf8(name), aad = "name")
 *   wrapped  = eph_pub65 ‖ nonce12 ‖ AES-256-GCM(HKDF(ECDH(eph, pub_kex), "", "obsync/wrap/v1"), K_e ‖ K_id,
 *                                                aad = vault_id ‖ epoch u32LE ‖ recipient_id)
 *              Every row carries the identity key too, so a device that joins
 *              through the recovery identity (which holds no invite) gets it.
 *   invite   = nonce12 ‖ AES-256-GCM(I, JSON{k_id, epochs}, aad = "invite")
 *   recovery = 0x01 ‖ salt16 ‖ nonce12 ‖ AES-256-GCM(K_wrap, pkcs8(priv_kex), aad = "recovery")
 *     PBKDF2-SHA-256(NFC(passphrase), salt16, 600000) → 64 bytes: K_wrap ‖ auth
 *     auth token = "rc_" ‖ base64url(auth)
 */

import {
  b64url,
  bytesEqual,
  concat,
  fromB64url,
  fromHex,
  fromUtf8,
  hex,
  randomBytes,
  readU32le,
  u32le,
  utf8,
} from "./encoding";

const subtle = crypto.subtle;

/**
 * TypeScript 5.9 types WebCrypto inputs as ArrayBuffer-backed views. Every
 * array we hand it is ArrayBuffer-backed in practice (TextEncoder, new
 * Uint8Array, subarray of those); this cast only satisfies the checker.
 */
const B = (b: Uint8Array): Uint8Array<ArrayBuffer> => b as Uint8Array<ArrayBuffer>;

export const BLOB_VERSION = 0x01;
export const BLOB_HEADER_LEN = 1 + 4 + 16 + 12;
export const PAD_BLOCK = 4096;
export const PBKDF2_ITERATIONS = 600_000;

const INFO_BLOBID = utf8("obsync/blob-id/v1");
const INFO_PATHID = utf8("obsync/path-id/v1");
const INFO_META = utf8("obsync/meta/v1");
const INFO_BLOB = utf8("obsync/blob/v1");
const INFO_WRAP = utf8("obsync/wrap/v1");

/** Source of randomness; tests inject a deterministic one to pin vectors. */
export type Rng = (n: number) => Uint8Array;
export const defaultRng: Rng = randomBytes;

// ---------- primitives ----------

async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len = 32): Promise<Uint8Array> {
  const key = await subtle.importKey("raw", B(ikm), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: B(salt), info: B(info) }, key, len * 8));
}

async function hmacKey(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", B(raw), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function hmac(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.sign("HMAC", key, B(data)));
}

async function aesKey(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", B(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function gcmEncrypt(key: CryptoKey, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: B(nonce), additionalData: B(aad) }, key, B(pt)));
}

async function gcmDecrypt(key: CryptoKey, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Promise<Uint8Array> {
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: B(nonce), additionalData: B(aad) }, key, B(ct)));
  } catch {
    throw new CryptoError("authentication failed");
  }
}

export class CryptoError extends Error {}

// ---------- keyring ----------

/** Everything a device needs to read and write the vault. */
export interface Keyring {
  kId: Uint8Array;
  /** epoch → content key. Only epochs ≥ the vault's min_epoch are needed. */
  epochs: Map<number, Uint8Array>;
  /** Epoch to encrypt new data with (the vault's current epoch). */
  current: number;
}

export function newKeyring(): Keyring {
  return { kId: randomBytes(32), epochs: new Map([[1, randomBytes(32)]]), current: 1 };
}

/** Serialisable form for plugin data / invite payloads. */
export interface KeyringJSON {
  k_id: string; // hex
  epochs: Record<string, string>; // epoch → hex
  current: number;
}

export function keyringToJSON(k: Keyring): KeyringJSON {
  const epochs: Record<string, string> = {};
  for (const [e, key] of k.epochs) epochs[String(e)] = hex(key);
  return { k_id: hex(k.kId), epochs, current: k.current };
}

export function keyringFromJSON(j: KeyringJSON): Keyring {
  const epochs = new Map<number, Uint8Array>();
  for (const [e, h] of Object.entries(j.epochs)) epochs.set(Number(e), fromHex(h));
  return { kId: fromHex(j.k_id), epochs, current: j.current };
}

/**
 * Derived keys are cached per keyring instance because HKDF/importKey are
 * not free and a sync touches thousands of IDs.
 */
export class VaultCrypto {
  private blobIdKey?: Promise<CryptoKey>;
  private pathIdKey?: Promise<CryptoKey>;
  private metaKeys = new Map<number, Promise<CryptoKey>>();

  constructor(public readonly keyring: Keyring) {}

  /** Adopt a newly learned epoch key (after a rotation). */
  addEpoch(epoch: number, key: Uint8Array): void {
    this.keyring.epochs.set(epoch, key);
    if (epoch > this.keyring.current) this.keyring.current = epoch;
  }

  /** Forget keys below min_epoch once the server reports nothing uses them. */
  pruneBelow(minEpoch: number): void {
    for (const e of [...this.keyring.epochs.keys()]) {
      if (e < minEpoch) {
        this.keyring.epochs.delete(e);
        this.metaKeys.delete(e);
      }
    }
  }

  private epochKey(epoch: number): Uint8Array {
    const k = this.keyring.epochs.get(epoch);
    if (!k) throw new CryptoError(`no key for epoch ${epoch}`);
    return k;
  }

  private metaKey(epoch: number): Promise<CryptoKey> {
    let p = this.metaKeys.get(epoch);
    if (!p) {
      p = hkdf(this.epochKey(epoch), new Uint8Array(0), INFO_META).then(aesKey);
      this.metaKeys.set(epoch, p);
    }
    return p;
  }

  // ----- identifiers -----

  async blobId(plaintext: Uint8Array): Promise<string> {
    this.blobIdKey ??= hkdf(this.keyring.kId, new Uint8Array(0), INFO_BLOBID).then(hmacKey);
    return hex(await hmac(await this.blobIdKey, plaintext));
  }

  async pathId(path: string): Promise<string> {
    this.pathIdKey ??= hkdf(this.keyring.kId, new Uint8Array(0), INFO_PATHID).then(hmacKey);
    return hex(await hmac(await this.pathIdKey, utf8(path.normalize("NFC"))));
  }

  // ----- blobs -----

  async encryptBlob(
    blobId: string,
    plaintext: Uint8Array,
    opts: { compress?: boolean; pad?: boolean; epoch?: number; rng?: Rng } = {},
  ): Promise<Uint8Array> {
    const epoch = opts.epoch ?? this.keyring.current;
    const rng = opts.rng ?? defaultRng;
    let flags = 0;
    let body = plaintext;
    if (opts.compress) {
      const c = await deflate(body);
      // Only keep compression when it actually helps.
      if (c && c.length < body.length) {
        body = c;
        flags |= 1;
      }
    }
    let bodyFull: Uint8Array;
    if (opts.pad) {
      flags |= 2;
      const raw = 1 + 4 + body.length;
      const padded = Math.ceil(raw / PAD_BLOCK) * PAD_BLOCK;
      bodyFull = new Uint8Array(padded);
      bodyFull[0] = flags;
      bodyFull.set(u32le(body.length), 1);
      bodyFull.set(body, 5);
    } else {
      bodyFull = concat(new Uint8Array([flags]), body);
    }
    const salt = rng(16);
    const nonce = rng(12);
    const key = await aesKey(await hkdf(this.epochKey(epoch), salt, INFO_BLOB));
    const aad = concat(utf8("blob"), fromHex(blobId), u32le(epoch));
    const ct = await gcmEncrypt(key, nonce, aad, bodyFull);
    return concat(new Uint8Array([BLOB_VERSION]), u32le(epoch), salt, nonce, ct);
  }

  /** Decrypts and verifies that the plaintext really has the claimed blob_id. */
  async decryptBlob(blobId: string, blob: Uint8Array): Promise<Uint8Array> {
    if (blob.length < BLOB_HEADER_LEN + 16 || blob[0] !== BLOB_VERSION) throw new CryptoError("bad blob header");
    const epoch = readU32le(blob, 1);
    const salt = blob.subarray(5, 21);
    const nonce = blob.subarray(21, 33);
    const ct = blob.subarray(33);
    const key = await aesKey(await hkdf(this.epochKey(epoch), salt, INFO_BLOB));
    const aad = concat(utf8("blob"), fromHex(blobId), u32le(epoch));
    const bodyFull = await gcmDecrypt(key, nonce, aad, ct);
    const flags = bodyFull[0];
    let body: Uint8Array;
    if (flags & 2) {
      const len = readU32le(bodyFull, 1);
      body = bodyFull.subarray(5, 5 + len);
    } else {
      body = bodyFull.subarray(1);
    }
    const plaintext = flags & 1 ? await inflate(body) : body;
    // Belt and braces: AEAD already bound the id, but a buggy writer could
    // have mislabelled the content. Never trust a mismatched blob.
    if ((await this.blobId(plaintext)) !== blobId) throw new CryptoError("blob_id mismatch after decrypt");
    return plaintext;
  }

  static blobEpoch(blob: Uint8Array): number {
    return readU32le(blob, 1);
  }

  // ----- metadata -----

  async encryptMeta(pathId: string, meta: FileMeta, opts: { epoch?: number; rng?: Rng } = {}): Promise<Uint8Array> {
    const epoch = opts.epoch ?? this.keyring.current;
    const nonce = (opts.rng ?? defaultRng)(12);
    const aad = concat(utf8("meta"), fromHex(pathId), u32le(epoch));
    const ct = await gcmEncrypt(await this.metaKey(epoch), nonce, aad, utf8(JSON.stringify(meta)));
    return concat(u32le(epoch), nonce, ct);
  }

  async decryptMeta(pathId: string, metaEnc: Uint8Array): Promise<FileMeta> {
    if (metaEnc.length < 16 + 16) throw new CryptoError("bad meta");
    const epoch = readU32le(metaEnc, 0);
    const nonce = metaEnc.subarray(4, 16);
    const aad = concat(utf8("meta"), fromHex(pathId), u32le(epoch));
    const pt = await gcmDecrypt(await this.metaKey(epoch), nonce, aad, metaEnc.subarray(16));
    const m = JSON.parse(fromUtf8(pt)) as FileMeta;
    if (typeof m.path !== "string") throw new CryptoError("bad meta json");
    return m;
  }

  static metaEpoch(metaEnc: Uint8Array): number {
    return readU32le(metaEnc, 0);
  }

  async encryptName(name: string, opts: { epoch?: number; rng?: Rng } = {}): Promise<Uint8Array> {
    const epoch = opts.epoch ?? this.keyring.current;
    const nonce = (opts.rng ?? defaultRng)(12);
    const ct = await gcmEncrypt(await this.metaKey(epoch), nonce, utf8("name"), utf8(name));
    return concat(u32le(epoch), nonce, ct);
  }

  async decryptName(nameEnc: Uint8Array): Promise<string> {
    if (nameEnc.length < 16 + 16) throw new CryptoError("bad name");
    const epoch = readU32le(nameEnc, 0);
    try {
      return fromUtf8(await gcmDecrypt(await this.metaKey(epoch), nameEnc.subarray(4, 16), utf8("name"), nameEnc.subarray(16)));
    } catch {
      return "(unreadable name)";
    }
  }
}

/** Plaintext metadata carried inside meta_enc. `path` uses $CONFIG for the config dir. */
export interface FileMeta {
  path: string;
  mtime: number;
  size: number;
  flags?: number;
}

// ---------- device keypair (ECDH P-256) ----------

export interface DeviceKeypair {
  /** 65-byte uncompressed SEC1 point, what the server stores as pub_kex. */
  pub: Uint8Array;
  /** JWK private key, for persistence in plugin data. */
  privJwk: JsonWebKey;
}

export async function generateKeypair(): Promise<DeviceKeypair> {
  const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  return {
    pub: new Uint8Array(await subtle.exportKey("raw", kp.publicKey)),
    privJwk: await subtle.exportKey("jwk", kp.privateKey),
  };
}

async function importPriv(jwk: JsonWebKey): Promise<CryptoKey> {
  return subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

async function importPub(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", B(raw), { name: "ECDH", namedCurve: "P-256" }, false, []);
}

function wrapAad(vaultId: string, epoch: number, recipientId: string): Uint8Array {
  return concat(utf8(vaultId), u32le(epoch), utf8(recipientId));
}

/** ECIES: wrap an epoch key plus the identity key to a recipient's public key (keybox row). */
export async function wrapEpochKey(
  recipientPub: Uint8Array,
  vaultId: string,
  epoch: number,
  recipientId: string,
  epochKey: Uint8Array,
  kId: Uint8Array,
  rng: Rng = defaultRng,
): Promise<Uint8Array> {
  if (epochKey.length !== 32 || kId.length !== 32) throw new CryptoError("keys must be 32 bytes");
  const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const ephPub = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
  const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: await importPub(recipientPub) }, eph.privateKey, 256));
  const key = await aesKey(await hkdf(shared, new Uint8Array(0), INFO_WRAP));
  const nonce = rng(12);
  const ct = await gcmEncrypt(key, nonce, wrapAad(vaultId, epoch, recipientId), concat(epochKey, kId));
  return concat(ephPub, nonce, ct);
}

export async function unwrapEpochKey(
  privJwk: JsonWebKey,
  vaultId: string,
  epoch: number,
  recipientId: string,
  wrapped: Uint8Array,
): Promise<{ epochKey: Uint8Array; kId: Uint8Array }> {
  if (wrapped.length < 65 + 12 + 16) throw new CryptoError("bad wrapped key");
  const ephPub = wrapped.subarray(0, 65);
  const nonce = wrapped.subarray(65, 77);
  const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: await importPub(ephPub) }, await importPriv(privJwk), 256));
  const key = await aesKey(await hkdf(shared, new Uint8Array(0), INFO_WRAP));
  const k = await gcmDecrypt(key, nonce, wrapAad(vaultId, epoch, recipientId), wrapped.subarray(77));
  if (k.length !== 64) throw new CryptoError("bad wrapped payload length");
  return { epochKey: k.subarray(0, 32), kId: k.subarray(32, 64) };
}

// ---------- invites ----------

/** The invite key I travels in the link fragment; the keybox travels via the server. */
export async function encryptInviteKeybox(inviteKey: Uint8Array, keyring: Keyring, rng: Rng = defaultRng): Promise<Uint8Array> {
  const nonce = rng(12);
  const ct = await gcmEncrypt(await aesKey(inviteKey), nonce, utf8("invite"), utf8(JSON.stringify(keyringToJSON(keyring))));
  return concat(nonce, ct);
}

export async function decryptInviteKeybox(inviteKey: Uint8Array, enc: Uint8Array): Promise<Keyring> {
  if (enc.length < 12 + 16) throw new CryptoError("bad invite keybox");
  const pt = await gcmDecrypt(await aesKey(inviteKey), enc.subarray(0, 12), utf8("invite"), enc.subarray(12));
  return keyringFromJSON(JSON.parse(fromUtf8(pt)));
}

/** obsync://join#<server>,<invite token>,<I base64url> */
export function buildInviteLink(server: string, token: string, inviteKey: Uint8Array): string {
  return `obsync://join#${encodeURIComponent(server)},${token},${b64url(inviteKey)}`;
}

export function parseInviteLink(link: string): { server: string; token: string; inviteKey: Uint8Array } {
  const m = /^obsync:\/\/join#([^,]+),([^,]+),([A-Za-z0-9_-]+)$/.exec(link.trim());
  if (!m) throw new Error("not an obsync invite link");
  return { server: decodeURIComponent(m[1]).replace(/\/+$/, ""), token: m[2], inviteKey: fromB64url(m[3]) };
}

// ---------- recovery passphrase ----------

export interface RecoveryMaterial {
  /** Goes to the server as recovery_enc. */
  recoveryEnc: Uint8Array;
  /** Goes to the server as pub_kex of the recovery identity. */
  pub: Uint8Array;
  /** Bearer for the recovery join route; the server stores only its hash. */
  authToken: string;
}

async function pbkdf2(passphrase: string, salt: Uint8Array): Promise<{ wrapKey: Uint8Array; auth: Uint8Array }> {
  const base = await subtle.importKey("raw", B(utf8(passphrase.normalize("NFC"))), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: B(salt), iterations: PBKDF2_ITERATIONS }, base, 512));
  return { wrapKey: bits.subarray(0, 32), auth: bits.subarray(32, 64) };
}

export function recoveryAuthToken(auth: Uint8Array): string {
  return "rc_" + b64url(auth);
}

/** Create a recovery identity: a fresh keypair whose private key is wrapped under the passphrase. */
export async function createRecovery(passphrase: string, rng: Rng = defaultRng): Promise<RecoveryMaterial> {
  const kp = await generateKeypair();
  const priv = await importPriv(kp.privJwk);
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", priv));
  const salt = rng(16);
  const { wrapKey, auth } = await pbkdf2(passphrase, salt);
  const nonce = rng(12);
  const ct = await gcmEncrypt(await aesKey(wrapKey), nonce, utf8("recovery"), pkcs8);
  return { recoveryEnc: concat(new Uint8Array([1]), salt, nonce, ct), pub: kp.pub, authToken: recoveryAuthToken(auth) };
}

/** Open a recovery blob with the passphrase: returns the private key (JWK) and the auth token. */
export async function openRecovery(passphrase: string, recoveryEnc: Uint8Array): Promise<{ privJwk: JsonWebKey; authToken: string }> {
  if (recoveryEnc.length < 1 + 16 + 12 + 16 || recoveryEnc[0] !== 1) throw new CryptoError("bad recovery blob");
  const salt = recoveryEnc.subarray(1, 17);
  const nonce = recoveryEnc.subarray(17, 29);
  const { wrapKey, auth } = await pbkdf2(passphrase, salt);
  let pkcs8: Uint8Array;
  try {
    pkcs8 = await gcmDecrypt(await aesKey(wrapKey), nonce, utf8("recovery"), recoveryEnc.subarray(29));
  } catch {
    throw new CryptoError("wrong passphrase");
  }
  const priv = await subtle.importKey("pkcs8", B(pkcs8), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  return { privJwk: await subtle.exportKey("jwk", priv), authToken: recoveryAuthToken(auth) };
}

// ---------- compression (optional, feature-detected) ----------

async function pipe(data: Uint8Array, stream: { readable: ReadableStream; writable: WritableStream }): Promise<Uint8Array> {
  const w = stream.writable.getWriter();
  const done = w.write(B(data)).then(() => w.close());
  const chunks: Uint8Array[] = [];
  const r = stream.readable.getReader();
  for (;;) {
    const { value, done: d } = await r.read();
    if (d) break;
    chunks.push(value);
  }
  await done;
  return concat(...chunks);
}

export async function deflate(data: Uint8Array): Promise<Uint8Array | null> {
  if (typeof CompressionStream === "undefined") return null;
  try {
    return await pipe(data, new CompressionStream("deflate-raw"));
  } catch {
    return null;
  }
}

export async function inflate(data: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream === "undefined") throw new CryptoError("compressed blob but no DecompressionStream");
  return pipe(data, new DecompressionStream("deflate-raw"));
}

export { bytesEqual };
