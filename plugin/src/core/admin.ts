/**
 * Enrolment and key administration: create a vault, join one, invite another
 * device, remove a device (rotate + re-encrypt), and recovery passphrases.
 * Platform-free so the tests and the Obsidian UI share it exactly.
 *
 * Flows (DESIGN.md §5.3–5.6):
 *   createVault      admin token → vault, keys, first device
 *   createInviteLink device → obsync://join#server,token,I
 *   joinWithLink     link → device (keys from the invite keybox)
 *   removeDevice     rotate without it, re-encrypt everything
 *   setRecoveryPassphrase / joinWithPassphrase
 */

import {
  VaultCrypto,
  createRecovery,
  decryptInviteKeybox,
  encryptInviteKeybox,
  generateKeypair,
  keyringFromJSON,
  keyringToJSON,
  newKeyring,
  authTokenFor,
  deriveRecovery,
  openRecoveryWith,
  parseInviteLink,
  buildInviteLink,
  unwrapEpochKey,
  wrapEpochKey,
  type DeviceKeypair,
  type Keyring,
  type KeyringJSON, RECOVERY_ITERATIONS, LEGACY_RECOVERY_ITERATIONS, CryptoError, type FileMeta } from "./crypto";
import { b64, fromB64, randomBytes, utf8 } from "./encoding";
import { Client, HttpError, type WireDevice, NetworkError } from "./transport";

/** Everything a device persists to come back as itself. Stored in plugin data. */
export interface Identity {
  server: string;
  vaultId: string;
  deviceId: string;
  deviceToken: string;
  deviceName: string;
  /** base64 of the 65-byte ECDH public key */
  pub: string;
  privJwk: JsonWebKey;
  keyring: KeyringJSON;
}

export interface Session {
  identity: Identity;
  client: Client;
  vc: VaultCrypto;
}

export function openSession(identity: Identity, fetchImpl?: typeof fetch): Session {
  const vc = new VaultCrypto(keyringFromJSON(identity.keyring));
  return { identity, client: new Client(identity.server, identity.deviceToken, { fetchImpl, vaultAuth: () => vc.authToken() }), vc };
}

/** Keep the stored keyring in step with the in-memory one after rotations. */
export function syncIdentityKeys(s: Session): void {
  s.identity.keyring = keyringToJSON(s.vc.keyring);
}

type Redeemed = { device_id: string; device_token: string; epoch: number };

/**
 * Common tail of every enrolment: build the identity, write our own keybox
 * rows (so later rotations can address us) and set our encrypted name.
 */
async function finishEnrol(server: string, vaultId: string, deviceName: string, keyring: Keyring, kp: DeviceKeypair, red: Redeemed, fetchImpl?: typeof fetch): Promise<Session> {
  const identity: Identity = {
    server,
    vaultId,
    deviceId: red.device_id,
    deviceToken: red.device_token,
    deviceName,
    pub: b64(kp.pub),
    privJwk: kp.privJwk,
    keyring: keyringToJSON(keyring),
  };
  const s = openSession(identity, fetchImpl);
  const rows = [];
  for (const [epoch, key] of keyring.epochs) {
    // Only epochs the server knows: an inviter that kept keys from before a
    // server restore (§6.8) would otherwise offer rows the server refuses.
    if (epoch > red.epoch) continue;
    rows.push({ epoch, recipient_id: red.device_id, wrapped: await wrapEpochKey(kp.pub, vaultId, epoch, red.device_id, key, keyring.kId) });
  }
  await s.client.putKeybox(vaultId, rows);
  // Register the vault authority hash. Only the first device actually sets
  // it; every later device derives the same token and gets a no-op, or a
  // 401 (409 from servers before 0.1.5) if its keyring is behind the
  // server's epoch (refreshKeys catches up).
  try {
    await s.client.registerAuth(vaultId, await s.vc.authToken(red.epoch));
  } catch (e) {
    // 401/409: a different token is already set (every device after the
    // first, when its keyring is behind), or this vault has more than one
    // device and no authority yet (pre-§5.8 database; the admin installs it,
    // see `obsync vault auth`). Either way enrolment is done.
    if (!(e instanceof HttpError && (e.status === 409 || e.status === 401))) throw e;
  }
  try {
    await s.client.setDeviceName(vaultId, await s.vc.encryptName(deviceName, red.device_id));
  } catch (e) {
    // Naming needs vault authority; a pre-§5.8 vault without one leaves the device "(unnamed)" until the admin installs it.
    if (!(e instanceof HttpError && e.status === 401)) throw e;
  }
  return s;
}

/** First device: create the vault on the server (needs the admin token) and enrol. */
export async function createVault(server: string, adminToken: string, deviceName: string, fetchImpl?: typeof fetch): Promise<Session> {
  server = server.replace(/\/+$/, "");
  const v = await Client.createVault(server, adminToken, fetchImpl);
  const keyring = newKeyring();
  const kp = await generateKeypair();
  const inviteKey = randomBytes(32);
  const admin = new Client(server, adminToken, { fetchImpl });
  const inv = await admin.createInvite(v.vault_id, await encryptInviteKeybox(inviteKey, keyring), 600);
  const red = await Client.redeemInvite(server, inv.token, kp.pub, new Uint8Array(0), fetchImpl);
  return finishEnrol(server, v.vault_id, deviceName, keyring, kp, red, fetchImpl);
}

/** Mint an invite link for another device. The link carries the keys; guard it. */
export async function createInviteLink(s: Session, ttlSeconds = 3600): Promise<string> {
  const inviteKey = randomBytes(32);
  const inv = await s.client.createInvite(s.identity.vaultId, await encryptInviteKeybox(inviteKey, s.vc.keyring), ttlSeconds);
  return buildInviteLink(s.identity.server, inv.token, inviteKey);
}

/** Join from an invite link. */
export async function joinWithLink(link: string, deviceName: string, fetchImpl?: typeof fetch): Promise<Session> {
  const { server, token, inviteKey } = parseInviteLink(link);
  const kp = await generateKeypair();
  const red = await Client.redeemInvite(server, token, kp.pub, new Uint8Array(0), fetchImpl);
  const keyring = await decryptInviteKeybox(inviteKey, fromB64(red.keybox_enc));
  if (red.epoch > keyring.current) keyring.current = red.epoch; // inviter was behind; refreshKeys will fetch the rest
  return finishEnrol(server, red.vault_id, deviceName, keyring, kp, red, fetchImpl);
}

/** Decrypted roster for display. */
export async function listDevices(s: Session): Promise<(WireDevice & { name: string; isSelf: boolean })[]> {
  const ds = await s.client.devices(s.identity.vaultId);
  const out = [];
  for (const d of ds) {
    const name = d.recovery ? "(recovery passphrase)" : d.name_enc ? await s.vc.decryptName(fromB64(d.name_enc), d.id) : "(unnamed)";
    out.push({ ...d, name, isSelf: d.id === s.identity.deviceId });
  }
  return out;
}

/**
 * Make sure this device's own name row proves it holds the keys: written
 * with the vault's name key and this device's id in the AAD. Rows written by
 * 0.1.0 (no id) or by versions before the name key (under an epoch key that
 * re-encryption later prunes) do not, and the next rotation from another
 * device would revoke this one as unproven. Rewrites the row when needed and
 * returns whether it did. Cheap (one roster fetch) and safe to run at every
 * start.
 */
export function ensureOwnName(s: Session): Promise<boolean> {
  const key = s.identity.deviceId;
  const set = nameRewriteInFlight.get(key) ?? new Set();
  nameRewriteInFlight.set(key, set);
  const p: Promise<boolean> = ensureOwnNameNow(s).finally(() => {
    set.delete(p);
    if (set.size === 0 && nameRewriteInFlight.get(key) === set) nameRewriteInFlight.delete(key);
  });
  set.add(p);
  return p;
}

/**
 * Fetch any keybox rows this keyring lacks and unwrap them (the engine does
 * the same at sync time). Used by re-encryption when a blob names an epoch
 * the keyring has not seen.
 */
export async function refreshKeyring(s: Session): Promise<boolean> {
  const rows = await s.client.keybox(s.identity.vaultId);
  let changed = false;
  for (const r of rows) {
    if (s.vc.keyring.epochs.has(r.epoch)) continue;
    try {
      const { epochKey } = await unwrapEpochKey(s.identity.privJwk, s.identity.vaultId, r.epoch, s.identity.deviceId, fromB64(r.wrapped));
      s.vc.addEpoch(r.epoch, epochKey);
      changed = true;
    } catch {
      /* a row we cannot unwrap is not ours to read */
    }
  }
  if (changed) syncIdentityKeys(s);
  return changed;
}

/**
 * The start-up rewrite that may still be in flight, per device, so a rename
 * waits for it instead of being undone by it. Keyed by device id, not by
 * the Session object: a restart opens a new Session while the old one's
 * request may still be on the wire.
 */
const nameRewriteInFlight = new Map<string, Set<Promise<boolean>>>();

async function ensureOwnNameNow(s: Session): Promise<boolean> {
  const v = s.identity.vaultId;
  const me = (await s.client.devices(v)).find((d) => d.id === s.identity.deviceId);
  if (!me || me.revoked_at) return false;
  if (me.name_enc && (await s.vc.verifyName(fromB64(me.name_enc), me.id)) !== null) return false;
  await s.client.setDeviceName(v, await s.vc.encryptName(s.identity.deviceName, me.id));
  return true;
}

/**
 * Rename this device in the roster. Waits for a start-up name rewrite that
 * is still in flight, which would otherwise land after the rename and put
 * the old name back.
 */
export async function renameOwnDevice(s: Session, name: string): Promise<void> {
  // Every rewrite still in flight for this device, from any Session (a
  // restart opens a new one while the old request may still be on the wire).
  await Promise.all([...(nameRewriteInFlight.get(s.identity.deviceId) ?? [])].map((p) => p.catch(() => {})));
  await s.client.setDeviceName(s.identity.vaultId, await s.vc.encryptName(name, s.identity.deviceId));
  s.identity.deviceName = name;
}

/**
 * Rotate to a new epoch, optionally revoking devices (DESIGN.md §5.4).
 * Wraps the new key to every remaining live device and the recovery identity.
 * Returns the new epoch. Call `reencrypt` afterwards (resumable).
 *
 * A device receives the new key only if it proved it held the old ones: its
 * name must authenticate under its own id (names are written with vault
 * authority). A row planted through the admin token, or one that never
 * finished enrolling, has no such proof; it is revoked instead, so a stranger
 * in the roster cannot be handed `K_e ‖ K_id` by the owner's next rotation.
 *
 * `confirmUnproven` is asked before anything is posted when such devices
 * exist, with their ids (and the names their rows carry, when readable). It
 * returns whether to go ahead; a false answer cancels the rotation and
 * nothing changes. An honest device can be in that list only if its name
 * row predates the current format and it has not started since (every
 * 0.1.1+ device rewrites its row at start, see `ensureOwnName`).
 */
export class RotationCancelled extends Error {}

export async function rotate(s: Session, revoke: string[] = [], confirmUnproven?: (ids: string[], names: string[]) => boolean | Promise<boolean>): Promise<number> {
  const v = s.identity.vaultId;
  const info = await s.client.vault(v);
  const epoch = info.epoch + 1;
  const key = randomBytes(32);
  const devices = await s.client.devices(v);
  const rows = [];
  const unproven: string[] = [];
  const unprovenNames: string[] = [];
  for (const d of devices) {
    if (d.revoked_at || revoke.includes(d.id) || !d.pub_kex) continue;
    if (!d.recovery && d.id !== s.identity.deviceId && (!d.name_enc || (await s.vc.verifyName(fromB64(d.name_enc), d.id)) === null)) {
      unproven.push(d.id);
      unprovenNames.push(d.name_enc ? (await s.vc.legacyName(fromB64(d.name_enc))) ?? "(unnamed)" : "(unnamed)");
      continue;
    }
    let wrapped: Uint8Array;
    try {
      wrapped = await wrapEpochKey(fromB64(d.pub_kex), v, epoch, d.id, key, s.vc.keyring.kId);
    } catch {
      // A row whose key does not import (not a P-256 point) can never
      // receive a wrapped key; treat it like any other device without proof
      // rather than aborting the whole rotation with no hint which row.
      unproven.push(d.id);
      unprovenNames.push(((d.name_enc && (await s.vc.decryptName(fromB64(d.name_enc), d.id))) || "(unnamed)") + " [unusable key]");
      continue;
    }
    rows.push({ epoch, recipient_id: d.id, wrapped });
  }
  if (unproven.length && confirmUnproven && !(await confirmUnproven(unproven, unprovenNames))) throw new RotationCancelled("key rotation cancelled: unproven devices were not confirmed");
  await s.client.rotate(v, epoch, [...revoke, ...unproven], rows, await authTokenFor(key));
  s.vc.addEpoch(epoch, key);
  syncIdentityKeys(s);
  return epoch;
}

/**
 * Re-encrypt everything still under an older epoch (DESIGN.md §5.4 step 5).
 * Idempotent and resumable: any device can run it, repeatedly, until the
 * server reports min_epoch == epoch. Old blobs are re-uploaded under the
 * same blob_id; the server accepts the replacement because the header epoch
 * is higher.
 */
export async function reencrypt(s: Session, onProgress?: (done: number, remaining: number) => void): Promise<{ blobs: number; ops: number; skipped: string[] }> {
  const v = s.identity.vaultId;
  const target = (await s.client.vault(v)).epoch;
  let blobs = 0;
  let ops = 0;
  const skipped: string[] = [];
  let lastIds = "";
  for (;;) {
    const ids = await s.client.blobsBelowEpoch(v, target, 200);
    if (ids.length === 0) break;
    const key = ids.join(",");
    if (key === lastIds) throw new Error(`re-encryption is not making progress on ${ids.length} blob(s)`);
    lastIds = key;
    for (const id of ids) {
      let ct: Uint8Array;
      try {
        ct = await s.client.getBlob(v, id);
      } catch (e) {
        if (e instanceof HttpError && e.status === 404) {
          skipped.push(id); // the server dropped an orphaned row meanwhile; nothing to carry over
          continue;
        }
        throw e;
      }
      let pt: Uint8Array;
      let store: { compress?: boolean; pad?: boolean } = {};
      try {
        const info = await decryptForReencrypt(s, id, ct);
        pt = info.plaintext;
        // Keep the body as it was stored: dropping compression and padding
        // here would undo the length hiding vault-wide at every rotation.
        store = { compress: info.compressed, pad: info.padded };
      } catch (e) {
        // Only a transport failure aborts (and is retried as a whole). Any
        // other failure is a blob no key holder can read: bytes that do not
        // hash to the id, a body that is not deflate, an epoch no row gives
        // us a key for, garbage. It was never applicable, and it must not
        // hold the whole vault on the old keys: carry it over as a marked
        // placeholder under the new epoch. Every device keeps skipping that
        // op (blob_id mismatch), a later op for the path heals it, and the
        // retired epoch can be pruned.
        if (e instanceof HttpError || e instanceof NetworkError) throw e;
        pt = utf8(`obsync: blob ${id} could not be decrypted during re-encryption and was replaced`);
        skipped.push(id);
      }
      await s.client.putBlob(v, id, await s.vc.encryptBlob(id, pt, { epoch: target, ...store }), { replace: true });
      onProgress?.(++blobs, ids.length);
    }
  }
  for (;;) {
    const seqs = await s.client.opsBelowMetaEpoch(v, target, 200);
    if (seqs.length === 0) break;
    const want = new Set(seqs);
    let since = Math.min(...seqs) - 1;
    const hi = Math.max(...seqs);
    while (since < hi) {
      const f = await s.client.changes(v, since, { limit: 500 });
      if (f.ops.length === 0) break;
      for (const op of f.ops) {
        if (!want.has(op.seq)) continue;
        let meta: FileMeta;
        try {
          meta = await s.vc.decryptMeta(op.path_id, fromB64(op.meta_enc));
          // Rows from older versions gain the blob binding here. A row that
          // already carries one keeps it: the applier refuses an op whose
          // authenticated metadata names another blob than the row, and
          // re-encryption must not launder such a row into a consistent one.
          if (meta.blob === undefined) meta.blob = op.blob_id;
        } catch (e) {
          if (e instanceof HttpError || e instanceof NetworkError) throw e;
          if (e instanceof CryptoError && /epoch/.test(e.message) && (await refreshKeyring(s))) {
            try {
              meta = await s.vc.decryptMeta(op.path_id, fromB64(op.meta_enc));
              if (meta.blob === undefined) meta.blob = op.blob_id;
              await s.client.patchMeta(v, op.seq, await s.vc.encryptMeta(op.path_id, meta, { epoch: target }), target);
              ops++;
              continue;
            } catch {
              /* still unreadable: placeholder below */
            }
          }
          // Unreadable metadata (a member's garbage, or not JSON at all):
          // carry a placeholder that no applier accepts (an empty path fails
          // validation), so the op stays skipped and the old epoch can still
          // be retired.
          meta = { path: "", mtime: 0, size: 0, blob: op.blob_id };
          skipped.push(`op ${op.seq}`);
        }
        await s.client.patchMeta(v, op.seq, await s.vc.encryptMeta(op.path_id, meta, { epoch: target }), target);
        ops++;
      }
      since = f.cursor;
      if (!f.more) break;
    }
  }
  if ((await s.client.vault(v)).min_epoch >= target) {
    s.vc.pruneBelow(target);
    syncIdentityKeys(s);
  }
  return { blobs, ops, skipped };
}

/** Decrypt for re-encryption; on "no key for epoch" fetch the keybox once and retry before giving up. */
async function decryptForReencrypt(s: Session, id: string, ct: Uint8Array): Promise<{ plaintext: Uint8Array; compressed: boolean; padded: boolean }> {
  try {
    return await s.vc.decryptBlobInfo(id, ct);
  } catch (e) {
    if (e instanceof CryptoError && /epoch/.test(e.message) && (await refreshKeyring(s))) return s.vc.decryptBlobInfo(id, ct);
    throw e;
  }
}

/** Remove a device: rotate without it, then re-encrypt. */
export async function removeDevice(s: Session, deviceId: string, onProgress?: (done: number, remaining: number) => void, confirmUnproven?: (ids: string[], names: string[]) => boolean | Promise<boolean>): Promise<{ resumed: boolean; skipped: string[] }> {
  if (!deviceId) {
    // "Rotate keys" with an earlier rotation's re-encryption still unfinished
    // resumes that work instead of minting yet another epoch on top of it.
    const info = await s.client.vault(s.identity.vaultId);
    if (info.min_epoch < info.epoch) {
      const r = await reencrypt(s, onProgress);
      return { resumed: true, skipped: r.skipped };
    }
  }
  await rotate(s, deviceId ? [deviceId] : [], confirmUnproven);
  const r = await reencrypt(s, onProgress);
  return { resumed: false, skipped: r.skipped };
}

/** Install or replace the recovery passphrase. Wraps every current epoch key to it. */
export async function setRecoveryPassphrase(s: Session, passphrase: string): Promise<void> {
  const v = s.identity.vaultId;
  const rec = await createRecovery(passphrase);
  const { device_id } = await s.client.setRecovery(v, rec.pub, rec.recoveryEnc, rec.salt, rec.authToken);
  const rows = [];
  for (const [epoch, key] of s.vc.keyring.epochs) rows.push({ epoch, recipient_id: device_id, wrapped: await wrapEpochKey(rec.pub, v, epoch, device_id, key, s.vc.keyring.kId) });
  await s.client.putKeybox(v, rows, { authority: true });
}

/** Join with only the server URL, vault id, and recovery passphrase. */
export async function joinWithPassphrase(server: string, vaultId: string, passphrase: string, deviceName: string, fetchImpl?: typeof fetch): Promise<Session> {
  server = server.replace(/\/+$/, "");
  // The server hands out only the KDF salt; the wrapped key comes back from
  // the join itself, after the derived auth token proved the passphrase.
  const info = await Client.getRecovery(server, vaultId, fetchImpl);
  const kp = await generateKeypair();
  // The server does not say how many iterations the passphrase was set
  // with (only the salt leaves it before the proof), so try today's count,
  // then the one versions before 0.1.3 used. A legacy hit is re-set at
  // today's count once joined.
  let joined: Awaited<ReturnType<typeof Client.recoveryJoin>> | null = null;
  let wrapKey: Uint8Array | null = null;
  let legacy = false;
  for (const iterations of [RECOVERY_ITERATIONS, LEGACY_RECOVERY_ITERATIONS]) {
    const d = await deriveRecovery(passphrase, fromB64(info.salt), iterations);
    try {
      joined = await Client.recoveryJoin(server, vaultId, d.authToken, kp.pub, new Uint8Array(0), fetchImpl);
      wrapKey = d.wrapKey;
      legacy = iterations !== RECOVERY_ITERATIONS;
      break;
    } catch (e) {
      if (!(e instanceof HttpError && e.status === 401)) throw e;
    }
  }
  if (!joined || !wrapKey) throw new Error("wrong recovery passphrase");
  const privJwk = await openRecoveryWith(wrapKey, fromB64(joined.recovery_enc));
  const epochs = new Map<number, Uint8Array>();
  let kId: Uint8Array | null = null;
  for (const r of joined.keybox) {
    const u = await unwrapEpochKey(privJwk, vaultId, r.epoch, info.device_id, fromB64(r.wrapped));
    epochs.set(r.epoch, u.epochKey);
    kId = u.kId;
  }
  if (!kId || epochs.size === 0) throw new Error("recovery identity holds no keys for this vault");
  const keyring: Keyring = { kId, epochs, current: Math.max(joined.epoch, ...epochs.keys()) };
  const s = await finishEnrol(server, vaultId, deviceName, keyring, kp, joined, fetchImpl);
  if (legacy) await setRecoveryPassphrase(s, passphrase);
  return s;
}
