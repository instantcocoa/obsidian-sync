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
  type KeyringJSON,
} from "./crypto";
import { b64, fromB64, randomBytes } from "./encoding";
import { Client, HttpError, type WireDevice } from "./transport";

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
    rows.push({ epoch, recipient_id: red.device_id, wrapped: await wrapEpochKey(kp.pub, vaultId, epoch, red.device_id, key, keyring.kId) });
  }
  await s.client.putKeybox(vaultId, rows);
  // Register the vault authority hash. Only the first device actually sets
  // it; every later device derives the same token and gets a no-op, or a
  // 409 if its keyring is behind the server's epoch (refreshKeys catches up).
  try {
    await s.client.registerAuth(vaultId, await s.vc.authToken(Math.max(...keyring.epochs.keys())));
  } catch (e) {
    if (!(e instanceof HttpError && e.status === 409)) throw e;
  }
  await s.client.setDeviceName(vaultId, await s.vc.encryptName(deviceName));
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
export async function createInviteLink(s: Session, ttlSeconds = 24 * 3600): Promise<string> {
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
    const name = d.recovery ? "(recovery passphrase)" : d.name_enc ? await s.vc.decryptName(fromB64(d.name_enc)) : "(unnamed)";
    out.push({ ...d, name, isSelf: d.id === s.identity.deviceId });
  }
  return out;
}

/**
 * Rotate to a new epoch, optionally revoking devices (DESIGN.md §5.4).
 * Wraps the new key to every remaining live device and the recovery identity.
 * Returns the new epoch. Call `reencrypt` afterwards (resumable).
 */
export async function rotate(s: Session, revoke: string[] = []): Promise<number> {
  const v = s.identity.vaultId;
  const info = await s.client.vault(v);
  const epoch = info.epoch + 1;
  const key = randomBytes(32);
  const devices = await s.client.devices(v);
  const rows = [];
  for (const d of devices) {
    if (d.revoked_at || revoke.includes(d.id) || !d.pub_kex) continue;
    rows.push({ epoch, recipient_id: d.id, wrapped: await wrapEpochKey(fromB64(d.pub_kex), v, epoch, d.id, key, s.vc.keyring.kId) });
  }
  await s.client.rotate(v, epoch, revoke, rows, await authTokenFor(key));
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
export async function reencrypt(s: Session, onProgress?: (done: number, remaining: number) => void): Promise<{ blobs: number; ops: number }> {
  const v = s.identity.vaultId;
  const target = (await s.client.vault(v)).epoch;
  let blobs = 0;
  let ops = 0;
  for (;;) {
    const ids = await s.client.blobsBelowEpoch(v, target, 200);
    if (ids.length === 0) break;
    for (const id of ids) {
      const pt = await s.vc.decryptBlob(id, await s.client.getBlob(v, id));
      await s.client.putBlob(v, id, await s.vc.encryptBlob(id, pt, { epoch: target }), { replace: true });
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
        const meta = await s.vc.decryptMeta(op.path_id, fromB64(op.meta_enc));
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
  return { blobs, ops };
}

/** Remove a device: rotate without it, then re-encrypt. */
export async function removeDevice(s: Session, deviceId: string, onProgress?: (done: number, remaining: number) => void): Promise<void> {
  await rotate(s, [deviceId]);
  await reencrypt(s, onProgress);
}

/** Install or replace the recovery passphrase. Wraps every current epoch key to it. */
export async function setRecoveryPassphrase(s: Session, passphrase: string): Promise<void> {
  const v = s.identity.vaultId;
  const rec = await createRecovery(passphrase);
  const { device_id } = await s.client.setRecovery(v, rec.pub, rec.recoveryEnc, rec.salt, rec.authToken);
  const rows = [];
  for (const [epoch, key] of s.vc.keyring.epochs) rows.push({ epoch, recipient_id: device_id, wrapped: await wrapEpochKey(rec.pub, v, epoch, device_id, key, s.vc.keyring.kId) });
  await s.client.putKeybox(v, rows);
}

/** Join with only the server URL, vault id, and recovery passphrase. */
export async function joinWithPassphrase(server: string, vaultId: string, passphrase: string, deviceName: string, fetchImpl?: typeof fetch): Promise<Session> {
  server = server.replace(/\/+$/, "");
  // The server hands out only the KDF salt; the wrapped key comes back from
  // the join itself, after the derived auth token proved the passphrase.
  const info = await Client.getRecovery(server, vaultId, fetchImpl);
  const { wrapKey, authToken } = await deriveRecovery(passphrase, fromB64(info.salt));
  const kp = await generateKeypair();
  let joined;
  try {
    joined = await Client.recoveryJoin(server, vaultId, authToken, kp.pub, new Uint8Array(0), fetchImpl);
  } catch (e) {
    if (e instanceof HttpError && e.status === 401) throw new Error("wrong recovery passphrase");
    throw e;
  }
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
  return finishEnrol(server, vaultId, deviceName, keyring, kp, joined, fetchImpl);
}
