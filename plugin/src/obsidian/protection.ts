/**
 * Per-device key protection backends (DESIGN.md §5.5a), measured against
 * real Obsidian: WebAuthn is unavailable on the app:// origin, so the
 * options are the OS keychain through Electron's safeStorage (desktop),
 * optionally gated by Touch ID on macOS, and a PIN anywhere.
 */
import { Platform } from "obsidian";
import { fromHex, hex } from "../core/encoding";

interface ElectronRemote {
  safeStorage?: {
    isEncryptionAvailable(): boolean;
    getSelectedStorageBackend?(): string;
    encryptString(s: string): { toString(enc: string): string };
    decryptString(b: unknown): string;
  };
  systemPreferences?: { promptTouchID?(reason: string): Promise<void>; canPromptTouchID?(): boolean };
}

function remote(): ElectronRemote | null {
  try {
    const req = (globalThis as unknown as { require?: (m: string) => { remote?: ElectronRemote } }).require;
    return req ? (req("electron").remote ?? null) : null;
  } catch {
    return null;
  }
}

/** True when the OS keychain backend is real (not Electron's basic_text fallback). */
export function safeStorageAvailable(): boolean {
  const ss = remote()?.safeStorage;
  if (!ss || !ss.isEncryptionAvailable()) return false;
  const backend = ss.getSelectedStorageBackend?.();
  // macOS and Windows report no backend (always a real keychain); Linux must
  // name a real one: not the plaintext fallback and not the pre-selection value.
  return backend === undefined || (backend !== "basic_text" && backend !== "unknown");
}

/**
 * True only when this Mac can actually show a Touch ID prompt. The API
 * exists on every Mac (a Mac mini has it and no sensor), so the presence of
 * `promptTouchID` says nothing; `canPromptTouchID` asks the hardware.
 */
export function touchIdAvailable(): boolean {
  const sp = remote()?.systemPreferences;
  if (!Platform.isMacOS || typeof sp?.promptTouchID !== "function" || typeof sp.canPromptTouchID !== "function") return false;
  try {
    return sp.canPromptTouchID() === true;
  } catch {
    return false;
  }
}

/** Wrap a 32-byte key with the OS keychain; returns base64 of the opaque ciphertext. */
export function safeWrap(wrapKey: Uint8Array): string {
  const ss = remote()?.safeStorage;
  if (!ss || !safeStorageAvailable()) throw new Error("OS keychain protection is not available on this device");
  return ss.encryptString(hex(wrapKey)).toString("base64");
}

export function safeUnwrap(stored: string): Uint8Array {
  const ss = remote()?.safeStorage;
  if (!ss) throw new Error("OS keychain protection is not available on this device");
  const buf = (globalThis as unknown as { Buffer: { from(s: string, e: string): unknown } }).Buffer.from(stored, "base64");
  return fromHex(ss.decryptString(buf));
}

/**
 * Obsidian's own secret storage (`app.secretStorage`, 1.11.4+). Read from
 * Obsidian 1.15.1's code: on iOS and Android it is the Capacitor
 * SecureStorage plugin, i.e. a generic-password item in the iOS Keychain
 * (accessible when unlocked, not synchronised to iCloud Keychain) or an
 * Android-Keystore-encrypted preference; all secrets of all vaults live in
 * one item, loaded into memory before plugins start, and `setSecret`
 * returns before the native write has finished. On desktop it is
 * safeStorage plus localStorage, which method "safe" already covers without
 * the detour, so this method is offered on mobile only.
 *
 * Because the write is not awaited, a caller must not give up its previous
 * protection until a later launch has read the secret back (see
 * Protection.fallback in main.ts).
 */
interface SecretStore {
  setSecret(id: string, secret: string): void;
  getSecret(id: string): string | null;
  deleteSecret?(id: string): boolean;
}

function secretStore(app: unknown): SecretStore | null {
  const ss = (app as { secretStorage?: SecretStore } | null)?.secretStorage;
  return ss && typeof ss.setSecret === "function" && typeof ss.getSecret === "function" ? ss : null;
}

export function secretStorageAvailable(app: unknown): boolean {
  return Platform.isMobile && secretStore(app) !== null;
}

/** Ids are lowercase alphanumerics and dashes, 64 at most (Obsidian's rule). */
export function secretId(vaultId: string, deviceId: string): string {
  const clean = (s: string, n: number) => s.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, n);
  return `obsync-${clean(vaultId, 32)}-${clean(deviceId, 16)}`;
}

export function secretPut(app: unknown, id: string, wrapKey: Uint8Array): void {
  const ss = secretStore(app);
  if (!ss) throw new Error("the device keychain is not available in this version of Obsidian");
  ss.setSecret(id, hex(wrapKey));
}

/** The wrapping key, or null when the keychain has no (usable) entry under `id`. */
export function secretGet(app: unknown, id: string): Uint8Array | null {
  const v = secretStore(app)?.getSecret(id);
  if (!v || !/^[0-9a-f]{64}$/.test(v)) return null;
  return fromHex(v);
}

export function secretDrop(app: unknown, id: string): void {
  try {
    secretStore(app)?.deleteSecret?.(id);
  } catch {
    /* best effort */
  }
}

/** Resolves if the user passes Touch ID; rejects on cancel/failure/unavailable. */
export async function promptTouchId(reason: string): Promise<void> {
  const sp = remote()?.systemPreferences;
  if (!sp?.promptTouchID) throw new Error("Touch ID is not available on this device");
  await sp.promptTouchID(reason);
}
