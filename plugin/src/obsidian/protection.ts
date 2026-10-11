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
  systemPreferences?: { promptTouchID?(reason: string): Promise<void> };
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
  return backend === undefined || backend !== "basic_text";
}

export function touchIdAvailable(): boolean {
  return Platform.isMacOS && typeof remote()?.systemPreferences?.promptTouchID === "function";
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

/** Resolves if the user passes Touch ID; rejects on cancel/failure/unavailable. */
export async function promptTouchId(reason: string): Promise<void> {
  const sp = remote()?.systemPreferences;
  if (!sp?.promptTouchID) throw new Error("Touch ID is not available on this device");
  await sp.promptTouchID(reason);
}
