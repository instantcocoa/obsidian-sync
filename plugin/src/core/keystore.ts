/**
 * Local key-store protection (DESIGN.md §5.8).
 *
 * The device's identity (vault keys, device private key, token) is sealed
 * under a 32-byte wrapping key before it is written to the plugin's
 * data.json. Where that wrapping key comes from is the "method":
 *
 *   none  – no sealing; identity stored in the clear (the previous behaviour)
 *   pin   – wrapping key = PBKDF2(pin, salt); the user types it at launch
 *   safe  – wrapping key is random and itself stored encrypted by the OS
 *           keychain (Electron safeStorage: macOS Keychain, Windows DPAPI,
 *           Linux libsecret/kwallet). Desktop only. Optionally gated by a
 *           Touch ID prompt on macOS, which is a gate our code enforces,
 *           not a cryptographic input.
 *
 * Sealed form (base64 fields in JSON):
 *   { v: 1, method, salt?, nonce, ct }   ct = AES-256-GCM(wrapKey, utf8(identity JSON), aad = "obsync/keystore/v1")
 *
 * The format is independent of where the wrapping key came from, so a
 * device can switch methods by re-sealing.
 */
import { concat, fromB64, b64, fromUtf8, randomBytes, utf8 } from "./encoding";
import { PBKDF2_ITERATIONS, CryptoError } from "./crypto";

export type ProtectionMethod = "none" | "pin" | "safe";

export interface SealedKeystore {
  v: 1;
  method: Exclude<ProtectionMethod, "none">;
  /** PBKDF2 salt (pin) */
  salt?: string;
  nonce: string;
  ct: string;
}

const AAD = utf8("obsync/keystore/v1");
const B = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;

export async function deriveWrapKeyFromPin(pin: string, salt: Uint8Array): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", B(utf8(pin.normalize("NFC"))), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: B(salt), iterations: PBKDF2_ITERATIONS }, base, 256));
}

export function newWrapKey(): Uint8Array {
  return randomBytes(32);
}

async function aes(key: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", B(key), "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function seal(identity: unknown, method: "pin" | "safe", wrapKey: Uint8Array, salt?: Uint8Array): Promise<SealedKeystore> {
  const nonce = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: B(nonce), additionalData: B(AAD) }, await aes(wrapKey), B(utf8(JSON.stringify(identity)))));
  const out: SealedKeystore = { v: 1, method, nonce: b64(nonce), ct: b64(ct) };
  if (salt) out.salt = b64(salt);
  return out;
}

export async function open<T = unknown>(sealed: SealedKeystore, wrapKey: Uint8Array): Promise<T> {
  if (sealed.v !== 1) throw new CryptoError("unknown keystore version");
  try {
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: B(fromB64(sealed.nonce)), additionalData: B(AAD) }, await aes(wrapKey), B(fromB64(sealed.ct))));
    return JSON.parse(fromUtf8(pt)) as T;
  } catch {
    throw new CryptoError("wrong PIN or corrupted key store");
  }
}

/** Convenience: seal with a PIN (fresh salt). */
export async function sealWithPin(identity: unknown, pin: string): Promise<SealedKeystore> {
  const salt = randomBytes(16);
  return seal(identity, "pin", await deriveWrapKeyFromPin(pin, salt), salt);
}

export async function openWithPin<T = unknown>(sealed: SealedKeystore, pin: string): Promise<T> {
  if (sealed.method !== "pin" || !sealed.salt) throw new CryptoError("key store is not PIN-protected");
  return open<T>(sealed, await deriveWrapKeyFromPin(pin, fromB64(sealed.salt)));
}

export { concat };
