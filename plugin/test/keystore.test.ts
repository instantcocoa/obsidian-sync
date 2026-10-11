import { describe, expect, it } from "vitest";
import { sealWithPin, openWithPin, seal, open, newWrapKey } from "../src/core/keystore";

describe("keystore", () => {
  const identity = { server: "https://x", vaultId: "v", deviceToken: "dv_secret", keyring: { k_id: "00".repeat(32) } };

  it("PIN seal/open round-trips and rejects a wrong PIN", async () => {
    const sealed = await sealWithPin(identity, "1234-5678");
    expect(JSON.stringify(sealed)).not.toContain("dv_secret");
    expect(JSON.stringify(sealed)).not.toContain("00".repeat(32));
    expect(await openWithPin(sealed, "1234-5678")).toEqual(identity);
    await expect(openWithPin(sealed, "1234-5679")).rejects.toThrow(/wrong PIN/);
    // Different salts per seal.
    const again = await sealWithPin(identity, "1234-5678");
    expect(again.salt).not.toBe(sealed.salt);
  }, 20_000);

  it("safe-method seal/open with a random wrapping key", async () => {
    const k = newWrapKey();
    const sealed = await seal(identity, "safe", k);
    expect(sealed.method).toBe("safe");
    expect(await open(sealed, k)).toEqual(identity);
    await expect(open(sealed, newWrapKey())).rejects.toThrow();
    // Tampering is detected.
    const bad = { ...sealed, ct: sealed.ct.slice(0, -4) + "AAAA" };
    await expect(open(bad, k)).rejects.toThrow();
  });
});
