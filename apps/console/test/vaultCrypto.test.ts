import { describe, expect, it } from "vitest";
import {
  decryptData,
  deriveKek,
  encryptData,
  formatRecoveryKey,
  generateRecoveryKey,
  importDek,
  parseRecoveryKey,
  unwrapDek,
  wrapDek,
  type VaultData,
  type VaultEnvelope,
} from "../src/client/lib/vaultCrypto.ts";

const data: VaultData = { v: 1, rev: 3, pins: {}, signers: [], cloudflare: { apiToken: "secret-token", accountId: "abc" } };

describe("vault crypto", () => {
  it("round-trips recovery keys, tolerating formatting", () => {
    const { bytes, text } = generateRecoveryKey();
    expect(text).toMatch(/^NSRK-[0-9A-Z]{4}(-[0-9A-Z]{1,4})+$/);
    expect(parseRecoveryKey(text)).toEqual(bytes);
    expect(parseRecoveryKey(text.toLowerCase().replace(/-/g, " "))).toEqual(bytes);
    expect(() => parseRecoveryKey("NSRK-ABCD")).toThrow(/length/);
    expect(formatRecoveryKey(new Uint8Array(32))).toBe("NSRK-" + "0000-".repeat(12) + "0000");
  });

  it("opens the vault with any wrapped key and nothing else", async () => {
    const dekRaw = crypto.getRandomValues(new Uint8Array(32));
    const prf = crypto.getRandomValues(new Uint8Array(32));
    const recovery = generateRecoveryKey();
    const prfKek = await deriveKek(prf, "prf");
    const recKek = await deriveKek(recovery.bytes, "recovery");
    const keys = [
      await wrapDek(prfKek, dekRaw, "usr_1", { kind: "prf", credentialId: "cred1" }),
      await wrapDek(recKek, dekRaw, "usr_1", { kind: "recovery" }),
    ];
    const env: VaultEnvelope = { v: 1, keys, data: await encryptData(await importDek(dekRaw), data, "usr_1") };
    expect(JSON.stringify(env)).not.toContain("secret-token");

    for (const [kek, w] of [[prfKek, keys[0]!], [recKek, keys[1]!]] as const) {
      const dek = await importDek(await unwrapDek(kek, w, "usr_1"));
      expect(await decryptData(dek, env, "usr_1")).toEqual(data);
    }
    // Wrong key, swapped wrapper, or another user's binding all fail.
    await expect(unwrapDek(await deriveKek(crypto.getRandomValues(new Uint8Array(32)), "prf"), keys[0]!, "usr_1")).rejects.toThrow();
    await expect(unwrapDek(prfKek, keys[1]!, "usr_1")).rejects.toThrow();
    await expect(unwrapDek(prfKek, keys[0]!, "usr_2")).rejects.toThrow();
    await expect(decryptData(await importDek(dekRaw), env, "usr_2")).rejects.toThrow();
  });
});

describe("pin lookup", () => {
  it("ignores prototype keys and malformed pins", async () => {
    const { getPin } = await import("../src/client/lib/vaultCrypto.ts");
    const good = { agentId: "ag_" + "a".repeat(32), publicKey: "pk", sealKey: "sk", pinnedAt: 1 };
    const data: VaultData = { v: 1, rev: 1, signers: [], pins: { srv_1: good, srv_bad: { ...good, agentId: "nope" } } };
    expect(getPin(data, "srv_1")).toEqual(good);
    for (const id of ["constructor", "toString", "__proto__", "hasOwnProperty", "srv_bad", "srv_missing"]) expect(getPin(data, id)).toBeUndefined();
  });
});
