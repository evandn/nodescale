import { b64, concat, unb64, utf8 } from "./encoding.ts";

/**
 * End-to-end encrypted values between a browser and one server's gate.
 * Mirrors gate/internal/gate/seal.go:
 *
 *   nsseal1.<b64 eph X25519 pub>.<b64 iv>.<b64 AES-256-GCM ciphertext>
 *   key  = HKDF-SHA256(X25519(eph, recipient), salt = eph_pub || recipient_pub,
 *                      info = "nodescale/v1/seal" || 0x00 || agentId)
 *   AAD  = label (the environment variable name, or "containers.env")
 */
export const SEAL_PREFIX = "nsseal1.";

async function aeadKey(shared: ArrayBuffer, ephPub: Uint8Array, recipientPub: Uint8Array, agentId: string, usage: KeyUsage) {
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: concat(ephPub, recipientPub), info: utf8(`nodescale/v1/seal\u0000${agentId}`) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

/** Encrypts `plaintext` so only the server with `sealKey` can read it. */
export async function seal(sealKey: string, agentId: string, plaintext: string, label: string): Promise<string> {
  const recipientRaw = unb64(sealKey);
  const recipient = await crypto.subtle.importKey("raw", recipientRaw, { name: "X25519" }, false, []);
  const eph = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const ephPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: recipient }, eph.privateKey, 256);
  const key = await aeadKey(shared, ephPub, recipientRaw, agentId, "encrypt");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(label) }, key, utf8(plaintext));
  return `${SEAL_PREFIX}${b64(ephPub)}.${b64(iv)}.${b64(ct)}`;
}

export function isSealed(v: string): boolean {
  return v.startsWith(SEAL_PREFIX);
}

/** An ephemeral key pair for receiving one sealed reply. */
export async function replyKeyPair(): Promise<{ privateKey: CryptoKey; publicKey: string }> {
  const kp = (await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
  return { privateKey: kp.privateKey, publicKey: b64(await crypto.subtle.exportKey("raw", kp.publicKey)) };
}

/** Opens a value the gate sealed to our reply key. */
export async function openSealed(privateKey: CryptoKey, publicKey: string, agentId: string, sealed: string, label: string): Promise<string> {
  const parts = sealed.slice(SEAL_PREFIX.length).split(".");
  if (!sealed.startsWith(SEAL_PREFIX) || parts.length !== 3) throw new Error("malformed sealed value");
  const ephPub = unb64(parts[0]!);
  const peer = await crypto.subtle.importKey("raw", ephPub, { name: "X25519" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: peer }, privateKey, 256);
  const key = await aeadKey(shared, ephPub, unb64(publicKey), agentId, "decrypt");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(parts[1]!), additionalData: utf8(label) }, key, unb64(parts[2]!));
  return new TextDecoder().decode(pt);
}

/** Seals every value of KEY=value entries (already-sealed values are kept). */
export async function sealEnv(sealKey: string, agentId: string, env: string[]): Promise<string[]> {
  return Promise.all(
    env.map(async (e) => {
      const i = e.indexOf("=");
      if (i <= 0) return e;
      const k = e.slice(0, i);
      const v = e.slice(i + 1);
      return isSealed(v) || v === "" ? e : `${k}=${await seal(sealKey, agentId, v, k)}`;
    }),
  );
}
