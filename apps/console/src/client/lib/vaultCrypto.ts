import { b64, unb64, utf8, fromUtf8, type SignerKey } from "@nodescale/protocol";

/**
 * Client-side vault encryption.
 *
 *   DEK (random AES-256)  --encrypts-->  vault data (provider tokens, pins…)
 *   KEK_i = HKDF(PRF output of passkey i)            --wraps--> DEK
 *   KEK_r = HKDF(recovery key, printed once)         --wraps--> DEK
 *
 * The server stores only the envelope below. Without a user's authenticator
 * (or the offline recovery key) it cannot recover the DEK.
 */

export interface TailscaleCreds {
  kind: "oauth" | "apikey";
  /** OAuth client ID (kind=oauth). */
  clientId?: string;
  /** OAuth client secret or API access token. */
  secret: string;
  tailnet: string;
}

export interface CloudflareCreds {
  apiToken: string;
  accountId: string;
}

export interface Pin {
  agentId: string;
  publicKey: string;
  /** X25519 key that environment values are sealed to. */
  sealKey: string;
  pinnedAt: number;
}

export interface VaultData {
  v: 1;
  /** Monotonic revision; a decrease means the server served an old copy. */
  rev: number;
  tailscale?: TailscaleCreds;
  cloudflare?: CloudflareCreds;
  /** Trusted agent identities, keyed by server ID (trust on first use). */
  pins: Record<string, Pin>;
  /** Trusted copy of my own passkey public keys, used for server bootstrap. */
  signers: SignerKey[];
  /** Values for ${NAME} placeholders in stack definitions. */
  secrets?: Record<string, string>;
}

export type WrappedKey =
  | { kind: "prf"; credentialId: string; iv: string; wrapped: string }
  | { kind: "recovery"; iv: string; wrapped: string };

export interface VaultEnvelope {
  v: 1;
  keys: WrappedKey[];
  data: { iv: string; ct: string };
}

const HKDF_SALT = utf8("nodescale/v1/vault");

function aad(userId: string, purpose: string) {
  return utf8(`nodescale/v1/vault/${purpose}/${userId}`);
}

export async function deriveKek(secret: Uint8Array<ArrayBuffer>, info: "prf" | "recovery"): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: utf8(`kek/${info}`) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function seal(key: CryptoKey, plaintext: Uint8Array<ArrayBuffer>, additional: Uint8Array<ArrayBuffer>) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: additional }, key, plaintext);
  return { iv: b64(iv), ct: b64(ct) };
}

async function open(key: CryptoKey, iv: string, ct: string, additional: Uint8Array<ArrayBuffer>) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv), additionalData: additional }, key, unb64(ct)));
}

export async function wrapDek(kek: CryptoKey, dekRaw: Uint8Array<ArrayBuffer>, userId: string, k: { kind: "prf"; credentialId: string } | { kind: "recovery" }): Promise<WrappedKey> {
  const purpose = k.kind === "prf" ? `prf/${k.credentialId}` : "recovery";
  const { iv, ct } = await seal(kek, dekRaw, aad(userId, purpose));
  return k.kind === "prf" ? { kind: "prf", credentialId: k.credentialId, iv, wrapped: ct } : { kind: "recovery", iv, wrapped: ct };
}

export async function unwrapDek(kek: CryptoKey, w: WrappedKey, userId: string): Promise<Uint8Array<ArrayBuffer>> {
  const purpose = w.kind === "prf" ? `prf/${w.credentialId}` : "recovery";
  return open(kek, w.iv, w.wrapped, aad(userId, purpose));
}

export function importDek(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptData(dek: CryptoKey, data: VaultData, userId: string) {
  return seal(dek, utf8(JSON.stringify(data)), aad(userId, "data"));
}

export async function decryptData(dek: CryptoKey, env: VaultEnvelope, userId: string): Promise<VaultData> {
  return JSON.parse(fromUtf8(await open(dek, env.data.iv, env.data.ct, aad(userId, "data")))) as VaultData;
}

// Recovery keys: 32 random bytes rendered as Crockford base32 in groups of 4.

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function formatRecoveryKey(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return "NSRK-" + out.match(/.{1,4}/g)!.join("-");
}

export function parseRecoveryKey(s: string): Uint8Array<ArrayBuffer> {
  const clean = s
    .toUpperCase()
    .replace(/^NSRK/, "")
    .replace(/[\s-]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error("Recovery key contains invalid characters");
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (out.length !== 32) throw new Error("Recovery key has the wrong length");
  return new Uint8Array(out);
}

export function generateRecoveryKey(): { bytes: Uint8Array<ArrayBuffer>; text: string } {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return { bytes, text: formatRecoveryKey(bytes) };
}
