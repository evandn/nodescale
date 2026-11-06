import { b64, concat, equalBytes, fromUtf8, hex, randomB64, sha256, unb64, utf8 } from "./encoding.ts";
import type { Op, Scope } from "./ops.ts";
import {
  ALG,
  DOMAIN,
  TYP,
  type Alg,
  type Assertion,
  type Certificate,
  type Domain,
  type RequestPayload,
  type ResponsePayload,
  type SessionCertPayload,
  type SignedRequest,
  type SignedResponse,
} from "./types.ts";

export function message(domain: Domain, payload: Uint8Array): Uint8Array<ArrayBuffer> {
  return concat(utf8(domain), new Uint8Array([0]), payload);
}

/** The WebAuthn challenge a passkey signs to authorise `payload` directly. */
export function challenge(domain: Domain, payload: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return sha256(message(domain, payload));
}

export async function requestHash(payload: Uint8Array): Promise<string> {
  return b64(await sha256(payload));
}

/** Self-certifying agent ID: "ag_" + hex(sha256(ed25519 public key)[:16]). */
export async function agentIdFromKey(publicKey: Uint8Array): Promise<string> {
  return "ag_" + hex((await sha256(publicKey)).subarray(0, 16));
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Serialises a request payload. The returned bytes are exactly what gets signed. */
export function encodeRequest<A>(aud: string, op: Op, args?: A, ttlSeconds = 60, now = nowSeconds()): Uint8Array<ArrayBuffer> {
  const p: RequestPayload<A> = { v: 1, typ: TYP.request, aud, op, iat: now, exp: now + ttlSeconds, nonce: randomB64(18) };
  if (args !== undefined) p.args = args;
  return utf8(JSON.stringify(p));
}

export function encodeSessionCert(opts: { key: string; aud?: string[]; scope: Scope; ttlSeconds: number; nonce?: string; now?: number }): Uint8Array<ArrayBuffer> {
  const now = opts.now ?? nowSeconds();
  const c: SessionCertPayload = {
    v: 1,
    typ: TYP.session,
    key: opts.key,
    aud: opts.aud ?? ["*"],
    scope: opts.scope,
    iat: now,
    exp: now + opts.ttlSeconds,
    nonce: opts.nonce ?? randomB64(18),
  };
  return utf8(JSON.stringify(c));
}

export function decodePayload<T>(payloadB64: string): T {
  return JSON.parse(fromUtf8(unb64(payloadB64))) as T;
}

/** Signs a request with a delegated, non-extractable P-256 session key. */
export async function signWithSession(key: CryptoKey, certificate: Certificate, payload: Uint8Array): Promise<SignedRequest> {
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, message(DOMAIN.sessionRequest, payload));
  return { payload: b64(payload), auth: { kind: "session", certificate, signature: b64(sig) } };
}

export class ResponseVerificationError extends Error {}

/**
 * Verifies an agent response: the Ed25519 signature, that the key matches the
 * pinned agent ID, and that the response answers the request we sent.
 */
export async function verifyResponse<R>(
  resp: SignedResponse,
  expect: { agentId: string | null; requestPayload: Uint8Array },
): Promise<ResponsePayload<R> & { agentPublicKey: string }> {
  const pub = unb64(resp.publicKey);
  const payload = unb64(resp.payload);
  const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, unb64(resp.signature), message(DOMAIN.response, payload));
  if (!ok) throw new ResponseVerificationError("agent response signature is invalid");
  const id = await agentIdFromKey(pub);
  // null means "public call, identity not yet known"; anything else must match.
  if (expect.agentId !== null && id !== expect.agentId) {
    throw new ResponseVerificationError(`agent identity changed: expected ${expect.agentId}, got ${id}`);
  }
  const r = JSON.parse(fromUtf8(payload)) as ResponsePayload<R>;
  if (r.typ !== TYP.response || r.agent !== id) throw new ResponseVerificationError("malformed agent response");
  if (r.req !== (await requestHash(expect.requestPayload))) {
    throw new ResponseVerificationError("agent response does not match the request");
  }
  return { ...r, agentPublicKey: resp.publicKey };
}

// ---------------------------------------------------------------------------
// WebAuthn assertion verification (used by the control plane for sign-in; the
// agent has an equivalent Go implementation).

export interface RelyingParty {
  id: string;
  origins: string[];
}

export class AssertionError extends Error {}

async function importPasskey(alg: Alg, spki: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  switch (alg) {
    case ALG.ES256:
      return crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    case ALG.EdDSA:
      return crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
    case ALG.RS256:
      return crypto.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    default:
      throw new AssertionError(`unsupported algorithm ${alg as number}`);
  }
}

/** Converts an ASN.1 DER ECDSA signature to IEEE P1363 (r||s) for WebCrypto. */
export function derToRaw(der: Uint8Array, size = 32): Uint8Array<ArrayBuffer> {
  let i = 0;
  const fail = () => new AssertionError("malformed ECDSA signature");
  if (der[i++] !== 0x30) throw fail();
  let len = der[i++]!;
  if (len & 0x80) i += len & 0x7f;
  const out = new Uint8Array(size * 2);
  for (let k = 0; k < 2; k++) {
    if (der[i++] !== 0x02) throw fail();
    len = der[i++]!;
    let int = der.subarray(i, i + len);
    i += len;
    while (int.length > size && int[0] === 0) int = int.subarray(1);
    if (int.length > size) throw fail();
    out.set(int, k * size + (size - int.length));
  }
  return out;
}

export interface VerifiedAssertion {
  flags: number;
  signCount: number;
  clientData: { type: string; challenge: string; origin: string; crossOrigin?: boolean };
}

export async function verifyAssertion(opts: {
  rp: RelyingParty;
  alg: Alg;
  publicKey: string;
  assertion: Assertion;
  challenge: Uint8Array;
  requireUserVerification: boolean;
}): Promise<VerifiedAssertion> {
  const cdj = unb64(opts.assertion.clientDataJSON);
  const authData = unb64(opts.assertion.authenticatorData);
  let sig = unb64(opts.assertion.signature);
  const cd = JSON.parse(fromUtf8(cdj)) as VerifiedAssertion["clientData"];
  if (cd.type !== "webauthn.get") throw new AssertionError("unexpected clientData type");
  if (!equalBytes(unb64(cd.challenge), opts.challenge)) throw new AssertionError("challenge mismatch");
  if (!opts.rp.origins.includes(cd.origin)) throw new AssertionError(`untrusted origin ${cd.origin}`);
  if (cd.crossOrigin) throw new AssertionError("cross-origin assertion");
  if (authData.length < 37) throw new AssertionError("authenticatorData too short");
  if (!equalBytes(authData.subarray(0, 32), await sha256(utf8(opts.rp.id)))) throw new AssertionError("rpId mismatch");
  const flags = authData[32]!;
  if (!(flags & 0x01)) throw new AssertionError("user presence required");
  if (opts.requireUserVerification && !(flags & 0x04)) throw new AssertionError("user verification required");
  const key = await importPasskey(opts.alg, unb64(opts.publicKey));
  const signed = concat(authData, await sha256(cdj));
  let algo: Parameters<typeof crypto.subtle.verify>[0] = { name: "Ed25519" };
  if (opts.alg === ALG.ES256) {
    sig = derToRaw(sig);
    algo = { name: "ECDSA", hash: "SHA-256" };
  } else if (opts.alg === ALG.RS256) {
    algo = { name: "RSASSA-PKCS1-v1_5" };
  }
  if (!(await crypto.subtle.verify(algo, key, sig, signed))) throw new AssertionError("invalid signature");
  const signCount = new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0);
  return { flags, signCount, clientData: cd };
}

/** Key fingerprint shown to humans when comparing passkeys out of band. */
export async function fingerprint(spkiB64: string): Promise<string> {
  const h = hex((await sha256(unb64(spkiB64))).subarray(0, 10)).toUpperCase();
  return h.match(/.{4}/g)!.join("-");
}
