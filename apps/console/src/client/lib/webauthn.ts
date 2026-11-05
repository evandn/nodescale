import { b64, sha256, unb64, utf8, type Assertion } from "@nodescale/protocol";

/**
 * Input to the WebAuthn PRF extension. The authenticator mixes it with a
 * secret that never leaves the device; the output is the root of the vault
 * key. Using a fixed, app-specific salt lets one ceremony both sign in and
 * unlock the vault.
 */
let prfSalt: Promise<Uint8Array<ArrayBuffer>> | null = null;
function getPrfSalt() {
  prfSalt ??= sha256(utf8("nodescale/v1/vault-prf"));
  return prfSalt;
}

interface PrfResults {
  prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
}

export function webauthnSupported(): boolean {
  return typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

export class PasskeyCancelled extends Error {
  constructor() {
    super("Passkey prompt was cancelled");
  }
}

function wrapErr(e: unknown): never {
  if (e instanceof DOMException && (e.name === "NotAllowedError" || e.name === "AbortError")) throw new PasskeyCancelled();
  throw e;
}

export interface CreatedPasskey {
  id: string;
  publicKey: string;
  alg: number;
  transports: string[];
  clientDataJSON: string;
  authenticatorData: string;
  prf: boolean;
  prfOutput?: Uint8Array;
}

export async function createPasskey(opts: {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string };
  exclude?: string[];
}): Promise<CreatedPasskey> {
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.create({
      publicKey: {
        // The server issued base64url bytes; clientDataJSON echoes them back
        // re-encoded, which must equal the issued string.
        challenge: unb64(opts.challenge),
        rp: opts.rp,
        user: { id: utf8(opts.user.id), name: opts.user.name, displayName: opts.user.name },
        pubKeyCredParams: [
          { type: "public-key", alg: -8 },
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
        attestation: "none",
        excludeCredentials: (opts.exclude ?? []).map((id) => ({ type: "public-key" as const, id: unb64(id) })),
        timeout: 120_000,
        extensions: { prf: { eval: { first: await getPrfSalt() } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch (e) {
    wrapErr(e);
  }
  const r = cred.response as AuthenticatorAttestationResponse;
  const pk = r.getPublicKey();
  if (!pk) throw new Error("This authenticator uses an unsupported key type.");
  const ext = cred.getClientExtensionResults() as PrfResults;
  const first = ext.prf?.results?.first;
  return {
    id: b64(cred.rawId),
    publicKey: b64(pk),
    alg: r.getPublicKeyAlgorithm(),
    transports: r.getTransports?.() ?? [],
    clientDataJSON: b64(r.clientDataJSON),
    authenticatorData: b64(r.getAuthenticatorData()),
    prf: !!ext.prf?.enabled || !!first,
    prfOutput: first ? new Uint8Array(first) : undefined,
  };
}

export interface GotAssertion {
  assertion: Assertion;
  prfOutput?: Uint8Array;
}

/** Asks a passkey to sign `challenge` (and optionally evaluate the PRF). */
export async function getAssertion(opts: { challenge: Uint8Array<ArrayBuffer>; rpId: string; allow?: string[]; prf?: boolean }): Promise<GotAssertion> {
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.get({
      publicKey: {
        challenge: opts.challenge,
        rpId: opts.rpId,
        userVerification: "required",
        timeout: 120_000,
        allowCredentials: (opts.allow ?? []).map((id) => ({ type: "public-key" as const, id: unb64(id) })),
        extensions: opts.prf ? ({ prf: { eval: { first: await getPrfSalt() } } } as AuthenticationExtensionsClientInputs) : undefined,
      },
    })) as PublicKeyCredential;
  } catch (e) {
    wrapErr(e);
  }
  const r = cred.response as AuthenticatorAssertionResponse;
  const first = (cred.getClientExtensionResults() as PrfResults).prf?.results?.first;
  return {
    assertion: {
      credentialId: b64(cred.rawId),
      authenticatorData: b64(r.authenticatorData),
      clientDataJSON: b64(r.clientDataJSON),
      signature: b64(r.signature),
    },
    prfOutput: first ? new Uint8Array(first) : undefined,
  };
}
