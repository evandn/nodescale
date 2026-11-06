import type { Op, Role, Scope } from "./ops.ts";

export const VERSION = 1;

export const TYP = {
  request: "nodescale.request",
  session: "nodescale.session",
  response: "nodescale.response",
} as const;

/** Signatures are always over `domain || 0x00 || payload`. */
export const DOMAIN = {
  request: "nodescale/v1/request",
  session: "nodescale/v1/session",
  sessionRequest: "nodescale/v1/session-request",
  response: "nodescale/v1/response",
  /** Proves a newly registered passkey's private key is held by the registrant. */
  possession: "nodescale/v1/possession",
} as const;

export type Domain = (typeof DOMAIN)[keyof typeof DOMAIN];

/** COSE algorithm identifiers accepted for passkeys. */
export const ALG = { ES256: -7, EdDSA: -8, RS256: -257 } as const;
export type Alg = (typeof ALG)[keyof typeof ALG];

export interface Assertion {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
}

export interface Certificate {
  payload: string;
  assertion: Assertion;
}

export type Auth =
  | { kind: "webauthn"; assertion: Assertion }
  | { kind: "session"; certificate: Certificate; signature: string };

export interface SignedRequest {
  payload: string;
  auth?: Auth;
}

export interface RequestPayload<A = unknown> {
  v: 1;
  typ: typeof TYP.request;
  aud: string;
  op: Op;
  args?: A;
  iat: number;
  exp: number;
  nonce: string;
}

export interface SessionCertPayload {
  v: 1;
  typ: typeof TYP.session;
  key: string;
  aud: string[];
  scope: Scope;
  iat: number;
  exp: number;
  nonce: string;
}

export interface ProtocolError {
  code: string;
  message: string;
}

export interface ResponsePayload<R = unknown> {
  v: 1;
  typ: typeof TYP.response;
  agent: string;
  req: string;
  ok: boolean;
  result?: R;
  error?: ProtocolError;
  ts: number;
}

export interface SignedResponse {
  payload: string;
  signature: string;
  publicKey: string;
}

/** A passkey as enrolled on an agent. */
export interface SignerKey {
  id: string;
  alg: Alg;
  publicKey: string;
  role: Role;
  label?: string;
  user?: string;
  addedAt?: number;
  addedBy?: string;
}
