import {
  DOMAIN,
  b64,
  challenge,
  encodeRequest,
  levelOf,
  openSealed,
  replyKeyPair,
  sealEnv,
  sessionCanSign,
  signWithSession,
  verifyResponse,
  type Op,
  type SignedRequest,
} from "@nodescale/protocol";
import type { Pin } from "./vaultCrypto.ts";
import { api, ApiError, type Server } from "./api.ts";
import { app, renewSession as renew, requireVault, sessionValid } from "./app.ts";
import { RELAY_TAG, tailscale } from "./providers.ts";
import { getAssertion } from "./webauthn.ts";

export class AgentError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export class NotPinnedError extends Error {
  constructor() {
    super("This server's identity has not been verified yet.");
  }
}

// ---------------------------------------------------------------------------
// Relay

let relayPromise: Promise<void> | null = null;

/** Makes sure the workspace relay is on the tailnet, minting a one-time key if needed. */
export function ensureRelay(): Promise<void> {
  relayPromise ??= (async () => {
    const s = await api.get<{ state: string; error?: string }>("/relay");
    if (s.state === "up") return;
    const authKey = await tailscale.createAuthKey({ tags: [RELAY_TAG], ephemeral: true, reusable: false, expirySeconds: 300, description: "nodescale relay" });
    const r = await api.post<{ state: string; error?: string }>("/relay/up", { authKey });
    if (r.state !== "up") throw new Error(`Relay could not join the tailnet: ${r.error ?? r.state}`);
  })().finally(() => {
    relayPromise = null;
  });
  return relayPromise;
}

async function rpc(server: Server, request: SignedRequest): Promise<unknown> {
  try {
    return await api.post(`/servers/${server.id}/rpc`, { request });
  } catch (e) {
    if (e instanceof ApiError && (e.status === 502 || e.status === 503) && /not connected|unavailable|tailnet/i.test(e.message)) {
      await ensureRelay();
      return api.post(`/servers/${server.id}/rpc`, { request });
    }
    throw e;
  }
}

// One passkey prompt for any number of concurrent calls that need a session.
let renewing: Promise<void> | null = null;
function renewSession(): Promise<void> {
  renewing ??= renew().finally(() => {
    renewing = null;
  });
  return renewing;
}

// ---------------------------------------------------------------------------
// Calls

export interface CallOptions {
  /** Require a fresh passkey touch even if the session key could sign. */
  passkey?: boolean;
  /** Request lifetime; long-running operations such as image pulls need more. */
  ttl?: number;
}

/**
 * Signs `op` and sends it to the server's agent, then verifies the agent's
 * signed response against the identity pinned in the encrypted vault.
 */
export async function callAgent<R>(server: Server, op: Op, args?: unknown, opts: CallOptions = {}): Promise<R> {
  const level = levelOf(op);
  const pin = requireVault().pins[server.id];
  if (level !== "public" && !pin) throw new NotPinnedError();
  const aud = level === "public" ? "*" : pin!.agentId;
  if (pin) args = await sealArgs(op, args, pin);
  const payload = encodeRequest(aud, op, args, opts.ttl ?? 60);

  let request: SignedRequest;
  if (level === "public") {
    request = { payload: b64(payload) };
  } else {
    let s = app.get().session;
    if (!opts.passkey && level !== "admin" && (!sessionValid(s) || !sessionCanSign(s.scope, op))) {
      // Session expired: one touch renews it for every subsequent call.
      await renewSession();
      s = app.get().session;
    }
    if (!opts.passkey && sessionValid(s) && sessionCanSign(s.scope, op)) {
      request = await signWithSession(s.key, s.certificate, payload);
    } else {
      const me = app.get().me!;
      const mine = requireVault().signers.map((k) => k.id);
      const got = await getAssertion({ challenge: await challenge(DOMAIN.request, payload), rpId: me.rp.id, allow: mine });
      request = { payload: b64(payload), auth: { kind: "webauthn", assertion: got.assertion } };
    }
  }

  const raw = (await rpc(server, request)) as { payload: string; signature: string; publicKey: string };
  const resp = await verifyResponse<R>(raw, { agentId: level === "public" ? null : pin!.agentId, requestPayload: payload });
  if (!resp.ok) throw new AgentError(resp.error?.code ?? "error", resp.error?.message ?? "request failed");
  return resp.result as R;
}

/**
 * Encrypts every environment value to the server before signing, so the
 * console and relay only ever carry ciphertext.
 */
async function sealArgs(op: Op, args: unknown, pin: Pin): Promise<unknown> {
  const seal = (env?: string[]) => (env?.length ? sealEnv(pin.sealKey, pin.agentId, env) : Promise.resolve(env));
  if (op === "containers.create" || op === "containers.exec") {
    const a = args as { env?: string[] };
    return { ...a, env: await seal(a.env) };
  }
  if (op === "stacks.deploy") {
    const a = args as { services: { env?: string[] }[] };
    return { ...a, services: await Promise.all(a.services.map(async (s) => ({ ...s, env: await seal(s.env) }))) };
  }
  return args;
}

/** Reveals a container's environment; the gate encrypts it to a key only this tab holds. */
export async function revealEnv(server: Server, id: string): Promise<string[]> {
  const pin = requireVault().pins[server.id];
  if (!pin) throw new NotPinnedError();
  const reply = await replyKeyPair();
  const r = await callAgent<{ sealed: string }>(server, "containers.env", { id, replyKey: reply.publicKey });
  return JSON.parse(await openSealed(reply.privateKey, reply.publicKey, pin.agentId, r.sealed, "containers.env")) as string[];
}

export interface Hello {
  agent: string;
  publicKey: string;
  sealKey: string;
  version: string;
  hostname: string;
  rpId: string;
  origins: string[];
}

/** Unauthenticated identity probe used before pinning a server. */
export function hello(server: Server) {
  return callAgent<Hello>(server, "agent.hello");
}
