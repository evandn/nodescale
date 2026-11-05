import {
  DOMAIN,
  b64,
  challenge,
  encodeRequest,
  levelOf,
  sessionCanSign,
  signWithSession,
  verifyResponse,
  type Op,
  type SignedRequest,
} from "@nodescale/protocol";
import { api, ApiError, type Server } from "./api.ts";
import { app, renewSession, requireVault, sessionValid } from "./app.ts";
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

export interface Hello {
  agent: string;
  publicKey: string;
  version: string;
  hostname: string;
  rpId: string;
  origins: string[];
}

/** Unauthenticated identity probe used before pinning a server. */
export function hello(server: Server) {
  return callAgent<Hello>(server, "agent.hello");
}
