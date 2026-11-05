import {
  DOMAIN,
  b64,
  challenge,
  decodePayload,
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
    const s = await api.get<{ state: string; error?: string; ips?: string[] | null }>("/relay");
    if (s.state === "up") {
      await verifyRelay(s.ips ?? []);
      return;
    }
    const authKey = await tailscale.createAuthKey({ tags: [RELAY_TAG], ephemeral: true, reusable: false, expirySeconds: 300, description: "nodescale relay" });
    const r = await api.post<{ state: string; error?: string; ips?: string[] | null }>("/relay/up", { authKey });
    if (r.state !== "up") throw new Error(`Relay could not join the tailnet: ${r.error ?? r.state}`);
    await verifyRelay(r.ips ?? []);
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

let verifiedRelayIp: string | null = null;

/**
 * Checks that the relay is a node of *your* tailnet, tagged as the nodescale
 * relay. Any workspace member can bring the relay up; this stops one from
 * attaching it to a tailnet they control. Skipped without Tailscale credentials.
 */
async function verifyRelay(ips: string[]) {
  const ip = ips.find((a) => a.startsWith("100."));
  if (!ip || ip === verifiedRelayIp) return;
  const v = app.get().vault;
  if (v.status !== "unlocked" || !v.data.tailscale) return;
  const devices = await tailscale.listDevices();
  const dev = devices.find((d) => d.addresses.includes(ip));
  if (!dev || !(dev.tags ?? []).includes(RELAY_TAG)) {
    throw new Error(`The relay (${ip}) is not a nodescale relay in your tailnet. Ask an admin to check the workspace relay.`);
  }
  verifiedRelayIp = ip;
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

  const raw = (await rpc(server, request)) as { payload: string; signature?: string; publicKey?: string };
  if (!raw.signature || !raw.publicKey) {
    // The gate does not sign rejections that happen before authentication,
    // so this message may come from the relay rather than the server.
    let e: { code?: string; message?: string } = {};
    try {
      e = decodePayload<{ error?: typeof e }>(raw.payload).error ?? {};
    } catch {
      /* malformed */
    }
    throw new AgentError(e.code ?? "unverified", `Request rejected (unverified response): ${e.message ?? "no details"}`);
  }
  const resp = await verifyResponse<R>(raw as { payload: string; signature: string; publicKey: string }, { agentId: level === "public" ? null : pin!.agentId, requestPayload: payload });
  if (!resp.ok) throw new AgentError(resp.error?.code ?? "error", resp.error?.message ?? "request failed");
  if (op === "agent.hello") {
    // Before pinning, the identity in the result must be the key that signed
    // it; otherwise anyone could vouch for a server's (or a seal) key.
    const h = resp.result as { agent?: string; publicKey?: string; sealKey?: string };
    if (h.agent !== resp.agent || h.publicKey !== resp.agentPublicKey || !h.sealKey) {
      throw new AgentError("identity", "The server's identity does not match the key that signed it");
    }
  }
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
