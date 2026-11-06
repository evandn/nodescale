// Security regression tests for the Worker API, run against the real Hono
// app with an in-memory D1. The relay is stubbed.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { b64, concat, sha256, utf8 } from "../../../packages/protocol/src/encoding.ts";
import { challenge } from "../../../packages/protocol/src/crypto.ts";
import { makeD1 } from "./helpers/d1.ts";

vi.mock("../src/worker/relay.ts", () => ({
  Relay: class {},
  relayFetch: async (_e: unknown, _ws: string, path: string) => Response.json({ relayed: path }),
}));

const ORIGIN = "https://ns.example.com";
const RP = "ns.example.com";
const ctx = { waitUntil: (p: Promise<unknown>) => p, passThroughOnException() {} } as unknown as ExecutionContext;
let worker: { fetch: (r: Request, e: unknown, c: unknown) => Promise<Response> };
let D1: ReturnType<typeof makeD1>;
let env: Record<string, unknown>;
const now = () => Math.floor(Date.now() / 1000);
const H = async (s: string) => b64(await sha256(utf8(s)));

async function seedUser(id: string, ws: string, role: string, token: string) {
  const t = now();
  D1.raw.prepare("INSERT OR IGNORE INTO workspaces (id,name,created_at) VALUES (?,?,?)").run(ws, ws, t);
  D1.raw.prepare("INSERT INTO users (id,name,created_at) VALUES (?,?,?)").run(id, id, t);
  D1.raw.prepare("INSERT INTO memberships (workspace_id,user_id,role,created_at) VALUES (?,?,?,?)").run(ws, id, role, t);
  D1.raw.prepare("INSERT INTO sessions (id,user_id,credential_id,created_at,expires_at) VALUES (?,?,?,?,?)").run(await H(token), id, null, t, t + 3600);
}

function call(method: string, path: string, token?: string, body?: unknown, headers: Record<string, string> = {}) {
  const h: Record<string, string> = { ...headers };
  if (token) h.cookie = `__Host-nodescale=${token}`;
  if (method !== "GET" && !("origin" in headers)) {
    h.origin = ORIGIN;
    h["x-nodescale"] = "1";
  }
  return worker.fetch(new Request(ORIGIN + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }), env, ctx);
}

function rawToDer(raw: Uint8Array) {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.subarray(i);
    if (v[0]! & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([2, v.length]), v);
  };
  const body = concat(int(raw.subarray(0, 32)), int(raw.subarray(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

/** A software authenticator for one P-256 credential. */
async function authenticator() {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
  const idBytes = crypto.getRandomValues(new Uint8Array(16));
  const rpHash = await sha256(utf8(RP));
  return {
    id: b64(idBytes),
    spki: b64(new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer)),
    attestation(serverChallenge: string) {
      const authData = concat(rpHash, new Uint8Array([0x45, 0, 0, 0, 0]), new Uint8Array(16), new Uint8Array([0, idBytes.length]), idBytes);
      const cdj = utf8(JSON.stringify({ type: "webauthn.create", challenge: serverChallenge, origin: ORIGIN }));
      return { id: b64(idBytes), alg: -7, clientDataJSON: b64(cdj), authenticatorData: b64(authData) };
    },
    async assert(chal: Uint8Array) {
      const ad = concat(rpHash, new Uint8Array([0x05, 0, 0, 0, 1]));
      const cdj = utf8(JSON.stringify({ type: "webauthn.get", challenge: b64(chal), origin: ORIGIN }));
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, concat(ad, await sha256(cdj))));
      return { credentialId: b64(idBytes), authenticatorData: b64(ad), clientDataJSON: b64(cdj), signature: b64(rawToDer(sig)) };
    },
  };
}

beforeEach(async () => {
  worker = (await import("../src/worker/index.ts")).default as never;
  D1 = makeD1();
  env = { DB: D1, ORIGIN, RP_ID: RP, SIGNUP: "invite", ASSETS: { fetch: async () => new Response("spa") }, RELAY_SECRET: "x".repeat(40), RELAY: {} };
  await seedUser("usr_owner", "ws_a", "owner", "tok-owner");
  await seedUser("usr_admin", "ws_a", "admin", "tok-admin");
  await seedUser("usr_mem", "ws_a", "member", "tok-mem");
});

describe("passkey registration requires proof of possession", () => {
  async function addPasskey(token: string, a: Awaited<ReturnType<typeof authenticator>>, spki: string, proofBy?: Awaited<ReturnType<typeof authenticator>>) {
    const st = (await (await call("POST", "/api/passkeys/start", token)).json()) as { challengeId: string; challenge: string };
    const proof = proofBy ? await proofBy.assert(await challenge("nodescale/v1/possession", utf8(st.challenge))) : undefined;
    return call("POST", "/api/passkeys/finish", token, { challengeId: st.challengeId, credential: { ...a.attestation(st.challenge), publicKey: spki }, proof });
  }

  it("accepts a passkey that proves possession", async () => {
    const a = await authenticator();
    expect((await addPasskey("tok-mem", a, a.spki, a)).status).toBe(200);
  });

  it("refuses someone else's credential ID and public key", async () => {
    const victim = await authenticator();
    const attacker = await authenticator();
    expect((await addPasskey("tok-mem", victim, victim.spki)).status).toBe(400); // no proof
    // A proof by a different key (the attacker's own) does not count either.
    const st = (await (await call("POST", "/api/passkeys/start", "tok-mem")).json()) as { challengeId: string; challenge: string };
    const proof = await attacker.assert(await challenge("nodescale/v1/possession", utf8(st.challenge)));
    const r = await call("POST", "/api/passkeys/finish", "tok-mem", { challengeId: st.challengeId, credential: { ...victim.attestation(st.challenge), publicKey: victim.spki }, proof });
    expect(r.status).toBe(400);
  });

  it("never re-registers a removed credential ID", async () => {
    const a = await authenticator();
    const b = await authenticator();
    expect((await addPasskey("tok-mem", a, a.spki, a)).status).toBe(200);
    expect((await addPasskey("tok-mem", b, b.spki, b)).status).toBe(200);
    expect((await call("DELETE", `/api/passkeys/${a.id}`, "tok-mem")).status).toBe(200);
    expect((await addPasskey("tok-admin", a, a.spki, a)).status).toBe(409);
    // The last passkey cannot be removed.
    expect((await call("DELETE", `/api/passkeys/${b.id}`, "tok-mem")).status).toBe(409);
  });
});

describe("roles", () => {
  it("only owners and admins control the relay", async () => {
    expect((await call("POST", "/api/relay/up", "tok-mem", { authKey: "tskey-auth-abc" })).status).toBe(403);
    expect((await call("POST", "/api/relay/up", "tok-admin", { authKey: "tskey-auth-abc" })).status).toBe(200);
    expect((await call("POST", "/api/relay/down", "tok-mem")).status).toBe(403);
  });

  it("only the owner invites or removes admins, and removal revokes their invites", async () => {
    expect((await call("POST", "/api/workspace/invites", "tok-admin", { role: "admin" })).status).toBe(403);
    expect((await call("POST", "/api/workspace/invites", "tok-admin", { role: "member" })).status).toBe(200);
    await seedUser("usr_admin2", "ws_a", "admin", "tok-admin2");
    expect((await call("DELETE", "/api/workspace/members/usr_admin2", "tok-admin")).status).toBe(403);
    expect((await call("DELETE", "/api/workspace/members/usr_admin", "tok-owner")).status).toBe(200);
    expect(D1.raw.prepare("SELECT COUNT(*) AS n FROM invites WHERE created_by = 'usr_admin' AND used_by IS NULL").get()).toEqual({ n: 0 });
  });

  it("members cannot write stack definitions", async () => {
    D1.raw.prepare("INSERT INTO servers (id, workspace_id, name, created_at) VALUES ('srv_1','ws_a','web',?)").run(now());
    expect((await call("PUT", "/api/servers/srv_1/stacks/app", "tok-mem", { compose: "services: {}" })).status).toBe(403);
  });
});

describe("rpc payloads", () => {
  beforeEach(() => {
    D1.raw.prepare("INSERT INTO servers (id, workspace_id, name, tailnet_ip, created_at) VALUES ('srv_1','ws_a','web','100.64.0.10',?)").run(now());
  });
  const send = (payload: string) => call("POST", "/api/servers/srv_1/rpc", "tok-mem", { request: { payload: b64(utf8(payload)) } });
  const base = { v: 1, typ: "nodescale.request", aud: "ag_00000000000000000000000000000000", op: "containers.list", iat: now(), exp: now() + 60, nonce: "n".repeat(20) };

  it("relays canonical payloads", async () => {
    expect((await send(JSON.stringify(base))).status).toBe(200);
  });

  it("rejects case-variant, unknown or non-canonical keys", async () => {
    expect((await send(JSON.stringify(base).replace('"op":"containers.list"', '"op":"containers.list","Op":"signers.add"'))).status).toBe(400);
    expect((await send(JSON.stringify({ ...base, extra: 1 }))).status).toBe(400);
    expect((await send(JSON.stringify(base, null, 1))).status).toBe(400);
  });
});

describe("transport hardening", () => {
  it("rejects cross-site writes without caching", async () => {
    const r = await call("PUT", "/api/vault", "tok-mem", { version: 0, blob: "x" }, { origin: "https://evil.example" });
    expect(r.status).toBe(403);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("content-security-policy")).toContain("default-src 'none'");
  });

  it("never serves upstream HTML from the console origin", async () => {
    const real = globalThis.fetch;
    globalThis.fetch = (async () => new Response("<script>alert(1)</script>", { headers: { "content-type": "text/html" } })) as typeof fetch;
    try {
      const r = await call("GET", "/api/egress/cloudflare/zones", "tok-mem");
      expect(r.headers.get("content-type")).toMatch(/^text\/plain/);
      expect(r.headers.get("content-disposition")).toBe("attachment");
    } finally {
      globalThis.fetch = real;
    }
  });
});
