import { OPS, decodePayload, requestHash, unb64, type RequestPayload, type SignedRequest } from "@nodescale/protocol";
import { Hono } from "hono";
import type { AppEnv } from "../env.ts";
import { relayFetch, type RelayStatus } from "../relay.ts";
import { body, fail, newId, now, optStr, str } from "../util.ts";
import { requireRole, requireUser } from "./auth.ts";

const TAILNET_IP = /^(100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}|fd7a:115c:a1e0:[0-9a-f:]+)$/i;
const AGENT_ID = /^ag_[0-9a-f]{32}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;

const COLUMNS = `id, name, provider, notes, tailnet_ip AS tailnetIp, tailnet_name AS tailnetName,
  tailscale_device_id AS deviceId, agent_id AS agentId, agent_public_key AS agentPublicKey,
  status, last_seen_at AS lastSeenAt, created_at AS createdAt, tunnel_id AS tunnelId`;

export const servers = new Hono<AppEnv>();
servers.use(requireUser);

servers.get("/", async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT ${COLUMNS} FROM servers WHERE workspace_id = ? ORDER BY name`).bind(c.get("user").workspaceId).all();
  return c.json(results);
});

servers.get("/:id", async (c) => {
  const row = await c.env.DB.prepare(`SELECT ${COLUMNS} FROM servers WHERE id = ? AND workspace_id = ?`).bind(c.req.param("id"), c.get("user").workspaceId).first();
  if (!row) fail(404, "server not found");
  return c.json(row);
});

interface ServerInput {
  name?: unknown;
  provider?: unknown;
  notes?: unknown;
  tailnetIp?: unknown;
  tailnetName?: unknown;
  deviceId?: unknown;
  agentId?: unknown;
  agentPublicKey?: unknown;
  tunnelId?: unknown;
}

function parseServer(b: ServerInput) {
  return {
    provider: optStr(b.provider, "provider", { max: 60 }),
    notes: optStr(b.notes, "notes", { max: 1000 }),
    tailnetIp: optStr(b.tailnetIp, "tailnetIp", { max: 64, pattern: TAILNET_IP }),
    tailnetName: optStr(b.tailnetName, "tailnetName", { max: 253, pattern: /^[a-z0-9.-]+$/i }),
    deviceId: optStr(b.deviceId, "deviceId", { max: 64, pattern: /^[A-Za-z0-9]+$/ }),
    agentId: optStr(b.agentId, "agentId", { max: 40, pattern: AGENT_ID }),
    agentPublicKey: optStr(b.agentPublicKey, "agentPublicKey", { max: 64, pattern: B64URL }),
    tunnelId: optStr(b.tunnelId, "tunnelId", { max: 64, pattern: /^[0-9a-f-]{36}$/ }),
  };
}

servers.post("/", requireRole("owner", "admin"), async (c) => {
  const u = c.get("user");
  const b = await body<ServerInput>(c);
  const name = str(b.name, "name", { max: 63, pattern: /^[a-z0-9][a-z0-9-]*$/ });
  const s = parseServer(b);
  const id = newId("srv", 12);
  const r = await c.env.DB.prepare(
    `INSERT INTO servers (id, workspace_id, name, provider, notes, tailnet_ip, tailnet_name, tailscale_device_id, tunnel_id, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (workspace_id, name) DO NOTHING`,
  )
    .bind(id, u.workspaceId, name, s.provider, s.notes, s.tailnetIp, s.tailnetName, s.deviceId, s.tunnelId, u.id, now())
    .run();
  if (!r.meta.changes) fail(409, "a server with that name already exists");
  return c.json({ id });
});

servers.patch("/:id", requireRole("owner", "admin"), async (c) => {
  const b = await body<ServerInput>(c);
  const s = parseServer(b);
  const sets: string[] = [];
  const vals: unknown[] = [];
  const set = (col: string, v: unknown) => {
    sets.push(`${col} = ?`);
    vals.push(v);
  };
  if (b.name !== undefined) set("name", str(b.name, "name", { max: 63, pattern: /^[a-z0-9][a-z0-9-]*$/ }));
  if (b.provider !== undefined) set("provider", s.provider);
  if (b.notes !== undefined) set("notes", s.notes);
  if (b.tailnetIp !== undefined) set("tailnet_ip", s.tailnetIp);
  if (b.tailnetName !== undefined) set("tailnet_name", s.tailnetName);
  if (b.deviceId !== undefined) set("tailscale_device_id", s.deviceId);
  if (b.tunnelId !== undefined) set("tunnel_id", s.tunnelId);
  if (b.agentId !== undefined) {
    set("agent_id", s.agentId);
    set("agent_public_key", s.agentPublicKey);
    set("status", s.agentId ? "active" : "pending");
  }
  if (!sets.length) return c.json({ ok: true });
  await c.env.DB.prepare(`UPDATE servers SET ${sets.join(", ")} WHERE id = ? AND workspace_id = ?`)
    .bind(...vals, c.req.param("id"), c.get("user").workspaceId)
    .run();
  return c.json({ ok: true });
});

servers.delete("/:id", requireRole("owner", "admin"), async (c) => {
  await c.env.DB.prepare("DELETE FROM servers WHERE id = ? AND workspace_id = ?").bind(c.req.param("id"), c.get("user").workspaceId).run();
  return c.json({ ok: true });
});

/**
 * Forwards a signed request to the server's agent through the relay. The
 * control plane can read the request (it is not secret) but cannot alter it
 * without breaking the passkey signature, and cannot forge the agent's signed
 * response.
 */
servers.post("/:id/rpc", async (c) => {
  const u = c.get("user");
  const server = await c.env.DB.prepare("SELECT id, tailnet_ip FROM servers WHERE id = ? AND workspace_id = ?")
    .bind(c.req.param("id"), u.workspaceId)
    .first<{ id: string; tailnet_ip: string | null }>();
  if (!server) fail(404, "server not found");
  if (!server.tailnet_ip) fail(409, "server has no tailnet address yet");

  const b = await body<{ request?: SignedRequest }>(c, 1 << 20);
  const req = b.request;
  if (!req || typeof req.payload !== "string") fail(400, "request is required");
  let payload: RequestPayload;
  let hash: string;
  try {
    payload = decodePayload<RequestPayload>(req.payload);
    hash = await requestHash(unb64(req.payload));
  } catch {
    fail(400, "request payload is not valid base64url JSON");
  }

  const res = await relayFetch(c.env, u.workspaceId, "/v1/rpc", {
    method: "POST",
    body: JSON.stringify({ host: server.tailnet_ip, request: req }),
  });
  const text = await res.text();

  // Record state-changing operations (and unknown ones, which the agent rejects).
  const level = OPS[payload.op as keyof typeof OPS]?.level;
  if (level !== "public" && level !== "read") {
    let ok = res.ok;
    let detail: string | null = null;
    if (res.ok) {
      try {
        const resp = decodePayload<{ ok: boolean; error?: { message: string } }>(JSON.parse(text).payload);
        ok = resp.ok;
        detail = resp.error?.message ?? null;
      } catch {
        ok = false;
      }
    } else {
      detail = text.slice(0, 300);
    }
    c.executionCtx.waitUntil(
      c.env.DB.prepare("INSERT INTO audit_events (workspace_id, user_id, server_id, action, request_hash, ok, detail, ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(u.workspaceId, u.id, server.id, String(payload.op).slice(0, 64), hash, ok ? 1 : 0, detail, c.req.header("cf-connecting-ip") ?? null, now())
        .run(),
    );
  }
  if (res.ok) {
    c.executionCtx.waitUntil(c.env.DB.prepare("UPDATE servers SET last_seen_at = ? WHERE id = ?").bind(now(), server.id).run());
  }
  return new Response(text, { status: res.status, headers: { "Content-Type": "application/json" } });
});

// ---------------------------------------------------------------------------
// Stack definitions (no secrets: see migrations/0002_stacks.sql)

const STACK_NAME = /^[a-z0-9][a-z0-9_-]{0,62}$/;

async function ownServer(c: { env: AppEnv["Bindings"]; get: (k: "user") => AppEnv["Variables"]["user"] }, id: string) {
  const row = await c.env.DB.prepare("SELECT id FROM servers WHERE id = ? AND workspace_id = ?").bind(id, c.get("user").workspaceId).first();
  if (!row) fail(404, "server not found");
}

servers.get("/:id/stacks", async (c) => {
  await ownServer(c, c.req.param("id"));
  const { results } = await c.env.DB.prepare(
    `SELECT s.name, s.compose, s.updated_at AS updatedAt, s.deployed_at AS deployedAt, u.name AS updatedBy
       FROM stacks s LEFT JOIN users u ON u.id = s.updated_by
      WHERE s.server_id = ? ORDER BY s.name`,
  )
    .bind(c.req.param("id"))
    .all();
  return c.json(results);
});

servers.put("/:id/stacks/:name", async (c) => {
  const u = c.get("user");
  await ownServer(c, c.req.param("id"));
  const name = str(c.req.param("name"), "name", { max: 63, pattern: STACK_NAME });
  const b = await body<{ compose?: unknown; deployed?: unknown }>(c, 256 << 10);
  const compose = str(b.compose, "compose", { max: 200 << 10 });
  const t = now();
  await c.env.DB.prepare(
    `INSERT INTO stacks (server_id, workspace_id, name, compose, updated_by, updated_at, deployed_at) VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (server_id, name) DO UPDATE SET compose = excluded.compose, updated_by = excluded.updated_by,
       updated_at = excluded.updated_at, deployed_at = COALESCE(excluded.deployed_at, stacks.deployed_at)`,
  )
    .bind(c.req.param("id"), u.workspaceId, name, compose, u.id, t, b.deployed ? t : null)
    .run();
  return c.json({ ok: true });
});

servers.delete("/:id/stacks/:name", async (c) => {
  await ownServer(c, c.req.param("id"));
  await c.env.DB.prepare("DELETE FROM stacks WHERE server_id = ? AND name = ?").bind(c.req.param("id"), c.req.param("name")).run();
  return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Relay lifecycle

export const relay = new Hono<AppEnv>();
relay.use(requireUser);

relay.get("/", async (c) => {
  const res = await relayFetch(c.env, c.get("user").workspaceId, "/v1/status");
  if (!res.ok) return c.json({ state: "error", error: (await res.text()).slice(0, 300) } satisfies RelayStatus);
  return c.json((await res.json()) as RelayStatus);
});

relay.post("/up", async (c) => {
  const u = c.get("user");
  const b = await body<{ authKey?: unknown }>(c);
  const authKey = str(b.authKey, "authKey", { max: 200, pattern: /^tskey-auth-[A-Za-z0-9-]+$/ });
  const hostname = `nodescale-relay-${u.workspaceId.slice(3, 11).toLowerCase().replace(/[^a-z0-9]/g, "0")}`;
  const res = await relayFetch(c.env, u.workspaceId, "/v1/tailnet/up", { method: "POST", body: JSON.stringify({ authKey, hostname }) });
  return new Response(res.body, { status: res.status, headers: { "Content-Type": "application/json" } });
});
