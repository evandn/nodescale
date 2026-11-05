import { Hono } from "hono";
import type { AppEnv } from "../env.ts";
import { requireRole, requireUser } from "./auth.ts";
import { body, fail, hashToken, now, randomToken, str } from "../util.ts";

// ---------------------------------------------------------------------------
// Current user

export const me = new Hono<AppEnv>();
me.use(requireUser);
me.get("/", async (c) => {
  const u = c.get("user");
  const ws = await c.env.DB.prepare("SELECT id, name FROM workspaces WHERE id = ?").bind(u.workspaceId).first<{ id: string; name: string }>();
  return c.json({
    user: { id: u.id, name: u.name, credentialId: u.credentialId },
    workspace: { ...ws, role: u.role },
    rp: { id: c.env.RP_ID, origin: c.env.ORIGIN },
  });
});

// ---------------------------------------------------------------------------
// Vault: an opaque, client-encrypted blob. The server cannot read it and only
// enforces optimistic concurrency so two tabs cannot silently overwrite each
// other.

export const vault = new Hono<AppEnv>();
vault.use(requireUser);

vault.get("/", async (c) => {
  const row = await c.env.DB.prepare("SELECT version, blob, updated_at AS updatedAt FROM vaults WHERE user_id = ?").bind(c.get("user").id).first();
  return c.json(row ?? null);
});

vault.put("/", async (c) => {
  const u = c.get("user");
  const b = await body<{ version?: unknown; blob?: unknown }>(c, 300 << 10);
  const expected = typeof b.version === "number" ? b.version : -1;
  const blob = str(b.blob, "blob", { max: 256 << 10 });
  const t = now();
  if (expected === 0) {
    const r = await c.env.DB.prepare("INSERT INTO vaults (user_id, version, blob, updated_at) VALUES (?, 1, ?, ?) ON CONFLICT (user_id) DO NOTHING").bind(u.id, blob, t).run();
    if (!r.meta.changes) fail(409, "vault already exists");
    return c.json({ version: 1 });
  }
  const r = await c.env.DB.prepare("UPDATE vaults SET version = version + 1, blob = ?, updated_at = ? WHERE user_id = ? AND version = ?").bind(blob, t, u.id, expected).run();
  if (!r.meta.changes) fail(409, "vault changed in another tab; reload and try again");
  return c.json({ version: expected + 1 });
});

// ---------------------------------------------------------------------------
// Workspace, members and invites

export const workspace = new Hono<AppEnv>();
workspace.use(requireUser);

workspace.get("/members", async (c) => {
  const u = c.get("user");
  const { results: members } = await c.env.DB.prepare(
    `SELECT u.id, u.name, m.role, m.created_at AS joinedAt
       FROM memberships m JOIN users u ON u.id = m.user_id
      WHERE m.workspace_id = ? ORDER BY m.created_at`,
  )
    .bind(u.workspaceId)
    .all<{ id: string; name: string; role: string; joinedAt: number }>();
  // Public keys are published so admins can enrol teammates' passkeys on
  // servers. The UI shows fingerprints to compare out of band because this
  // list comes from the (untrusted) control plane.
  const { results: creds } = await c.env.DB.prepare(
    `SELECT c.id, c.user_id AS userId, c.label, c.alg, c.public_key AS publicKey, c.created_at AS createdAt
       FROM credentials c JOIN memberships m ON m.user_id = c.user_id
      WHERE m.workspace_id = ? ORDER BY c.created_at`,
  )
    .bind(u.workspaceId)
    .all<{ id: string; userId: string; label: string; alg: number; publicKey: string; createdAt: number }>();
  return c.json(members.map((m) => ({ ...m, passkeys: creds.filter((k) => k.userId === m.id) })));
});

workspace.patch("/", requireRole("owner", "admin"), async (c) => {
  const b = await body<{ name?: unknown }>(c);
  await c.env.DB.prepare("UPDATE workspaces SET name = ? WHERE id = ?").bind(str(b.name, "name", { max: 80 }).trim(), c.get("user").workspaceId).run();
  return c.json({ ok: true });
});

workspace.patch("/members/:id", requireRole("owner"), async (c) => {
  const b = await body<{ role?: unknown }>(c);
  const role = str(b.role, "role", { pattern: /^(admin|member)$/ });
  if (c.req.param("id") === c.get("user").id) fail(409, "you cannot change your own role");
  await c.env.DB.prepare("UPDATE memberships SET role = ? WHERE workspace_id = ? AND user_id = ? AND role != 'owner'").bind(role, c.get("user").workspaceId, c.req.param("id")).run();
  return c.json({ ok: true });
});

workspace.delete("/members/:id", requireRole("owner", "admin"), async (c) => {
  const u = c.get("user");
  if (c.req.param("id") === u.id) fail(409, "you cannot remove yourself");
  await c.env.DB.prepare("DELETE FROM memberships WHERE workspace_id = ? AND user_id = ? AND role != 'owner'").bind(u.workspaceId, c.req.param("id")).run();
  return c.json({ ok: true });
});

workspace.get("/invites", requireRole("owner", "admin"), async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT id, role, created_at AS createdAt, expires_at AS expiresAt, used_at AS usedAt FROM invites WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 50",
  )
    .bind(c.get("user").workspaceId)
    .all();
  return c.json(results);
});

workspace.post("/invites", requireRole("owner", "admin"), async (c) => {
  const u = c.get("user");
  const b = await body<{ role?: unknown }>(c);
  const role = str(b.role ?? "member", "role", { pattern: /^(admin|member)$/ });
  const code = randomToken(24);
  const t = now();
  await c.env.DB.prepare("INSERT INTO invites (id, workspace_id, role, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(await hashToken(code), u.workspaceId, role, u.id, t, t + 7 * 86400)
    .run();
  return c.json({ code, url: `${c.env.ORIGIN}/join?invite=${code}`, expiresAt: t + 7 * 86400 });
});

workspace.delete("/invites/:id", requireRole("owner", "admin"), async (c) => {
  await c.env.DB.prepare("DELETE FROM invites WHERE id = ? AND workspace_id = ?").bind(c.req.param("id"), c.get("user").workspaceId).run();
  return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Audit log (control-plane view). The authoritative record of what happened
// on a server is the agent's own audit log on that server.

export const audit = new Hono<AppEnv>();
audit.use(requireUser);

audit.get("/", async (c) => {
  const before = Number(c.req.query("before") ?? "0") || Number.MAX_SAFE_INTEGER;
  const { results } = await c.env.DB.prepare(
    `SELECT a.id, a.action, a.ok, a.detail, a.request_hash AS requestHash, a.created_at AS createdAt, a.ip,
            u.name AS userName, s.name AS serverName, a.server_id AS serverId
       FROM audit_events a
       LEFT JOIN users u ON u.id = a.user_id
       LEFT JOIN servers s ON s.id = a.server_id
      WHERE a.workspace_id = ? AND a.id < ?
      ORDER BY a.id DESC LIMIT 100`,
  )
    .bind(c.get("user").workspaceId, before)
    .all();
  return c.json(results.map((r) => ({ ...r, ok: !!r.ok })));
});

audit.post("/", async (c) => {
  const u = c.get("user");
  const b = await body<{ action?: unknown; ok?: unknown; detail?: unknown; serverId?: unknown }>(c);
  await c.env.DB.prepare("INSERT INTO audit_events (workspace_id, user_id, server_id, action, ok, detail, ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(
      u.workspaceId,
      u.id,
      typeof b.serverId === "string" ? b.serverId.slice(0, 64) : null,
      str(b.action, "action", { max: 64, pattern: /^[a-z0-9._-]+$/ }),
      b.ok === false ? 0 : 1,
      typeof b.detail === "string" ? b.detail.slice(0, 1000) : null,
      c.req.header("cf-connecting-ip") ?? null,
      now(),
    )
    .run();
  return c.json({ ok: true });
});
