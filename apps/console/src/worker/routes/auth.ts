import {
  ALG,
  DOMAIN,
  b64,
  challenge as payloadChallenge,
  equalBytes,
  fromUtf8,
  sha256,
  unb64,
  utf8,
  verifyAssertion,
  type Alg,
  type Assertion,
  type SessionCertPayload,
} from "@nodescale/protocol";
import { Hono, type Context, type MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AppEnv, Env, SessionUser, WorkspaceRole } from "../env.ts";
import { body, clientIp, fail, hashToken, newId, now, optStr, randomToken, str } from "../util.ts";

export const SESSION_COOKIE = "__Host-nodescale";
const SESSION_TTL = 12 * 3600;
const CHALLENGE_TTL = 300;
const MAX_CERT_TTL = 8 * 3600;
const B64URL = /^[A-Za-z0-9_-]+$/;

// ---------------------------------------------------------------------------
// Session middleware

export const requireUser: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) fail(401, "not signed in");
  const row = await c.env.DB.prepare(
    `SELECT s.id AS sid, s.credential_id, u.id, u.name, m.workspace_id, m.role
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       JOIN memberships m ON m.user_id = u.id
      WHERE s.id = ? AND s.expires_at > ?
      ORDER BY m.created_at LIMIT 1`,
  )
    .bind(await hashToken(token), now())
    .first<{ sid: string; credential_id: string | null; id: string; name: string; workspace_id: string; role: WorkspaceRole }>();
  if (!row) fail(401, "session expired");
  const user: SessionUser = {
    id: row.id,
    name: row.name,
    sessionId: row.sid,
    credentialId: row.credential_id,
    workspaceId: row.workspace_id,
    role: row.role,
  };
  c.set("user", user);
  await next();
};

export function requireRole(...roles: WorkspaceRole[]): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    if (!roles.includes(c.get("user").role)) fail(403, "your workspace role does not allow this");
    await next();
  };
}

async function rateLimit(c: Context<AppEnv>) {
  if (!c.env.AUTH_LIMITER) return;
  const { success } = await c.env.AUTH_LIMITER.limit({ key: `auth:${clientIp(c) ?? "unknown"}` });
  if (!success) fail(429, "too many attempts; try again shortly");
}

// ---------------------------------------------------------------------------
// Challenges

async function issueChallenge(env: Env, purpose: string, userId: string | null, data: unknown = null) {
  const id = newId("ch");
  const challenge = randomToken(32);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM challenges WHERE expires_at < ?").bind(now()),
    env.DB.prepare("INSERT INTO challenges (id, challenge, purpose, user_id, data, expires_at) VALUES (?, ?, ?, ?, ?, ?)").bind(
      id,
      challenge,
      purpose,
      userId,
      data === null ? null : JSON.stringify(data),
      now() + CHALLENGE_TTL,
    ),
  ]);
  return { id, challenge };
}

/** Consumes a challenge exactly once. */
async function takeChallenge(env: Env, id: unknown, purpose: string) {
  const cid = str(id, "challengeId", { max: 64, pattern: /^ch_[A-Za-z0-9_-]+$/ });
  const row = await env.DB.prepare("DELETE FROM challenges WHERE id = ? RETURNING challenge, purpose, user_id, data, expires_at")
    .bind(cid)
    .first<{ challenge: string; purpose: string; user_id: string | null; data: string | null; expires_at: number }>();
  if (!row || row.purpose !== purpose || row.expires_at < now()) fail(400, "challenge expired; try again");
  return row;
}

// ---------------------------------------------------------------------------
// Registration (new account, or an additional passkey for the current user)

interface RegistrationCredential {
  id: string;
  publicKey: string;
  alg: number;
  transports?: string[];
  clientDataJSON: string;
  authenticatorData: string;
  prf?: boolean;
}

async function verifyRegistration(env: Env, cred: RegistrationCredential, expected: string) {
  str(cred?.id, "credential.id", { max: 1400, pattern: B64URL });
  str(cred.publicKey, "credential.publicKey", { max: 2000, pattern: B64URL });
  if (![ALG.ES256, ALG.EdDSA, ALG.RS256].includes(cred.alg as Alg)) fail(400, "unsupported passkey algorithm");

  const cdj = unb64(str(cred.clientDataJSON, "clientDataJSON", { max: 4000, pattern: B64URL }));
  const cd = JSON.parse(fromUtf8(cdj)) as { type?: string; challenge?: string; origin?: string; crossOrigin?: boolean };
  if (cd.type !== "webauthn.create") fail(400, "unexpected clientData type");
  if (cd.challenge !== expected) fail(400, "challenge mismatch");
  if (cd.origin !== env.ORIGIN || cd.crossOrigin) fail(400, "origin mismatch");

  const authData = unb64(str(cred.authenticatorData, "authenticatorData", { max: 8000, pattern: B64URL }));
  if (authData.length < 55) fail(400, "authenticatorData too short");
  if (!equalBytes(authData.subarray(0, 32), await sha256(utf8(env.RP_ID)))) fail(400, "rpId mismatch");
  const flags = authData[32]!;
  if (!(flags & 0x01) || !(flags & 0x04)) fail(400, "user verification (PIN or biometric) is required");
  if (!(flags & 0x40)) fail(400, "no attested credential data");
  const idLen = (authData[53]! << 8) | authData[54]!;
  if (!equalBytes(authData.subarray(55, 55 + idLen), unb64(cred.id))) fail(400, "credential ID mismatch");

  // Make sure the key actually parses for the declared algorithm.
  const spki = unb64(cred.publicKey);
  const params =
    cred.alg === ALG.ES256
      ? { name: "ECDSA", namedCurve: "P-256" }
      : cred.alg === ALG.EdDSA
        ? { name: "Ed25519" }
        : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  try {
    await crypto.subtle.importKey("spki", spki, params, false, ["verify"]);
  } catch {
    fail(400, "public key does not match algorithm");
  }
  return { id: b64(unb64(cred.id)), signCount: new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0) };
}

function rpInfo(env: Env) {
  return { id: env.RP_ID, name: "nodescale" };
}

// ---------------------------------------------------------------------------
// Sign-in: one passkey ceremony signs a session certificate that (a) proves
// possession for the control-plane session and (b) is later presented to
// agents to authorise a short-lived browser key. The WebAuthn PRF extension
// in the same ceremony derives the vault key on the client.

async function verifyLogin(c: Context<AppEnv>, challengeId: unknown, certificate: { payload?: unknown; assertion?: Assertion }) {
  const ch = await takeChallenge(c.env, challengeId, "login");
  const certBytes = unb64(str(certificate?.payload, "certificate.payload", { max: 4000, pattern: B64URL }));
  const cert = JSON.parse(fromUtf8(certBytes)) as SessionCertPayload;
  const t = now();
  if (cert.v !== 1 || cert.typ !== "nodescale.session") fail(400, "invalid certificate");
  if (cert.nonce !== ch.challenge) fail(400, "certificate is not bound to this sign-in");
  if (Math.abs(cert.iat - t) > 120) fail(400, "certificate time is off; check your clock");
  if (!(cert.exp > cert.iat && cert.exp - cert.iat <= MAX_CERT_TTL)) fail(400, "certificate lifetime invalid");
  if (cert.scope !== "read" && cert.scope !== "operate") fail(400, "invalid scope");

  const a = certificate.assertion;
  const credId = b64(unb64(str(a?.credentialId, "credentialId", { max: 1400, pattern: B64URL })));
  const cred = await c.env.DB.prepare("SELECT id, user_id, public_key, alg, sign_count FROM credentials WHERE id = ?")
    .bind(credId)
    .first<{ id: string; user_id: string; public_key: string; alg: Alg; sign_count: number }>();
  if (!cred) fail(401, "unknown passkey");

  let verified;
  try {
    verified = await verifyAssertion({
      rp: { id: c.env.RP_ID, origins: [c.env.ORIGIN] },
      alg: cred.alg,
      publicKey: cred.public_key,
      assertion: a!,
      challenge: await payloadChallenge(DOMAIN.session, certBytes),
      requireUserVerification: true,
    });
  } catch (e) {
    fail(401, `passkey verification failed: ${(e as Error).message}`);
  }
  // Authenticators that keep a counter must always increase it; a regression
  // suggests a cloned authenticator.
  if (cred.sign_count > 0 && verified.signCount <= cred.sign_count) fail(401, "passkey counter regressed; possible cloned authenticator");

  const token = randomToken(32);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE credentials SET sign_count = ?, last_used_at = ? WHERE id = ?").bind(verified.signCount, t, cred.id),
    c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND expires_at < ?").bind(cred.user_id, t),
    c.env.DB.prepare("INSERT INTO sessions (id, user_id, credential_id, created_at, expires_at, user_agent, ip) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(
      await hashToken(token),
      cred.user_id,
      cred.id,
      t,
      t + SESSION_TTL,
      (c.req.header("user-agent") ?? "").slice(0, 300),
      clientIp(c),
    ),
  ]);
  setCookie(c, SESSION_COOKIE, token, { path: "/", secure: true, httpOnly: true, sameSite: "Strict", maxAge: SESSION_TTL });
  return cred.user_id;
}

export const auth = new Hono<AppEnv>();

auth.post("/register/start", async (c) => {
  await rateLimit(c);
  const b = await body<{ name?: unknown; invite?: unknown }>(c);
  const name = str(b.name, "name", { max: 80 }).trim();
  const invite = optStr(b.invite, "invite", { max: 100, pattern: B64URL });

  const users = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
  let inviteRow: { id: string; workspace_id: string; role: string } | null = null;
  if (invite) {
    inviteRow = await c.env.DB.prepare("SELECT id, workspace_id, role FROM invites WHERE id = ? AND used_by IS NULL AND expires_at > ?")
      .bind(await hashToken(invite), now())
      .first();
    if (!inviteRow) fail(403, "invite is invalid or has expired");
  } else if ((users?.n ?? 0) > 0 && c.env.SIGNUP !== "open") {
    fail(403, "sign-up is invite-only; ask a workspace admin for an invite link");
  }

  const userId = newId("usr");
  const ch = await issueChallenge(c.env, "register", userId, { name, invite: inviteRow?.id ?? null });
  return c.json({ challengeId: ch.id, challenge: ch.challenge, user: { id: userId, name }, rp: rpInfo(c.env) });
});

auth.post("/register/finish", async (c) => {
  await rateLimit(c);
  const b = await body<{ challengeId?: unknown; credential?: RegistrationCredential; label?: unknown }>(c);
  const ch = await takeChallenge(c.env, b.challengeId, "register");
  const cred = await verifyRegistration(c.env, b.credential!, ch.challenge);
  const label = optStr(b.label, "label", { max: 80 }) ?? "Passkey";
  const data = JSON.parse(ch.data ?? "{}") as { name: string; invite: string | null };
  const userId = ch.user_id!;
  const t = now();

  // Re-check the sign-up policy here: a challenge issued while the instance
  // had no users must not let a second person open their own workspace.
  if (!data.invite) {
    const created = await c.env.DB.prepare(
      "INSERT INTO users (id, name, created_at) SELECT ?, ?, ? WHERE ? = 'open' OR NOT EXISTS (SELECT 1 FROM users)",
    )
      .bind(userId, data.name, t, c.env.SIGNUP ?? "invite")
      .run();
    if (!created.meta.changes) fail(403, "sign-up is invite-only; ask a workspace admin for an invite link");
  }
  const stmts = [
    ...(data.invite ? [c.env.DB.prepare("INSERT INTO users (id, name, created_at) VALUES (?, ?, ?)").bind(userId, data.name, t)] : []),
    c.env.DB.prepare(
      "INSERT INTO credentials (id, user_id, public_key, alg, label, transports, prf, sign_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(cred.id, userId, b.credential!.publicKey, b.credential!.alg, label, JSON.stringify(b.credential!.transports ?? []), b.credential!.prf ? 1 : 0, cred.signCount, t),
  ];
  if (data.invite) {
    const inv = await c.env.DB.prepare("UPDATE invites SET used_by = ?, used_at = ? WHERE id = ? AND used_by IS NULL AND expires_at > ? RETURNING workspace_id, role")
      .bind(userId, t, data.invite, t)
      .first<{ workspace_id: string; role: string }>();
    if (!inv) fail(403, "invite is invalid or has expired");
    stmts.push(c.env.DB.prepare("INSERT INTO memberships (workspace_id, user_id, role, created_at) VALUES (?, ?, ?, ?)").bind(inv.workspace_id, userId, inv.role, t));
  } else {
    const ws = newId("ws");
    stmts.push(
      c.env.DB.prepare("INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)").bind(ws, `${data.name}'s workspace`, t),
      c.env.DB.prepare("INSERT INTO memberships (workspace_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)").bind(ws, userId, t),
    );
  }
  await c.env.DB.batch(stmts);
  return c.json({ userId, credentialId: cred.id });
});

auth.post("/login/start", async (c) => {
  await rateLimit(c);
  const ch = await issueChallenge(c.env, "login", null);
  return c.json({ challengeId: ch.id, nonce: ch.challenge, rp: rpInfo(c.env) });
});

auth.post("/login/finish", async (c) => {
  await rateLimit(c);
  const b = await body<{ challengeId?: unknown; certificate?: { payload?: unknown; assertion?: Assertion } }>(c);
  const userId = await verifyLogin(c, b.challengeId, b.certificate ?? {});
  return c.json({ userId });
});

auth.post("/logout", async (c) => {
  const token = getCookie(c, SESSION_COOKIE);
  if (token) await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(await hashToken(token)).run();
  deleteCookie(c, SESSION_COOKIE, { path: "/", secure: true });
  return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Passkey management for the signed-in user

export const passkeys = new Hono<AppEnv>();
passkeys.use(requireUser);

passkeys.get("/", async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT id, label, alg, public_key AS publicKey, prf, created_at AS createdAt, last_used_at AS lastUsedAt FROM credentials WHERE user_id = ? ORDER BY created_at",
  )
    .bind(c.get("user").id)
    .all();
  return c.json(results.map((r) => ({ ...r, prf: !!r.prf })));
});

passkeys.post("/start", async (c) => {
  const u = c.get("user");
  const ch = await issueChallenge(c.env, "add-passkey", u.id);
  const { results } = await c.env.DB.prepare("SELECT id FROM credentials WHERE user_id = ?").bind(u.id).all<{ id: string }>();
  return c.json({ challengeId: ch.id, challenge: ch.challenge, user: { id: u.id, name: u.name }, rp: rpInfo(c.env), exclude: results.map((r) => r.id) });
});

passkeys.post("/finish", async (c) => {
  const u = c.get("user");
  const b = await body<{ challengeId?: unknown; credential?: RegistrationCredential; label?: unknown }>(c);
  const ch = await takeChallenge(c.env, b.challengeId, "add-passkey");
  if (ch.user_id !== u.id) fail(403, "challenge belongs to another user");
  const cred = await verifyRegistration(c.env, b.credential!, ch.challenge);
  await c.env.DB.prepare(
    "INSERT INTO credentials (id, user_id, public_key, alg, label, transports, prf, sign_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(cred.id, u.id, b.credential!.publicKey, b.credential!.alg, optStr(b.label, "label", { max: 80 }) ?? "Passkey", JSON.stringify(b.credential!.transports ?? []), b.credential!.prf ? 1 : 0, cred.signCount, now())
    .run();
  return c.json({ credentialId: cred.id });
});

passkeys.patch("/:id", async (c) => {
  const b = await body<{ label?: unknown }>(c);
  await c.env.DB.prepare("UPDATE credentials SET label = ? WHERE id = ? AND user_id = ?").bind(str(b.label, "label", { max: 80 }), c.req.param("id"), c.get("user").id).run();
  return c.json({ ok: true });
});

passkeys.delete("/:id", async (c) => {
  const u = c.get("user");
  const n = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?").bind(u.id).first<{ n: number }>();
  if ((n?.n ?? 0) <= 1) fail(409, "you cannot remove your only passkey");
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM credentials WHERE id = ? AND user_id = ?").bind(c.req.param("id"), u.id),
    c.env.DB.prepare("DELETE FROM sessions WHERE credential_id = ? AND user_id = ?").bind(c.req.param("id"), u.id),
  ]);
  return c.json({ ok: true });
});
