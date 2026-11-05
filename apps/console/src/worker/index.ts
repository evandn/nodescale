import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import type { AppEnv, Env } from "./env.ts";
import { audit, me, vault, workspace } from "./routes/account.ts";
import { auth, passkeys } from "./routes/auth.ts";
import { egress } from "./routes/egress.ts";
import { relay, servers } from "./routes/servers.ts";

export { Relay } from "./relay.ts";

/**
 * Strict CSP: the SPA is entirely same-origin static files with no inline
 * script and no third-party code at runtime. This matters because the
 * frontend is the one place passkey prompts originate from.
 */
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": CSP,
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)",
  "X-Frame-Options": "DENY",
};

const api = new Hono<AppEnv>();

// CSRF defence in depth on top of SameSite=Strict cookies: every mutating API
// call must come from our own origin and carry a custom header that a
// cross-site form cannot set.
api.use(async (c, next) => {
  if (c.req.method !== "GET" && c.req.method !== "HEAD") {
    if (c.req.header("origin") !== c.env.ORIGIN || c.req.header("x-nodescale") !== "1") {
      throw new HTTPException(403, { message: "cross-site request rejected" });
    }
  }
  await next();
  c.header("Cache-Control", "no-store");
});

api.route("/auth", auth);
api.route("/passkeys", passkeys);
api.route("/me", me);
api.route("/vault", vault);
api.route("/workspace", workspace);
api.route("/audit", audit);
api.route("/servers", servers);
api.route("/relay", relay);
api.route("/egress", egress);
api.all("*", (c) => c.json({ error: "not found" }, 404));

const app = new Hono<AppEnv>();
app.onError((err, c) => {
  if (err instanceof HTTPException) return c.json({ error: err.message }, err.status);
  console.error("unhandled", err);
  return c.json({ error: "internal error" }, 500);
});
app.route("/api", api);
app.all("*", (c) => c.env.ASSETS.fetch(c.req.raw));

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const res = await app.fetch(req, env, ctx);
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
    return out;
  },
} satisfies ExportedHandler<Env>;
