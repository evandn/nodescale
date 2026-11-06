import { Hono } from "hono";
import type { AppEnv } from "../env.ts";
import { fail } from "../util.ts";
import { requireUser } from "./auth.ts";

/**
 * Stateless pass-through to provider APIs, needed only because they do not
 * allow browser (CORS) calls. The provider credential arrives from the
 * browser's unlocked vault in `X-Upstream-Authorization`, is forwarded once,
 * and is never stored or logged. Only fixed upstream hosts are reachable.
 */
const UPSTREAMS: Record<string, string> = {
  cloudflare: "https://api.cloudflare.com/client/v4/",
  tailscale: "https://api.tailscale.com/api/v2/",
};

const SAFE_PATH = /^[A-Za-z0-9._~:@!$&'()*+,;=\-/]*$/;
const FORWARD_REQUEST_HEADERS = ["content-type", "accept"];
const FORWARD_RESPONSE_HEADERS = ["content-type", "retry-after", "ratelimit-remaining", "x-ratelimit-remaining"];

export const egress = new Hono<AppEnv>();
egress.use(requireUser);

egress.all("/:provider/*", async (c) => {
  const base = UPSTREAMS[c.req.param("provider")];
  if (!base) fail(404, "unknown provider");
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(c.req.method)) fail(400, "method not allowed");

  const url = new URL(c.req.url);
  const prefix = `/api/egress/${c.req.param("provider")}/`;
  const path = url.pathname.slice(prefix.length);
  if (!SAFE_PATH.test(path) || path.split("/").some((seg) => seg === ".." || seg === ".")) fail(400, "invalid upstream path");
  const target = new URL(path + url.search, base);
  if (!target.href.startsWith(base)) fail(400, "invalid upstream path");

  const headers = new Headers();
  for (const h of FORWARD_REQUEST_HEADERS) {
    const v = c.req.header(h);
    if (v) headers.set(h, v);
  }
  const upstreamAuth = c.req.header("x-upstream-authorization");
  if (upstreamAuth) headers.set("authorization", upstreamAuth);
  headers.set("user-agent", "nodescale-console");

  let reqBody: ArrayBuffer | undefined;
  if (c.req.method !== "GET" && c.req.method !== "DELETE") {
    reqBody = await c.req.arrayBuffer();
    if (reqBody.byteLength > 1 << 20) fail(413, "request body too large");
  }

  const res = await fetch(target, { method: c.req.method, headers, body: reqBody, redirect: "manual" });
  const out = new Headers({ "Cache-Control": "no-store" });
  for (const h of FORWARD_RESPONSE_HEADERS) {
    const v = res.headers.get(h);
    if (v) out.set(h, v);
  }
  // Never serve upstream HTML (or anything but JSON) as a document from
  // the console's origin.
  if (!/^application\/json\b/i.test(out.get("content-type") ?? "")) out.set("content-type", "text/plain; charset=utf-8");
  out.set("Content-Disposition", "attachment");
  return new Response(res.body, { status: res.status >= 300 && res.status < 400 ? 502 : res.status, headers: out });
});
