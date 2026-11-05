import { b64, sha256, utf8 } from "@nodescale/protocol";
import type { Context } from "hono";
import { HTTPException } from "hono/http-exception";

export const now = () => Math.floor(Date.now() / 1000);

export function newId(prefix: string, bytes = 16): string {
  return `${prefix}_${b64(crypto.getRandomValues(new Uint8Array(bytes)))}`;
}

export function randomToken(bytes = 32): string {
  return b64(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function hashToken(token: string): Promise<string> {
  return b64(await sha256(utf8(token)));
}

export function fail(status: 400 | 401 | 403 | 404 | 409 | 413 | 429 | 502 | 503, message: string): never {
  throw new HTTPException(status, { message });
}

export async function body<T>(c: Context, maxBytes = 64 << 10): Promise<T> {
  const len = Number(c.req.header("content-length") ?? "0");
  if (len > maxBytes) fail(413, "request body too large");
  const text = await c.req.text();
  if (text.length > maxBytes) fail(413, "request body too large");
  try {
    return JSON.parse(text) as T;
  } catch {
    fail(400, "request body must be JSON");
  }
}

export function str(v: unknown, field: string, { min = 1, max = 200, pattern }: { min?: number; max?: number; pattern?: RegExp } = {}): string {
  if (typeof v !== "string" || v.length < min || v.length > max || (pattern && !pattern.test(v))) {
    fail(400, `${field} is invalid`);
  }
  return v;
}

export function optStr(v: unknown, field: string, opts: { max?: number; pattern?: RegExp } = {}): string | null {
  if (v === undefined || v === null || v === "") return null;
  return str(v, field, { min: 0, ...opts });
}

export function clientIp(c: Context): string | null {
  return c.req.header("cf-connecting-ip") ?? null;
}
