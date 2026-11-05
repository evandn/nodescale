import { requireVault } from "./app.ts";
import type { CloudflareCreds, TailscaleCreds } from "./vaultCrypto.ts";

/**
 * Provider API clients. Calls go through the control plane's stateless
 * egress route only because these APIs do not allow browser CORS; the
 * credential is attached here, from the in-memory vault, per request.
 */

export class ProviderError extends Error {
  constructor(
    public provider: string,
    public status: number,
    message: string,
  ) {
    super(`${provider}: ${message}`);
  }
}

async function egress<T>(provider: "cloudflare" | "tailscale", path: string, auth: string | null, init: { method?: string; body?: unknown; form?: Record<string, string> } = {}): Promise<T> {
  const headers: Record<string, string> = { "X-Nodescale": "1", Accept: "application/json" };
  if (auth) headers["X-Upstream-Authorization"] = auth;
  let body: string | undefined;
  if (init.form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(init.form).toString();
  } else if (init.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(init.body);
  }
  const res = await fetch(`/api/egress/${provider}/${path}`, { method: init.method ?? "GET", headers, body, credentials: "same-origin" });
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    if (data && typeof data === "object") {
      const d = data as { message?: string; error?: string; errors?: { message: string }[] };
      msg = d.errors?.[0]?.message ?? d.message ?? d.error ?? msg;
    }
    throw new ProviderError(provider, res.status, msg);
  }
  return data as T;
}

// ---------------------------------------------------------------------------
// Tailscale

export interface TailscaleDevice {
  id: string;
  nodeId: string;
  name: string;
  hostname: string;
  addresses: string[];
  os: string;
  tags?: string[];
  lastSeen: string;
  connectedToControl?: boolean;
  authorized: boolean;
}

export { RELAY_TAG, SERVER_TAG } from "./tags.ts";

let tsToken: { forSecret: string; token: string; exp: number } | null = null;

async function tailscaleAuth(c: TailscaleCreds): Promise<string> {
  if (c.kind === "apikey") return `Bearer ${c.secret}`;
  if (tsToken && tsToken.forSecret === c.secret && tsToken.exp > Date.now() + 60_000) return `Bearer ${tsToken.token}`;
  const r = await egress<{ access_token: string; expires_in: number }>("tailscale", "oauth/token", null, {
    method: "POST",
    form: { client_id: c.clientId ?? "", client_secret: c.secret },
  });
  tsToken = { forSecret: c.secret, token: r.access_token, exp: Date.now() + r.expires_in * 1000 };
  return `Bearer ${r.access_token}`;
}

function tsCreds(): TailscaleCreds {
  const c = requireVault().tailscale;
  if (!c) throw new Error("Add your Tailscale credentials in Settings → Integrations first");
  return c;
}

async function ts<T>(path: string, init: { method?: string; body?: unknown } = {}, creds = tsCreds()): Promise<T> {
  return egress<T>("tailscale", path, await tailscaleAuth(creds), init);
}

export const tailscale = {
  tailnet: (c = tsCreds()) => encodeURIComponent(c.tailnet || "-"),

  async listDevices(creds?: TailscaleCreds): Promise<TailscaleDevice[]> {
    const c = creds ?? tsCreds();
    const r = await ts<{ devices: TailscaleDevice[] }>(`tailnet/${tailscale.tailnet(c)}/devices`, {}, c);
    return r.devices;
  },

  async createAuthKey(opts: { tags: string[]; ephemeral: boolean; reusable?: boolean; expirySeconds: number; description: string }): Promise<string> {
    const r = await ts<{ key: string }>(`tailnet/${tailscale.tailnet()}/keys`, {
      method: "POST",
      body: {
        capabilities: { devices: { create: { reusable: !!opts.reusable, ephemeral: opts.ephemeral, preauthorized: true, tags: opts.tags } } },
        expirySeconds: opts.expirySeconds,
        description: opts.description.slice(0, 50),
      },
    });
    return r.key;
  },

  async setDeviceTags(deviceId: string, tags: string[]) {
    await ts(`device/${encodeURIComponent(deviceId)}/tags`, { method: "POST", body: { tags } });
  },
};

// ---------------------------------------------------------------------------
// Cloudflare

export interface Tunnel {
  id: string;
  name: string;
  status: "inactive" | "degraded" | "healthy" | "down";
  created_at: string;
  connections: { colo_name: string; origin_ip: string; opened_at: string; client_version: string }[];
}

export interface IngressRule {
  hostname?: string;
  service: string;
  path?: string;
  originRequest?: Record<string, unknown>;
}

export interface Zone {
  id: string;
  name: string;
  status: string;
}

export interface DnsRecord {
  id: string;
  name: string;
  type: string;
  content: string;
  proxied: boolean;
}

function cfCreds(): CloudflareCreds {
  const c = requireVault().cloudflare;
  if (!c) throw new Error("Add your Cloudflare API token in Settings → Integrations first");
  return c;
}

async function cf<T>(path: string, init: { method?: string; body?: unknown } = {}, creds = cfCreds()): Promise<T> {
  const r = await egress<{ success: boolean; result: T; errors: { message: string }[] }>("cloudflare", path, `Bearer ${creds.apiToken}`, init);
  if (!r.success) throw new ProviderError("cloudflare", 200, r.errors?.[0]?.message ?? "request failed");
  return r.result;
}

const acct = (c = cfCreds()) => `accounts/${encodeURIComponent(c.accountId)}`;

export const cloudflare = {
  async verify(creds: CloudflareCreds) {
    try {
      return await cf<{ status: string }>(`${acct(creds)}/tokens/verify`, {}, creds);
    } catch {
      return cf<{ status: string }>(`user/tokens/verify`, {}, creds);
    }
  },
  listTunnels: () => cf<Tunnel[]>(`${acct()}/cfd_tunnel?is_deleted=false&per_page=100`),
  createTunnel: (name: string) =>
    cf<Tunnel & { token?: string }>(`${acct()}/cfd_tunnel`, { method: "POST", body: { name, config_src: "cloudflare", tunnel_secret: randomSecret() } }),
  tunnelToken: (id: string) => cf<string>(`${acct()}/cfd_tunnel/${id}/token`),
  deleteTunnel: (id: string) => cf(`${acct()}/cfd_tunnel/${id}`, { method: "DELETE" }),
  async getIngress(id: string): Promise<IngressRule[]> {
    const r = await cf<{ config: { ingress?: IngressRule[] } | null }>(`${acct()}/cfd_tunnel/${id}/configurations`);
    return r.config?.ingress ?? [];
  },
  /** Replaces the routes; the mandatory catch-all is appended automatically. */
  putIngress: (id: string, rules: IngressRule[]) =>
    cf(`${acct()}/cfd_tunnel/${id}/configurations`, {
      method: "PUT",
      body: { config: { ingress: [...rules.filter((r) => r.hostname), { service: "http_status:404" }] } },
    }),
  listZones: () => cf<Zone[]>(`zones?account.id=${encodeURIComponent(cfCreds().accountId)}&per_page=50`),
  findDns: (zoneId: string, name: string) => cf<DnsRecord[]>(`zones/${zoneId}/dns_records?name=${encodeURIComponent(name)}`),
  createTunnelCname: (zoneId: string, name: string, tunnelId: string) =>
    cf<DnsRecord>(`zones/${zoneId}/dns_records`, {
      method: "POST",
      body: { type: "CNAME", name, content: `${tunnelId}.cfargotunnel.com`, proxied: true, comment: "managed by nodescale" },
    }),
  deleteDns: (zoneId: string, id: string) => cf(`zones/${zoneId}/dns_records/${id}`, { method: "DELETE" }),
};

function randomSecret() {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...b));
}
