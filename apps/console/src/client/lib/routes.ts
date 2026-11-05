import { recordAudit } from "./api.ts";
import { cloudflare, type IngressRule, type Zone } from "./providers.ts";

let zonesCache: { at: number; zones: Zone[] } | null = null;

async function zones(): Promise<Zone[]> {
  if (!zonesCache || Date.now() - zonesCache.at > 60_000) zonesCache = { at: Date.now(), zones: await cloudflare.listZones() };
  return zonesCache.zones;
}

/** Finds the most specific zone that contains `hostname`. */
export async function zoneFor(hostname: string): Promise<Zone> {
  const z = (await zones()).filter((z) => hostname === z.name || hostname.endsWith("." + z.name)).sort((a, b) => b.name.length - a.name.length)[0];
  if (!z) throw new Error(`No Cloudflare zone in this account covers ${hostname}`);
  return z;
}

/**
 * Points `hostname` at `service` through a tunnel: upserts the ingress rule
 * and creates the proxied CNAME if needed. Refuses to take over a DNS record
 * that points elsewhere.
 */
export async function ensureRoute(tunnelId: string, tunnelName: string, hostname: string, service: string): Promise<"created" | "updated" | "unchanged"> {
  const zone = await zoneFor(hostname);
  const target = `${tunnelId}.cfargotunnel.com`;
  const existing = await cloudflare.findDns(zone.id, hostname);
  if (existing.some((r) => !(r.type === "CNAME" && r.content === target))) {
    throw new Error(`${hostname} already has a DNS record that does not point to this tunnel; remove it first`);
  }
  const rules = (await cloudflare.getIngress(tunnelId)).filter((r) => r.hostname);
  const current = rules.find((r) => r.hostname === hostname && !r.path);
  let result: "created" | "updated" | "unchanged" = "unchanged";
  if (!current || current.service !== service) {
    const next: IngressRule[] = [...rules.filter((r) => !(r.hostname === hostname && !r.path)), { hostname, service }];
    await cloudflare.putIngress(tunnelId, next);
    result = current ? "updated" : "created";
  }
  if (!existing.length) {
    await cloudflare.createTunnelCname(zone.id, hostname, tunnelId);
    result = result === "unchanged" ? "updated" : result;
  }
  if (result !== "unchanged") recordAudit("tunnel.route.add", true, `${hostname} → ${service} (${tunnelName})`);
  return result;
}

/** Removes a hostname from a tunnel and deletes its CNAME. */
export async function removeRoute(tunnelId: string, tunnelName: string, hostname: string) {
  const rules = (await cloudflare.getIngress(tunnelId)).filter((r) => r.hostname);
  await cloudflare.putIngress(tunnelId, rules.filter((r) => r.hostname !== hostname));
  const zone = await zoneFor(hostname).catch(() => null);
  if (zone) {
    for (const rec of await cloudflare.findDns(zone.id, hostname)) {
      if (rec.type === "CNAME" && rec.content === `${tunnelId}.cfargotunnel.com`) await cloudflare.deleteDns(zone.id, rec.id);
    }
  }
  recordAudit("tunnel.route.remove", true, `${hostname} (${tunnelName})`);
}
