import { Container, getContainer } from "@cloudflare/containers";
import type { Env } from "./env.ts";

/**
 * One relay container per workspace. It joins the workspace's tailnet as an
 * ephemeral node tagged `tag:nodescale-relay`, using a single-use auth key
 * minted by a user's browser, and forwards already-signed requests to agents
 * over Tailscale SSH. It holds nothing that can authorise an action.
 */
export class Relay extends Container<Env> {
  override defaultPort = 8080;
  override sleepAfter = "30m";
  override enableInternet = true;
  // Field initialisers run after the base constructor has set `this.env`.
  override envVars = { RELAY_SECRET: this.env.RELAY_SECRET };
}

export interface RelayStatus {
  state: "down" | "starting" | "up" | "error";
  error?: string;
  hostname?: string;
  ips?: string[] | null;
}

export async function relayFetch(env: Env, workspaceId: string, path: string, init: RequestInit = {}): Promise<Response> {
  if (!env.RELAY_SECRET || env.RELAY_SECRET.length < 32) {
    return Response.json({ error: "RELAY_SECRET is not configured" }, { status: 503 });
  }
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${env.RELAY_SECRET}`);
  if (init.body) headers.set("Content-Type", "application/json");
  try {
    // Local development only: talk to a relay process on this machine
    // instead of a Cloudflare Container.
    if (env.RELAY_DEV_URL && env.ORIGIN.startsWith("http://localhost")) {
      return await fetch(new Request(`${env.RELAY_DEV_URL}${path}`, { ...init, headers }));
    }
    const stub = getContainer(env.RELAY, workspaceId);
    return await stub.fetch(new Request(`http://relay${path}`, { ...init, headers }));
  } catch (e) {
    return Response.json({ error: `relay unavailable: ${(e as Error).message}` }, { status: 503 });
  }
}
