import type { Relay } from "./relay.ts";

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  RELAY: DurableObjectNamespace<Relay>;
  /** WebAuthn relying-party ID, e.g. "nodescale.example.com". */
  RP_ID: string;
  /** Exact public origin, e.g. "https://nodescale.example.com". */
  ORIGIN: string;
  /** "invite" (default) or "open". The very first user can always sign up. */
  SIGNUP?: string;
  /** Shared secret between the Worker and the relay container. */
  RELAY_SECRET: string;
  AUTH_LIMITER?: RateLimit;
  /** Gate release used by generated install scripts. */
  GATE_REPO?: string;
  GATE_VERSION?: string;
  GATE_SHA256_AMD64?: string;
  GATE_SHA256_ARM64?: string;
  /** Optional mirror for gate binaries (must serve SHA256SUMS too). */
  GATE_BASE_URL?: string;
  /** Development only (honoured when ORIGIN is http://localhost…). */
  RELAY_DEV_URL?: string;
}

export interface SessionUser {
  id: string;
  name: string;
  sessionId: string;
  credentialId: string | null;
  workspaceId: string;
  role: WorkspaceRole;
}

export type WorkspaceRole = "owner" | "admin" | "member";

export type AppEnv = { Bindings: Env; Variables: { user: SessionUser } };
