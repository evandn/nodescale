/**
 * Operation catalogue. Mirrors `Ops` in agent/internal/agent/auth.go — the
 * agent is the source of truth and rejects anything it does not list.
 */
export type Level = "public" | "read" | "operate" | "admin";
export type Role = "viewer" | "operator" | "admin";
export type Scope = "read" | "operate";

export const LEVELS: Level[] = ["public", "read", "operate", "admin"];

export const OPS = {
  "agent.hello": { level: "public", label: "Identify agent" },

  "agent.info": { level: "read", label: "Read agent info" },
  "system.info": { level: "read", label: "Read system info" },
  "containers.list": { level: "read", label: "List containers" },
  "containers.inspect": { level: "read", label: "Inspect container" },
  "containers.logs": { level: "read", label: "Read container logs" },
  "containers.stats": { level: "read", label: "Read container stats" },
  "images.list": { level: "read", label: "List images" },
  "networks.list": { level: "read", label: "List networks" },
  "signers.list": { level: "read", label: "List trusted passkeys" },

  "containers.start": { level: "operate", label: "Start container" },
  "containers.stop": { level: "operate", label: "Stop container" },
  "containers.restart": { level: "operate", label: "Restart container" },

  "containers.create": { level: "admin", label: "Create container" },
  "containers.remove": { level: "admin", label: "Remove container" },
  "images.pull": { level: "admin", label: "Pull image" },
  "images.remove": { level: "admin", label: "Remove image" },
  "signers.add": { level: "admin", label: "Trust a passkey" },
  "signers.remove": { level: "admin", label: "Revoke a passkey" },
} as const satisfies Record<string, { level: Level; label: string }>;

export type Op = keyof typeof OPS;

export function levelOf(op: Op): Level {
  return OPS[op].level;
}

export function rank(l: Level): number {
  return LEVELS.indexOf(l);
}

export const ROLE_LEVEL: Record<Role, Level> = { viewer: "read", operator: "operate", admin: "admin" };

/** Whether a session key with `scope` may sign `op` (admin ops never can). */
export function sessionCanSign(scope: Scope, op: Op): boolean {
  const l = levelOf(op);
  return l !== "admin" && rank(l) <= rank(scope);
}
