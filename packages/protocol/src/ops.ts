/**
 * Operation catalogue. Mirrors `Ops` in gate/internal/gate/auth.go; the gate
 * on each server is the source of truth and rejects anything it does not
 * list. A test keeps the two tables identical.
 */
export type Level = "public" | "read" | "operate" | "admin";
export type Role = "viewer" | "operator" | "admin";
export type Scope = "read" | "operate";

export const LEVELS: Level[] = ["public", "read", "operate", "admin"];

export const OPS = {
  "agent.hello": { level: "public", label: "Identify server" },

  "agent.info": { level: "read", label: "Read gate info" },
  "audit.read": { level: "read", label: "Read server audit log" },
  "host.info": { level: "read", label: "Read host stats" },
  "system.info": { level: "read", label: "Read Docker info" },
  "system.df": { level: "read", label: "Read disk usage" },
  "containers.list": { level: "read", label: "List containers" },
  "containers.inspect": { level: "read", label: "Inspect container" },
  "containers.logs": { level: "read", label: "Read container logs" },
  "containers.stats": { level: "read", label: "Read container stats" },
  "containers.top": { level: "read", label: "List container processes" },
  "images.list": { level: "read", label: "List images" },
  "networks.list": { level: "read", label: "List networks" },
  "volumes.list": { level: "read", label: "List volumes" },
  "signers.list": { level: "read", label: "List trusted passkeys" },

  "containers.start": { level: "operate", label: "Start container" },
  "containers.stop": { level: "operate", label: "Stop container" },
  "containers.restart": { level: "operate", label: "Restart container" },
  "containers.kill": { level: "operate", label: "Kill container" },
  "containers.pause": { level: "operate", label: "Pause container" },
  "containers.unpause": { level: "operate", label: "Resume container" },

  "containers.create": { level: "admin", label: "Create container" },
  "containers.remove": { level: "admin", label: "Remove container" },
  "containers.rename": { level: "admin", label: "Rename container" },
  "containers.update": { level: "admin", label: "Update container limits" },
  "containers.exec": { level: "admin", label: "Run command in container" },
  "containers.env": { level: "admin", label: "Reveal environment" },
  "images.pull": { level: "admin", label: "Pull image" },
  "images.remove": { level: "admin", label: "Remove image" },
  "images.prune": { level: "admin", label: "Prune images" },
  "networks.create": { level: "admin", label: "Create network" },
  "networks.remove": { level: "admin", label: "Remove network" },
  "volumes.create": { level: "admin", label: "Create volume" },
  "volumes.remove": { level: "admin", label: "Remove volume" },
  "stacks.deploy": { level: "admin", label: "Deploy stack" },
  "stacks.remove": { level: "admin", label: "Remove stack" },
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
