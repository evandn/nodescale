export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers: { "X-Nodescale": "1", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const err = data && typeof data === "object" && "error" in data ? String((data as { error: unknown }).error) : "";
    const msg = err || `HTTP ${res.status}`;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body: unknown = {}) => request<T>("POST", path, body),
  put: <T>(path: string, body: unknown) => request<T>("PUT", path, body),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};

// Shared API types -----------------------------------------------------------

export interface Me {
  user: { id: string; name: string; credentialId: string | null };
  workspace: { id: string; name: string; role: "owner" | "admin" | "member" };
  rp: { id: string; origin: string };
}

export interface Server {
  id: string;
  name: string;
  provider: string | null;
  notes: string | null;
  tailnetIp: string | null;
  tailnetName: string | null;
  deviceId: string | null;
  agentId: string | null;
  agentPublicKey: string | null;
  status: "pending" | "active";
  lastSeenAt: number | null;
  createdAt: number;
  tunnelId: string | null;
}

export interface StackDef {
  name: string;
  compose: string;
  updatedAt: number;
  deployedAt: number | null;
  updatedBy: string | null;
}

export interface PasskeyInfo {
  id: string;
  label: string;
  alg: number;
  publicKey: string;
  prf: boolean;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface Member {
  id: string;
  name: string;
  role: "owner" | "admin" | "member";
  joinedAt: number;
  passkeys: { id: string; label: string; alg: number; publicKey: string; createdAt: number }[];
}

export interface AuditEvent {
  id: number;
  action: string;
  ok: boolean;
  detail: string | null;
  requestHash: string | null;
  createdAt: number;
  ip: string | null;
  userName: string | null;
  serverName: string | null;
  serverId: string | null;
  /** "relay" = recorded by the console while relaying; "browser" = reported by a client. */
  source: "relay" | "browser";
}

export function recordAudit(action: string, ok: boolean, detail?: string, serverId?: string) {
  void api.post("/audit", { action, ok, detail, serverId }).catch(() => {});
}
