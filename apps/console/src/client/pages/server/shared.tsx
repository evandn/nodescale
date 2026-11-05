import { OPS, fingerprint, type Op } from "@nodescale/protocol";
import { useEffect, useState, type ReactNode } from "react";
import type { Server } from "../../lib/api.ts";
import { callAgent, NotPinnedError, type CallOptions } from "../../lib/agent.ts";
import { useAsync } from "../../lib/hooks.ts";
import { Button, Callout, confirmAction, cx, toast } from "../../components/ui.tsx";

export function useAgent<T>(server: Server, op: Op, args?: unknown, deps: unknown[] = []) {
  return useAsync(() => callAgent<T>(server, op, args), [server.id, op, ...deps]);
}

export function AgentError({ error, onRetry }: { error: Error; onRetry: () => void }) {
  return (
    <Callout tone={error instanceof NotPinnedError ? "yellow" : "red"} title="Could not complete the request">
      <p className="break-words">{error.message}</p>
      <Button size="sm" className="mt-2" onClick={onRetry}>
        Retry
      </Button>
    </Callout>
  );
}

/**
 * Runs an operation. Admin operations are described first, because browsers
 * cannot show custom text in the passkey prompt itself.
 */
export async function run(server: Server, op: Op, args: unknown, describe: ReactNode, opts: CallOptions & { danger?: boolean; quiet?: boolean } = {}): Promise<boolean> {
  const admin = OPS[op].level === "admin";
  if (admin && !(await confirmAction({ title: OPS[op].label, body: describe, confirm: "Sign with passkey", danger: opts.danger ?? /remove|prune/.test(op), passkey: true }))) return false;
  await callAgent(server, op, args, opts);
  if (!opts.quiet) toast(`${OPS[op].label}: done`, "success");
  return true;
}

export function Fingerprint({ publicKey, className }: { publicKey: string; className?: string }) {
  const [fp, setFp] = useState("");
  useEffect(() => {
    void fingerprint(publicKey).then(setFp);
  }, [publicKey]);
  return <span className={cx("font-mono text-xs text-zinc-500", className)}>{fp}</span>;
}

export function Meter({ label, used, total, format, warn = 0.8 }: { label: string; used: number; total: number; format: (n: number) => string; warn?: number }) {
  const pct = total > 0 ? Math.min(1, used / total) : 0;
  return (
    <div>
      <div className="mb-1 flex justify-between text-xs">
        <span className="font-medium text-zinc-600 dark:text-zinc-400">{label}</span>
        <span className="tabular-nums text-zinc-500">
          {format(used)} / {format(total)}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
        <div className={cx("h-full rounded-full", pct > 0.9 ? "bg-red-500" : pct > warn ? "bg-amber-500" : "bg-indigo-500")} style={{ width: `${Math.max(2, pct * 100)}%` }} />
      </div>
    </div>
  );
}

export interface HostInfo {
  hostname: string;
  os: string;
  kernel: string;
  arch: string;
  cpus: number;
  uptime: number;
  load: [number, number, number];
  memTotal: number;
  memAvailable: number;
  swapTotal: number;
  swapFree: number;
  disks: { path: string; total: number; free: number }[];
}

export interface Container {
  id: string;
  names: string[];
  image: string;
  state: string;
  status: string;
  created: number;
  labels: Record<string, string> | null;
  ports: { privatePort: number; publicPort?: number; type: string; ip?: string }[];
  networks: string[];
}

export const containerName = (c: Container) => c.names[0]?.replace(/^\//, "") ?? c.id.slice(0, 12);

export function stateTone(state: string): "green" | "gray" | "yellow" | "red" {
  if (state === "running") return "green";
  if (state === "exited" || state === "created") return "gray";
  if (state === "dead") return "red";
  return "yellow";
}

export function uptime(s: number): string {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}
