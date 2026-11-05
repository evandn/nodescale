import type { Server } from "../../lib/api.ts";
import { bytes } from "../../lib/hooks.ts";
import { Badge, Card, Code, Spinner } from "../../components/ui.tsx";
import { AgentError, Fingerprint, Meter, uptime, useAgent, type HostInfo } from "./shared.tsx";

interface GateInfo {
  agent: string;
  publicKey: string;
  sealKey: string;
  version: string;
  origins: string[];
  signers: number;
  policy: {
    maxSessionSeconds: number;
    allowSessionScopes: string[];
    containers: { allowPrivileged?: boolean; allowHostNamespaces?: boolean; allowDevices?: boolean; allowPublishedPorts?: boolean; bindMountPrefixes: string[] };
  };
}

export function OverviewTab({ server }: { server: Server }) {
  const host = useAgent<HostInfo>(server, "host.info");
  const docker = useAgent<Record<string, string | number>>(server, "system.info");
  const gate = useAgent<GateInfo>(server, "agent.info");

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <Card title="Host" className="lg:col-span-2">
        {host.error ? (
          <AgentError error={host.error} onRetry={() => void host.reload()} />
        ) : !host.data ? (
          <Spinner />
        ) : (
          <div className="space-y-5">
            <div className="grid gap-4 sm:grid-cols-3">
              <Meter label={`Load (${host.data.cpus} CPUs)`} used={host.data.load[0]} total={host.data.cpus} format={(n) => n.toFixed(2)} />
              <Meter label="Memory" used={host.data.memTotal - host.data.memAvailable} total={host.data.memTotal} format={bytes} />
              {host.data.disks.map((d) => (
                <Meter key={d.path} label={`Disk ${d.path}`} used={d.total - d.free} total={d.total} format={bytes} />
              ))}
            </div>
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
              {(
                [
                  ["Hostname", host.data.hostname],
                  ["OS", host.data.os],
                  ["Kernel", host.data.kernel],
                  ["Uptime", uptime(host.data.uptime)],
                  ["Docker", docker.data?.serverVersion ?? "…"],
                  ["Containers", docker.data ? `${docker.data.containersRunning} running / ${docker.data.containers}` : "…"],
                  ["Images", docker.data?.images ?? "…"],
                  ["Arch", host.data.arch],
                ] as const
              ).map(([k, v]) => (
                <div key={k}>
                  <dt className="text-xs text-zinc-500">{k}</dt>
                  <dd className="truncate">{v}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}
      </Card>

      <Card title="nodescale gate">
        {gate.error ? (
          <AgentError error={gate.error} onRetry={() => void gate.reload()} />
        ) : !gate.data ? (
          <Spinner />
        ) : (
          <dl className="space-y-2.5 text-sm">
            <div>
              <dt className="text-xs text-zinc-500">Identity</dt>
              <dd className="truncate font-mono text-xs">{gate.data.agent}</dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Secret sealing key</dt>
              <dd>
                <Fingerprint publicKey={gate.data.sealKey} />
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-zinc-500">Version</dt>
              <dd>{gate.data.version}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-zinc-500">Trusted passkeys</dt>
              <dd>{gate.data.signers}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-zinc-500">Max session</dt>
              <dd>{Math.round(gate.data.policy.maxSessionSeconds / 3600)}h ({gate.data.policy.allowSessionScopes.join(", ")})</dd>
            </div>
            <div>
              <dt className="mb-1 text-xs text-zinc-500">Container policy</dt>
              <dd className="flex flex-wrap gap-1">
                {(
                  [
                    ["privileged", gate.data.policy.containers.allowPrivileged],
                    ["host namespaces", gate.data.policy.containers.allowHostNamespaces],
                    ["devices", gate.data.policy.containers.allowDevices],
                    ["published ports", gate.data.policy.containers.allowPublishedPorts],
                  ] as const
                ).map(([k, v]) => (
                  <Badge key={k} tone={v ? "yellow" : "green"}>
                    {v ? "allows" : "denies"} {k}
                  </Badge>
                ))}
              </dd>
              <dd className="mt-2 text-xs text-zinc-500">
                Bind mounts only from {gate.data.policy.containers.bindMountPrefixes.map((p) => <Code key={p}>{p}</Code>)}
              </dd>
            </div>
            <p className="pt-1 text-xs text-zinc-500">
              The policy is set by root on the server in <Code>/etc/nodescale/gate.json</Code> and cannot be changed from the console.
            </p>
          </dl>
        )}
      </Card>
    </div>
  );
}
