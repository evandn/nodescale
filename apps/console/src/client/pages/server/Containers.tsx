import { useMemo, useState } from "react";
import type { Server } from "../../lib/api.ts";
import { callAgent, revealEnv } from "../../lib/agent.ts";
import { splitCommand } from "../../lib/compose.ts";
import { timeAgo, useAsync } from "../../lib/hooks.ts";
import {
  ActionButton,
  Badge,
  Button,
  Callout,
  Card,
  Code,
  Empty,
  Field,
  Input,
  KeyIcon,
  Modal,
  PlusIcon,
  RefreshIcon,
  Select,
  Spinner,
  Table,
  Tabs,
  Td,
  Textarea,
} from "../../components/ui.tsx";
import { AgentError, containerName, run, stateTone, useAgent, type Container } from "./shared.tsx";

export function ContainersTab({ server }: { server: Server }) {
  const list = useAgent<Container[]>(server, "containers.list", { all: true });
  const [selected, setSelected] = useState<Container | null>(null);
  const [deploy, setDeploy] = useState(false);
  const [filter, setFilter] = useState("");

  const groups = useMemo(() => {
    const m = new Map<string, Container[]>();
    for (const c of list.data ?? []) {
      if (filter && !`${containerName(c)} ${c.image}`.toLowerCase().includes(filter.toLowerCase())) continue;
      const g = c.labels?.["io.nodescale.stack"] ?? "";
      m.set(g, [...(m.get(g) ?? []), c]);
    }
    return [...m.entries()].sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)));
  }, [list.data, filter]);

  const act = (op: "containers.start" | "containers.stop" | "containers.restart" | "containers.pause" | "containers.unpause", c: Container) => () => run(server, op, { id: c.id }, "").then(() => list.reload());

  return (
    <Card
      padded={false}
      title="Containers"
      actions={
        <>
          <Input className="w-48 py-1 text-xs" placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <Button size="sm" variant="ghost" onClick={() => void list.reload()}>
            <RefreshIcon /> Refresh
          </Button>
          <Button size="sm" variant="primary" onClick={() => setDeploy(true)}>
            <PlusIcon /> Run container
          </Button>
        </>
      }
    >
      {list.error ? (
        <div className="p-5">
          <AgentError error={list.error} onRetry={() => void list.reload()} />
        </div>
      ) : list.loading && !list.data ? (
        <div className="p-5">
          <Spinner className="size-5 text-zinc-400" />
        </div>
      ) : !list.data?.length ? (
        <div className="p-5">
          <Empty title="No containers">Run a single container, or deploy a stack from the Stacks tab.</Empty>
        </div>
      ) : (
        <Table head={["Name", "Image", "State", "Networks", ""]}>
          {groups.map(([stack, cs]) => [
            stack && (
              <tr key={`g-${stack}`} className="bg-zinc-50/70 dark:bg-zinc-800/30">
                <td colSpan={5} className="px-5 py-1.5 text-xs font-medium text-zinc-500">
                  stack <span className="text-zinc-800 dark:text-zinc-200">{stack}</span>
                </td>
              </tr>
            ),
            ...cs.map((c) => (
              <tr key={c.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/40">
                <Td>
                  <button type="button" className="font-medium text-zinc-900 hover:text-indigo-600 dark:text-zinc-100" onClick={() => setSelected(c)}>
                    {containerName(c)}
                  </button>
                </Td>
                <Td className="max-w-64 truncate font-mono text-xs">{c.image}</Td>
                <Td>
                  <Badge tone={stateTone(c.state)}>{c.state}</Badge>
                  <span className="ml-2 text-xs text-zinc-500">{c.status}</span>
                </Td>
                <Td className="text-xs">{c.networks.join(", ")}</Td>
                <Td className="text-right">
                  <div className="flex justify-end gap-1">
                    <Button size="sm" variant="ghost" onClick={() => setSelected(c)}>
                      Details
                    </Button>
                    {c.state === "running" ? (
                      <>
                        <ActionButton size="sm" variant="ghost" action={act("containers.restart", c)}>
                          Restart
                        </ActionButton>
                        <ActionButton size="sm" variant="ghost" action={act("containers.stop", c)}>
                          Stop
                        </ActionButton>
                      </>
                    ) : c.state === "paused" ? (
                      <ActionButton size="sm" variant="ghost" action={act("containers.unpause", c)}>
                        Resume
                      </ActionButton>
                    ) : (
                      <ActionButton size="sm" variant="ghost" action={act("containers.start", c)}>
                        Start
                      </ActionButton>
                    )}
                    <ActionButton
                      size="sm"
                      variant="ghost"
                      className="text-red-600 dark:text-red-400"
                      action={async () => {
                        const note = c.labels?.["io.nodescale.stack"] ? " It belongs to a stack; redeploying the stack will recreate it." : "";
                        if (await run(server, "containers.remove", { id: c.id, force: true }, `Permanently remove container “${containerName(c)}” (${c.image}) on ${server.name}. Named volumes are kept.${note}`)) await list.reload();
                      }}
                    >
                      Remove
                    </ActionButton>
                  </div>
                </Td>
              </tr>
            )),
          ])}
        </Table>
      )}
      <ContainerModal server={server} container={selected} onClose={() => setSelected(null)} onChanged={() => void list.reload()} />
      <RunModal server={server} open={deploy} onClose={() => setDeploy(false)} onDone={() => void list.reload()} />
    </Card>
  );
}

// ---------------------------------------------------------------------------

type DetailTab = "overview" | "logs" | "env" | "exec" | "top";

interface Inspect {
  Id: string;
  Created: string;
  State: { Status: string; StartedAt: string; ExitCode: number; Health?: { Status: string } };
  RestartCount: number;
  Config: { Image: string; Env: string[] | null; Cmd: string[] | null; Entrypoint: string[] | null; Labels: Record<string, string> | null; User: string; WorkingDir: string };
  HostConfig: { RestartPolicy: { Name: string }; Memory: number; NanoCpus: number };
  Mounts: { Type: string; Name?: string; Source: string; Destination: string; RW: boolean }[];
  NetworkSettings: { Networks: Record<string, { IPAddress: string; Aliases: string[] | null }> };
}

function ContainerModal({ server, container, onClose, onChanged }: { server: Server; container: Container | null; onClose: () => void; onChanged: () => void }) {
  const [tab, setTab] = useState<DetailTab>("overview");
  return (
    <Modal open={!!container} onClose={onClose} wide title={container ? containerName(container) : ""} footer={<Button onClick={onClose}>Close</Button>}>
      {container && (
        <>
          <Tabs
            value={tab}
            onChange={setTab}
            tabs={[
              { id: "overview", label: "Overview" },
              { id: "logs", label: "Logs" },
              { id: "env", label: "Environment" },
              { id: "exec", label: "Run command" },
              { id: "top", label: "Processes" },
            ]}
          />
          {tab === "overview" && <InspectView server={server} id={container.id} onChanged={onChanged} />}
          {tab === "logs" && <LogsView server={server} id={container.id} />}
          {tab === "env" && <EnvView server={server} id={container.id} />}
          {tab === "exec" && <ExecView server={server} id={container.id} />}
          {tab === "top" && <TopView server={server} id={container.id} />}
        </>
      )}
    </Modal>
  );
}

function InspectView({ server, id, onChanged }: { server: Server; id: string; onChanged: () => void }) {
  const i = useAgent<Inspect>(server, "containers.inspect", { id }, [id]);
  const [restart, setRestart] = useState("");
  if (i.error) return <AgentError error={i.error} onRetry={() => void i.reload()} />;
  if (!i.data) return <Spinner />;
  const d = i.data;
  return (
    <div className="space-y-4 text-sm">
      <dl className="grid grid-cols-2 gap-x-6 gap-y-2">
        <div>
          <dt className="text-xs text-zinc-500">Image</dt>
          <dd className="truncate font-mono text-xs">{d.Config.Image}</dd>
        </div>
        <div>
          <dt className="text-xs text-zinc-500">State</dt>
          <dd>
            {d.State.Status}
            {d.State.Health && ` · ${d.State.Health.Status}`} · started {timeAgo(Date.parse(d.State.StartedAt) / 1000)}
            {d.RestartCount > 0 && ` · ${d.RestartCount} restarts`}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-zinc-500">Command</dt>
          <dd className="truncate font-mono text-xs">{[...(d.Config.Entrypoint ?? []), ...(d.Config.Cmd ?? [])].join(" ") || "—"}</dd>
        </div>
        <div>
          <dt className="text-xs text-zinc-500">Limits</dt>
          <dd>
            {d.HostConfig.Memory ? `${Math.round(d.HostConfig.Memory / 1048576)} MiB` : "no memory limit"} · {d.HostConfig.NanoCpus ? `${d.HostConfig.NanoCpus / 1e9} CPUs` : "no CPU limit"}
          </dd>
        </div>
      </dl>
      <div>
        <p className="mb-1 text-xs text-zinc-500">Networks</p>
        {Object.entries(d.NetworkSettings.Networks).map(([n, v]) => (
          <p key={n} className="text-xs">
            <Code>{n}</Code> {v.IPAddress} {v.Aliases?.length ? `(aliases: ${v.Aliases.join(", ")})` : ""}
          </p>
        ))}
      </div>
      <div>
        <p className="mb-1 text-xs text-zinc-500">Mounts</p>
        {d.Mounts.length ? (
          d.Mounts.map((m) => (
            <p key={m.Destination} className="text-xs">
              <Code>{m.Type === "volume" ? m.Name : m.Source}</Code> → <Code>{m.Destination}</Code> {m.RW ? "" : "(read-only)"}
            </p>
          ))
        ) : (
          <p className="text-xs text-zinc-500">none</p>
        )}
      </div>
      <div className="flex items-end gap-2 border-t border-zinc-200 pt-4 dark:border-zinc-800">
        <Field label="Restart policy">
          <Select className="w-44" value={restart || d.HostConfig.RestartPolicy.Name || "no"} onChange={(e) => setRestart(e.target.value)}>
            {["no", "always", "unless-stopped", "on-failure"].map((p) => (
              <option key={p}>{p}</option>
            ))}
          </Select>
        </Field>
        <ActionButton
          disabled={!restart || restart === d.HostConfig.RestartPolicy.Name}
          action={async () => {
            if (await run(server, "containers.update", { id, restart }, `Set the restart policy of this container to “${restart}”.`)) {
              await i.reload();
              onChanged();
            }
          }}
        >
          <KeyIcon /> Update
        </ActionButton>
      </div>
    </div>
  );
}

function LogsView({ server, id }: { server: Server; id: string }) {
  const [tail, setTail] = useState(300);
  const logs = useAgent<{ stream: string; text: string }[]>(server, "containers.logs", { id, tail }, [id, tail]);
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Select className="w-40" value={tail} onChange={(e) => setTail(Number(e.target.value))}>
          {[100, 300, 1000, 5000].map((n) => (
            <option key={n} value={n}>
              Last {n} lines
            </option>
          ))}
        </Select>
        <Button size="sm" variant="ghost" onClick={() => void logs.reload()}>
          <RefreshIcon /> Refresh
        </Button>
      </div>
      {logs.error ? (
        <AgentError error={logs.error} onRetry={() => void logs.reload()} />
      ) : !logs.data ? (
        <Spinner />
      ) : (
        <pre className="max-h-[50vh] overflow-auto rounded-lg bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-200">
          {logs.data.length ? logs.data.map((l, n) => <div key={n} className={l.stream === "stderr" ? "text-amber-300" : ""}>{l.text}</div>) : <span className="text-zinc-500">No output.</span>}
        </pre>
      )}
    </div>
  );
}

function EnvView({ server, id }: { server: Server; id: string }) {
  const i = useAgent<Inspect>(server, "containers.inspect", { id }, [id]);
  const [revealed, setRevealed] = useState<string[] | null>(null);
  const env = revealed ?? i.data?.Config.Env ?? [];
  return (
    <div className="space-y-3">
      <Callout>
        Values are hidden by the server. Revealing them needs an admin passkey, and the server encrypts them to a key that exists only in this tab: the console never sees them.
      </Callout>
      {i.error ? (
        <AgentError error={i.error} onRetry={() => void i.reload()} />
      ) : !i.data ? (
        <Spinner />
      ) : (
        <>
          <div className="max-h-[45vh] overflow-auto rounded-lg ring-1 ring-zinc-200 dark:ring-zinc-800">
            <table className="w-full text-xs">
              <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800">
                {env.map((e) => {
                  const k = e.split("=")[0];
                  return (
                    <tr key={e}>
                      <td className="px-3 py-1.5 font-mono font-medium">{k}</td>
                      <td className="break-all px-3 py-1.5 font-mono text-zinc-600 dark:text-zinc-400">{e.slice(e.indexOf("=") + 1)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {!revealed && (
            <ActionButton
              action={async () => {
                setRevealed(await revealEnv(server, id));
              }}
            >
              <KeyIcon /> Reveal values
            </ActionButton>
          )}
        </>
      )}
    </div>
  );
}

function ExecView({ server, id }: { server: Server; id: string }) {
  const [cmd, setCmd] = useState("");
  const [result, setResult] = useState<{ exitCode: number; output: { stream: string; text: string }[]; truncated: boolean } | null>(null);
  return (
    <div className="space-y-3">
      <p className="text-sm text-zinc-600 dark:text-zinc-400">
        Runs one command inside the container (no TTY) and shows its output. Each run needs your passkey. For an interactive shell, use <Code>tailscale ssh</Code> with your own identity.
      </p>
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
        }}
      >
        <Input className="font-mono" placeholder="ls -la /app" value={cmd} onChange={(e) => setCmd(e.target.value)} />
        <ActionButton
          variant="primary"
          disabled={!cmd.trim()}
          action={async () => {
            const argv = splitCommand(cmd);
            setResult(null);
            setResult(await callAgent(server, "containers.exec", { id, cmd: argv, timeout: 120 }, { ttl: 120 }));
          }}
        >
          <KeyIcon /> Run
        </ActionButton>
      </form>
      {result && (
        <div>
          <p className="mb-1 text-xs text-zinc-500">
            exit code <Badge tone={result.exitCode === 0 ? "green" : "red"}>{result.exitCode}</Badge> {result.truncated && "· output truncated"}
          </p>
          <pre className="max-h-[45vh] overflow-auto rounded-lg bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-200">
            {result.output.map((l, n) => <div key={n} className={l.stream === "stderr" ? "text-amber-300" : ""}>{l.text}</div>)}
          </pre>
        </div>
      )}
    </div>
  );
}

function TopView({ server, id }: { server: Server; id: string }) {
  const top = useAsync(() => callAgent<{ Titles: string[]; Processes: string[][] }>(server, "containers.top", { id }), [id]);
  if (top.error) return <AgentError error={top.error} onRetry={() => void top.reload()} />;
  if (!top.data) return <Spinner />;
  return (
    <div className="max-h-[50vh] overflow-auto">
      <table className="w-full text-xs">
        <thead>
          <tr>
            {top.data.Titles.map((t) => (
              <th key={t} className="px-2 py-1 text-left font-medium text-zinc-500">
                {t}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-100 font-mono dark:divide-zinc-800">
          {top.data.Processes.map((p, n) => (
            <tr key={n}>
              {p.map((c, k) => (
                <td key={k} className="px-2 py-1">
                  {c}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------

function RunModal({ server, open, onClose, onDone }: { server: Server; open: boolean; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ name: "", image: "", env: "", network: "nodescale", restart: "unless-stopped", volumes: "", command: "" });
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  async function go() {
    const env = f.env
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));
    const mounts = f.volumes
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [source, target, mode] = l.split(":");
        return { type: source!.startsWith("/") ? "bind" : "volume", source, target, readOnly: mode === "ro" };
      });
    const spec = { name: f.name, image: f.image, env, cmd: f.command ? splitCommand(f.command) : undefined, networks: f.network ? [f.network] : undefined, restart: f.restart, mounts, start: true };
    const describe = (
      <div className="space-y-2">
        <p>
          Create and start <strong>{f.name}</strong> from <Code>{f.image}</Code> on <strong>{server.name}</strong>.
        </p>
        <p className="text-xs text-zinc-500">{env.length} environment value(s) will be encrypted to the server before signing.</p>
      </div>
    );
    if (await run(server, "containers.create", spec, describe, { ttl: 300 })) {
      onDone();
      onClose();
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Run container"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <ActionButton variant="primary" disabled={!f.name || !f.image} action={go}>
            <KeyIcon /> Run
          </ActionButton>
        </>
      }
    >
      <Callout>
        For multi-service apps, prefer a stack (Stacks tab). No ports are published: put the container on the <Code>nodescale</Code> network and route a hostname to it from Tunnels.
      </Callout>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Name">
          <Input value={f.name} onChange={set("name")} placeholder="app" />
        </Field>
        <Field label="Image">
          <Input value={f.image} onChange={set("image")} placeholder="ghcr.io/org/app:1.2.3" />
        </Field>
        <Field label="Network">
          <Input value={f.network} onChange={set("network")} />
        </Field>
        <Field label="Restart policy">
          <Select value={f.restart} onChange={set("restart")}>
            {["unless-stopped", "always", "on-failure", "no"].map((p) => (
              <option key={p}>{p}</option>
            ))}
          </Select>
        </Field>
      </div>
      <Field label="Command (optional)">
        <Input className="font-mono" value={f.command} onChange={set("command")} placeholder="--port 8080" />
      </Field>
      <Field label="Environment" hint="One KEY=value per line. Values are encrypted to this server in your browser.">
        <Textarea rows={4} value={f.env} onChange={set("env")} placeholder="PORT=8080" />
      </Field>
      <Field label="Volumes" hint="One per line: name:/path or /srv/host/path:/path[:ro]">
        <Textarea rows={2} value={f.volumes} onChange={set("volumes")} placeholder="appdata:/data" />
      </Field>
    </Modal>
  );
}
