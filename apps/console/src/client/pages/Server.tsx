import { OPS, fingerprint, type Op, type SignerKey } from "@nodescale/protocol";
import { useEffect, useState, type ReactNode } from "react";
import { api, recordAudit, type Member, type Server } from "../lib/api.ts";
import { callAgent, NotPinnedError } from "../lib/agent.ts";
import { app } from "../lib/app.ts";
import { bytes, timeAgo, useAsync } from "../lib/hooks.ts";
import { navigate } from "../lib/router.tsx";
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
  PageHeader,
  PlusIcon,
  RefreshIcon,
  Select,
  ShieldIcon,
  Spinner,
  Table,
  Tabs,
  Td,
  Textarea,
  confirmAction,
  toast,
} from "../components/ui.tsx";
import { TrustServer } from "./TrustServer.tsx";

interface Container {
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

interface Image {
  id: string;
  repoTags: string[];
  created: number;
  size: number;
}

type Tab = "containers" | "images" | "access" | "system";

export function ServerPage({ id }: { id: string }) {
  const server = useAsync(() => api.get<Server>(`/servers/${id}`), [id]);
  const pin = app.use((s) => (s.vault.status === "unlocked" ? s.vault.data.pins[id] : undefined));
  const role = app.use((s) => s.me!.workspace.role);
  const [tab, setTab] = useState<Tab>("containers");

  if (server.loading && !server.data) return <Spinner className="size-5 text-zinc-400" />;
  if (server.error || !server.data) return <p className="text-sm text-red-600">{server.error?.message ?? "Not found"}</p>;
  const s = server.data;

  return (
    <>
      <PageHeader
        title={
          <span className="flex items-center gap-3">
            {s.name}
            {pin ? (
              <Badge tone="green">
                <ShieldIcon className="size-3" /> verified
              </Badge>
            ) : (
              <Badge tone="yellow">unverified</Badge>
            )}
          </span>
        }
        description={
          <span className="font-mono text-xs">
            {s.tailnetIp ?? "no tailnet address"} · {pin?.agentId ?? s.agentId ?? "agent not enrolled"}
          </span>
        }
        actions={
          role !== "member" && (
            <ActionButton
              variant="ghost"
              action={async () => {
                if (!(await confirmAction({ title: `Remove ${s.name}?`, body: "This only removes the server from the console. Nothing on the server is changed; its agent keeps trusting the same passkeys.", confirm: "Remove", danger: true }))) return;
                await api.del(`/servers/${s.id}`);
                recordAudit("server.delete", true, s.name, s.id);
                navigate("/servers");
              }}
            >
              Remove
            </ActionButton>
          )
        }
      />
      {!pin ? (
        <TrustServer server={s} onDone={() => void server.reload()} />
      ) : pin && s.agentId && pin.agentId !== s.agentId ? (
        <Callout tone="red" title="Server identity mismatch">
          The console reports agent <Code>{s.agentId}</Code> but you pinned <Code>{pin.agentId}</Code>. Requests are still addressed to your pinned identity and responses are verified against it. If the server was reinstalled, remove and re-add it.
        </Callout>
      ) : null}
      {pin && (
        <>
          <Tabs
            value={tab}
            onChange={setTab}
            tabs={[
              { id: "containers", label: "Containers" },
              { id: "images", label: "Images" },
              { id: "access", label: "Access" },
              { id: "system", label: "System" },
            ]}
          />
          {tab === "containers" && <ContainersTab server={s} />}
          {tab === "images" && <ImagesTab server={s} />}
          {tab === "access" && <AccessTab server={s} />}
          {tab === "system" && <SystemTab server={s} />}
        </>
      )}
    </>
  );
}

function useAgent<T>(server: Server, op: Op, args?: unknown, deps: unknown[] = []) {
  return useAsync(() => callAgent<T>(server, op, args), [server.id, op, ...deps]);
}

function AgentError({ error, onRetry }: { error: Error; onRetry: () => void }) {
  return (
    <Callout tone={error instanceof NotPinnedError ? "yellow" : "red"} title="Could not reach the agent">
      <p>{error.message}</p>
      <Button size="sm" className="mt-2" onClick={onRetry}>
        Retry
      </Button>
    </Callout>
  );
}

/** Runs a state-changing op, describing admin actions before the passkey prompt. */
async function run(server: Server, op: Op, args: unknown, describe: ReactNode, opts: { ttl?: number } = {}) {
  const admin = OPS[op].level === "admin";
  if (admin && !(await confirmAction({ title: OPS[op].label, body: describe, confirm: "Sign with passkey", danger: op.endsWith("remove"), passkey: true }))) return false;
  await callAgent(server, op, args, opts);
  toast(`${OPS[op].label}: done`, "success");
  return true;
}

// ---------------------------------------------------------------------------

function ContainersTab({ server }: { server: Server }) {
  const list = useAgent<Container[]>(server, "containers.list", { all: true });
  const [logsFor, setLogsFor] = useState<Container | null>(null);
  const [deploy, setDeploy] = useState(false);

  const name = (c: Container) => c.names[0]?.replace(/^\//, "") ?? c.id.slice(0, 12);
  const isAgent = (c: Container) => c.labels?.["io.nodescale.role"] === "agent";

  return (
    <Card
      padded={false}
      title="Containers"
      actions={
        <>
          <Button size="sm" variant="ghost" onClick={() => void list.reload()}>
            <RefreshIcon /> Refresh
          </Button>
          <Button size="sm" variant="primary" onClick={() => setDeploy(true)}>
            <PlusIcon /> Deploy
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
          <Empty title="No containers" />
        </div>
      ) : (
        <Table head={["Name", "Image", "State", "Networks", ""]}>
          {list.data.map((c) => (
            <tr key={c.id}>
              <Td>
                <span className="font-medium text-zinc-900 dark:text-zinc-100">{name(c)}</span>
                {isAgent(c) && (
                  <Badge tone="blue">
                    <ShieldIcon className="size-3" /> agent
                  </Badge>
                )}
              </Td>
              <Td className="max-w-64 truncate font-mono text-xs">{c.image}</Td>
              <Td>
                <Badge tone={c.state === "running" ? "green" : c.state === "exited" ? "gray" : "yellow"}>{c.state}</Badge>
                <span className="ml-2 text-xs text-zinc-500">{c.status}</span>
              </Td>
              <Td className="text-xs">{c.networks.join(", ")}</Td>
              <Td className="text-right">
                <div className="flex justify-end gap-1">
                  <Button size="sm" variant="ghost" onClick={() => setLogsFor(c)}>
                    Logs
                  </Button>
                  {c.state === "running" ? (
                    <>
                      <ActionButton size="sm" variant="ghost" action={() => run(server, "containers.restart", { id: c.id }, "").then(() => list.reload())}>
                        Restart
                      </ActionButton>
                      {!isAgent(c) && (
                        <ActionButton size="sm" variant="ghost" action={() => run(server, "containers.stop", { id: c.id }, "").then(() => list.reload())}>
                          Stop
                        </ActionButton>
                      )}
                    </>
                  ) : (
                    <ActionButton size="sm" variant="ghost" action={() => run(server, "containers.start", { id: c.id }, "").then(() => list.reload())}>
                      Start
                    </ActionButton>
                  )}
                  {!isAgent(c) && (
                    <ActionButton
                      size="sm"
                      variant="ghost"
                      className="text-red-600 dark:text-red-400"
                      action={async () => {
                        if (await run(server, "containers.remove", { id: c.id, force: true }, `Permanently remove container “${name(c)}” (${c.image}) on ${server.name}. Named volumes are kept.`)) await list.reload();
                      }}
                    >
                      Remove
                    </ActionButton>
                  )}
                </div>
              </Td>
            </tr>
          ))}
        </Table>
      )}
      <LogsModal server={server} container={logsFor} onClose={() => setLogsFor(null)} />
      <DeployModal server={server} open={deploy} onClose={() => setDeploy(false)} onDeployed={() => void list.reload()} />
    </Card>
  );
}

function LogsModal({ server, container, onClose }: { server: Server; container: Container | null; onClose: () => void }) {
  const [tail, setTail] = useState(300);
  const logs = useAsync(async () => (container ? callAgent<{ stream: string; text: string }[]>(server, "containers.logs", { id: container.id, tail }) : []), [container?.id, tail]);
  return (
    <Modal open={!!container} onClose={onClose} wide title={`Logs — ${container?.names[0]?.replace(/^\//, "") ?? ""}`} footer={<Button onClick={onClose}>Close</Button>}>
      <div className="flex items-center gap-2">
        <Select className="w-36" value={tail} onChange={(e) => setTail(Number(e.target.value))}>
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
      ) : logs.loading && !logs.data ? (
        <Spinner />
      ) : (
        <pre className="max-h-[55vh] overflow-auto rounded-lg bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-200">
          {logs.data?.map((l, i) => (
            <div key={i} className={l.stream === "stderr" ? "text-amber-300" : ""}>
              {l.text}
            </div>
          ))}
        </pre>
      )}
    </Modal>
  );
}

function DeployModal({ server, open, onClose, onDeployed }: { server: Server; open: boolean; onClose: () => void; onDeployed: () => void }) {
  const [f, setF] = useState({ name: "", image: "", env: "", network: "nodescale", restart: "unless-stopped", volumes: "" });
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  async function deploy() {
    const env = f.env.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    const mounts = f.volumes
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [source, target, mode] = l.split(":");
        return { type: source!.startsWith("/") ? "bind" : "volume", source, target, readOnly: mode === "ro" };
      });
    const spec = { name: f.name, image: f.image, env, network: f.network || undefined, restart: f.restart, mounts, pull: true, start: true };
    const body = (
      <div className="space-y-2">
        <p>
          Create and start <strong>{f.name}</strong> from <Code>{f.image}</Code> on <strong>{server.name}</strong>.
        </p>
        <pre className="max-h-48 overflow-auto rounded bg-zinc-100 p-2 text-xs dark:bg-zinc-800">{JSON.stringify(spec, null, 2)}</pre>
      </div>
    );
    if (await run(server, "containers.create", spec, body, { ttl: 300 })) {
      onDeployed();
      onClose();
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Deploy container"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <ActionButton variant="primary" disabled={!f.name || !f.image} action={deploy}>
            <KeyIcon /> Deploy
          </ActionButton>
        </>
      }
    >
      <Callout>
        No ports are published. Put the container on the <Code>nodescale</Code> network and route a hostname to it (e.g. <Code>http://{f.name || "app"}:8080</Code>) from the Tunnels page.
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
            <option value="unless-stopped">unless-stopped</option>
            <option value="always">always</option>
            <option value="on-failure">on-failure</option>
            <option value="no">no</option>
          </Select>
        </Field>
      </div>
      <Field label="Environment" hint="One KEY=value per line. Values are visible to anyone who can read the request; use Docker secrets for sensitive data.">
        <Textarea rows={4} value={f.env} onChange={set("env")} placeholder="PORT=8080" />
      </Field>
      <Field label="Volumes" hint="One per line: name:/path or /host/path:/path[:ro]">
        <Textarea rows={2} value={f.volumes} onChange={set("volumes")} placeholder="appdata:/data" />
      </Field>
    </Modal>
  );
}

// ---------------------------------------------------------------------------

function ImagesTab({ server }: { server: Server }) {
  const list = useAgent<Image[]>(server, "images.list");
  const [pull, setPull] = useState("");
  return (
    <Card
      padded={false}
      title="Images"
      actions={
        <div className="flex gap-2">
          <Input className="w-64 py-1 text-xs" placeholder="nginx:1.27-alpine" value={pull} onChange={(e) => setPull(e.target.value)} />
          <ActionButton
            size="sm"
            variant="primary"
            disabled={!pull}
            action={async () => {
              if (await run(server, "images.pull", { image: pull }, `Pull image ${pull} onto ${server.name}.`, { ttl: 300 })) {
                setPull("");
                await list.reload();
              }
            }}
          >
            Pull
          </ActionButton>
        </div>
      }
    >
      {list.error ? (
        <div className="p-5">
          <AgentError error={list.error} onRetry={() => void list.reload()} />
        </div>
      ) : !list.data ? (
        <div className="p-5">
          <Spinner />
        </div>
      ) : (
        <Table head={["Tags", "ID", "Size", "Created", ""]}>
          {list.data.map((i) => (
            <tr key={i.id}>
              <Td className="font-mono text-xs">{i.repoTags.join(", ") || <span className="text-zinc-400">&lt;none&gt;</span>}</Td>
              <Td className="font-mono text-xs text-zinc-500">{i.id.replace("sha256:", "").slice(0, 12)}</Td>
              <Td>{bytes(i.size)}</Td>
              <Td className="text-zinc-500">{timeAgo(i.created)}</Td>
              <Td className="text-right">
                <ActionButton
                  size="sm"
                  variant="ghost"
                  className="text-red-600 dark:text-red-400"
                  action={async () => {
                    if (await run(server, "images.remove", { id: i.id }, `Remove image ${i.repoTags[0] ?? i.id} from ${server.name}.`)) await list.reload();
                  }}
                >
                  Remove
                </ActionButton>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------

function Fingerprint({ publicKey }: { publicKey: string }) {
  const [fp, setFp] = useState("");
  useEffect(() => {
    void fingerprint(publicKey).then(setFp);
  }, [publicKey]);
  return <span className="font-mono text-xs text-zinc-500">{fp}</span>;
}

function AccessTab({ server }: { server: Server }) {
  const signers = useAgent<SignerKey[]>(server, "signers.list");
  const members = useAsync(() => api.get<Member[]>("/workspace/members"));
  const [adding, setAdding] = useState<{ key: Member["passkeys"][number]; member: Member } | null>(null);
  const [role, setRole] = useState<SignerKey["role"]>("operator");

  const enrolled = new Set(signers.data?.map((s) => s.id));
  const candidates = (members.data ?? []).flatMap((m) => m.passkeys.filter((k) => !enrolled.has(k.id)).map((key) => ({ key, member: m })));

  return (
    <div className="space-y-6">
      <Callout>
        This list is read from the server itself. Only passkeys listed here can act on <strong>{server.name}</strong>; changing it requires a fresh admin passkey signature. A compromised console cannot add itself.
      </Callout>
      <Card padded={false} title="Trusted passkeys on this server">
        {signers.error ? (
          <div className="p-5">
            <AgentError error={signers.error} onRetry={() => void signers.reload()} />
          </div>
        ) : !signers.data ? (
          <div className="p-5">
            <Spinner />
          </div>
        ) : (
          <Table head={["Passkey", "Role", "Fingerprint", "Added", ""]}>
            {signers.data.map((s) => (
              <tr key={s.id}>
                <Td>
                  <span className="font-medium">{s.label || s.id.slice(0, 12)}</span>
                </Td>
                <Td>
                  <Badge tone={s.role === "admin" ? "blue" : s.role === "operator" ? "green" : "gray"}>{s.role}</Badge>
                </Td>
                <Td>
                  <Fingerprint publicKey={s.publicKey} />
                </Td>
                <Td className="text-zinc-500">{s.addedAt ? `${timeAgo(s.addedAt)} by ${s.addedBy ?? "?"}` : "at install"}</Td>
                <Td className="text-right">
                  <ActionButton
                    size="sm"
                    variant="ghost"
                    className="text-red-600 dark:text-red-400"
                    action={async () => {
                      if (await run(server, "signers.remove", { id: s.id }, `Revoke “${s.label ?? s.id}” on ${server.name}. It will no longer be able to sign any request for this server.`)) await signers.reload();
                    }}
                  >
                    Revoke
                  </ActionButton>
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      {candidates.length > 0 && (
        <Card title="Trust a teammate's passkey">
          <ul className="divide-y divide-zinc-100 dark:divide-zinc-800">
            {candidates.map((c) => (
              <li key={c.key.id} className="flex items-center justify-between py-2.5">
                <div>
                  <p className="text-sm font-medium">
                    {c.member.name} — {c.key.label}
                  </p>
                  <Fingerprint publicKey={c.key.publicKey} />
                </div>
                <Button size="sm" onClick={() => setAdding(c)}>
                  Trust…
                </Button>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <Modal
        open={!!adding}
        onClose={() => setAdding(null)}
        title="Trust passkey"
        footer={
          <>
            <Button onClick={() => setAdding(null)}>Cancel</Button>
            <ActionButton
              variant="primary"
              action={async () => {
                if (!adding) return;
                const k = adding.key;
                await callAgent(server, "signers.add", { id: k.id, alg: k.alg, publicKey: k.publicKey, role, label: `${adding.member.name}: ${k.label}`, user: adding.member.name });
                toast("Passkey trusted", "success");
                setAdding(null);
                await signers.reload();
              }}
            >
              <KeyIcon /> Sign with passkey
            </ActionButton>
          </>
        }
      >
        {adding && (
          <>
            <p className="text-sm">
              Ask <strong>{adding.member.name}</strong> to read out the fingerprint shown in their Settings → Passkeys, and check it matches:
            </p>
            <p className="rounded-lg bg-zinc-100 px-4 py-3 text-center dark:bg-zinc-800">
              <Fingerprint publicKey={adding.key.publicKey} />
            </p>
            <Field label="Role on this server">
              <Select value={role} onChange={(e) => setRole(e.target.value as SignerKey["role"])}>
                <option value="viewer">Viewer — read containers, logs and status</option>
                <option value="operator">Operator — also start, stop and restart</option>
                <option value="admin">Admin — also deploy, remove and manage passkeys</option>
              </Select>
            </Field>
          </>
        )}
      </Modal>
    </div>
  );
}

// ---------------------------------------------------------------------------

function SystemTab({ server }: { server: Server }) {
  const info = useAgent<Record<string, string | number>>(server, "system.info");
  const agent = useAgent<{ agent: string; version: string; startedAt: number; signers: number; rpId: string; origins: string[]; policy: Record<string, unknown> }>(server, "agent.info");
  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card title="Host">
        {info.error ? (
          <AgentError error={info.error} onRetry={() => void info.reload()} />
        ) : !info.data ? (
          <Spinner />
        ) : (
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            {(
              [
                ["Hostname", info.data.name],
                ["OS", info.data.operatingSystem],
                ["Kernel", info.data.kernelVersion],
                ["Arch", info.data.architecture],
                ["CPUs", info.data.ncpu],
                ["Memory", bytes(Number(info.data.memTotal))],
                ["Docker", info.data.serverVersion],
                ["Containers", `${info.data.containersRunning} running / ${info.data.containers}`],
                ["Images", info.data.images],
              ] as const
            ).map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-zinc-500">{k}</dt>
                <dd className="truncate">{v}</dd>
              </div>
            ))}
          </dl>
        )}
      </Card>
      <Card title="Agent">
        {agent.error ? (
          <AgentError error={agent.error} onRetry={() => void agent.reload()} />
        ) : !agent.data ? (
          <Spinner />
        ) : (
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <dt className="text-zinc-500">Identity</dt>
            <dd className="truncate font-mono text-xs">{agent.data.agent}</dd>
            <dt className="text-zinc-500">Version</dt>
            <dd>{agent.data.version}</dd>
            <dt className="text-zinc-500">Started</dt>
            <dd>{timeAgo(agent.data.startedAt)}</dd>
            <dt className="text-zinc-500">Trusted passkeys</dt>
            <dd>{agent.data.signers}</dd>
            <dt className="text-zinc-500">Accepted origin</dt>
            <dd className="truncate">{agent.data.origins.join(", ")}</dd>
            <dt className="text-zinc-500">Max session</dt>
            <dd>{Math.round(Number(agent.data.policy.maxSessionSeconds) / 3600)}h</dd>
          </dl>
        )}
      </Card>
    </div>
  );
}
