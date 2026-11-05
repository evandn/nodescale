import { b64, sha256, utf8 } from "@nodescale/protocol";
import { useMemo, useState } from "react";
import { api, recordAudit, type Server, type StackDef } from "../../lib/api.ts";
import { callAgent } from "../../lib/agent.ts";
import { app, updateVault } from "../../lib/app.ts";
import { ComposeError, interpolateEnv, parseCompose, type ParsedStack } from "../../lib/compose.ts";
import { timeAgo, useAsync } from "../../lib/hooks.ts";
import { cloudflare } from "../../lib/providers.ts";
import { ensureRoute } from "../../lib/routes.ts";
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
  Spinner,
  Textarea,
  confirmAction,
  toast,
} from "../../components/ui.tsx";
import { AgentError, containerName, stateTone, useAgent, type Container } from "./shared.tsx";

const TEMPLATE = `# Docker Compose subset. Secrets: write \${NAME}; values come from your
# encrypted vault and are sealed to this server in your browser.
services:
  web:
    image: nginx:1.27-alpine
    restart: unless-stopped
    x-nodescale:
      # Routes https://<hostname> through this server's Cloudflare Tunnel.
      expose: { hostname: app.example.com, port: 80 }
  # db:
  #   image: postgres:17-alpine
  #   environment:
  #     POSTGRES_PASSWORD: \${DB_PASSWORD}
  #   volumes: [pgdata:/var/lib/postgresql/data]
# volumes:
#   pgdata:
`;

interface StackRow {
  name: string;
  def?: StackDef;
  containers: Container[];
}

interface StackResult {
  service: string;
  action: string;
}

export function StacksTab({ server }: { server: Server }) {
  const defs = useAsync(() => api.get<StackDef[]>(`/servers/${server.id}/stacks`), [server.id]);
  const live = useAgent<Container[]>(server, "containers.list", { all: true });
  const [editing, setEditing] = useState<{ name: string; compose: string; isNew: boolean } | null>(null);

  const rows = useMemo<StackRow[]>(() => {
    const m = new Map<string, StackRow>();
    for (const d of defs.data ?? []) m.set(d.name, { name: d.name, def: d, containers: [] });
    for (const c of live.data ?? []) {
      const s = c.labels?.["io.nodescale.stack"];
      if (!s) continue;
      const row = m.get(s) ?? { name: s, containers: [] };
      row.containers.push(c);
      m.set(s, row);
    }
    return [...m.values()].sort((a, b) => a.name.localeCompare(b.name));
  }, [defs.data, live.data]);

  const reload = () => {
    void defs.reload();
    void live.reload();
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="max-w-2xl text-sm text-zinc-500">
          Stacks are groups of services deployed from a compose file. Redeploying only recreates services whose image or configuration changed. Services reach each other by service name.
        </p>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={reload}>
            <RefreshIcon /> Refresh
          </Button>
          <Button variant="primary" onClick={() => setEditing({ name: "", compose: TEMPLATE, isNew: true })}>
            <PlusIcon /> New stack
          </Button>
        </div>
      </div>
      {live.error && <AgentError error={live.error} onRetry={reload} />}
      {(defs.loading || live.loading) && !rows.length ? (
        <Spinner />
      ) : !rows.length ? (
        <Empty
          title="No stacks yet"
          action={
            <Button variant="primary" onClick={() => setEditing({ name: "", compose: TEMPLATE, isNew: true })}>
              <PlusIcon /> Create a stack
            </Button>
          }
        >
          Paste a docker-compose.yml. Secrets stay encrypted end to end.
        </Empty>
      ) : (
        rows.map((r) => (
          <StackCard key={r.name} server={server} row={r} live={!!live.data && !live.loading} onEdit={() => setEditing({ name: r.name, compose: r.def?.compose ?? "", isNew: false })} onChanged={reload} />
        ))
      )}
      {editing && <StackEditor server={server} initial={editing} onClose={() => setEditing(null)} onDeployed={reload} />}
    </div>
  );
}

function StackCard({ server, row, live, onEdit, onChanged }: { server: Server; row: StackRow; live: boolean; onEdit: () => void; onChanged: () => void }) {
  const running = row.containers.filter((c) => c.state === "running").length;
  return (
    <Card
      padded={false}
      title={
        <span className="flex items-center gap-2">
          {row.name}
          {!live ? (
            <Spinner className="size-3.5 text-zinc-400" />
          ) : (
            <Badge tone={row.containers.length && running === row.containers.length ? "green" : row.containers.length ? "yellow" : "gray"}>
              {row.containers.length ? `${running}/${row.containers.length} running` : "not deployed"}
            </Badge>
          )}
          {!row.def && <Badge tone="yellow">no saved definition</Badge>}
        </span>
      }
      actions={
        <>
          {row.def && (
            <>
              <ActionButton size="sm" disabled={!live} action={() => deployFromDef(server, row.name, row.def!.compose, false).then(onChanged)}>
                <KeyIcon /> Redeploy
              </ActionButton>
              <ActionButton size="sm" variant="ghost" disabled={!live} action={() => deployFromDef(server, row.name, row.def!.compose, true).then(onChanged)}>
                Pull &amp; redeploy
              </ActionButton>
              <Button size="sm" variant="ghost" onClick={onEdit}>
                Edit
              </Button>
            </>
          )}
          <ActionButton
            size="sm"
            variant="ghost"
            className="text-red-600 dark:text-red-400"
            // Only decide what "remove" means once the server's state is known;
            // otherwise a running stack could look undeployed.
            disabled={!live}
            action={async () => {
              if (!row.containers.length) {
                if (!(await confirmAction({ title: `Delete ${row.name}?`, body: "The stack is not deployed on this server. Its saved definition will be deleted from the console.", confirm: "Delete", danger: true }))) return;
              } else {
                const ok = await confirmAction({
                  title: `Remove stack ${row.name}?`,
                  body: (
                    <div className="space-y-2">
                      <p>
                        Stops and removes {row.containers.length} container(s) and the stack network on {server.name}. Named volumes are kept; remove them from Networks &amp; volumes if you no longer need the data.
                      </p>
                    </div>
                  ),
                  confirm: "Sign with passkey",
                  danger: true,
                  passkey: true,
                });
                if (!ok) return;
                await callAgent(server, "stacks.remove", { name: row.name });
              }
              if (row.def) await api.del(`/servers/${server.id}/stacks/${row.name}`);
              recordAudit("stack.remove", true, row.name, server.id);
              toast(`Stack ${row.name} removed`, "success");
              onChanged();
            }}
          >
            Remove
          </ActionButton>
        </>
      }
    >
      <ul className="divide-y divide-zinc-100 dark:divide-zinc-800">
        {row.containers.map((c) => (
          <li key={c.id} className="flex items-center justify-between px-5 py-2.5 text-sm">
            <span>
              <span className="font-medium">{c.labels?.["io.nodescale.service"] ?? containerName(c)}</span>
              <span className="ml-2 font-mono text-xs text-zinc-500">{c.image}</span>
            </span>
            <span className="flex items-center gap-2 text-xs text-zinc-500">
              {c.status}
              <Badge tone={stateTone(c.state)}>{c.state}</Badge>
            </span>
          </li>
        ))}
        {row.def && (
          <li className="px-5 py-2 text-xs text-zinc-500">
            Definition saved {timeAgo(row.def.updatedAt)}
            {row.def.updatedBy && ` by ${row.def.updatedBy}`}
            {row.def.deployedAt ? ` · last deployed ${timeAgo(row.def.deployedAt)}` : " · never deployed"}
          </li>
        )}
      </ul>
    </Card>
  );
}

/** Redeploys a saved definition, asking for any secrets missing from the vault. */
async function deployFromDef(server: Server, name: string, compose: string, pull: boolean) {
  const parsed = parseCompose(compose, name);
  const secrets = vaultSecrets();
  const missing = parsed.variables.filter((v) => !(v in secrets));
  if (missing.length) throw new Error(`Missing secret values for ${missing.join(", ")}; open Edit to provide them`);
  await deploy(server, name, compose, parsed, secrets, pull);
}

function vaultSecrets(): Record<string, string> {
  const v = app.get().vault;
  return v.status === "unlocked" ? (v.data.secrets ?? {}) : {};
}

async function composeHash(text: string) {
  return b64(await sha256(utf8(text)));
}

const PLACEHOLDER = /\$\{([A-Za-z_][A-Za-z0-9_]*)/g;

async function deploy(server: Server, name: string, compose: string, parsed: ParsedStack, secrets: Record<string, string>, pull: boolean): Promise<StackResult[]> {
  const spec = interpolateEnv(parsed.spec, secrets);
  if (pull) spec.pull = "always";
  // The compose text comes from the console, which is not trusted. If it is
  // not exactly what this user last deployed, show all of it before signing.
  const key = `${server.id}/${name}`;
  const hash = await composeHash(compose);
  const v = app.get().vault;
  const lastHash = v.status === "unlocked" ? v.data.deployed?.[key] : undefined;
  const changed = lastHash !== hash;
  const secretsBySvc = parsed.spec.services.map((s) => ({
    service: s.service,
    names: [...new Set((s.env ?? []).flatMap((e) => [...e.slice(e.indexOf("=") + 1).matchAll(PLACEHOLDER)].map((m) => m[1]!)))],
  }));
  const risky = parsed.spec.services.filter((s) => s.privileged || s.networkMode === "host" || s.pidMode === "host" || s.capAdd?.length || s.devices?.length || s.mounts?.some((m) => m.type === "bind"));
  const ok = await confirmAction({
    title: `Deploy stack ${name}`,
    body: (
      <div className="space-y-3 text-sm">
        <p>
          Deploy {spec.services.length} service(s) to <strong>{server.name}</strong>. Environment values are sealed to the server.
        </p>
        <ul className="space-y-1 text-xs">
          {spec.services.map((s) => {
            const sec = secretsBySvc.find((x) => x.service === s.service)!.names;
            return (
              <li key={s.service}>
                <strong>{s.service}</strong> <Code>{s.image}</Code>
                {sec.length > 0 && <span className="ml-1 text-amber-700 dark:text-amber-400">receives secrets: {sec.join(", ")}</span>}
              </li>
            );
          })}
        </ul>
        {parsed.expose.length > 0 && <p className="text-xs">Public hostnames: {parsed.expose.map((e) => e.hostname).join(", ")}</p>}
        {risky.length > 0 && <Callout tone="yellow">Host access requested by: {risky.map((s) => s.service).join(", ")} (bind mounts, capabilities or host namespaces; the server policy still applies).</Callout>}
        {changed && (
          <>
            <Callout tone="yellow" title={lastHash ? "This definition changed since you last deployed it" : "You have not deployed this definition before"}>
              Review the full compose file below. It is stored in the console, so make sure it is what you expect before signing.
            </Callout>
            <pre className="max-h-64 overflow-auto rounded bg-zinc-100 p-2 text-[11px] dark:bg-zinc-800">{compose}</pre>
          </>
        )}
        {pull && <p className="text-xs">Images will be pulled again even if present.</p>}
      </div>
    ),
    confirm: "Sign with passkey",
    passkey: true,
  });
  if (!ok) return [];
  const results = await callAgent<StackResult[]>(server, "stacks.deploy", spec, { ttl: 300 });
  await api.put(`/servers/${server.id}/stacks/${name}`, { compose, deployed: true });
  await updateVault((d) => {
    d.deployed = { ...(d.deployed ?? {}), [key]: hash };
  });

  // Tunnel routes for exposed services.
  const notes: string[] = [];
  if (parsed.expose.length) {
    const hasCf = app.get().vault.status === "unlocked" && !!(app.get().vault as { data: { cloudflare?: unknown } }).data.cloudflare;
    if (!server.tunnelId) notes.push("This server has no linked tunnel (Settings tab), so public hostnames were not configured.");
    else if (!hasCf) notes.push("Add a Cloudflare token in Settings to configure public hostnames.");
    else {
      const tunnels = await cloudflare.listTunnels();
      const t = tunnels.find((x) => x.id === server.tunnelId);
      for (const e of parsed.expose) {
        try {
          const r = await ensureRoute(server.tunnelId, t?.name ?? server.name, e.hostname, `http://${e.container}:${e.port}`);
          if (r !== "unchanged") notes.push(`https://${e.hostname} → ${e.container}:${e.port}`);
        } catch (err) {
          notes.push(`${e.hostname}: ${(err as Error).message}`);
        }
      }
    }
  }
  const touched = results.filter((r) => r.action !== "unchanged");
  toast(touched.length ? `Deployed ${name}: ${touched.map((r) => `${r.service} ${r.action}`).join(", ")}` : `${name} is up to date`, "success");
  for (const n of notes) toast(n, n.includes("→") ? "success" : "info");
  return results;
}

function StackEditor({ server, initial, onClose, onDeployed }: { server: Server; initial: { name: string; compose: string; isNew: boolean }; onClose: () => void; onDeployed: () => void }) {
  const [name, setName] = useState(initial.name);
  const [compose, setCompose] = useState(initial.compose);
  const [values, setValues] = useState<Record<string, string>>({});
  const [save, setSave] = useState(true);
  const [results, setResults] = useState<StackResult[] | null>(null);
  const saved = vaultSecrets();

  const parsed = useMemo<{ ok: ParsedStack } | { err: string }>(() => {
    try {
      return { ok: parseCompose(compose, name || "stack") };
    } catch (e) {
      return { err: e instanceof ComposeError ? e.message : String(e) };
    }
  }, [compose, name]);

  const p = "ok" in parsed ? parsed.ok : null;
  const missing = p ? p.variables.filter((v) => !(v in saved) && !values[v]) : [];
  const nameOk = /^[a-z0-9][a-z0-9_-]{0,62}$/.test(name);

  async function doDeploy() {
    if (!p) return;
    const secrets = { ...saved, ...Object.fromEntries(Object.entries(values).filter(([, v]) => v)) };
    if (save && Object.keys(values).length) {
      await updateVault((d) => {
        d.secrets = { ...(d.secrets ?? {}), ...Object.fromEntries(Object.entries(values).filter(([, v]) => v)) };
      });
    }
    const r = await deploy(server, name, compose, p, secrets, false);
    if (r.length) {
      setResults(r);
      onDeployed();
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      wide
      title={initial.isNew ? "New stack" : `Edit ${initial.name}`}
      footer={
        <>
          <Button onClick={onClose}>{results ? "Close" : "Cancel"}</Button>
          <ActionButton
            disabled={!nameOk || !p}
            action={async () => {
              await api.put(`/servers/${server.id}/stacks/${name}`, { compose });
              toast("Definition saved", "success");
              onDeployed();
            }}
          >
            Save only
          </ActionButton>
          <ActionButton variant="primary" disabled={!nameOk || !p || missing.length > 0} action={doDeploy}>
            <KeyIcon /> Deploy
          </ActionButton>
        </>
      }
    >
      {initial.isNew && (
        <Field label="Stack name" hint="Lowercase; containers are named <stack>-<service>.">
          <Input value={name} onChange={(e) => setName(e.target.value.toLowerCase())} placeholder="shop" />
        </Field>
      )}
      <Field label="Compose file">
        <Textarea rows={16} value={compose} onChange={(e) => setCompose(e.target.value)} spellCheck={false} className="text-xs leading-relaxed" />
      </Field>
      {"err" in parsed ? (
        <Callout tone="red">{parsed.err}</Callout>
      ) : (
        <div className="space-y-3">
          <p className="text-xs text-zinc-500">
            {p!.spec.services.length} service(s): {p!.spec.services.map((s) => s.service).join(", ")}
            {p!.spec.volumes?.length ? ` · volumes ${p!.spec.volumes.join(", ")}` : ""}
            {p!.expose.length ? ` · public: ${p!.expose.map((e) => e.hostname).join(", ")}` : ""}
          </p>
          {p!.warnings.map((w) => (
            <Callout key={w} tone="yellow">
              {w}
            </Callout>
          ))}
          {p!.variables.length > 0 && (
            <div className="space-y-2 rounded-lg p-3 ring-1 ring-zinc-200 dark:ring-zinc-800">
              <p className="text-sm font-medium">Secrets</p>
              <p className="text-xs text-zinc-500">Stored only in your encrypted vault and sealed to {server.name} in this browser. The console never receives them.</p>
              {p!.variables.map((v) => (
                <div key={v} className="flex items-center gap-2">
                  <Code>{v}</Code>
                  {v in saved && !(v in values) ? (
                    <>
                      <Badge tone="green">in vault</Badge>
                      <button type="button" className="text-xs text-indigo-600 hover:underline" onClick={() => setValues({ ...values, [v]: "" })}>
                        change
                      </button>
                    </>
                  ) : (
                    <Input type="password" className="py-1 text-xs" autoComplete="off" value={values[v] ?? ""} onChange={(e) => setValues({ ...values, [v]: e.target.value })} placeholder="value" />
                  )}
                </div>
              ))}
              <label className="flex items-center gap-2 text-xs">
                <input type="checkbox" checked={save} onChange={(e) => setSave(e.target.checked)} /> Save new values to my vault
              </label>
            </div>
          )}
        </div>
      )}
      {results && (
        <Callout tone="green" title="Deployed">
          {results.map((r) => `${r.service}: ${r.action}`).join(" · ")}
        </Callout>
      )}
    </Modal>
  );
}
