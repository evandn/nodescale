import { api, type Server } from "../lib/api.ts";
import { callAgent } from "../lib/agent.ts";
import { app } from "../lib/app.ts";
import { bytes, timeAgo, useAsync } from "../lib/hooks.ts";
import { Link, navigate } from "../lib/router.tsx";
import { Badge, Button, Empty, PageHeader, PlusIcon, RefreshIcon, ServerIcon, ShieldIcon, Spinner } from "../components/ui.tsx";
import { Meter, uptime, type Container, type HostInfo } from "./server/shared.tsx";

const NO_PINS = {} as Record<string, { agentId: string }>;

export function ServersPage() {
  const me = app.use((s) => s.me)!;
  const pins = app.use((s) => (s.vault.status === "unlocked" ? s.vault.data.pins : NO_PINS));
  const { data, loading, error, reload } = useAsync(() => api.get<Server[]>("/servers"));
  const canManage = me.workspace.role !== "member";

  return (
    <>
      <PageHeader
        title="Servers"
        description="Every action on a server is signed by your passkey and verified by that server itself, not by this console."
        actions={
          <>
            <Button variant="ghost" onClick={() => void reload()}>
              <RefreshIcon /> Refresh
            </Button>
            {canManage && (
              <Button variant="primary" onClick={() => navigate("/servers/new")}>
                <PlusIcon /> Add server
              </Button>
            )}
          </>
        }
      />
      {loading && !data ? (
        <Spinner className="size-5 text-zinc-400" />
      ) : error ? (
        <p className="text-sm text-red-600">{error.message}</p>
      ) : !data?.length ? (
        <Empty
          title="No servers yet"
          action={
            canManage && (
              <Button variant="primary" onClick={() => navigate("/servers/new")}>
                <PlusIcon /> Add your first server
              </Button>
            )
          }
        >
          Add a new Debian/Ubuntu machine or adopt one already on your tailnet. nodescale generates a one-time bootstrap script; nothing runs in the background on the server.
        </Empty>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {data.map((s) => (
            <ServerCard key={s.id} server={s} pinned={!!pins[s.id]} mismatch={!!pins[s.id] && !!s.agentId && pins[s.id]!.agentId !== s.agentId} />
          ))}
        </div>
      )}
    </>
  );
}

function ServerCard({ server, pinned, mismatch }: { server: Server; pinned: boolean; mismatch: boolean }) {
  const live = useAsync(async () => {
    if (!pinned) return null;
    const [host, containers] = await Promise.all([callAgent<HostInfo>(server, "host.info"), callAgent<Container[]>(server, "containers.list", { all: true })]);
    return { host, containers };
  }, [server.id, pinned]);

  const h = live.data?.host;
  const running = live.data?.containers.filter((c) => c.state === "running").length ?? 0;
  const total = live.data?.containers.length ?? 0;
  const unhealthy = live.data?.containers.filter((c) => c.state !== "running" && c.labels?.["io.nodescale.stack"]).length ?? 0;
  const disk = h?.disks[h.disks.length - 1];

  return (
    <Link
      to={`/servers/${server.id}`}
      className="group block rounded-xl bg-white p-5 ring-1 ring-zinc-200 transition hover:ring-indigo-300 dark:bg-zinc-900 dark:ring-zinc-800 dark:hover:ring-indigo-500/50"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300">
            <ServerIcon />
          </span>
          <div className="min-w-0">
            <p className="truncate font-semibold text-zinc-900 group-hover:text-indigo-600 dark:text-zinc-100">{server.name}</p>
            <p className="truncate font-mono text-xs text-zinc-500">
              {server.tailnetIp ?? "—"}
              {server.provider && ` · ${server.provider}`}
            </p>
          </div>
        </div>
        {mismatch ? (
          <Badge tone="red">identity changed</Badge>
        ) : !pinned ? (
          <Badge tone="yellow">{server.agentId ? "verify" : "setup"}</Badge>
        ) : live.error ? (
          <Badge tone="red">unreachable</Badge>
        ) : live.data ? (
          <Badge tone="green">
            <ShieldIcon className="size-3" /> online
          </Badge>
        ) : (
          <Spinner className="size-4 text-zinc-400" />
        )}
      </div>

      {pinned && h && (
        <div className="mt-4 space-y-3">
          <Meter label={`Load · ${h.cpus} CPU`} used={h.load[0]} total={h.cpus} format={(n) => n.toFixed(1)} />
          <Meter label="Memory" used={h.memTotal - h.memAvailable} total={h.memTotal} format={bytes} />
          {disk && <Meter label="Disk" used={disk.total - disk.free} total={disk.total} format={bytes} />}
          <div className="flex items-center justify-between pt-1 text-xs text-zinc-500">
            <span>
              {running}/{total} containers running {unhealthy > 0 && <Badge tone="yellow">{unhealthy} stack service(s) down</Badge>}
            </span>
            <span>up {uptime(h.uptime)}</span>
          </div>
        </div>
      )}
      {pinned && live.error && <p className="mt-4 line-clamp-2 text-xs text-red-600 dark:text-red-400">{live.error.message}</p>}
      {!pinned && <p className="mt-4 text-xs text-zinc-500">{server.agentId ? "Confirm this server's identity to manage it." : "Run the install script, then verify the server."}</p>}
      {server.lastSeenAt && <p className="mt-2 text-[11px] text-zinc-400">last contact {timeAgo(server.lastSeenAt)}</p>}
    </Link>
  );
}
