import { api, type Server } from "../lib/api.ts";
import { app } from "../lib/app.ts";
import { timeAgo, useAsync } from "../lib/hooks.ts";
import { Link, navigate } from "../lib/router.tsx";
import { Badge, Button, Card, Empty, PageHeader, PlusIcon, ShieldIcon, Spinner, Table, Td } from "../components/ui.tsx";

const NO_PINS = {} as Record<string, { agentId: string }>;

export function ServersPage() {
  const me = app.use((s) => s.me)!;
  const pins = app.use((s) => (s.vault.status === "unlocked" ? s.vault.data.pins : NO_PINS));
  const { data, loading, error } = useAsync(() => api.get<Server[]>("/servers"));
  const canManage = me.workspace.role !== "member";

  return (
    <>
      <PageHeader
        title="Servers"
        description="Every action on a server is signed by your passkey and verified by the agent on that server, not by this console."
        actions={
          canManage && (
            <Button variant="primary" onClick={() => navigate("/servers/new")}>
              <PlusIcon /> Add server
            </Button>
          )
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
          Add a new Debian/Ubuntu machine or adopt one already on your tailnet. nodescale generates a one-time bootstrap script for it.
        </Empty>
      ) : (
        <Card padded={false}>
          <Table head={["Name", "Tailnet", "Identity", "Provider", "Last seen"]}>
            {data.map((s) => {
              const pin = pins[s.id];
              const mismatch = pin && s.agentId && pin.agentId !== s.agentId;
              return (
                <tr key={s.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/40">
                  <Td>
                    <Link to={`/servers/${s.id}`} className="font-medium text-zinc-900 hover:text-indigo-600 dark:text-zinc-100">
                      {s.name}
                    </Link>
                  </Td>
                  <Td className="font-mono text-xs">{s.tailnetIp ?? <span className="text-zinc-400">—</span>}</Td>
                  <Td>
                    {mismatch ? (
                      <Badge tone="red">identity changed</Badge>
                    ) : pin ? (
                      <Badge tone="green">
                        <ShieldIcon className="size-3" /> verified
                      </Badge>
                    ) : s.agentId ? (
                      <Badge tone="yellow">not verified by you</Badge>
                    ) : (
                      <Badge>pending setup</Badge>
                    )}
                  </Td>
                  <Td>{s.provider ?? <span className="text-zinc-400">—</span>}</Td>
                  <Td className="text-zinc-500">{timeAgo(s.lastSeenAt)}</Td>
                </tr>
              );
            })}
          </Table>
        </Card>
      )}
    </>
  );
}
