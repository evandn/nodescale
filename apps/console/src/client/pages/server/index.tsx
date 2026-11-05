import { useState } from "react";
import { api, type Server } from "../../lib/api.ts";
import { app } from "../../lib/app.ts";
import { useAsync } from "../../lib/hooks.ts";
import { Link } from "../../lib/router.tsx";
import { Badge, Callout, Code, PageHeader, ShieldIcon, Spinner, Tabs } from "../../components/ui.tsx";
import { TrustServer } from "../TrustServer.tsx";
import { AccessTab, ServerAuditTab } from "./Access.tsx";
import { ContainersTab } from "./Containers.tsx";
import { OverviewTab } from "./Overview.tsx";
import { ImagesTab, ResourcesTab } from "./Resources.tsx";
import { ServerSettingsTab } from "./Settings.tsx";
import { StacksTab } from "./Stacks.tsx";

type Tab = "overview" | "containers" | "stacks" | "images" | "resources" | "access" | "audit" | "settings";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "containers", label: "Containers" },
  { id: "stacks", label: "Stacks" },
  { id: "images", label: "Images" },
  { id: "resources", label: "Networks & volumes" },
  { id: "access", label: "Access" },
  { id: "audit", label: "Audit" },
  { id: "settings", label: "Settings" },
];

export function ServerPage({ id }: { id: string }) {
  const server = useAsync(() => api.get<Server>(`/servers/${id}`), [id]);
  const pin = app.use((s) => (s.vault.status === "unlocked" ? s.vault.data.pins[id] : undefined));
  const [tab, setTab] = useState<Tab>(() => (TABS.some((t) => t.id === location.hash.slice(1)) ? (location.hash.slice(1) as Tab) : "overview"));

  if (server.loading && !server.data) return <Spinner className="size-5 text-zinc-400" />;
  if (server.error || !server.data) return <p className="text-sm text-red-600">{server.error?.message ?? "Not found"}</p>;
  const s = server.data;
  const select = (t: Tab) => {
    setTab(t);
    history.replaceState(null, "", `#${t}`);
  };

  return (
    <>
      <p className="mb-2 text-sm">
        <Link to="/servers" className="text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100">
          ← Servers
        </Link>
      </p>
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
            {s.tailnetIp ?? "no tailnet address"} · {pin?.agentId ?? s.agentId ?? "not set up"}
            {s.provider && ` · ${s.provider}`}
          </span>
        }
      />
      {!pin ? (
        <TrustServer server={s} onDone={() => void server.reload()} />
      ) : (
        <>
          {s.agentId && pin.agentId !== s.agentId && (
            <div className="mb-6">
              <Callout tone="red" title="Server identity mismatch">
                The console reports identity <Code>{s.agentId}</Code> but you pinned <Code>{pin.agentId}</Code>. Requests are addressed to your pinned identity and responses are verified against it. If the server was reinstalled, remove and re-add it.
              </Callout>
            </div>
          )}
          <Tabs value={tab} onChange={select} tabs={TABS} />
          {tab === "overview" && <OverviewTab server={s} />}
          {tab === "containers" && <ContainersTab server={s} />}
          {tab === "stacks" && <StacksTab server={s} />}
          {tab === "images" && <ImagesTab server={s} />}
          {tab === "resources" && <ResourcesTab server={s} />}
          {tab === "access" && <AccessTab server={s} />}
          {tab === "audit" && <ServerAuditTab server={s} />}
          {tab === "settings" && <ServerSettingsTab server={s} onChanged={() => void server.reload()} />}
        </>
      )}
    </>
  );
}
