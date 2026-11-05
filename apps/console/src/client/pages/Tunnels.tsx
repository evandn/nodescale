import { useState } from "react";
import { recordAudit } from "../lib/api.ts";
import { app } from "../lib/app.ts";
import { timeAgo, useAsync } from "../lib/hooks.ts";
import { cloudflare, type IngressRule, type Tunnel } from "../lib/providers.ts";
import { navigate } from "../lib/router.tsx";
import { ActionButton, Badge, Button, Callout, Card, Code, Empty, Field, Input, Modal, PageHeader, PlusIcon, RefreshIcon, Select, Spinner, confirmAction, toast } from "../components/ui.tsx";

export function TunnelsPage() {
  const hasCf = app.use((s) => s.vault.status === "unlocked" && !!s.vault.data.cloudflare);
  const tunnels = useAsync(async () => (hasCf ? cloudflare.listTunnels() : []), [hasCf]);

  if (!hasCf) {
    return (
      <>
        <PageHeader title="Tunnels" />
        <Callout tone="yellow" title="Cloudflare API token needed">
          Add a token with <Code>Cloudflare Tunnel:Edit</Code> and <Code>DNS:Edit</Code> permissions in{" "}
          <button type="button" className="font-medium underline" onClick={() => navigate("/settings")}>
            Settings → Integrations
          </button>
          .
        </Callout>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Tunnels"
        description="Cloudflare Tunnels expose services without opening inbound ports. Routes point a public hostname at a container on the server's “nodescale” Docker network."
        actions={
          <Button variant="ghost" onClick={() => void tunnels.reload()}>
            <RefreshIcon /> Refresh
          </Button>
        }
      />
      {tunnels.error ? (
        <Callout tone="red">{tunnels.error.message}</Callout>
      ) : !tunnels.data ? (
        <Spinner className="size-5 text-zinc-400" />
      ) : !tunnels.data.length ? (
        <Empty title="No tunnels">Create one when adding a server, or with cloudflared directly.</Empty>
      ) : (
        <div className="space-y-6">
          {tunnels.data.map((t) => (
            <TunnelCard key={t.id} tunnel={t} onChanged={() => void tunnels.reload()} />
          ))}
        </div>
      )}
    </>
  );
}

function TunnelCard({ tunnel, onChanged }: { tunnel: Tunnel; onChanged: () => void }) {
  const ingress = useAsync(() => cloudflare.getIngress(tunnel.id), [tunnel.id]);
  const [adding, setAdding] = useState(false);
  const routes = (ingress.data ?? []).filter((r) => r.hostname);

  async function removeRoute(rule: IngressRule) {
    if (!(await confirmAction({ title: `Remove ${rule.hostname}?`, body: "The hostname stops routing to this tunnel and its DNS record is deleted.", confirm: "Remove", danger: true }))) return;
    await cloudflare.putIngress(tunnel.id, routes.filter((r) => r !== rule));
    const zones = await cloudflare.listZones();
    const zone = zones.find((z) => rule.hostname === z.name || rule.hostname!.endsWith("." + z.name));
    if (zone) {
      for (const rec of await cloudflare.findDns(zone.id, rule.hostname!)) {
        if (rec.type === "CNAME" && rec.content === `${tunnel.id}.cfargotunnel.com`) await cloudflare.deleteDns(zone.id, rec.id);
      }
    }
    recordAudit("tunnel.route.remove", true, `${rule.hostname} → ${tunnel.name}`);
    toast("Route removed", "success");
    await ingress.reload();
  }

  return (
    <Card
      padded={false}
      title={
        <span className="flex items-center gap-2">
          {tunnel.name}
          <Badge tone={tunnel.status === "healthy" ? "green" : tunnel.status === "degraded" ? "yellow" : tunnel.status === "down" ? "red" : "gray"}>{tunnel.status}</Badge>
          <span className="text-xs font-normal text-zinc-500">
            {tunnel.connections.length} connection{tunnel.connections.length === 1 ? "" : "s"}
            {tunnel.connections[0] && ` · ${[...new Set(tunnel.connections.map((c) => c.colo_name))].join(", ")}`}
          </span>
        </span>
      }
      actions={
        <>
          <Button size="sm" onClick={() => setAdding(true)}>
            <PlusIcon /> Route
          </Button>
          <ActionButton
            size="sm"
            variant="ghost"
            className="text-red-600 dark:text-red-400"
            action={async () => {
              if (!(await confirmAction({ title: `Delete tunnel ${tunnel.name}?`, body: "cloudflared on the server will stop serving traffic. Remove its routes first.", confirm: "Delete", danger: true }))) return;
              await cloudflare.deleteTunnel(tunnel.id);
              recordAudit("tunnel.delete", true, tunnel.name);
              onChanged();
            }}
          >
            Delete
          </ActionButton>
        </>
      }
    >
      {ingress.loading && !ingress.data ? (
        <div className="p-5">
          <Spinner />
        </div>
      ) : !routes.length ? (
        <p className="px-5 py-4 text-sm text-zinc-500">No public hostnames. Created {timeAgo(Date.parse(tunnel.created_at) / 1000)}.</p>
      ) : (
        <ul className="divide-y divide-zinc-100 dark:divide-zinc-800">
          {routes.map((r) => (
            <li key={r.hostname! + (r.path ?? "")} className="flex items-center justify-between px-5 py-3 text-sm">
              <span>
                <a href={`https://${r.hostname}`} target="_blank" rel="noreferrer noopener" className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
                  {r.hostname}
                </a>
                {r.path && <span className="text-zinc-500">{r.path}</span>}
                <span className="mx-2 text-zinc-400">→</span>
                <Code>{r.service}</Code>
              </span>
              <ActionButton size="sm" variant="ghost" action={() => removeRoute(r)}>
                Remove
              </ActionButton>
            </li>
          ))}
        </ul>
      )}
      <AddRouteModal
        open={adding}
        onClose={() => setAdding(false)}
        onAdd={async (hostname, service, zoneId) => {
          await cloudflare.putIngress(tunnel.id, [...routes.filter((r) => r.hostname !== hostname), { hostname, service }]);
          const existing = await cloudflare.findDns(zoneId, hostname);
          if (!existing.some((r) => r.type === "CNAME" && r.content === `${tunnel.id}.cfargotunnel.com`)) {
            if (existing.length) throw new Error(`${hostname} already has a DNS record pointing elsewhere; remove it first.`);
            await cloudflare.createTunnelCname(zoneId, hostname, tunnel.id);
          }
          recordAudit("tunnel.route.add", true, `${hostname} → ${service} (${tunnel.name})`);
          toast(`${hostname} is live`, "success");
          setAdding(false);
          await ingress.reload();
        }}
      />
    </Card>
  );
}

function AddRouteModal({ open, onClose, onAdd }: { open: boolean; onClose: () => void; onAdd: (hostname: string, service: string, zoneId: string) => Promise<void> }) {
  const zones = useAsync(async () => (open ? cloudflare.listZones() : []), [open]);
  const [sub, setSub] = useState("");
  const [zoneId, setZoneId] = useState("");
  const [service, setService] = useState("http://app:8080");
  const zone = zones.data?.find((z) => z.id === (zoneId || zones.data?.[0]?.id));
  const hostname = zone ? (sub ? `${sub}.${zone.name}` : zone.name) : "";
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add public hostname"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <ActionButton variant="primary" disabled={!zone || !/^(https?|tcp|ssh):\/\/.+/.test(service)} action={() => onAdd(hostname, service, zone!.id)}>
            Add route
          </ActionButton>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        <Field label="Subdomain">
          <Input value={sub} onChange={(e) => setSub(e.target.value.toLowerCase())} placeholder="app" />
        </Field>
        <Field label="Domain">
          <Select value={zone?.id ?? ""} onChange={(e) => setZoneId(e.target.value)}>
            {zones.data?.map((z) => (
              <option key={z.id} value={z.id}>
                {z.name}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <Field label="Service" hint="As seen from cloudflared on the server, e.g. http://container-name:port on the “nodescale” network.">
        <Input value={service} onChange={(e) => setService(e.target.value)} className="font-mono" />
      </Field>
      {hostname && (
        <p className="text-sm text-zinc-500">
          <Code>https://{hostname}</Code> → <Code>{service}</Code>
        </p>
      )}
    </Modal>
  );
}
