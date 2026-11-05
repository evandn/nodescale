import { useState } from "react";
import { api, recordAudit, type Server } from "../../lib/api.ts";
import { app, updateVault } from "../../lib/app.ts";
import { useAsync } from "../../lib/hooks.ts";
import { uninstallScript, upgradeScript } from "../../lib/install.ts";
import { cloudflare } from "../../lib/providers.ts";
import { navigate } from "../../lib/router.tsx";
import { ActionButton, Button, Callout, Card, CodeBlock, Field, Select, confirmAction, toast } from "../../components/ui.tsx";

export function ServerSettingsTab({ server, onChanged }: { server: Server; onChanged: () => void }) {
  const me = app.use((s) => s.me)!;
  const hasCf = app.use((s) => s.vault.status === "unlocked" && !!s.vault.data.cloudflare);
  const tunnels = useAsync(async () => (hasCf ? cloudflare.listTunnels() : []), [hasCf]);
  const [tunnel, setTunnel] = useState(server.tunnelId ?? "");
  const [script, setScript] = useState<"upgrade" | "uninstall" | null>(null);
  const canManage = me.workspace.role !== "member";

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title="Cloudflare Tunnel">
        <p className="mb-4 text-sm text-zinc-600 dark:text-zinc-400">
          The tunnel this server's cloudflared runs. Stacks with <code>x-nodescale.expose</code> get their public hostnames routed through it.
        </p>
        {!hasCf ? (
          <Callout tone="yellow">Add a Cloudflare API token in Settings to link a tunnel.</Callout>
        ) : (
          <div className="flex items-end gap-2">
            <Field label="Tunnel">
              <Select className="w-64" value={tunnel} onChange={(e) => setTunnel(e.target.value)}>
                <option value="">None</option>
                {tunnels.data?.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.status})
                  </option>
                ))}
              </Select>
            </Field>
            <ActionButton
              disabled={!canManage || tunnel === (server.tunnelId ?? "")}
              action={async () => {
                await api.patch(`/servers/${server.id}`, { tunnelId: tunnel || null });
                toast("Tunnel linked", "success");
                onChanged();
              }}
            >
              Save
            </ActionButton>
          </div>
        )}
      </Card>

      <Card title="Maintenance">
        <div className="space-y-3 text-sm">
          <p className="text-zinc-600 dark:text-zinc-400">
            nodescale runs nothing in the background on your server. Upgrading replaces the gate binary; trusted passkeys and the server identity are kept. Run the scripts as root, e.g. with <code>tailscale ssh root@{server.tailnetName ?? server.name}</code>.
          </p>
          <div className="flex gap-2">
            <Button onClick={() => setScript(script === "upgrade" ? null : "upgrade")}>Upgrade script</Button>
            <Button onClick={() => setScript(script === "uninstall" ? null : "uninstall")}>Uninstall script</Button>
          </div>
          {script === "upgrade" && <CodeBlock code={upgradeScript(server.name, me.gate)} filename="nodescale-upgrade.sh" />}
          {script === "uninstall" && <CodeBlock code={uninstallScript(server.name)} filename="nodescale-uninstall.sh" />}
        </div>
      </Card>

      {canManage && (
        <Card title="Remove from console" className="lg:col-span-2">
          <div className="flex items-center justify-between gap-4">
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              Removes the server and its saved stack definitions from the console and forgets its pinned identity. Nothing on the server changes; its gate keeps trusting the same passkeys.
            </p>
            <ActionButton
              variant="danger"
              action={async () => {
                if (!(await confirmAction({ title: `Remove ${server.name}?`, body: "This only affects the console.", confirm: "Remove", danger: true }))) return;
                await api.del(`/servers/${server.id}`);
                await updateVault((d) => {
                  delete d.pins[server.id];
                });
                recordAudit("server.delete", true, server.name, server.id);
                navigate("/servers");
              }}
            >
              Remove
            </ActionButton>
          </div>
        </Card>
      )}
    </div>
  );
}
