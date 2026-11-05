import { useState } from "react";
import { api, recordAudit, type Server } from "../lib/api.ts";
import { ensureRelay, hello, type Hello } from "../lib/agent.ts";
import { updateVault } from "../lib/app.ts";
import { tailscale } from "../lib/providers.ts";
import { ActionButton, Button, Callout, Card, Code } from "../components/ui.tsx";

/**
 * Trust on first use: fetch the server's self-certifying identity over the
 * relay, have the human compare it with what the install script printed on
 * the server, then pin it in the encrypted vault. From then on every
 * response must be signed by that key.
 */
export function TrustServer({ server: initial, onDone }: { server: Server; onDone: () => void }) {
  const [server, setServer] = useState(initial);
  const [found, setFound] = useState<Hello | null>(null);
  const [confirm, setConfirm] = useState("");

  async function locate() {
    let s = server;
    if (!s.tailnetIp) {
      const devices = await tailscale.listDevices();
      const d = devices.find((x) => x.hostname.toLowerCase() === s.name || x.name.split(".")[0] === s.name);
      if (!d) throw new Error("The server has not joined the tailnet yet. Wait for the script to finish and try again.");
      const ip = d.addresses.find((a) => a.startsWith("100."));
      await api.patch(`/servers/${s.id}`, { tailnetIp: ip, tailnetName: d.name, deviceId: d.nodeId ?? d.id });
      s = await api.get<Server>(`/servers/${s.id}`);
      setServer(s);
    }
    await ensureRelay();
    setFound(await hello(s));
  }

  async function trust() {
    if (!found) return;
    await updateVault((d) => {
      d.pins[server.id] = { agentId: found.agent, publicKey: found.publicKey, sealKey: found.sealKey, pinnedAt: Math.floor(Date.now() / 1000) };
    });
    await api.patch(`/servers/${server.id}`, { agentId: found.agent, agentPublicKey: found.publicKey });
    recordAudit("server.trust", true, found.agent, server.id);
    onDone();
  }

  // The full identity must match: a short prefix can be brute-forced.
  const typed = confirm.trim().toLowerCase().replace(/^.*"agent":"/, "").replace(/".*$/, "");
  const matches = !!found && (typed === found.agent || `ag_${typed}` === found.agent);

  return (
    <Card title="Verify server identity">
      {!found ? (
        <div className="space-y-4">
          <p className="text-sm text-zinc-600 dark:text-zinc-400">nodescale will find the server on your tailnet and ask its gate for its identity key.</p>
          <ActionButton variant="primary" action={locate}>
            Find server
          </ActionButton>
        </div>
      ) : (
        <div className="space-y-4">
          <p className="text-sm">
            The gate on <strong>{found.hostname}</strong> (version {found.version}) reports this identity:
          </p>
          <p className="rounded-lg bg-zinc-100 px-4 py-3 font-mono text-sm dark:bg-zinc-800">{found.agent}</p>
          {!found.origins.includes(location.origin) && (
            <Callout tone="red">
              This server does not trust this console's origin (<Code>{location.origin}</Code>). It accepts: {found.origins.join(", ")}.
            </Callout>
          )}
          <Callout tone="blue">
            Paste the server identity printed by the last line of the install script (<Code>"agent":"ag_…"</Code>, or run <Code>sudo nodescale-gate id</Code> on the server). It must match exactly.
          </Callout>
          <input
            className="block w-full rounded-lg border-0 bg-white px-3 py-2 font-mono text-sm ring-1 ring-zinc-300 dark:bg-zinc-900 dark:ring-zinc-700"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="ag_…"
            spellCheck={false}
          />
          <div className="flex gap-2">
            <ActionButton variant="primary" disabled={!matches} action={trust}>
              Trust this server
            </ActionButton>
            <Button variant="ghost" onClick={() => setFound(null)}>
              Retry
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}
