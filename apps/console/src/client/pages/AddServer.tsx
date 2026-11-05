import { fingerprint, type SignerKey } from "@nodescale/protocol";
import { useEffect, useState } from "react";
import { api, recordAudit, type Member, type Server } from "../lib/api.ts";
import { app, requireVault } from "../lib/app.ts";
import { useAsync } from "../lib/hooks.ts";
import { installScript } from "../lib/install.ts";
import { cloudflare, SERVER_TAG, tailscale, type TailscaleDevice } from "../lib/providers.ts";
import { navigate } from "../lib/router.tsx";
import { Badge, Button, Callout, Card, CodeBlock, Field, Input, PageHeader, Select, Spinner, toastError } from "../components/ui.tsx";
import { TrustServer } from "./TrustServer.tsx";

type Mode = "new" | "existing";

export function AddServerPage() {
  const me = app.use((s) => s.me)!;
  const vault = app.use((s) => (s.vault.status === "unlocked" ? s.vault.data : null))!;
  const [mode, setMode] = useState<Mode>("new");
  const [name, setName] = useState("");
  const [provider, setProvider] = useState("");
  const [device, setDevice] = useState<TailscaleDevice | null>(null);
  const [withTunnel, setWithTunnel] = useState(!!vault.cloudflare);
  const [extraSigners, setExtraSigners] = useState<Record<string, SignerKey["role"] | "">>({});
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ server: Server; script: string } | null>(null);

  const devices = useAsync(async () => (mode === "existing" && vault.tailscale ? tailscale.listDevices() : []), [mode]);
  const members = useAsync(() => api.get<Member[]>("/workspace/members"));

  const teammateKeys = (members.data ?? []).filter((m) => m.id !== me.user.id).flatMap((m) => m.passkeys.map((k) => ({ ...k, member: m })));

  if (!vault.tailscale) {
    return (
      <>
        <PageHeader title="Add server" />
        <Callout tone="yellow" title="Tailscale credentials needed">
          nodescale mints one-time Tailscale auth keys for new servers and for its relay. Add an OAuth client or API key in{" "}
          <button type="button" className="font-medium underline" onClick={() => navigate("/settings")}>
            Settings → Integrations
          </button>
          .
        </Callout>
      </>
    );
  }

  async function generate() {
    setBusy(true);
    try {
      const n = name.trim().toLowerCase();
      if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(n)) throw new Error("Name must be lowercase letters, digits and dashes");
      if (mode === "existing" && !device) throw new Error("Pick a tailnet device");

      // Signers come from the encrypted vault (my keys) and, for teammates,
      // from the console after showing fingerprints to compare.
      const signers: SignerKey[] = requireVault().signers.map((s) => ({ ...s, role: "admin", user: me.user.name }));
      for (const k of teammateKeys) {
        const role = extraSigners[k.id];
        if (role) signers.push({ id: k.id, alg: k.alg as SignerKey["alg"], publicKey: k.publicKey, role, label: `${k.member.name}: ${k.label}`, user: k.member.name });
      }

      let authKey: string | undefined;
      if (mode === "new") {
        authKey = await tailscale.createAuthKey({ tags: [SERVER_TAG], ephemeral: false, reusable: false, expirySeconds: 3600, description: `nodescale ${n}` });
      } else if (device && !(device.tags ?? []).includes(SERVER_TAG)) {
        await tailscale.setDeviceTags(device.nodeId ?? device.id, [...(device.tags ?? []), SERVER_TAG]);
      }

      let tunnelToken: string | undefined;
      if (withTunnel) {
        const t = await cloudflare.createTunnel(n);
        tunnelToken = t.token ?? (await cloudflare.tunnelToken(t.id));
        recordAudit("tunnel.create", true, t.name);
      }

      const ip = device?.addresses.find((a) => a.startsWith("100.")) ?? null;
      const { id } = await api.post<{ id: string }>("/servers", {
        name: n,
        provider: provider || null,
        tailnetIp: ip,
        tailnetName: device?.name ?? null,
        deviceId: device?.nodeId ?? device?.id ?? null,
      });
      const server = await api.get<Server>(`/servers/${id}`);
      recordAudit("server.create", true, n, id);
      setResult({
        server,
        script: installScript({ serverName: n, rpId: me.rp.id, origin: me.rp.origin, signers, release: me.gate, tailscaleAuthKey: authKey, cloudflareTunnelToken: tunnelToken }),
      });
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  }

  if (result) return <InstallStep server={result.server} script={result.script} />;

  return (
    <>
      <PageHeader title="Add server" description="Generate a one-time bootstrap script for a Debian or Ubuntu server." />
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card title="Server">
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-2">
                {(["new", "existing"] as Mode[]).map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setMode(m)}
                    className={`rounded-lg p-3 text-left text-sm ring-1 ${mode === m ? "bg-indigo-50 ring-indigo-500 dark:bg-indigo-500/10" : "ring-zinc-200 hover:bg-zinc-50 dark:ring-zinc-800 dark:hover:bg-zinc-800/50"}`}
                  >
                    <span className="block font-medium">{m === "new" ? "New server" : "Already on my tailnet"}</span>
                    <span className="text-xs text-zinc-500">{m === "new" ? "Joins the tailnet with a one-time key" : "Adopt an existing device"}</span>
                  </button>
                ))}
              </div>
              {mode === "existing" && (
                <Field label="Tailnet device">
                  {devices.loading ? (
                    <Spinner />
                  ) : (
                    <Select
                      value={device?.id ?? ""}
                      onChange={(e) => {
                        const d = devices.data?.find((x) => x.id === e.target.value) ?? null;
                        setDevice(d);
                        if (d && !name) setName(d.hostname.toLowerCase().replace(/[^a-z0-9-]/g, "-"));
                      }}
                    >
                      <option value="">Select a device…</option>
                      {devices.data?.filter((d) => /linux/i.test(d.os)).map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.hostname} — {d.addresses[0]} {d.tags?.length ? `(${d.tags.join(", ")})` : ""}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
              )}
              <Field label="Name" hint="Lowercase; used as the tailnet hostname and tunnel name.">
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="web-1" />
              </Field>
              <Field label="Provider (optional)">
                <Input value={provider} onChange={(e) => setProvider(e.target.value)} placeholder="Hetzner, OVH, DigitalOcean…" />
              </Field>
              <label className="flex items-start gap-2 text-sm">
                <input type="checkbox" className="mt-0.5" checked={withTunnel} disabled={!vault.cloudflare} onChange={(e) => setWithTunnel(e.target.checked)} />
                <span>
                  Create a Cloudflare Tunnel for this server
                  <span className="block text-xs text-zinc-500">{vault.cloudflare ? "Runs cloudflared on a Docker network named “nodescale”. Add public hostnames later under Tunnels." : "Add a Cloudflare API token in Settings to enable."}</span>
                </span>
              </label>
            </div>
          </Card>

          <Card title="Trusted passkeys">
            <p className="mb-4 text-sm text-zinc-500">The server will only accept requests signed by these passkeys. You can change this later from the server's Access tab (requires an admin passkey).</p>
            <ul className="divide-y divide-zinc-100 dark:divide-zinc-800">
              {vault.signers.map((s) => (
                <SignerRow key={s.id} label={`You — ${s.label ?? "passkey"}`} publicKey={s.publicKey} right={<Badge tone="blue">admin</Badge>} />
              ))}
              {teammateKeys.map((k) => (
                <SignerRow
                  key={k.id}
                  label={`${k.member.name} — ${k.label}`}
                  publicKey={k.publicKey}
                  right={
                    <Select className="w-32 py-1" value={extraSigners[k.id] ?? ""} onChange={(e) => setExtraSigners({ ...extraSigners, [k.id]: e.target.value as SignerKey["role"] })}>
                      <option value="">Not trusted</option>
                      <option value="viewer">Viewer</option>
                      <option value="operator">Operator</option>
                      <option value="admin">Admin</option>
                    </Select>
                  }
                />
              ))}
            </ul>
            {teammateKeys.length > 0 && <p className="mt-3 text-xs text-zinc-500">Teammate keys come from the console. Compare fingerprints with them (Settings → Passkeys on their side) before trusting.</p>}
          </Card>
        </div>
        <div>
          <Card title="What happens next">
            <ol className="list-decimal space-y-2 pl-4 text-sm text-zinc-600 dark:text-zinc-400">
              <li>Your browser mints a one-hour, single-use Tailscale auth key{withTunnel ? " and creates a Cloudflare Tunnel" : ""}.</li>
              <li>You run the generated script once on the server as root.</li>
              <li>You confirm the agent ID it prints. It is then pinned in your encrypted vault.</li>
            </ol>
            <Button variant="primary" className="mt-5 w-full" loading={busy} onClick={generate}>
              Generate install script
            </Button>
          </Card>
        </div>
      </div>
    </>
  );
}

function SignerRow({ label, publicKey, right }: { label: string; publicKey: string; right: React.ReactNode }) {
  const [fp, setFp] = useState("");
  useEffect(() => {
    void fingerprint(publicKey).then(setFp);
  }, [publicKey]);
  return (
    <li className="flex items-center justify-between gap-4 py-2.5">
      <div className="min-w-0">
        <p className="truncate text-sm font-medium">{label}</p>
        <p className="font-mono text-xs text-zinc-500">{fp}</p>
      </div>
      {right}
    </li>
  );
}

function InstallStep({ server, script }: { server: Server; script: string }) {
  const [step, setStep] = useState<"script" | "trust">("script");
  return (
    <>
      <PageHeader title={`Install ${server.name}`} description="Run this once on the server as root, for example from your provider's web console." />
      {step === "script" ? (
        <div className="space-y-5">
          <Callout tone="yellow" title="Contains one-time secrets">
            The Tailscale auth key expires in one hour and can join exactly one machine. Do not paste this script into chat or commit it.
          </Callout>
          <CodeBlock code={script} filename="nodescale-install.sh" maxHeight="28rem" />
          <div className="flex justify-end">
            <Button variant="primary" onClick={() => setStep("trust")}>
              I ran it, continue
            </Button>
          </div>
        </div>
      ) : (
        <TrustServer server={server} onDone={() => navigate(`/servers/${server.id}`)} />
      )}
    </>
  );
}
