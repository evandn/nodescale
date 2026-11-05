import { fingerprint, type Scope } from "@nodescale/protocol";
import { useEffect, useState } from "react";
import { api, type PasskeyInfo } from "../lib/api.ts";
import { addPasskey, app, removePasskeyFromVault, rotateRecoveryKey, setSessionPrefs, updateVault } from "../lib/app.ts";
import { timeAgo, useAsync } from "../lib/hooks.ts";
import { TAILNET_POLICY } from "../lib/install.ts";
import { cloudflare, tailscale } from "../lib/providers.ts";
import type { TailscaleCreds } from "../lib/vaultCrypto.ts";
import { ActionButton, Badge, Button, Callout, Card, Code, CodeBlock, Field, Input, Modal, PageHeader, PlusIcon, Select, Tabs, confirmAction, toast } from "../components/ui.tsx";

type Tab = "integrations" | "passkeys" | "security";

export function SettingsPage() {
  const [tab, setTab] = useState<Tab>("integrations");
  return (
    <>
      <PageHeader title="Settings" />
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "integrations", label: "Integrations" },
          { id: "passkeys", label: "Passkeys" },
          { id: "security", label: "Security" },
        ]}
      />
      {tab === "integrations" && <Integrations />}
      {tab === "passkeys" && <Passkeys />}
      {tab === "security" && <Security />}
    </>
  );
}

function Integrations() {
  const vault = app.use((s) => (s.vault.status === "unlocked" ? s.vault.data : null))!;
  const [ts, setTs] = useState<TailscaleCreds>(vault.tailscale ?? { kind: "oauth", clientId: "", secret: "", tailnet: "-" });
  const [cf, setCf] = useState(vault.cloudflare ?? { apiToken: "", accountId: "" });

  return (
    <div className="space-y-6">
      <Callout>
        Credentials are encrypted in this browser with your vault key before they are saved. The console stores only ciphertext and relays API calls without keeping the token. Scope tokens narrowly: nodescale never needs permission to edit your tailnet policy.
      </Callout>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Tailscale" actions={vault.tailscale && <Badge tone="green">configured</Badge>}>
          <div className="space-y-4">
            <Field label="Credential type">
              <Select value={ts.kind} onChange={(e) => setTs({ ...ts, kind: e.target.value as TailscaleCreds["kind"] })}>
                <option value="oauth">OAuth client (recommended)</option>
                <option value="apikey">API access token</option>
              </Select>
            </Field>
            {ts.kind === "oauth" && (
              <Field label="Client ID">
                <Input value={ts.clientId ?? ""} onChange={(e) => setTs({ ...ts, clientId: e.target.value.trim() })} autoComplete="off" />
              </Field>
            )}
            <Field
              label={ts.kind === "oauth" ? "Client secret" : "API access token"}
              hint={
                ts.kind === "oauth" ? (
                  <>
                    Scopes: <Code>auth_keys</Code> (write) and <Code>devices:core</Code> (write), tags <Code>tag:nodescale-server</Code> and <Code>tag:nodescale-relay</Code>. Do <strong>not</strong> grant <Code>policy_file</Code>.
                  </>
                ) : (
                  "API tokens carry all of your permissions and expire after at most 90 days. Prefer an OAuth client."
                )
              }
            >
              <Input type="password" value={ts.secret} onChange={(e) => setTs({ ...ts, secret: e.target.value.trim() })} autoComplete="off" />
            </Field>
            <Field label="Tailnet" hint="Use “-” for the default tailnet of the credential.">
              <Input value={ts.tailnet} onChange={(e) => setTs({ ...ts, tailnet: e.target.value.trim() || "-" })} />
            </Field>
            <div className="flex gap-2">
              <ActionButton
                variant="primary"
                disabled={!ts.secret}
                action={async () => {
                  const devices = await tailscale.listDevices(ts);
                  await updateVault((d) => {
                    d.tailscale = ts;
                  });
                  toast(`Tailscale connected: ${devices.length} devices visible`, "success");
                }}
              >
                Test & save
              </ActionButton>
              {vault.tailscale && (
                <ActionButton
                  variant="ghost"
                  action={() =>
                    updateVault((d) => {
                      delete d.tailscale;
                    })
                  }
                >
                  Remove
                </ActionButton>
              )}
            </div>
          </div>
        </Card>

        <Card title="Cloudflare" actions={vault.cloudflare && <Badge tone="green">configured</Badge>}>
          <div className="space-y-4">
            <Field label="Account ID" hint="Dashboard → any zone → Overview → API section.">
              <Input value={cf.accountId} onChange={(e) => setCf({ ...cf, accountId: e.target.value.trim() })} />
            </Field>
            <Field
              label="API token"
              hint={
                <>
                  Permissions: Account <Code>Cloudflare Tunnel:Edit</Code>, Zone <Code>DNS:Edit</Code> and <Code>Zone:Read</Code>, limited to the zones you use. Consider client IP filtering and an expiry.
                </>
              }
            >
              <Input type="password" value={cf.apiToken} onChange={(e) => setCf({ ...cf, apiToken: e.target.value.trim() })} autoComplete="off" />
            </Field>
            <div className="flex gap-2">
              <ActionButton
                variant="primary"
                disabled={!cf.apiToken || !cf.accountId}
                action={async () => {
                  await cloudflare.verify(cf);
                  await updateVault((d) => {
                    d.cloudflare = cf;
                  });
                  toast("Cloudflare token verified and saved", "success");
                }}
              >
                Test & save
              </ActionButton>
              {vault.cloudflare && (
                <ActionButton
                  variant="ghost"
                  action={() =>
                    updateVault((d) => {
                      delete d.cloudflare;
                    })
                  }
                >
                  Remove
                </ActionButton>
              )}
            </div>
          </div>
        </Card>
      </div>
      <Card title="Tailnet policy">
        <p className="mb-3 text-sm text-zinc-600 dark:text-zinc-400">
          Merge this into your tailnet policy file. It lets the relay reach servers only on SSH, and only as the restricted <Code>nodescale</Code> user. Your own SSH rules stay unchanged.
        </p>
        <CodeBlock code={TAILNET_POLICY} />
      </Card>
    </div>
  );
}

function Fp({ k }: { k: string }) {
  const [fp, setFp] = useState("");
  useEffect(() => {
    void fingerprint(k).then(setFp);
  }, [k]);
  return <span className="font-mono text-xs">{fp}</span>;
}

const NO_KEYS: never[] = [];

function Passkeys() {
  const me = app.use((s) => s.me)!;
  const unlockKeys = app.use((s) => (s.vault.status === "unlocked" ? s.vault.envelope.keys : NO_KEYS));
  const list = useAsync(() => api.get<PasskeyInfo[]>("/passkeys"));
  const [label, setLabel] = useState("");
  const [open, setOpen] = useState(false);

  return (
    <Card
      padded={false}
      title="Your passkeys"
      actions={
        <Button size="sm" variant="primary" onClick={() => setOpen(true)}>
          <PlusIcon /> Add passkey
        </Button>
      }
    >
      <ul className="divide-y divide-zinc-100 dark:divide-zinc-800">
        {(list.data ?? []).map((k) => {
          const unlocks = unlockKeys.some((w) => w.kind === "prf" && w.credentialId === k.id);
          return (
            <li key={k.id} className="flex items-center justify-between gap-4 px-5 py-3">
              <div>
                <p className="flex items-center gap-2 text-sm font-medium">
                  {k.label} {k.id === me.user.credentialId && <Badge tone="blue">this session</Badge>}
                </p>
                <p className="text-xs text-zinc-500">
                  Fingerprint <Fp k={k.publicKey} /> · added {timeAgo(k.createdAt)} · last used {timeAgo(k.lastUsedAt)}
                </p>
              </div>
              <div className="flex items-center gap-2">
                {unlocks ? <Badge tone="green">unlocks vault</Badge> : <Badge tone="yellow">needs recovery key</Badge>}
                <ActionButton
                  size="sm"
                  variant="ghost"
                  className="text-red-600 dark:text-red-400"
                  disabled={(list.data?.length ?? 0) <= 1}
                  action={async () => {
                    if (!(await confirmAction({ title: `Remove ${k.label}?`, body: "It can no longer sign in to the console. Also revoke it on each server (Server → Access), because servers keep their own lists.", confirm: "Remove", danger: true }))) return;
                    await api.del(`/passkeys/${encodeURIComponent(k.id)}`);
                    await removePasskeyFromVault(k.id);
                    await list.reload();
                  }}
                >
                  Remove
                </ActionButton>
              </div>
            </li>
          );
        })}
      </ul>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Add a passkey"
        footer={
          <>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <ActionButton
              variant="primary"
              action={async () => {
                const r = await addPasskey(label || "Passkey");
                toast(r.prfWrapped ? "Passkey added. It can unlock your vault." : "Passkey added. It will need the recovery key to unlock the vault.", "success");
                setOpen(false);
                setLabel("");
                await list.reload();
              }}
            >
              Create passkey
            </ActionButton>
          </>
        }
      >
        <Field label="Name">
          <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="YubiKey 5C (backup)" />
        </Field>
        <p className="text-sm text-zinc-500">Register at least two passkeys, for example a platform passkey and a hardware security key kept somewhere safe. To use a new passkey on existing servers, trust it from each server's Access tab.</p>
      </Modal>
    </Card>
  );
}

function Security() {
  const ttl = app.use((s) => s.sessionTtl);
  const scope = app.use((s) => s.sessionScope);
  const [newKey, setNewKey] = useState<string | null>(null);
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title="Operations session">
        <div className="space-y-4">
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            When you unlock, your passkey signs a certificate for a key that exists only in this tab. Agents accept it for read (and optionally operate) actions until it expires. Admin actions always need a fresh passkey touch.
          </p>
          <Field label="Duration">
            <Select value={ttl} onChange={(e) => setSessionPrefs(Number(e.target.value), scope)}>
              {[900, 1800, 3600, 4 * 3600, 8 * 3600].map((s) => (
                <option key={s} value={s}>
                  {s < 3600 ? `${s / 60} minutes` : `${s / 3600} hour${s > 3600 ? "s" : ""}`}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Scope" hint="Applies from the next unlock.">
            <Select value={scope} onChange={(e) => setSessionPrefs(ttl, e.target.value as Scope)}>
              <option value="operate">Read + start/stop/restart</option>
              <option value="read">Read only (touch passkey for every change)</option>
            </Select>
          </Field>
        </div>
      </Card>
      <Card title="Recovery key">
        <p className="mb-4 text-sm text-zinc-600 dark:text-zinc-400">Generate a new recovery key and invalidate the old one. Use this if you think the old key was exposed.</p>
        <ActionButton
          action={async () => {
            if (!(await confirmAction({ title: "Rotate recovery key?", body: "The current recovery key will stop working immediately.", confirm: "Rotate" }))) return;
            setNewKey(await rotateRecoveryKey());
          }}
        >
          Rotate recovery key
        </ActionButton>
        {newKey && (
          <div className="mt-4 space-y-2">
            <Callout tone="yellow">Store this now. It will not be shown again.</Callout>
            <CodeBlock code={newKey} />
          </div>
        )}
      </Card>
    </div>
  );
}
