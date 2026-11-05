import type { SignerKey } from "@nodescale/protocol";
import { useState } from "react";
import { api, type Member, type Server } from "../../lib/api.ts";
import { callAgent } from "../../lib/agent.ts";
import { timeAgo, useAsync } from "../../lib/hooks.ts";
import { ActionButton, Badge, Button, Callout, Card, Field, KeyIcon, Modal, Select, Spinner, Table, Td, toast } from "../../components/ui.tsx";
import { AgentError, Fingerprint, run, useAgent } from "./shared.tsx";

export function AccessTab({ server }: { server: Server }) {
  const signers = useAgent<SignerKey[]>(server, "signers.list");
  const members = useAsync(() => api.get<Member[]>("/workspace/members"));
  const [adding, setAdding] = useState<{ key: Member["passkeys"][number]; member: Member } | null>(null);
  const [role, setRole] = useState<SignerKey["role"]>("operator");

  const enrolled = new Set(signers.data?.map((s) => s.id));
  const candidates = (members.data ?? []).flatMap((m) => m.passkeys.filter((k) => !enrolled.has(k.id)).map((key) => ({ key, member: m })));

  return (
    <div className="space-y-6">
      <Callout>
        This list is read from the server itself. Only these passkeys can act on <strong>{server.name}</strong>, and changing the list needs a fresh admin passkey signature, so a compromised console cannot add itself.
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
              Ask <strong>{adding.member.name}</strong> to read out the fingerprint in their Settings → Passkeys, and check it matches:
            </p>
            <p className="rounded-lg bg-zinc-100 px-4 py-3 text-center dark:bg-zinc-800">
              <Fingerprint publicKey={adding.key.publicKey} className="text-sm" />
            </p>
            <Field label="Role on this server">
              <Select value={role} onChange={(e) => setRole(e.target.value as SignerKey["role"])}>
                <option value="viewer">Viewer — read containers, logs and status</option>
                <option value="operator">Operator — also start, stop and restart</option>
                <option value="admin">Admin — also deploy, remove, exec and manage passkeys</option>
              </Select>
            </Field>
          </>
        )}
      </Modal>
    </div>
  );
}

interface AuditEntry {
  ts: number;
  op: string;
  label?: string;
  auth?: string;
  ok: boolean;
  error?: string;
  args?: unknown;
}

export function ServerAuditTab({ server }: { server: Server }) {
  const log = useAgent<AuditEntry[]>(server, "audit.read", { lines: 300 });
  return (
    <div className="space-y-4">
      <Callout>
        Written by the gate on the server, in a directory neither the console nor the SSH user can reach. It records every authenticated state-changing request and every authenticated failure. Environment values are redacted.
      </Callout>
      <Card padded={false}>
        {log.error ? (
          <div className="p-5">
            <AgentError error={log.error} onRetry={() => void log.reload()} />
          </div>
        ) : !log.data ? (
          <div className="p-5">
            <Spinner />
          </div>
        ) : !log.data.length ? (
          <p className="p-5 text-sm text-zinc-500">No entries yet.</p>
        ) : (
          <Table head={["Time", "Passkey", "Operation", "Auth", "Result"]}>
            {log.data.map((e, i) => (
              <tr key={i}>
                <Td className="text-xs text-zinc-500">{new Date(e.ts * 1000).toLocaleString()}</Td>
                <Td>{e.label ?? "—"}</Td>
                <Td>
                  <span className="font-mono text-xs">{e.op}</span>
                  {e.args !== undefined && <span className="ml-2 inline-block max-w-80 truncate align-bottom font-mono text-[11px] text-zinc-500">{JSON.stringify(e.args)}</span>}
                </Td>
                <Td className="text-xs">{e.auth === "session" ? "session key" : "passkey"}</Td>
                <Td>{e.ok ? <Badge tone="green">ok</Badge> : <Badge tone="red">{e.error?.split(":")[0] ?? "failed"}</Badge>}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
