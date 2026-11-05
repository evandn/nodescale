import { fingerprint } from "@nodescale/protocol";
import { useEffect, useState } from "react";
import { api, type Member } from "../lib/api.ts";
import { app } from "../lib/app.ts";
import { timeAgo, useAsync } from "../lib/hooks.ts";
import { ActionButton, Badge, Button, Callout, Card, CodeBlock, PageHeader, PlusIcon, Select, Table, Td, confirmAction } from "../components/ui.tsx";

function Fp({ k }: { k: string }) {
  const [fp, setFp] = useState("");
  useEffect(() => {
    void fingerprint(k).then(setFp);
  }, [k]);
  return <span className="font-mono">{fp}</span>;
}

export function TeamPage() {
  const me = app.use((s) => s.me)!;
  const members = useAsync(() => api.get<Member[]>("/workspace/members"));
  const canAdmin = me.workspace.role !== "member";
  const invites = useAsync(async () => (canAdmin ? api.get<{ id: string; role: string; createdAt: number; expiresAt: number; usedAt: number | null }[]>("/workspace/invites") : []));
  const [role, setRole] = useState("member");
  const [link, setLink] = useState<string | null>(null);

  return (
    <>
      <PageHeader title="Team" description={`Members of ${me.workspace.name}. Workspace roles control the console; access to each server is controlled by the passkeys trusted on that server.`} />
      <div className="space-y-6">
        <Card padded={false} title="Members">
          <Table head={["Name", "Role", "Passkeys", "Joined", ""]}>
            {(members.data ?? []).map((m) => (
              <tr key={m.id}>
                <Td>
                  <span className="font-medium">{m.name}</span> {m.id === me.user.id && <Badge>you</Badge>}
                </Td>
                <Td>
                  {me.workspace.role === "owner" && m.role !== "owner" ? (
                    <Select
                      className="w-28 py-1"
                      value={m.role}
                      onChange={async (e) => {
                        await api.patch(`/workspace/members/${m.id}`, { role: e.target.value });
                        await members.reload();
                      }}
                    >
                      <option value="admin">admin</option>
                      <option value="member">member</option>
                    </Select>
                  ) : (
                    <Badge tone={m.role === "owner" ? "blue" : "gray"}>{m.role}</Badge>
                  )}
                </Td>
                <Td className="text-xs">
                  {m.passkeys.map((k) => (
                    <div key={k.id}>
                      {k.label} · <Fp k={k.publicKey} />
                    </div>
                  ))}
                </Td>
                <Td className="text-zinc-500">{timeAgo(m.joinedAt)}</Td>
                <Td className="text-right">
                  {canAdmin && m.role !== "owner" && m.id !== me.user.id && (
                    <ActionButton
                      size="sm"
                      variant="ghost"
                      className="text-red-600 dark:text-red-400"
                      action={async () => {
                        if (!(await confirmAction({ title: `Remove ${m.name}?`, body: "They lose access to the console. Also revoke their passkeys on each server (Server → Access): servers do not consult the console.", confirm: "Remove", danger: true }))) return;
                        await api.del(`/workspace/members/${m.id}`);
                        await members.reload();
                      }}
                    >
                      Remove
                    </ActionButton>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        </Card>

        {canAdmin && (
          <Card
            title="Invites"
            actions={
              <div className="flex gap-2">
                <Select className="w-28 py-1" value={role} onChange={(e) => setRole(e.target.value)}>
                  <option value="member">member</option>
                  <option value="admin">admin</option>
                </Select>
                <ActionButton
                  size="sm"
                  variant="primary"
                  action={async () => {
                    const r = await api.post<{ url: string }>("/workspace/invites", { role });
                    setLink(r.url);
                    await invites.reload();
                  }}
                >
                  <PlusIcon /> Create link
                </ActionButton>
              </div>
            }
          >
            {link && (
              <div className="mb-4 space-y-2">
                <Callout tone="yellow">Single use, valid for 7 days. Send it over a channel you trust; this is the only time it is shown.</Callout>
                <CodeBlock code={link} />
              </div>
            )}
            {invites.data?.length ? (
              <ul className="divide-y divide-zinc-100 text-sm dark:divide-zinc-800">
                {invites.data.map((i) => (
                  <li key={i.id} className="flex items-center justify-between py-2">
                    <span>
                      <Badge>{i.role}</Badge> <span className="ml-2 text-zinc-500">created {timeAgo(i.createdAt)}</span>
                    </span>
                    {i.usedAt ? (
                      <Badge tone="green">used {timeAgo(i.usedAt)}</Badge>
                    ) : i.expiresAt < Date.now() / 1000 ? (
                      <Badge>expired</Badge>
                    ) : (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={async () => {
                          await api.del(`/workspace/invites/${encodeURIComponent(i.id)}`);
                          await invites.reload();
                        }}
                      >
                        Revoke
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-zinc-500">No invites yet.</p>
            )}
          </Card>
        )}
      </div>
    </>
  );
}
