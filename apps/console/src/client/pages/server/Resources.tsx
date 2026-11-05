import { useState } from "react";
import type { Server } from "../../lib/api.ts";
import { bytes, timeAgo } from "../../lib/hooks.ts";
import { ActionButton, Badge, Card, Code, Input, KeyIcon, Spinner, Table, Td } from "../../components/ui.tsx";
import { AgentError, run, useAgent } from "./shared.tsx";

interface Image {
  id: string;
  repoTags: string[];
  created: number;
  size: number;
}

export function ImagesTab({ server }: { server: Server }) {
  const list = useAgent<Image[]>(server, "images.list");
  const [pull, setPull] = useState("");
  const total = (list.data ?? []).reduce((n, i) => n + i.size, 0);
  return (
    <Card
      padded={false}
      title={
        <span>
          Images <span className="font-normal text-zinc-500">· {bytes(total)}</span>
        </span>
      }
      actions={
        <div className="flex gap-2">
          <Input className="w-64 py-1 text-xs" placeholder="nginx:1.27-alpine" value={pull} onChange={(e) => setPull(e.target.value)} />
          <ActionButton
            size="sm"
            variant="primary"
            disabled={!pull}
            action={async () => {
              if (await run(server, "images.pull", { image: pull }, <>Pull <Code>{pull}</Code> onto {server.name}.</>, { ttl: 300 })) {
                setPull("");
                await list.reload();
              }
            }}
          >
            <KeyIcon /> Pull
          </ActionButton>
          <ActionButton
            size="sm"
            variant="ghost"
            action={async () => {
              if (await run(server, "images.prune", { all: false }, `Remove dangling (untagged) images on ${server.name}.`)) await list.reload();
            }}
          >
            Prune
          </ActionButton>
        </div>
      }
    >
      {list.error ? (
        <div className="p-5">
          <AgentError error={list.error} onRetry={() => void list.reload()} />
        </div>
      ) : !list.data ? (
        <div className="p-5">
          <Spinner />
        </div>
      ) : (
        <Table head={["Tags", "ID", "Size", "Created", ""]}>
          {list.data.map((i) => (
            <tr key={i.id}>
              <Td className="font-mono text-xs">{i.repoTags.join(", ") || <span className="text-zinc-400">&lt;none&gt;</span>}</Td>
              <Td className="font-mono text-xs text-zinc-500">{i.id.replace("sha256:", "").slice(0, 12)}</Td>
              <Td>{bytes(i.size)}</Td>
              <Td className="text-zinc-500">{timeAgo(i.created)}</Td>
              <Td className="text-right">
                <ActionButton
                  size="sm"
                  variant="ghost"
                  className="text-red-600 dark:text-red-400"
                  action={async () => {
                    if (await run(server, "images.remove", { id: i.id }, `Remove image ${i.repoTags[0] ?? i.id} from ${server.name}.`)) await list.reload();
                  }}
                >
                  Remove
                </ActionButton>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

interface Network {
  id: string;
  name: string;
  driver: string;
  scope: string;
}

interface Volume {
  name: string;
  driver: string;
  createdAt: string;
  labels: Record<string, string> | null;
}

export function ResourcesTab({ server }: { server: Server }) {
  const nets = useAgent<Network[]>(server, "networks.list");
  const vols = useAgent<Volume[]>(server, "volumes.list");
  const [newNet, setNewNet] = useState("");
  const [newVol, setNewVol] = useState("");
  const builtin = new Set(["bridge", "host", "none"]);

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card
        padded={false}
        title="Networks"
        actions={
          <div className="flex gap-2">
            <Input className="w-40 py-1 text-xs" placeholder="name" value={newNet} onChange={(e) => setNewNet(e.target.value)} />
            <ActionButton
              size="sm"
              disabled={!newNet}
              action={async () => {
                if (await run(server, "networks.create", { name: newNet }, `Create bridge network ${newNet} on ${server.name}.`)) {
                  setNewNet("");
                  await nets.reload();
                }
              }}
            >
              Create
            </ActionButton>
          </div>
        }
      >
        {nets.error ? (
          <div className="p-5">
            <AgentError error={nets.error} onRetry={() => void nets.reload()} />
          </div>
        ) : !nets.data ? (
          <div className="p-5">
            <Spinner />
          </div>
        ) : (
          <Table head={["Name", "Driver", ""]}>
            {nets.data.map((n) => (
              <tr key={n.id}>
                <Td>
                  <span className="font-medium">{n.name}</span> {n.name === "nodescale" && <Badge tone="blue">tunnel edge</Badge>}
                </Td>
                <Td className="text-xs">{n.driver}</Td>
                <Td className="text-right">
                  {!builtin.has(n.name) && (
                    <ActionButton
                      size="sm"
                      variant="ghost"
                      className="text-red-600 dark:text-red-400"
                      action={async () => {
                        if (await run(server, "networks.remove", { name: n.name }, `Remove network ${n.name} on ${server.name}. Containers must be disconnected first.`)) await nets.reload();
                      }}
                    >
                      Remove
                    </ActionButton>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card
        padded={false}
        title="Volumes"
        actions={
          <div className="flex gap-2">
            <Input className="w-40 py-1 text-xs" placeholder="name" value={newVol} onChange={(e) => setNewVol(e.target.value)} />
            <ActionButton
              size="sm"
              disabled={!newVol}
              action={async () => {
                if (await run(server, "volumes.create", { name: newVol }, `Create volume ${newVol} on ${server.name}.`)) {
                  setNewVol("");
                  await vols.reload();
                }
              }}
            >
              Create
            </ActionButton>
          </div>
        }
      >
        {vols.error ? (
          <div className="p-5">
            <AgentError error={vols.error} onRetry={() => void vols.reload()} />
          </div>
        ) : !vols.data ? (
          <div className="p-5">
            <Spinner />
          </div>
        ) : (
          <Table head={["Name", "Stack", ""]}>
            {vols.data.map((v) => (
              <tr key={v.name}>
                <Td className="max-w-64 truncate font-mono text-xs">{v.name}</Td>
                <Td className="text-xs">{v.labels?.["io.nodescale.stack"] ?? "—"}</Td>
                <Td className="text-right">
                  <ActionButton
                    size="sm"
                    variant="ghost"
                    className="text-red-600 dark:text-red-400"
                    action={async () => {
                      if (await run(server, "volumes.remove", { name: v.name }, <>Permanently delete volume <Code>{v.name}</Code> and all its data on {server.name}. This cannot be undone.</>)) await vols.reload();
                    }}
                  >
                    Delete
                  </ActionButton>
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
