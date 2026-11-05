import { api, type AuditEvent } from "../lib/api.ts";
import { useAsync } from "../lib/hooks.ts";
import { Badge, Button, Callout, Card, Code, PageHeader, RefreshIcon, Spinner, Table, Td } from "../components/ui.tsx";

export function AuditPage() {
  const events = useAsync(() => api.get<AuditEvent[]>("/audit"));
  return (
    <>
      <PageHeader
        title="Audit log"
        description="State-changing actions recorded by the console."
        actions={
          <Button variant="ghost" onClick={() => void events.reload()}>
            <RefreshIcon /> Refresh
          </Button>
        }
      />
      <div className="mb-6">
        <Callout>
          This log lives in the console and is only as trustworthy as the console. Each server's gate keeps its own log of authenticated requests at <Code>/var/lib/nodescale/audit.jsonl</Code> (Server → Audit). That is the authoritative record.
        </Callout>
      </div>
      <Card padded={false}>
        {!events.data ? (
          <div className="p-5">
            <Spinner />
          </div>
        ) : !events.data.length ? (
          <p className="p-5 text-sm text-zinc-500">No events yet.</p>
        ) : (
          <Table head={["Time", "Who", "Action", "Server", "Result"]}>
            {events.data.map((e) => (
              <tr key={e.id}>
                <Td className="text-xs text-zinc-500">{new Date(e.createdAt * 1000).toLocaleString()}</Td>
                <Td>{e.userName ?? "—"}</Td>
                <Td>
                  <Code>{e.action}</Code>
                  {e.detail && <span className="ml-2 max-w-md truncate text-xs text-zinc-500">{e.detail}</span>}
                </Td>
                <Td>{e.serverName ?? "—"}</Td>
                <Td>{e.ok ? <Badge tone="green">ok</Badge> : <Badge tone="red">failed</Badge>}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
