"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/form";
import { CopyButton, EmptyState, ErrorNote, Notice, Skeleton, TableWrap } from "@/components/ui/misc";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { api, apiBase } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { fmtNumber, timeAgo } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { Agent, AgentCreated } from "@/lib/types";
import { cn } from "@/lib/utils";

function serverUrl(): string {
  if (typeof window === "undefined") return "";
  return apiBase() || window.location.origin;
}

function Code({ children }: { children: string }) {
  return (
    <pre className="overflow-x-auto rounded border border-line bg-page p-3 font-mono text-xs leading-relaxed text-ink">{children}</pre>
  );
}

/** Shown once after creating or rotating a key: the server keeps only a hash, so it can never be shown again. */
function KeyDialog({ agent, onClose }: { agent: AgentCreated; onClose: () => void }) {
  const url = serverUrl();
  const linux = `cd agent\nsudo ./install/install-linux.sh ${url} ${agent.api_key}`;
  const windows = `cd agent\n.\\install\\install-windows.ps1 -Url ${url} -ApiKey ${agent.api_key}`;
  const test = `cd agent\npip install -r requirements.txt\nSENTINELX_URL=${url} SENTINELX_API_KEY=${agent.api_key} python -m sentinelx_agent --check`;
  return (
    <Panel className="mb-4 border-sev-medium/60">
      <PanelHeader title={`Agent key for ${agent.name}`} hint="Copy it now. It is shown only once and cannot be recovered." actions={<Button size="sm" onClick={onClose}>I have saved it</Button>} />
      <div className="space-y-4 p-4">
        <div>
          <p className="mb-1.5 text-xs font-medium text-ink-2">API key</p>
          <div className="flex flex-wrap items-center gap-2">
            <code className="break-all rounded border border-line bg-page px-3 py-2 font-mono text-sm text-ink">{agent.api_key}</code>
            <CopyButton text={agent.api_key} />
          </div>
        </div>
        <div>
          <div className="mb-1.5 flex items-center justify-between">
            <p className="text-xs font-medium text-ink-2">Install on Linux (run as root, from the project folder)</p>
            <CopyButton text={linux} />
          </div>
          <Code>{linux}</Code>
        </div>
        <div>
          <div className="mb-1.5 flex items-center justify-between">
            <p className="text-xs font-medium text-ink-2">Install on Windows (Administrator PowerShell)</p>
            <CopyButton text={windows} />
          </div>
          <Code>{windows}</Code>
        </div>
        <div>
          <div className="mb-1.5 flex items-center justify-between">
            <p className="text-xs font-medium text-ink-2">Check the connection first (optional)</p>
            <CopyButton text={test} />
          </div>
          <Code>{test}</Code>
        </div>
        {url.startsWith("http://") && !url.includes("localhost") && !url.includes("127.0.0.1") ? (
          <Notice tone="warn">This server address is not using HTTPS. The agent refuses to send logs over plain HTTP to anything except localhost.</Notice>
        ) : null}
      </div>
    </Panel>
  );
}

function statusOf(agent: Agent): { label: string; dot: string } {
  if (!agent.is_active) return { label: "Disabled", dot: "bg-ink-3" };
  if (agent.online) return { label: "Online", dot: "bg-good" };
  return { label: agent.last_seen ? "Offline" : "Waiting for first contact", dot: "bg-sev-medium" };
}

export function AgentsTab() {
  const { can } = useAuth();
  const admin = can("admin");
  const { data, error, loading, reload } = useApi<Agent[]>("/api/agents", {}, { every: 15_000 });
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [created, setCreated] = useState<AgentCreated | null>(null);

  async function run<T>(action: () => Promise<T>): Promise<T | undefined> {
    setBusy(true);
    setActionError(null);
    try {
      const result = await action();
      reload();
      return result;
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Something went wrong");
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  async function createAgent() {
    const agent = await run(() => api<AgentCreated>("/api/agents", { method: "POST", body: { name: name.trim() } }));
    if (agent) {
      setCreated(agent);
      setName("");
    }
  }

  async function rotate(agent: Agent) {
    if (!window.confirm(`Create a new key for ${agent.name}? The old key stops working immediately.`)) return;
    const result = await run(() => api<AgentCreated>(`/api/agents/${agent.id}/rotate-key`, { method: "POST" }));
    if (result) setCreated(result);
  }

  async function remove(agent: Agent) {
    if (!window.confirm(`Delete agent ${agent.name}? Events it already sent are kept.`)) return;
    await run(() => api(`/api/agents/${agent.id}`, { method: "DELETE" }));
  }

  return (
    <div className="space-y-4">
      {created ? <KeyDialog agent={created} onClose={() => setCreated(null)} /> : null}

      {admin ? (
        <Panel>
          <PanelHeader title="Add an agent" hint="One agent per machine. Each gets its own key, so a single machine can be cut off without affecting the others." />
          <form
            className="flex flex-wrap items-end gap-3 p-4"
            onSubmit={(e) => {
              e.preventDefault();
              void createAgent();
            }}
          >
            <div className="w-full sm:w-72">
              <Field label="Agent name" hint="Letters, numbers, spaces, dots, dashes. Example: web-01">
                <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={128} />
              </Field>
            </div>
            <Button type="submit" variant="primary" disabled={busy || name.trim().length < 2}>
              Create agent
            </Button>
          </form>
        </Panel>
      ) : null}

      <Panel>
        <PanelHeader title="Agents" hint="Programs on your servers that read logs and send events here." />
        {error ? (
          <div className="p-3">
            <ErrorNote message={error} onRetry={reload} />
          </div>
        ) : null}
        {actionError ? (
          <div className="p-3">
            <ErrorNote message={actionError} />
          </div>
        ) : null}
        {loading && !data ? (
          <div className="p-4">
            <Skeleton className="h-24 w-full" />
          </div>
        ) : data && data.length === 0 ? (
          <EmptyState title="No agents yet">{admin ? "Create one above to start collecting real logs." : "An admin can add agents."}</EmptyState>
        ) : (
          <TableWrap>
            <table className="w-full min-w-[820px] text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">Agent</th>
                  <th className="th">Status</th>
                  <th className="th">Machine</th>
                  <th className="th">Key</th>
                  <th className="th text-right">Events</th>
                  <th className="th">Last contact</th>
                  {admin ? <th className="th text-right">Actions</th> : null}
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data?.map((agent) => {
                  const status = statusOf(agent);
                  return (
                    <tr key={agent.id}>
                      <td className="td font-medium text-ink">{agent.name}</td>
                      <td className="td">
                        <span className="inline-flex items-center gap-2">
                          <span className={cn("h-2 w-2 rounded-full", status.dot)} />
                          {status.label}
                        </span>
                      </td>
                      <td className="td text-ink-2">
                        {agent.hostname ?? "-"}
                        {agent.os_type ? `, ${agent.os_type}` : ""}
                        {agent.version ? `, v${agent.version}` : ""}
                      </td>
                      <td className="td font-mono text-xs text-ink-2">{agent.api_key_prefix}...</td>
                      <td className="td num text-right">{fmtNumber(agent.events_received)}</td>
                      <td className="td whitespace-nowrap text-ink-2">{timeAgo(agent.last_seen)}</td>
                      {admin ? (
                        <td className="td">
                          <div className="flex justify-end gap-1">
                            <Button size="sm" variant="ghost" disabled={busy} onClick={() => run(() => api(`/api/agents/${agent.id}`, { method: "PATCH", body: { is_active: !agent.is_active } }))}>
                              {agent.is_active ? "Disable" : "Enable"}
                            </Button>
                            <Button size="sm" variant="ghost" disabled={busy} onClick={() => rotate(agent)}>
                              New key
                            </Button>
                            <Button size="sm" variant="ghost" disabled={busy} onClick={() => remove(agent)}>
                              Delete
                            </Button>
                          </div>
                        </td>
                      ) : null}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Panel>
    </div>
  );
}
