"use client";

import { useState } from "react";
import { Mono, OriginBadge, SeverityBadge, StatusChip } from "@/components/badges";
import { Button } from "@/components/ui/button";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { EmptyState, ErrorNote, Pager, Skeleton, TableWrap } from "@/components/ui/misc";
import { PageHeader, Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useDetail } from "@/lib/detail";
import { timeAgo, titleCase } from "@/lib/format";
import { useApi, useDebounced } from "@/lib/hooks";
import { useOrigin } from "@/lib/origin";
import { SEVERITIES, type Incident, type Page, type Severity } from "@/lib/types";

const PAGE_SIZE = 25;

const STATUS_OPTIONS = [
  { value: "active", label: "Active" },
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
  { value: "", label: "Any status" },
];

function NewIncident({ onDone, onCancel }: { onDone: (id: number) => void; onCancel: () => void }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const created = await api<Incident>("/api/incidents", {
        method: "POST",
        body: { title: title.trim(), description: description.trim() || null, severity },
      });
      onDone(created.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the incident");
      setBusy(false);
    }
  }

  return (
    <Panel className="mb-4">
      <PanelHeader title="New incident" hint="To attach alerts, open an alert and choose Create incident." />
      <div className="grid gap-3 p-4 sm:grid-cols-3">
        <div className="sm:col-span-2">
          <Field label="Title">
            <Input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={300} autoFocus />
          </Field>
        </div>
        <Field label="Severity">
          <Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {titleCase(s)}
              </option>
            ))}
          </Select>
        </Field>
        <div className="sm:col-span-3">
          <Field label="Description">
            <Textarea value={description} onChange={(e) => setDescription(e.target.value)} maxLength={5000} />
          </Field>
        </div>
        {error ? (
          <div className="sm:col-span-3">
            <ErrorNote message={error} />
          </div>
        ) : null}
        <div className="flex gap-2 sm:col-span-3">
          <Button variant="primary" disabled={busy || title.trim().length < 3} onClick={submit}>
            Create incident
          </Button>
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </div>
    </Panel>
  );
}

export default function IncidentsPage() {
  const { param } = useOrigin();
  const { can } = useAuth();
  const { openIncident, openIp, refreshKey, bump } = useDetail();
  const [status, setStatus] = useState("active");
  const [text, setText] = useState("");
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const q = useDebounced(text.trim(), 350);

  const { data, error, loading, reload } = useApi<Page<Incident>>(
    "/api/incidents",
    { status, q, origin: param, page, page_size: PAGE_SIZE },
    { refreshKey, every: 30_000 },
  );

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title="Incidents"
        description="Cases that group related alerts so a team can investigate and close them together."
        actions={
          can("analyst", "admin") ? (
            <Button variant="primary" onClick={() => setCreating(true)} disabled={creating}>
              New incident
            </Button>
          ) : null
        }
      />

      {creating ? (
        <NewIncident
          onCancel={() => setCreating(false)}
          onDone={(id) => {
            setCreating(false);
            bump();
            openIncident(id);
          }}
        />
      ) : null}

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
          <Input
            className="w-full sm:w-64"
            placeholder="Search incidents"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setPage(1);
            }}
            aria-label="Search incidents"
          />
          <Select
            className="w-auto"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(1);
            }}
            aria-label="Status"
          >
            {STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>

        {error ? (
          <div className="p-3">
            <ErrorNote message={error} onRetry={reload} />
          </div>
        ) : null}

        {loading && !data ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : data && data.items.length === 0 ? (
          <EmptyState title="No incidents here">
            High-severity alerts open an incident automatically. You can also create one from any alert.
          </EmptyState>
        ) : (
          <TableWrap>
            <table className="w-full min-w-[760px] text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">Severity</th>
                  <th className="th">Incident</th>
                  <th className="th">Status</th>
                  <th className="th">Assigned to</th>
                  <th className="th text-right">Alerts</th>
                  <th className="th">Updated</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data?.items.map((incident) => (
                  <tr
                    key={incident.id}
                    tabIndex={0}
                    className="cursor-pointer hover:bg-raised"
                    onClick={() => openIncident(incident.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") openIncident(incident.id);
                    }}
                  >
                    <td className="td">
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td className="td max-w-[380px]">
                      <span className="flex items-center gap-2">
                        <span className="truncate font-medium text-ink">
                          #{incident.id} {incident.title}
                        </span>
                        <OriginBadge origin={incident.data_origin} />
                      </span>
                      {incident.source_ip ? (
                        <button
                          type="button"
                          className="text-xs text-ink-3 underline decoration-line underline-offset-2 hover:text-ink"
                          onClick={(e) => {
                            e.stopPropagation();
                            openIp(incident.source_ip as string);
                          }}
                        >
                          <Mono>{incident.source_ip}</Mono>
                        </button>
                      ) : null}
                    </td>
                    <td className="td">
                      <StatusChip status={incident.status} />
                    </td>
                    <td className="td text-ink-2">{incident.assignee_name ?? "Unassigned"}</td>
                    <td className="td num text-right">{incident.alert_count}</td>
                    <td className="td whitespace-nowrap text-ink-2">{timeAgo(incident.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        {data && data.total > 0 ? <Pager page={page} pageSize={PAGE_SIZE} total={data.total} onChange={setPage} /> : null}
      </Panel>
    </div>
  );
}
