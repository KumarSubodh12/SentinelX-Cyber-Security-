"use client";

import { ArrowLeft } from "lucide-react";
import { useState, type ReactNode } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useDetail } from "@/lib/detail";
import { fmtDateTime, fmtNumber, timeAgo, titleCase } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { AlertDetail, AlertStatus, Assignable, Incident, IncidentDetail, IncidentStatus, IpDetail, Severity } from "@/lib/types";
import { Mono, OriginBadge, RiskMeter, SeverityBadge, StatusChip } from "./badges";
import { EventTable } from "./event-table";
import { Button } from "./ui/button";
import { Field, Select, Textarea } from "./ui/form";
import { ErrorNote, KeyValue, Notice, Skeleton } from "./ui/misc";
import { Sheet } from "./ui/sheet";
import { BarList } from "./bar-list";

function BackBar() {
  const { canBack, back } = useDetail();
  if (!canBack) return null;
  return (
    <Button size="sm" variant="ghost" className="-ml-2 mb-3" onClick={back}>
      <ArrowLeft className="h-3.5 w-3.5" />
      Back
    </Button>
  );
}

function SectionTitle({ children }: { children: string }) {
  return <h3 className="mb-2 mt-6 text-sm font-semibold text-ink">{children}</h3>;
}

function LinkButton({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} className="text-left underline decoration-line underline-offset-2 hover:decoration-ink">
      {children}
    </button>
  );
}

function stringify(value: unknown): string {
  if (Array.isArray(value)) return value.map(stringify).join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

const HIDDEN_DETAIL_KEYS = new Set(["risk_factors", "window_event_count", "reputation"]);

function RiskBreakdown({ details }: { details: Record<string, unknown> | null }) {
  const factors = details?.risk_factors as Record<string, number> | undefined;
  if (!factors) return null;
  return (
    <>
      <SectionTitle>How the risk score was calculated</SectionTitle>
      <KeyValue
        items={[
          { label: "Starting score", value: <span className="num">{factors.base} (from the rule severity)</span> },
          { label: "Repeated activity", value: <span className="num">+{factors.frequency}</span> },
          { label: "IP reputation", value: <span className="num">+{factors.reputation}</span> },
          { label: "Unusual behaviour", value: <span className="num">+{factors.anomaly}</span> },
          { label: "Added in total", value: <span className="num">+{factors.bonus_applied} (limit +20)</span> },
        ]}
      />
    </>
  );
}

/* ----------------------------------------------------------------------------------------- Alert */

function AlertSheet({ id }: { id: number }) {
  const { close, openIncident, openIp, bump, refreshKey } = useDetail();
  const { can } = useAuth();
  const { data, error, loading } = useApi<AlertDetail>(`/api/alerts/${id}`, {}, { refreshKey });
  const [noteFor, setNoteFor] = useState<null | "resolved" | "false_positive">(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const canTriage = can("analyst", "admin");

  async function setStatus(status: AlertStatus, text?: string) {
    setBusy(true);
    setActionError(null);
    try {
      await api(`/api/alerts/${id}`, { method: "PATCH", body: { status, note: text } });
      setNoteFor(null);
      setNote("");
      bump();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Could not update the alert");
    } finally {
      setBusy(false);
    }
  }

  async function createIncident() {
    if (!data) return;
    setBusy(true);
    setActionError(null);
    try {
      const incident = await api<Incident>("/api/incidents", {
        method: "POST",
        body: { title: data.title, description: data.description, severity: data.severity, alert_ids: [data.id] },
      });
      bump();
      openIncident(incident.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Could not create the incident");
    } finally {
      setBusy(false);
    }
  }

  const extra = data?.details ? Object.entries(data.details).filter(([key]) => !HIDDEN_DETAIL_KEYS.has(key)) : [];

  return (
    <Sheet
      open
      onClose={close}
      wide
      title={data?.title ?? "Alert"}
      subtitle={
        data ? (
          <>
            <SeverityBadge severity={data.severity} />
            <StatusChip status={data.status} />
            <OriginBadge origin={data.data_origin} />
            <RiskMeter score={data.risk_score} />
          </>
        ) : null
      }
    >
      <BackBar />
      {error ? <ErrorNote message={error} /> : null}
      {loading && !data ? (
        <div className="space-y-3">
          <Skeleton className="h-4 w-2/3" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : null}

      {data ? (
        <>
          {data.data_origin === "simulated" ? (
            <div className="mb-4">
              <Notice>This alert comes from simulated test data. It is not a real attack.</Notice>
            </div>
          ) : null}
          {data.description ? <p className="mb-4 text-sm text-ink-2">{data.description}</p> : null}

          {canTriage ? (
            <div className="mb-2 space-y-3 rounded border border-line bg-page p-3">
              {actionError ? <ErrorNote message={actionError} /> : null}
              {noteFor ? (
                <div className="space-y-2">
                  <Field label={noteFor === "resolved" ? "How was this resolved?" : "Why is this a false positive?"}>
                    <Textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} autoFocus />
                  </Field>
                  <div className="flex gap-2">
                    <Button size="sm" variant="primary" disabled={busy || note.trim().length < 3} onClick={() => setStatus(noteFor, note.trim())}>
                      {noteFor === "resolved" ? "Mark resolved" : "Mark false positive"}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setNoteFor(null)}>
                      Cancel
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {data.status === "open" ? (
                    <Button size="sm" disabled={busy} onClick={() => setStatus("acknowledged")}>
                      Acknowledge
                    </Button>
                  ) : null}
                  {data.status === "open" || data.status === "acknowledged" ? (
                    <>
                      <Button size="sm" disabled={busy} onClick={() => setNoteFor("resolved")}>
                        Resolve
                      </Button>
                      <Button size="sm" disabled={busy} onClick={() => setNoteFor("false_positive")}>
                        False positive
                      </Button>
                    </>
                  ) : (
                    <Button size="sm" disabled={busy} onClick={() => setStatus("open")}>
                      Reopen
                    </Button>
                  )}
                  {data.incident_id === null ? (
                    <Button size="sm" variant="primary" disabled={busy} onClick={createIncident}>
                      Create incident
                    </Button>
                  ) : null}
                </div>
              )}
            </div>
          ) : null}

          <SectionTitle>Summary</SectionTitle>
          <KeyValue
            items={[
              { label: "Detected by", value: `${titleCase(data.detection_type)} detection (${data.rule_key})` },
              { label: "Category", value: data.category ? titleCase(data.category) : "-" },
              { label: "MITRE ATT&CK", value: data.mitre ?? "-" },
              {
                label: "Source IP",
                value: data.source_ip ? (
                  <LinkButton onClick={() => openIp(data.source_ip as string)}>
                    <Mono>{data.source_ip}</Mono>
                  </LinkButton>
                ) : (
                  "-"
                ),
              },
              { label: "User", value: data.username ?? "-" },
              { label: "Host", value: data.hostname ?? "-" },
              { label: "Events", value: <span className="num">{fmtNumber(data.event_count)}</span> },
              { label: "First seen", value: fmtDateTime(data.first_seen) },
              { label: "Last seen", value: `${fmtDateTime(data.last_seen)} (${timeAgo(data.last_seen)})` },
              {
                label: "Incident",
                value:
                  data.incident_id !== null ? (
                    <LinkButton onClick={() => openIncident(data.incident_id as number)}>Incident #{data.incident_id}</LinkButton>
                  ) : (
                    "Not part of an incident"
                  ),
              },
              ...(data.acknowledged_by ? [{ label: "Acknowledged", value: `${data.acknowledged_by}, ${fmtDateTime(data.acknowledged_at)}` }] : []),
              ...(data.resolved_by ? [{ label: "Closed by", value: `${data.resolved_by}, ${fmtDateTime(data.resolved_at)}` }] : []),
              ...(data.resolution_note ? [{ label: "Note", value: data.resolution_note }] : []),
            ]}
          />

          <RiskBreakdown details={data.details} />

          {extra.length > 0 ? (
            <>
              <SectionTitle>Evidence</SectionTitle>
              <KeyValue items={extra.map(([key, value]) => ({ label: titleCase(key), value: <span className="font-mono text-[13px]">{stringify(value)}</span> }))} />
            </>
          ) : null}

          <SectionTitle>Related events</SectionTitle>
          <EventTable events={data.events} />
        </>
      ) : null}
    </Sheet>
  );
}

/* -------------------------------------------------------------------------------------- Incident */

const INCIDENT_STATUSES: IncidentStatus[] = ["open", "investigating", "contained", "resolved", "closed"];

function IncidentSheet({ id }: { id: number }) {
  const { close, openAlert, openIp, bump, refreshKey } = useDetail();
  const { can } = useAuth();
  const canEdit = can("analyst", "admin");
  const { data, error, loading } = useApi<IncidentDetail>(`/api/incidents/${id}`, {}, { refreshKey });
  const people = useApi<Assignable[]>("/api/users/assignable", {}, { enabled: canEdit });
  const [resolution, setResolution] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  async function patch(body: Record<string, unknown>) {
    setBusy(true);
    setActionError(null);
    try {
      await api(`/api/incidents/${id}`, { method: "PATCH", body });
      bump();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Could not update the incident");
    } finally {
      setBusy(false);
    }
  }

  async function changeStatus(status: IncidentStatus) {
    const closing = status === "resolved" || status === "closed";
    const text = (resolution ?? data?.resolution ?? "").trim();
    if (closing && !text) {
      setActionError("Write how the incident was resolved first (field below), then choose the status again.");
      return;
    }
    await patch({ status, ...(closing ? { resolution: text } : {}) });
  }

  async function addNote() {
    const body = comment.trim();
    if (!body) return;
    setBusy(true);
    setActionError(null);
    try {
      await api(`/api/incidents/${id}/notes`, { method: "POST", body: { body } });
      setComment("");
      bump();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Could not add the note");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Sheet
      open
      onClose={close}
      wide
      title={data ? `#${data.id} ${data.title}` : "Incident"}
      subtitle={
        data ? (
          <>
            <SeverityBadge severity={data.severity} />
            <StatusChip status={data.status} />
            <OriginBadge origin={data.data_origin} />
          </>
        ) : null
      }
    >
      <BackBar />
      {error ? <ErrorNote message={error} /> : null}
      {loading && !data ? <Skeleton className="h-32 w-full" /> : null}

      {data ? (
        <>
          {data.description ? <p className="mb-4 text-sm text-ink-2">{data.description}</p> : null}
          {actionError ? (
            <div className="mb-3">
              <ErrorNote message={actionError} />
            </div>
          ) : null}

          {canEdit ? (
            <div className="grid gap-3 rounded border border-line bg-page p-3 sm:grid-cols-2">
              <Field label="Status">
                <Select value={data.status} disabled={busy} onChange={(e) => changeStatus(e.target.value as IncidentStatus)}>
                  {INCIDENT_STATUSES.map((status) => (
                    <option key={status} value={status}>
                      {titleCase(status)}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Assigned to">
                <Select
                  value={data.assigned_to_id ?? ""}
                  disabled={busy}
                  onChange={(e) => (e.target.value ? patch({ assigned_to_id: Number(e.target.value) }) : patch({ unassign: true }))}
                >
                  <option value="">Unassigned</option>
                  {(people.data ?? []).map((person) => (
                    <option key={person.id} value={person.id}>
                      {person.full_name || person.username}
                    </option>
                  ))}
                </Select>
              </Field>
              <div className="sm:col-span-2">
                <Field label="Resolution" hint="Required before the incident can be resolved or closed.">
                  <Textarea
                    value={resolution ?? data.resolution ?? ""}
                    onChange={(e) => setResolution(e.target.value)}
                    maxLength={5000}
                    placeholder="What happened and what was done about it"
                  />
                </Field>
              </div>
            </div>
          ) : (
            <KeyValue
              items={[
                { label: "Assigned to", value: data.assignee_name ?? "Unassigned" },
                { label: "Resolution", value: data.resolution ?? "-" },
              ]}
            />
          )}

          <SectionTitle>Alerts in this incident</SectionTitle>
          {data.alerts.length === 0 ? (
            <p className="text-sm text-ink-3">No alerts are linked yet.</p>
          ) : (
            <ul className="divide-y divide-line rounded border border-line">
              {data.alerts.map((alert) => (
                <li key={alert.id}>
                  <button type="button" onClick={() => openAlert(alert.id)} className="flex w-full items-center justify-between gap-3 px-3 py-2.5 text-left hover:bg-raised">
                    <span className="min-w-0">
                      <span className="block truncate text-sm text-ink">{alert.title}</span>
                      <span className="text-xs text-ink-3">{timeAgo(alert.last_seen)}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2">
                      <SeverityBadge severity={alert.severity} />
                      <StatusChip status={alert.status} />
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          <SectionTitle>Details</SectionTitle>
          <KeyValue
            items={[
              {
                label: "Source IP",
                value: data.source_ip ? (
                  <LinkButton onClick={() => openIp(data.source_ip as string)}>
                    <Mono>{data.source_ip}</Mono>
                  </LinkButton>
                ) : (
                  "-"
                ),
              },
              { label: "Created", value: `${fmtDateTime(data.created_at)} by ${data.created_by ?? "system"}` },
              { label: "Updated", value: timeAgo(data.updated_at) },
              ...(data.resolved_at ? [{ label: "Resolved", value: fmtDateTime(data.resolved_at) }] : []),
            ]}
          />

          <SectionTitle>Activity</SectionTitle>
          {canEdit ? (
            <div className="mb-3 space-y-2">
              <Textarea value={comment} onChange={(e) => setComment(e.target.value)} maxLength={5000} placeholder="Add a note for the next analyst" />
              <Button size="sm" disabled={busy || !comment.trim()} onClick={addNote}>
                Add note
              </Button>
            </div>
          ) : null}
          <ol className="space-y-3 border-l border-line pl-4">
            {[...data.notes].reverse().map((entry) => (
              <li key={entry.id} className="relative">
                <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-ink-3" />
                <p className="text-xs text-ink-3">
                  {entry.author}, {fmtDateTime(entry.created_at)}
                </p>
                <p className="mt-0.5 whitespace-pre-wrap break-words text-sm text-ink">{entry.body}</p>
              </li>
            ))}
          </ol>
        </>
      ) : null}
    </Sheet>
  );
}

/* ------------------------------------------------------------------------------------------ IP */

function IpSheet({ ip }: { ip: string }) {
  const { close, openAlert, openIncident, bump, refreshKey } = useDetail();
  const { can } = useAuth();
  const { data, error, loading } = useApi<IpDetail>(`/api/ips/${encodeURIComponent(ip)}`, {}, { refreshKey });
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  async function refreshReputation() {
    setBusy(true);
    setActionError(null);
    try {
      await api(`/api/ips/${encodeURIComponent(ip)}/refresh`, { method: "POST" });
      bump();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Reputation lookup failed");
    } finally {
      setBusy(false);
    }
  }

  const rep = data?.reputation ?? null;
  return (
    <Sheet
      open
      onClose={close}
      wide
      title={ip}
      subtitle={
        data ? (
          <>
            <span>{data.is_public ? "Public address" : "Private or internal address"}</span>
            {rep?.is_malicious ? <span className="rounded border border-sev-critical/50 bg-sev-critical/10 px-2 py-0.5 text-ink">Known malicious</span> : null}
          </>
        ) : null
      }
    >
      <BackBar />
      {error ? <ErrorNote message={error} /> : null}
      {loading && !data ? <Skeleton className="h-32 w-full" /> : null}

      {data ? (
        <>
          <KeyValue
            items={[
              { label: "Events seen", value: <span className="num">{fmtNumber(data.total_events)}</span> },
              { label: "First seen", value: fmtDateTime(data.first_seen) },
              { label: "Last seen", value: `${fmtDateTime(data.last_seen)} (${timeAgo(data.last_seen)})` },
              {
                label: "Reputation",
                value: rep ? (
                  <span>
                    Abuse score <span className="num">{rep.score}</span> / 100 ({rep.source}
                    {rep.country ? `, ${rep.country}` : ""}
                    {rep.isp ? `, ${rep.isp}` : ""}
                    {rep.total_reports ? `, ${fmtNumber(rep.total_reports)} reports` : ""})
                  </span>
                ) : data.is_public ? (
                  data.intel_configured ? (
                    "Not checked yet"
                  ) : (
                    "Not available: no reputation source is configured"
                  )
                ) : (
                  "Not applicable to private addresses"
                ),
              },
            ]}
          />
          {data.is_public && can("analyst", "admin") ? (
            <div className="mt-3 space-y-2">
              {actionError ? <ErrorNote message={actionError} /> : null}
              <Button size="sm" disabled={busy} onClick={refreshReputation}>
                {busy ? "Checking..." : "Check reputation now"}
              </Button>
            </div>
          ) : null}

          <SectionTitle>What this address did</SectionTitle>
          <div className="rounded border border-line">
            <BarList
              empty="No events yet."
              items={Object.entries(data.events_by_type)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8)
                .map(([type, count]) => ({ key: type, label: titleCase(type), value: count }))}
            />
          </div>

          {data.targeted_users.length > 0 ? (
            <>
              <SectionTitle>Accounts it tried</SectionTitle>
              <div className="rounded border border-line">
                <BarList
                  items={data.targeted_users.slice(0, 8).map((u) => ({ key: u.username, label: <Mono>{u.username}</Mono>, value: u.count, barClass: "bg-series-2" }))}
                />
              </div>
            </>
          ) : null}

          <SectionTitle>Alerts</SectionTitle>
          {data.alerts.length === 0 ? (
            <p className="text-sm text-ink-3">No alerts for this address.</p>
          ) : (
            <ul className="divide-y divide-line rounded border border-line">
              {data.alerts.map((alert) => (
                <li key={alert.id}>
                  <button type="button" onClick={() => openAlert(alert.id)} className="flex w-full items-center justify-between gap-3 px-3 py-2.5 text-left hover:bg-raised">
                    <span className="min-w-0">
                      <span className="block truncate text-sm text-ink">{alert.title}</span>
                      <span className="text-xs text-ink-3">{timeAgo(alert.last_seen)}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2">
                      <SeverityBadge severity={alert.severity} />
                      <StatusChip status={alert.status} />
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          {data.incidents.length > 0 ? (
            <>
              <SectionTitle>Incidents</SectionTitle>
              <ul className="divide-y divide-line rounded border border-line">
                {data.incidents.map((incident) => (
                  <li key={incident.id}>
                    <button type="button" onClick={() => openIncident(incident.id)} className="flex w-full items-center justify-between gap-3 px-3 py-2.5 text-left hover:bg-raised">
                      <span className="truncate text-sm text-ink">
                        #{incident.id} {incident.title}
                      </span>
                      <span className="flex shrink-0 items-center gap-2">
                        <SeverityBadge severity={incident.severity as Severity} />
                        <StatusChip status={incident.status} />
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </>
          ) : null}

          <SectionTitle>Recent events</SectionTitle>
          <EventTable events={data.recent_events} showIp={false} />
        </>
      ) : null}
    </Sheet>
  );
}

/** Rendered once in the app layout. Shows whichever detail panel is currently open. */
export function DetailHost() {
  const { current } = useDetail();
  if (!current) return null;
  switch (current.kind) {
    case "alert":
      return <AlertSheet key={`a${current.id}`} id={current.id} />;
    case "incident":
      return <IncidentSheet key={`i${current.id}`} id={current.id} />;
    case "ip":
      return <IpSheet key={`p${current.ip}`} ip={current.ip} />;
    default:
      return null;
  }
}
