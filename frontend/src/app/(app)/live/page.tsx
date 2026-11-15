"use client";

import { Pause, Play } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { Mono, OriginBadge, SeverityBadge } from "@/components/badges";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/form";
import { EmptyState, ErrorNote, KeyValue, TableWrap } from "@/components/ui/misc";
import { PageHeader, Panel } from "@/components/ui/panel";
import { useDetail } from "@/lib/detail";
import { fmtDateTime, fmtNumber, fmtTime, titleCase } from "@/lib/format";
import { useApi, useDebounced } from "@/lib/hooks";
import { useLive } from "@/lib/live";
import { useOrigin } from "@/lib/origin";
import { SEVERITIES, type EventRow, type Page } from "@/lib/types";

const LIMIT = 300;

function mergeRows(live: EventRow[], history: EventRow[]): EventRow[] {
  const seen = new Set<number>();
  const rows: EventRow[] = [];
  for (const row of [...live, ...history]) {
    if (seen.has(row.id)) continue;
    seen.add(row.id);
    rows.push(row);
  }
  rows.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : b.id - a.id));
  return rows.slice(0, LIMIT);
}

function EventDetails({ event }: { event: EventRow }) {
  const items = [
    { label: "Recorded", value: fmtDateTime(event.timestamp) },
    { label: "Source", value: titleCase(event.source) },
    { label: "Host", value: event.hostname ?? "-" },
    { label: "Destination", value: event.dest_ip ? `${event.dest_ip}${event.dest_port ? `:${event.dest_port}` : ""}` : "-" },
    { label: "Request", value: event.http_method || event.http_path ? `${event.http_method ?? ""} ${event.http_path ?? ""} ${event.status_code ?? ""}`.trim() : "-" },
    { label: "User agent", value: event.user_agent ?? "-" },
    { label: "Risk score", value: String(event.risk_score) },
    { label: "Anomaly score", value: event.anomaly_score === null ? "-" : event.anomaly_score.toFixed(2) },
    { label: "Message", value: event.message ?? "-" },
  ];
  return (
    <div className="space-y-3 bg-page px-4 py-3">
      <KeyValue items={items} />
      {event.extra && Object.keys(event.extra).length > 0 ? (
        <pre className="max-h-40 overflow-auto rounded border border-line bg-panel p-2 font-mono text-xs text-ink-2">{JSON.stringify(event.extra, null, 2)}</pre>
      ) : null}
    </div>
  );
}

export default function LivePage() {
  const { param } = useOrigin();
  const { openIp } = useDetail();
  const { events: liveEvents, status } = useLive();
  const history = useApi<Page<EventRow>>("/api/events", { page_size: 100, origin: param });

  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<EventRow[]>([]);
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [text, setText] = useState("");
  const [openId, setOpenId] = useState<number | null>(null);
  const query = useDebounced(text.trim().toLowerCase(), 250);

  const all = useMemo(() => {
    const rows = mergeRows(liveEvents, history.data?.items ?? []);
    return param ? rows.filter((row) => row.data_origin === param) : rows;
  }, [liveEvents, history.data, param]);

  const base = paused ? frozen : all;
  const newWhilePaused = paused ? all.filter((row) => !frozen.some((f) => f.id === row.id)).length : 0;

  const sources = useMemo(() => Array.from(new Set(all.map((row) => row.source))).sort(), [all]);
  const rows = useMemo(
    () =>
      base.filter((row) => {
        if (severity && row.severity !== severity) return false;
        if (source && row.source !== source) return false;
        if (!query) return true;
        return [row.source_ip, row.username, row.hostname, row.event_type, row.message, row.http_path].some((value) => value?.toLowerCase().includes(query));
      }),
    [base, severity, source, query],
  );

  function togglePause() {
    if (!paused) setFrozen(all);
    setPaused((p) => !p);
  }

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title="Live events"
        description="Events appear here the moment an agent sends them. Select a row for the full record."
        actions={
          <Button onClick={togglePause} variant={paused ? "primary" : "secondary"}>
            {paused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
            {paused ? (newWhilePaused > 0 ? `Resume (${fmtNumber(newWhilePaused)} new)` : "Resume") : "Pause"}
          </Button>
        }
      />

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
          <Input className="w-full sm:w-64" placeholder="Search IP, user, host or message" value={text} onChange={(e) => setText(e.target.value)} aria-label="Search events" />
          <Select className="w-auto" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
            <option value="">Any severity</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {titleCase(s)}
              </option>
            ))}
          </Select>
          <Select className="w-auto" value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source">
            <option value="">Any source</option>
            {sources.map((s) => (
              <option key={s} value={s}>
                {titleCase(s)}
              </option>
            ))}
          </Select>
          <span className="ml-auto text-xs text-ink-3">
            {status === "live" ? "Streaming" : status === "connecting" ? "Connecting to the live stream" : "Live stream offline, showing recent events"}
            {paused ? ", paused" : ""}
          </span>
        </div>

        {history.error ? (
          <div className="p-3">
            <ErrorNote message={history.error} onRetry={history.reload} />
          </div>
        ) : null}

        {rows.length === 0 ? (
          <EmptyState title={all.length === 0 ? "Waiting for events" : "No events match these filters"}>
            {all.length === 0
              ? "Once an agent is connected or you run a simulation, events show up here without refreshing the page."
              : "Clear a filter or the search box to see more."}
          </EmptyState>
        ) : (
          <TableWrap>
            <table className="w-full min-w-[760px] text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">Time</th>
                  <th className="th">Severity</th>
                  <th className="th">Event</th>
                  <th className="th">User</th>
                  <th className="th">Source IP</th>
                  <th className="th">Detail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.map((event) => (
                  <Fragment key={event.id}>
                    <tr
                      className="cursor-pointer hover:bg-raised"
                      tabIndex={0}
                      onClick={() => setOpenId(openId === event.id ? null : event.id)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setOpenId(openId === event.id ? null : event.id);
                        }
                      }}
                      aria-expanded={openId === event.id}
                    >
                      <td className="td num whitespace-nowrap text-ink-2">{fmtTime(event.timestamp)}</td>
                      <td className="td">{event.severity === "info" ? <span className="text-ink-3">Info</span> : <SeverityBadge severity={event.severity} />}</td>
                      <td className="td whitespace-nowrap">
                        <span className="flex items-center gap-2">
                          {titleCase(event.event_type)}
                          <OriginBadge origin={event.data_origin} />
                        </span>
                      </td>
                      <td className="td">{event.username ?? "-"}</td>
                      <td className="td">
                        {event.source_ip ? (
                          <button
                            type="button"
                            className="underline decoration-line underline-offset-2 hover:decoration-ink"
                            onClick={(e) => {
                              e.stopPropagation();
                              openIp(event.source_ip as string);
                            }}
                          >
                            <Mono>{event.source_ip}</Mono>
                          </button>
                        ) : (
                          "-"
                        )}
                      </td>
                      <td className="td max-w-[360px] truncate text-ink-2">{event.message ?? event.http_path ?? "-"}</td>
                    </tr>
                    {openId === event.id ? (
                      <tr>
                        <td colSpan={6} className="p-0">
                          <EventDetails event={event} />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        <p className="border-t border-line px-4 py-2 text-xs text-ink-3">
          Showing {fmtNumber(rows.length)} of the latest {fmtNumber(Math.min(all.length, LIMIT))} events. Older events are in Reports.
        </p>
      </Panel>
    </div>
  );
}
