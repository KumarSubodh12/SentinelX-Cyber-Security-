"use client";

import { useState } from "react";
import { Mono, OriginBadge, RiskMeter, SeverityBadge, StatusChip } from "@/components/badges";
import { Input, Select } from "@/components/ui/form";
import { EmptyState, ErrorNote, Pager, Skeleton, TableWrap } from "@/components/ui/misc";
import { PageHeader, Panel } from "@/components/ui/panel";
import { useDetail } from "@/lib/detail";
import { fmtNumber, timeAgo, titleCase } from "@/lib/format";
import { useApi, useDebounced } from "@/lib/hooks";
import { useOrigin } from "@/lib/origin";
import { SEVERITIES, type Alert, type Page } from "@/lib/types";

const PAGE_SIZE = 25;

const STATUS_OPTIONS = [
  { value: "active", label: "Needs attention" },
  { value: "open", label: "Open" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
  { value: "", label: "Any status" },
];

export default function AlertsPage() {
  const { param } = useOrigin();
  const { openAlert, openIp, refreshKey } = useDetail();
  const [status, setStatus] = useState("active");
  const [severity, setSeverity] = useState("");
  const [type, setType] = useState("");
  const [sort, setSort] = useState("risk");
  const [text, setText] = useState("");
  const [page, setPage] = useState(1);
  const q = useDebounced(text.trim(), 350);

  const { data, error, loading, reload } = useApi<Page<Alert>>(
    "/api/alerts",
    { status, severity, detection_type: type, sort, q, origin: param, page, page_size: PAGE_SIZE },
    { refreshKey, every: 30_000 },
  );

  /** Changing any filter goes back to the first page. */
  const filter = (apply: () => void) => {
    apply();
    setPage(1);
  };

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader title="Alerts" description="Detections raised by rules, the anomaly model and threat intelligence. Select an alert to triage it." />

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
          <Input
            className="w-full sm:w-64"
            placeholder="Search title, IP or user"
            value={text}
            onChange={(e) => filter(() => setText(e.target.value))}
            aria-label="Search alerts"
          />
          <Select className="w-auto" value={status} onChange={(e) => filter(() => setStatus(e.target.value))} aria-label="Status">
            {STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
          <Select className="w-auto" value={severity} onChange={(e) => filter(() => setSeverity(e.target.value))} aria-label="Severity">
            <option value="">Any severity</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {titleCase(s)}
              </option>
            ))}
          </Select>
          <Select className="w-auto" value={type} onChange={(e) => filter(() => setType(e.target.value))} aria-label="Detection type">
            <option value="">Any detection type</option>
            <option value="rule">Rule</option>
            <option value="ml">Anomaly model</option>
            <option value="intel">Threat intelligence</option>
          </Select>
          <Select className="ml-auto w-auto" value={sort} onChange={(e) => filter(() => setSort(e.target.value))} aria-label="Sort by">
            <option value="risk">Highest risk first</option>
            <option value="newest">Newest first</option>
            <option value="last_seen">Most recently active</option>
          </Select>
        </div>

        {error ? (
          <div className="p-3">
            <ErrorNote message={error} onRetry={reload} />
          </div>
        ) : null}

        {loading && !data ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2, 3, 4].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : data && data.items.length === 0 ? (
          <EmptyState title="No alerts match these filters">
            {status === "active" && !severity && !type && !q
              ? "Nothing needs attention right now. New detections will appear here automatically."
              : "Try another status or clear the search."}
          </EmptyState>
        ) : (
          <TableWrap>
            <table className="w-full min-w-[860px] text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">Severity</th>
                  <th className="th">Alert</th>
                  <th className="th">Source</th>
                  <th className="th">Status</th>
                  <th className="th">Risk</th>
                  <th className="th text-right">Events</th>
                  <th className="th">Last activity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data?.items.map((alert) => (
                  <tr
                    key={alert.id}
                    tabIndex={0}
                    className="cursor-pointer hover:bg-raised"
                    onClick={() => openAlert(alert.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") openAlert(alert.id);
                    }}
                  >
                    <td className="td">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="td max-w-[340px]">
                      <span className="flex items-center gap-2">
                        <span className="truncate font-medium text-ink">{alert.title}</span>
                        <OriginBadge origin={alert.data_origin} />
                      </span>
                      <span className="block truncate text-xs text-ink-3">
                        {titleCase(alert.detection_type)} detection{alert.mitre ? `, ${alert.mitre}` : ""}
                        {alert.incident_id !== null ? `, incident #${alert.incident_id}` : ""}
                      </span>
                    </td>
                    <td className="td">
                      {alert.source_ip ? (
                        <button
                          type="button"
                          className="underline decoration-line underline-offset-2 hover:decoration-ink"
                          onClick={(e) => {
                            e.stopPropagation();
                            openIp(alert.source_ip as string);
                          }}
                        >
                          <Mono>{alert.source_ip}</Mono>
                        </button>
                      ) : (
                        <span className="text-ink-3">-</span>
                      )}
                      {alert.username ? <span className="block text-xs text-ink-3">{alert.username}</span> : null}
                    </td>
                    <td className="td">
                      <StatusChip status={alert.status} />
                    </td>
                    <td className="td">
                      <RiskMeter score={alert.risk_score} />
                    </td>
                    <td className="td num text-right">{fmtNumber(alert.event_count)}</td>
                    <td className="td whitespace-nowrap text-ink-2">{timeAgo(alert.last_seen)}</td>
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
