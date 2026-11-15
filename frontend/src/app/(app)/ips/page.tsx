"use client";

import { useState } from "react";
import { Mono, RiskMeter } from "@/components/badges";
import { Checkbox, Input, Select } from "@/components/ui/form";
import { EmptyState, ErrorNote, Pager, Skeleton, TableWrap } from "@/components/ui/misc";
import { PageHeader, Panel } from "@/components/ui/panel";
import { useDetail } from "@/lib/detail";
import { fmtNumber, timeAgo, windowLabel } from "@/lib/format";
import { useApi, useDebounced } from "@/lib/hooks";
import { useOrigin } from "@/lib/origin";
import type { IpRow, Page } from "@/lib/types";

const PAGE_SIZE = 25;

const RANGES = [
  { value: 24, label: "Last 24 hours" },
  { value: 168, label: "Last 7 days" },
  { value: 720, label: "Last 30 days" },
  { value: 2160, label: "Last 90 days" },
];

function Reputation({ row }: { row: IpRow }) {
  if (!row.is_public) return <span className="text-ink-3">Internal</span>;
  if (!row.reputation) return <span className="text-ink-3">Not checked</span>;
  const { score, is_malicious, country } = row.reputation;
  return (
    <span className="flex items-center gap-2">
      <span className={is_malicious ? "font-medium text-ink" : "text-ink-2"}>
        {is_malicious ? "Malicious" : "No known abuse"}
      </span>
      <span className="num text-xs text-ink-3">
        {score}/100{country ? `, ${country}` : ""}
      </span>
    </span>
  );
}

export default function IpsPage() {
  const { param } = useOrigin();
  const { openIp, refreshKey } = useDetail();
  const [hours, setHours] = useState(168);
  const [text, setText] = useState("");
  const [suspicious, setSuspicious] = useState(false);
  const [page, setPage] = useState(1);
  const q = useDebounced(text.trim(), 350);

  const { data, error, loading, reload } = useApi<Page<IpRow>>(
    "/api/ips",
    { hours, q, suspicious_only: suspicious || undefined, origin: param, page, page_size: PAGE_SIZE },
    { refreshKey, every: 60_000 },
  );

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title="IP intelligence"
        description={`Every address that sent events in the ${windowLabel(hours)}, ordered by the highest risk seen.`}
      />

      <Panel>
        <div className="flex flex-wrap items-center gap-3 border-b border-line p-3">
          <Input
            className="w-full sm:w-56"
            placeholder="Starts with, e.g. 203.0.113"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setPage(1);
            }}
            aria-label="Filter by IP prefix"
          />
          <Select
            className="w-auto"
            value={hours}
            onChange={(e) => {
              setHours(Number(e.target.value));
              setPage(1);
            }}
            aria-label="Time range"
          >
            {RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </Select>
          <Checkbox
            checked={suspicious}
            onChange={(value) => {
              setSuspicious(value);
              setPage(1);
            }}
            label="Suspicious only"
          />
        </div>

        {error ? (
          <div className="p-3">
            <ErrorNote message={error} onRetry={reload} />
          </div>
        ) : null}

        {loading && !data ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : data && data.items.length === 0 ? (
          <EmptyState title="No addresses found">Events that carry a source IP will be listed here.</EmptyState>
        ) : (
          <TableWrap>
            <table className="w-full min-w-[820px] text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">IP address</th>
                  <th className="th">Reputation</th>
                  <th className="th">Max risk</th>
                  <th className="th text-right">Events</th>
                  <th className="th text-right">Failed logins</th>
                  <th className="th text-right">Active alerts</th>
                  <th className="th">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data?.items.map((row) => (
                  <tr
                    key={row.ip}
                    tabIndex={0}
                    className="cursor-pointer hover:bg-raised"
                    onClick={() => openIp(row.ip)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") openIp(row.ip);
                    }}
                  >
                    <td className="td">
                      <Mono>{row.ip}</Mono>
                    </td>
                    <td className="td">
                      <Reputation row={row} />
                    </td>
                    <td className="td">
                      <RiskMeter score={row.max_risk} />
                    </td>
                    <td className="td num text-right">{fmtNumber(row.events)}</td>
                    <td className="td num text-right">{fmtNumber(row.failed_logins)}</td>
                    <td className="td num text-right">{row.active_alerts > 0 ? row.active_alerts : <span className="text-ink-3">0</span>}</td>
                    <td className="td whitespace-nowrap text-ink-2">{timeAgo(row.last_seen)}</td>
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
