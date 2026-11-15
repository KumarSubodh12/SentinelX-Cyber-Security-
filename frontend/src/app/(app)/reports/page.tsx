"use client";

import { Download } from "lucide-react";
import { useState } from "react";
import { CHART, Columns } from "@/components/charts";
import { Button } from "@/components/ui/button";
import { Field, Select } from "@/components/ui/form";
import { EmptyState, ErrorNote, Notice, Segmented, Skeleton, TableWrap } from "@/components/ui/misc";
import { PageHeader, Panel, PanelHeader } from "@/components/ui/panel";
import { downloadFile } from "@/lib/api";
import { fmtNumber } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { useOrigin } from "@/lib/origin";
import type { Trends } from "@/lib/types";

const RANGES = [
  { value: 14, label: "14 days" },
  { value: 30, label: "30 days" },
  { value: 90, label: "90 days" },
];

const EXPORTS = [
  { value: "alerts", label: "Alerts" },
  { value: "incidents", label: "Incidents" },
  { value: "events", label: "Events" },
];

const shortDate = (value: string) => new Date(value).toLocaleDateString("en-GB", { day: "2-digit", month: "short" });

export default function ReportsPage() {
  const { param, origin } = useOrigin();
  const [days, setDays] = useState(30);
  const [kind, setKind] = useState("alerts");
  const [exportDays, setExportDays] = useState(7);
  const [busy, setBusy] = useState<"csv" | "html" | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  const { data, error, loading, reload } = useApi<Trends>("/api/analytics/trends", { days, origin: param }, { every: 120_000 });

  async function run(type: "csv" | "html") {
    setBusy(type);
    setExportError(null);
    const stamp = new Date().toISOString().slice(0, 10);
    const scope = origin === "all" ? "all" : origin;
    try {
      if (type === "csv") {
        await downloadFile("/api/reports/export", { kind, days: exportDays, origin: param }, `sentinelx-${kind}-${scope}-${stamp}.csv`);
      } else {
        await downloadFile("/api/reports/summary.html", { days: Math.min(exportDays, 90), origin: param }, `sentinelx-summary-${scope}-${stamp}.html`);
      }
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Download failed");
    } finally {
      setBusy(null);
    }
  }

  const daily = data?.daily ?? [];
  const weekly = data?.weekly ?? [];
  const nothing = !!data && daily.every((d) => d.events === 0 && d.alerts === 0);

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title="Reports"
        description="Trends over time, and exports you can share or load into other tools."
        actions={<Segmented<number> label="Time range" value={days} options={RANGES} onChange={setDays} />}
      />

      {error ? (
        <div className="mb-4">
          <ErrorNote message={error} onRetry={reload} />
        </div>
      ) : null}

      <div className="space-y-4">
        <Panel>
          <PanelHeader title="Export" hint={`Includes ${origin === "all" ? "real and simulated" : origin} data, matching the filter at the top of the page.`} />
          <div className="flex flex-wrap items-end gap-3 p-4">
            <Field label="What to export">
              <Select className="w-40" value={kind} onChange={(e) => setKind(e.target.value)}>
                {EXPORTS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="How far back">
              <Select className="w-40" value={exportDays} onChange={(e) => setExportDays(Number(e.target.value))}>
                <option value={1}>Last 24 hours</option>
                <option value={7}>Last 7 days</option>
                <option value={30}>Last 30 days</option>
                <option value={90}>Last 90 days</option>
              </Select>
            </Field>
            <Button variant="primary" onClick={() => run("csv")} disabled={busy !== null}>
              <Download className="h-4 w-4" />
              {busy === "csv" ? "Preparing..." : "Download CSV"}
            </Button>
            <Button onClick={() => run("html")} disabled={busy !== null}>
              <Download className="h-4 w-4" />
              {busy === "html" ? "Preparing..." : "Download summary report"}
            </Button>
          </div>
          <div className="space-y-2 border-t border-line px-4 py-3">
            <p className="text-xs text-ink-3">
              The summary report is a single HTML page. Open it in a browser and use Print, then Save as PDF, to share it. Spreadsheet formulas in exported text are neutralised.
            </p>
            {exportError ? <ErrorNote message={exportError} /> : null}
          </div>
        </Panel>

        {loading && !data ? <Skeleton className="h-64 w-full" /> : null}

        {nothing ? (
          <Panel>
            <EmptyState title="No data in this period">Charts appear once events have been collected.</EmptyState>
          </Panel>
        ) : null}

        {data && !nothing ? (
          <>
            <div className="grid gap-4 lg:grid-cols-2">
              <Panel>
                <PanelHeader title="Alerts per day" hint="High and critical alerts shown separately" />
                <div className="p-4">
                  <Columns
                    xKey="date"
                    formatX={shortDate}
                    data={daily.map((d) => ({ date: d.date, other: Math.max(0, d.alerts - d.high_alerts), high: d.high_alerts }))}
                    series={[
                      { key: "other", label: "Medium and lower", color: CHART.s1 },
                      { key: "high", label: "High and critical", color: CHART.s2 },
                    ]}
                  />
                </div>
              </Panel>
              <Panel>
                <PanelHeader title="Failed logins per day" hint="A sudden rise often means password guessing" />
                <div className="p-4">
                  <Columns xKey="date" formatX={shortDate} data={daily.map((d) => ({ date: d.date, failed_logins: d.failed_logins }))} series={[{ key: "failed_logins", label: "Failed logins", color: CHART.s2 }]} />
                </div>
              </Panel>
            </div>

            <Panel>
              <PanelHeader title="Week by week" />
              <TableWrap>
                <table className="w-full min-w-[560px] text-sm">
                  <thead>
                    <tr className="border-b border-line">
                      <th className="th">Week starting</th>
                      <th className="th text-right">Events</th>
                      <th className="th text-right">Failed logins</th>
                      <th className="th text-right">Alerts</th>
                      <th className="th text-right">High and critical</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {[...weekly].reverse().map((w) => (
                      <tr key={w.week_start}>
                        <td className="td">{shortDate(w.week_start)}</td>
                        <td className="td num text-right">{fmtNumber(w.events)}</td>
                        <td className="td num text-right">{fmtNumber(w.failed_logins)}</td>
                        <td className="td num text-right">{fmtNumber(w.alerts)}</td>
                        <td className="td num text-right">{fmtNumber(w.high_alerts)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </Panel>
          </>
        ) : null}

        {origin !== "real" ? <Notice>These numbers can include simulated test data. Switch the filter at the top to Real to see production figures only.</Notice> : null}
      </div>
    </div>
  );
}
