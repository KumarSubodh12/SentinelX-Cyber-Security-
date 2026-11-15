"use client";

import { useState } from "react";
import { OriginBadge, RiskMeter, SeverityBadge, StatusChip } from "@/components/badges";
import { CHART, Columns } from "@/components/charts";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/form";
import { EmptyState, ErrorNote, KeyValue, Notice, Segmented, Skeleton, TableWrap } from "@/components/ui/misc";
import { PageHeader, Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useDetail } from "@/lib/detail";
import { fmtDateTime, fmtNumber, timeAgo, titleCase } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { useOrigin } from "@/lib/origin";
import type { AiAnalytics, MlStatus } from "@/lib/types";

const RANGES = [
  { value: 7, label: "7 days" },
  { value: 14, label: "14 days" },
  { value: 30, label: "30 days" },
];

const FEATURE_LABELS: Record<string, string> = {
  total_events: "Events per 5 minutes",
  failed_logins: "Failed logins",
  success_logins: "Successful logins",
  distinct_users: "Different accounts",
  distinct_hosts: "Different hosts",
  http_requests: "Web requests",
  http_errors: "Web errors",
  blocked_conns: "Blocked connections",
};

function ModelPanel({ model, mlEnabled, onChanged }: { model: MlStatus; mlEnabled: boolean; onChanged: () => void }) {
  const { can } = useAuth();
  const [busy, setBusy] = useState(false);
  const [includeSim, setIncludeSim] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function train() {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const result = await api<{ trained: boolean; message: string }>("/api/ml/train", {
        method: "POST",
        body: { include_simulated: includeSim },
      });
      setMessage(result.trained ? "The model learned a new baseline from your data." : result.message);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Training failed");
    } finally {
      setBusy(false);
    }
  }

  const baseline = Object.entries(model.baseline ?? {});
  return (
    <Panel>
      <PanelHeader
        title="Anomaly model"
        hint="Learns what normal activity looks like for each IP and user, then flags large departures from it."
        actions={
          <span className="inline-flex items-center gap-2 rounded border border-line px-2.5 py-1 text-xs text-ink-2">
            <span className={`h-2 w-2 rounded-full ${model.trained && mlEnabled ? "bg-good" : "bg-sev-medium"}`} />
            {!mlEnabled ? "Turned off" : model.trained ? "Active" : "Needs training data"}
          </span>
        }
      />
      <div className="grid gap-6 p-4 lg:grid-cols-2">
        <div className="space-y-4">
          <KeyValue
            items={[
              { label: "Algorithm", value: model.algorithm },
              { label: "Last trained", value: model.trained_at ? `${fmtDateTime(model.trained_at)} (${timeAgo(model.trained_at)})` : "Never" },
              { label: "Training samples", value: model.samples !== undefined ? fmtNumber(model.samples) : "-" },
              { label: "Samples needed", value: fmtNumber(model.min_train_samples) },
              { label: "Alert threshold", value: model.threshold !== undefined ? model.threshold.toFixed(2) : "-" },
            ]}
          />
          {!model.trained ? (
            <Notice>
              The model needs at least {fmtNumber(model.min_train_samples)} five-minute activity samples of normal traffic. Collect real logs for a day or two, or an admin can create simulated baseline traffic in Settings.
            </Notice>
          ) : null}
          {can("admin") ? (
            <div className="space-y-2">
              <Checkbox checked={includeSim} onChange={setIncludeSim} label="Include simulated data when training" />
              <Button onClick={train} disabled={busy}>
                {busy ? "Training..." : "Train now"}
              </Button>
              {message ? <p className="text-sm text-ink-2">{message}</p> : null}
              {error ? <ErrorNote message={error} /> : null}
            </div>
          ) : (
            <p className="text-xs text-ink-3">Only admins can retrain the model. It also retrains automatically on a schedule.</p>
          )}
        </div>

        <div>
          <h3 className="mb-2 text-sm font-semibold text-ink">What normal looks like</h3>
          {baseline.length === 0 ? (
            <p className="text-sm text-ink-3">Shown after the first training run.</p>
          ) : (
            <TableWrap>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line">
                    <th className="th">Measure</th>
                    <th className="th text-right">Typical</th>
                    <th className="th text-right">Spread</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {baseline.map(([key, value]) => (
                    <tr key={key}>
                      <td className="td">{FEATURE_LABELS[key] ?? titleCase(key)}</td>
                      <td className="td num text-right">{value.mean.toFixed(1)}</td>
                      <td className="td num text-right text-ink-2">{value.std.toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </div>
      </div>
    </Panel>
  );
}

export default function AnalyticsPage() {
  const { param } = useOrigin();
  const { openAlert, refreshKey } = useDetail();
  const [days, setDays] = useState(14);
  const { data, error, loading, reload } = useApi<AiAnalytics>("/api/analytics/ai", { days, origin: param }, { refreshKey, every: 60_000 });

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title="AI analytics"
        description="How the anomaly model and the detection rules are performing."
        actions={<Segmented<number> label="Time range" value={days} options={RANGES} onChange={setDays} />}
      />

      {error ? (
        <div className="mb-4">
          <ErrorNote message={error} onRetry={reload} />
        </div>
      ) : null}

      {loading && !data ? (
        <div className="space-y-4">
          <Skeleton className="h-56 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      ) : null}

      {data ? (
        <div className="space-y-4">
          <Panel>
            <dl className="flex flex-wrap divide-x divide-line">
              <div className="min-w-[140px] flex-1 px-4 py-3">
                <dt className="text-xs text-ink-3">Anomaly alerts</dt>
                <dd className="num mt-1 text-xl font-semibold text-ink">{fmtNumber(data.ml_alerts_total)}</dd>
              </div>
              <div className="min-w-[140px] flex-1 px-4 py-3">
                <dt className="text-xs text-ink-3">Average risk score</dt>
                <dd className="num mt-1 text-xl font-semibold text-ink">{data.average_risk.toFixed(0)}</dd>
              </div>
              <div className="min-w-[140px] flex-1 px-4 py-3">
                <dt className="text-xs text-ink-3">Period</dt>
                <dd className="mt-1 text-xl font-semibold text-ink">{data.window_days} days</dd>
              </div>
            </dl>
          </Panel>

          <ModelPanel model={data.model} mlEnabled={data.ml_enabled} onChanged={reload} />

          <div className="grid gap-4 lg:grid-cols-5">
            <Panel className="lg:col-span-3">
              <PanelHeader title="Detections per day" hint="Which kind of detection raised each alert" />
              <div className="p-4">
                {data.detections_by_day.length === 0 ? (
                  <EmptyState title="No detections in this period" />
                ) : (
                  <Columns
                    data={data.detections_by_day.map((d) => ({ ...d }))}
                    xKey="date"
                    formatX={(v) => new Date(v).toLocaleDateString("en-GB", { day: "2-digit", month: "short" })}
                    series={[
                      { key: "rule", label: "Rules", color: CHART.s1 },
                      { key: "ml", label: "Anomaly model", color: CHART.s2 },
                      { key: "intel", label: "Threat intelligence", color: CHART.s3 },
                    ]}
                  />
                )}
              </div>
            </Panel>
            <Panel className="lg:col-span-2">
              <PanelHeader title="Risk score spread" hint="How many alerts fall in each score range" />
              <div className="p-4">
                {data.risk_histogram.every((b) => b.count === 0) ? (
                  <EmptyState title="No alerts to score yet" />
                ) : (
                  <Columns data={data.risk_histogram.map((b) => ({ ...b }))} xKey="range" series={[{ key: "count", label: "Alerts", color: CHART.s1 }]} />
                )}
              </div>
            </Panel>
          </div>

          <Panel>
            <PanelHeader title="Most unusual behaviour" hint="Anomaly-model alerts with the reasons the model gave" />
            {data.top_anomalies.length === 0 ? (
              <EmptyState title="No anomalies flagged">
                {data.model.trained ? "Nothing has deviated far enough from normal in this period." : "Train the model to start flagging unusual behaviour."}
              </EmptyState>
            ) : (
              <TableWrap>
                <table className="w-full min-w-[820px] text-sm">
                  <thead>
                    <tr className="border-b border-line">
                      <th className="th">Severity</th>
                      <th className="th">Who or what</th>
                      <th className="th">Why it was flagged</th>
                      <th className="th text-right">Anomaly</th>
                      <th className="th">Risk</th>
                      <th className="th">Status</th>
                      <th className="th">When</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {data.top_anomalies.map((row) => (
                      <tr
                        key={row.id}
                        tabIndex={0}
                        className="cursor-pointer hover:bg-raised"
                        onClick={() => openAlert(row.id)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") openAlert(row.id);
                        }}
                      >
                        <td className="td">
                          <SeverityBadge severity={row.severity} />
                        </td>
                        <td className="td">
                          <span className="flex items-center gap-2">
                            <span className="font-mono text-[13px]">{row.entity ?? "-"}</span>
                            <OriginBadge origin={row.data_origin} />
                          </span>
                        </td>
                        <td className="td max-w-[320px] text-ink-2">{row.reasons.length > 0 ? row.reasons.join("; ") : row.title}</td>
                        <td className="td num text-right">{row.anomaly_score === null ? "-" : row.anomaly_score.toFixed(2)}</td>
                        <td className="td">
                          <RiskMeter score={row.risk_score} />
                        </td>
                        <td className="td">
                          <StatusChip status={row.status} />
                        </td>
                        <td className="td whitespace-nowrap text-ink-2">{timeAgo(row.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </Panel>
        </div>
      ) : null}
    </div>
  );
}
