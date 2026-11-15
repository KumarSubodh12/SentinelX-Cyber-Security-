"use client";

import Link from "next/link";
import { useState } from "react";
import { BarList } from "@/components/bar-list";
import { Mono, OriginBadge, RiskMeter, SEV_BAR, SeverityBadge } from "@/components/badges";
import { Beacon, POSTURE_TEXT, type Posture } from "@/components/beacon";
import { ActivityChart, formatBucket } from "@/components/charts";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorNote, Notice, Segmented, Skeleton, TableWrap } from "@/components/ui/misc";
import { PageHeader, Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useDetail } from "@/lib/detail";
import { fmtNumber, timeAgo, titleCase, windowLabel } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { useOrigin } from "@/lib/origin";
import { SEVERITIES, type Alert, type Overview, type Page } from "@/lib/types";

const WINDOWS = [
  { value: 6, label: "6 hours" },
  { value: 24, label: "24 hours" },
  { value: 168, label: "7 days" },
];

function Metric({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="min-w-[120px] flex-1 px-4 py-3">
      <dt className="text-xs text-ink-3">{label}</dt>
      <dd className="num mt-1 text-xl font-semibold text-ink">{value}</dd>
      {note ? <dd className="mt-0.5 text-xs text-ink-3">{note}</dd> : null}
    </div>
  );
}

function SetupPanel() {
  const { can } = useAuth();
  const { origin, setOrigin } = useOrigin();
  const { bump } = useDetail();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function runDemo() {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const result = await api<{ alerts_created: number; accepted: number }>("/api/simulate", {
        method: "POST",
        body: { scenario: "mixed", intensity: 2 },
      });
      if (origin === "real") setOrigin("all");
      setMessage(`Created ${result.accepted} test events and ${result.alerts_created} alerts. They are labelled SIM.`);
      bump();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not run the demo");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel>
      <PanelHeader title="Nothing has been collected yet" hint="SentinelX shows real data from your servers. Choose how to start." />
      <div className="grid gap-6 p-4 md:grid-cols-2">
        <div>
          <h3 className="text-sm font-semibold text-ink">Connect a real system</h3>
          <p className="mt-1 text-sm text-ink-2">
            Create an agent, then install it on a Linux or Windows machine. It reads SSH logins, web server logs, firewall logs or Windows security events and sends them here in real time.
          </p>
          <Link href="/settings#agents" className="mt-3 inline-flex h-9 items-center rounded border border-line bg-raised px-4 text-sm font-medium text-ink hover:border-ink-3">
            Set up an agent
          </Link>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-ink">Try it with test data</h3>
          <p className="mt-1 text-sm text-ink-2">
            Generate a mixed set of attack scenarios (brute force, port scan, web attacks). Everything is labelled SIM and kept separate from real data.
          </p>
          {can("analyst", "admin") ? (
            <Button className="mt-3" variant="primary" onClick={runDemo} disabled={busy}>
              {busy ? "Generating..." : "Run demo simulation"}
            </Button>
          ) : (
            <p className="mt-3 text-sm text-ink-3">Ask an analyst or admin to run the demo.</p>
          )}
          {message ? <p className="mt-2 text-sm text-ink-2">{message}</p> : null}
          {error ? (
            <div className="mt-2">
              <ErrorNote message={error} />
            </div>
          ) : null}
        </div>
      </div>
    </Panel>
  );
}

export default function DashboardPage() {
  const { param } = useOrigin();
  const { openAlert, openIp, refreshKey } = useDetail();
  const [hours, setHours] = useState(24);
  const [asTable, setAsTable] = useState(false);

  const overview = useApi<Overview>("/api/analytics/overview", { hours, origin: param }, { refreshKey, every: 15_000 });
  const alerts = useApi<Page<Alert>>("/api/alerts", { status: "active", sort: "risk", page_size: 6, origin: param }, { refreshKey, every: 30_000 });

  const data = overview.data;
  const t = data?.totals;

  let posture: Posture = "calm";
  if (t) posture = t.critical_alerts_active > 0 ? "critical" : t.active_alerts > 0 ? "attention" : "calm";
  const headline = !t
    ? "Loading..."
    : t.critical_alerts_active > 0
      ? `${fmtNumber(t.critical_alerts_active)} critical ${t.critical_alerts_active === 1 ? "alert needs" : "alerts need"} attention`
      : t.active_alerts > 0
        ? `${fmtNumber(t.active_alerts)} active ${t.active_alerts === 1 ? "alert is" : "alerts are"} waiting for review`
        : POSTURE_TEXT.calm;

  const empty = !!t && t.events_total === 0 && t.agents_total === 0;
  const sourceItems = Object.entries(data?.by_source ?? {})
    .sort((a, b) => b[1] - a[1])
    .map(([source, count]) => ({ key: source, label: titleCase(source), value: count }));

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title="Dashboard"
        description={`What happened in the ${windowLabel(hours)}.`}
        actions={<Segmented<number> label="Time range" value={hours} options={WINDOWS} onChange={setHours} />}
      />

      {overview.error ? (
        <div className="mb-4">
          <ErrorNote message={overview.error} onRetry={overview.reload} />
        </div>
      ) : null}

      <Panel className="mb-4">
        <div className="flex items-center gap-3 border-b border-line px-4 py-3">
          <Beacon posture={posture} size={32} />
          <div>
            <p className="text-base font-semibold text-ink">{headline}</p>
            <p className="text-xs text-ink-3">Updates every few seconds while this page is open.</p>
          </div>
        </div>
        {t ? (
          <dl className="flex flex-wrap divide-x divide-line">
            <Metric label="Events" value={fmtNumber(t.events_window)} note={`${fmtNumber(t.events_total)} stored in total`} />
            <Metric label="Threat events" value={fmtNumber(t.threats_window)} note={`${fmtNumber(t.threats_total)} in total`} />
            <Metric label="Failed logins" value={fmtNumber(t.failed_logins_window)} note={`${fmtNumber(t.success_logins_window)} succeeded`} />
            <Metric label="Open incidents" value={fmtNumber(t.open_incidents)} note={t.critical_incidents > 0 ? `${t.critical_incidents} critical` : undefined} />
            <Metric label="Suspicious IPs" value={fmtNumber(t.suspicious_ips_window)} />
            <Metric label="Agents online" value={`${t.agents_online} / ${t.agents_total}`} />
          </dl>
        ) : (
          <div className="p-4">
            <Skeleton className="h-14 w-full" />
          </div>
        )}
      </Panel>

      {empty ? (
        <SetupPanel />
      ) : (
        <div className="space-y-4">
          <Panel>
            <PanelHeader
              title="Activity"
              hint="Each row has its own scale, so small spikes stay visible."
              actions={
                <Button size="sm" variant="ghost" onClick={() => setAsTable((v) => !v)}>
                  {asTable ? "Show chart" : "Show table"}
                </Button>
              }
            />
            <div className="p-4">
              {!data ? (
                <Skeleton className="h-64 w-full" />
              ) : data.timeseries.length === 0 ? (
                <EmptyState title="No activity in this time range" />
              ) : asTable ? (
                <div className="max-h-72 overflow-y-auto">
                  <TableWrap>
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-line">
                          <th className="th">Time</th>
                          <th className="th text-right">Events</th>
                          <th className="th text-right">Failed logins</th>
                          <th className="th text-right">Alerts</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-line">
                        {[...data.timeseries].reverse().map((row) => (
                          <tr key={row.t}>
                            <td className="td num text-ink-2">{formatBucket(row.t, data.bucket_seconds)}</td>
                            <td className="td num text-right">{fmtNumber(row.events)}</td>
                            <td className="td num text-right">{fmtNumber(row.failed_logins)}</td>
                            <td className="td num text-right">{fmtNumber(row.alerts)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </TableWrap>
                </div>
              ) : (
                <ActivityChart data={data.timeseries} bucketSeconds={data.bucket_seconds} />
              )}
            </div>
          </Panel>

          <div className="grid gap-4 lg:grid-cols-5">
            <Panel className="lg:col-span-3">
              <PanelHeader
                title="Alerts to review"
                hint="Highest risk first"
                actions={
                  <Link href="/alerts" className="text-xs text-ink-2 underline underline-offset-2 hover:text-ink">
                    View all
                  </Link>
                }
              />
              {alerts.loading && !alerts.data ? (
                <div className="p-4">
                  <Skeleton className="h-40 w-full" />
                </div>
              ) : (alerts.data?.items.length ?? 0) === 0 ? (
                <EmptyState title="No active alerts">New detections appear here as soon as they are raised.</EmptyState>
              ) : (
                <ul className="divide-y divide-line">
                  {alerts.data?.items.map((alert) => (
                    <li key={alert.id}>
                      <button type="button" onClick={() => openAlert(alert.id)} className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left hover:bg-raised">
                        <span className="min-w-0">
                          <span className="flex items-center gap-2">
                            <span className="truncate text-sm font-medium text-ink">{alert.title}</span>
                            <OriginBadge origin={alert.data_origin} />
                          </span>
                          <span className="mt-0.5 block truncate text-xs text-ink-3">
                            {alert.source_ip ? <Mono>{alert.source_ip}</Mono> : null}
                            {alert.source_ip && alert.username ? ", " : ""}
                            {alert.username ?? ""}
                            {alert.source_ip || alert.username ? ", " : ""}
                            {timeAgo(alert.last_seen)}
                          </span>
                        </span>
                        <span className="flex shrink-0 items-center gap-3">
                          <RiskMeter score={alert.risk_score} />
                          <SeverityBadge severity={alert.severity} />
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel className="lg:col-span-2">
              <PanelHeader title="Alerts by severity" hint="Active alerts only" />
              <BarList
                items={SEVERITIES.map((severity) => ({
                  key: severity,
                  label: titleCase(severity),
                  value: data?.severity_distribution?.[severity] ?? 0,
                  barClass: SEV_BAR[severity],
                })).filter((item) => item.value > 0)}
                empty="No active alerts."
              />
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <Panel>
              <PanelHeader title="Busiest source IPs" hint="Select one to investigate" />
              <BarList
                empty="No traffic from external addresses yet."
                items={(data?.top_ips ?? []).slice(0, 8).map((row) => ({
                  key: row.ip,
                  label: <Mono>{row.ip}</Mono>,
                  value: row.events,
                  note: row.failed_logins > 0 ? `${fmtNumber(row.failed_logins)} failed logins` : undefined,
                  onClick: () => openIp(row.ip),
                }))}
              />
            </Panel>
            <Panel>
              <PanelHeader title="Where events come from" />
              <BarList items={sourceItems} empty="No events yet." />
            </Panel>
            <Panel>
              <PanelHeader title="Most triggered detections" />
              <BarList
                empty="Nothing has triggered in this period."
                items={(data?.top_rules ?? []).slice(0, 8).map((row) => ({ key: row.rule_key, label: titleCase(row.rule_key), value: row.count, barClass: "bg-series-2" }))}
              />
            </Panel>
          </div>

          {t && t.agents_total === 0 ? (
            <Notice>
              No agents are connected, so only simulated or internal events are shown. <Link href="/settings#agents" className="underline underline-offset-2">Add an agent</Link> to collect real logs.
            </Notice>
          ) : null}
        </div>
      )}
    </div>
  );
}
