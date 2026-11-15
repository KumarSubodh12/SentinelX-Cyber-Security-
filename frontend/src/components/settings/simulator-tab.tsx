"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Field, Select } from "@/components/ui/form";
import { ErrorNote, KeyValue, Notice, Skeleton } from "@/components/ui/misc";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useDetail } from "@/lib/detail";
import { fmtNumber, titleCase } from "@/lib/format";
import { useApi } from "@/lib/hooks";

interface Scenario {
  key: string;
  description: string;
}

interface SimStats {
  events: number;
  alerts: number;
  incidents: number;
}

export function SimulatorTab() {
  const { can } = useAuth();
  const { bump } = useDetail();
  const canRun = can("analyst", "admin");
  const admin = can("admin");

  const scenarios = useApi<{ scenarios: Scenario[] }>("/api/simulate/scenarios", {}, { enabled: canRun });
  const stats = useApi<SimStats>("/api/simulate/stats", {}, { enabled: canRun });

  const [scenario, setScenario] = useState("mixed");
  const [intensity, setIntensity] = useState(2);
  const [days, setDays] = useState(7);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(label: string, action: () => Promise<string>) {
    setBusy(label);
    setError(null);
    setMessage(null);
    try {
      setMessage(await action());
      stats.reload();
      bump();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(null);
    }
  }

  if (!canRun) {
    return (
      <Panel>
        <div className="p-4 text-sm text-ink-2">Only analysts and admins can use the simulator.</div>
      </Panel>
    );
  }

  const disabled = scenarios.error?.toLowerCase().includes("disabled");
  if (disabled) {
    return (
      <Notice>The simulator is turned off on this server (ENABLE_SIMULATOR=false). That is the recommended setting for production.</Notice>
    );
  }

  const current = scenarios.data?.scenarios.find((s) => s.key === scenario);

  return (
    <div className="space-y-4">
      <Notice>
        Simulated data uses reserved documentation IP addresses and is labelled SIM everywhere. It is stored separately from real data and never mixes with it, and you can remove it at any time.
      </Notice>

      <Panel>
        <PanelHeader title="Run an attack scenario" hint="Generates events and sends them through the real detection pipeline." />
        <div className="space-y-4 p-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="w-full sm:w-64">
              <Field label="Scenario" hint={current?.description}>
                <Select value={scenario} onChange={(e) => setScenario(e.target.value)} disabled={!scenarios.data}>
                  {(scenarios.data?.scenarios ?? [{ key: "mixed", description: "" }]).map((s) => (
                    <option key={s.key} value={s.key}>
                      {titleCase(s.key)}
                    </option>
                  ))}
                </Select>
              </Field>
            </div>
            <Field label="Size">
              <Select className="w-36" value={intensity} onChange={(e) => setIntensity(Number(e.target.value))}>
                {[1, 2, 3, 4, 5].map((n) => (
                  <option key={n} value={n}>
                    {n === 1 ? "1 (small)" : n === 5 ? "5 (large)" : n}
                  </option>
                ))}
              </Select>
            </Field>
            <Button
              variant="primary"
              disabled={busy !== null}
              onClick={() =>
                run("scenario", async () => {
                  const r = await api<{ accepted: number; alerts_created: number; alerts_updated: number }>("/api/simulate", { method: "POST", body: { scenario, intensity } });
                  return `Sent ${fmtNumber(r.accepted)} events. ${fmtNumber(r.alerts_created)} new alerts, ${fmtNumber(r.alerts_updated)} updated.`;
                })
              }
            >
              {busy === "scenario" ? "Running..." : "Run scenario"}
            </Button>
          </div>
        </div>
      </Panel>

      {admin ? (
        <Panel>
          <PanelHeader title="Teach the anomaly model" hint="Creates days of normal-looking activity so the model has a baseline to learn from. Then train it on the AI analytics page." />
          <div className="flex flex-wrap items-end gap-3 p-4">
            <Field label="Days of normal activity">
              <Select className="w-36" value={days} onChange={(e) => setDays(Number(e.target.value))}>
                {[3, 7, 10, 14].map((n) => (
                  <option key={n} value={n}>
                    {n} days
                  </option>
                ))}
              </Select>
            </Field>
            <Button
              disabled={busy !== null}
              onClick={() =>
                run("baseline", async () => {
                  const r = await api<{ accepted: number }>("/api/simulate/baseline", { method: "POST", body: { days } });
                  return `Created ${fmtNumber(r.accepted)} baseline events.`;
                })
              }
            >
              {busy === "baseline" ? "Creating..." : "Create baseline traffic"}
            </Button>
          </div>
        </Panel>
      ) : null}

      <Panel>
        <PanelHeader title="Simulated data in the database" />
        <div className="space-y-3 p-4">
          {stats.data ? (
            <KeyValue
              items={[
                { label: "Events", value: <span className="num">{fmtNumber(stats.data.events)}</span> },
                { label: "Alerts", value: <span className="num">{fmtNumber(stats.data.alerts)}</span> },
                { label: "Incidents", value: <span className="num">{fmtNumber(stats.data.incidents)}</span> },
              ]}
            />
          ) : (
            <Skeleton className="h-16 w-full" />
          )}
          {admin ? (
            <Button
              variant="danger"
              disabled={busy !== null || !stats.data || (stats.data.events === 0 && stats.data.alerts === 0 && stats.data.incidents === 0)}
              onClick={() => {
                if (!window.confirm("Delete all simulated events, alerts and incidents? Real data is not touched.")) return;
                void run("clear", async () => {
                  const r = await api<{ events_deleted: number; alerts_deleted: number; incidents_deleted: number }>("/api/simulate/data", { method: "DELETE" });
                  return `Removed ${fmtNumber(r.events_deleted)} events, ${fmtNumber(r.alerts_deleted)} alerts and ${fmtNumber(r.incidents_deleted)} incidents.`;
                });
              }}
            >
              {busy === "clear" ? "Removing..." : "Remove all simulated data"}
            </Button>
          ) : null}
        </div>
      </Panel>

      {message ? <p className="text-sm text-ink-2">{message}</p> : null}
      {error ? <ErrorNote message={error} /> : null}
    </div>
  );
}
