"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, Select } from "@/components/ui/form";
import { ErrorNote, KeyValue, Notice, Skeleton } from "@/components/ui/misc";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { titleCase } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { SEVERITIES, type AppSettings, type Severity } from "@/lib/types";

export function NotificationsTab() {
  const { can } = useAuth();
  const admin = can("admin");
  const { data, error, loading, reload } = useApi<AppSettings>("/api/settings");

  const [webhook, setWebhook] = useState("");
  const [notifyMin, setNotifyMin] = useState<Severity>("high");
  const [incidentMin, setIncidentMin] = useState<Severity>("high");
  const [cooldown, setCooldown] = useState("60");
  const [mlEnabled, setMlEnabled] = useState(true);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    if (!data) return;
    setWebhook(data.alert_webhook_url);
    setNotifyMin(data.notify_min_severity);
    setIncidentMin(data.auto_incident_min_severity);
    setCooldown(String(Math.round(data.alert_cooldown_seconds / 60)));
    setMlEnabled(data.ml_enabled);
  }, [data]);

  async function save() {
    const minutes = Number(cooldown);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
      setActionError("Repeat-alert window must be a whole number of minutes between 1 and 1440.");
      return;
    }
    setBusy(true);
    setActionError(null);
    setSaved(false);
    try {
      await api("/api/settings", {
        method: "PUT",
        body: {
          alert_webhook_url: webhook.trim(),
          notify_min_severity: notifyMin,
          auto_incident_min_severity: incidentMin,
          alert_cooldown_seconds: minutes * 60,
          ml_enabled: mlEnabled,
        },
      });
      setSaved(true);
      reload();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Could not save settings");
    } finally {
      setBusy(false);
    }
  }

  if (loading && !data) return <Skeleton className="h-64 w-full" />;
  if (error) return <ErrorNote message={error} onRetry={reload} />;
  if (!data) return null;

  return (
    <div className="space-y-4">
      <Panel>
        <PanelHeader title="Alerts and notifications" hint={admin ? undefined : "Only admins can change these settings."} />
        <div className="grid gap-4 p-4 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <Field label="Webhook address" hint="Alerts are posted here as JSON. Works with Slack or Discord incoming webhooks and with your own service. Must start with https://">
              <Input type="url" value={webhook} onChange={(e) => setWebhook(e.target.value)} disabled={!admin} placeholder="https://hooks.example.com/..." maxLength={500} />
            </Field>
          </div>
          <Field label="Send a notification from" hint="Alerts below this severity are not sent.">
            <Select value={notifyMin} onChange={(e) => setNotifyMin(e.target.value as Severity)} disabled={!admin}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {titleCase(s)} and above
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Open an incident automatically from" hint="Related alerts from the same source are grouped into one incident.">
            <Select value={incidentMin} onChange={(e) => setIncidentMin(e.target.value as Severity)} disabled={!admin}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {titleCase(s)} and above
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Repeat-alert window (minutes)" hint="The same detection from the same source updates the existing alert instead of creating a new one.">
            <Input type="number" inputMode="numeric" min={1} max={1440} value={cooldown} onChange={(e) => setCooldown(e.target.value)} disabled={!admin} />
          </Field>
          <div className="flex items-end pb-2">
            <Checkbox checked={mlEnabled} onChange={setMlEnabled} disabled={!admin} label="Use the anomaly model" />
          </div>
        </div>
        {admin ? (
          <div className="flex flex-wrap items-center gap-3 border-t border-line px-4 py-3">
            <Button variant="primary" onClick={save} disabled={busy}>
              {busy ? "Saving..." : "Save settings"}
            </Button>
            {saved ? <span className="text-sm text-ink-2">Saved.</span> : null}
            {actionError ? <ErrorNote message={actionError} /> : null}
          </div>
        ) : null}
      </Panel>

      <Panel>
        <PanelHeader title="Set on the server" hint="These come from environment variables. Change them in your .env file or hosting dashboard." />
        <div className="space-y-3 p-4">
          <KeyValue
            items={[
              { label: "Reputation lookups", value: data.abuseipdb_configured ? "AbuseIPDB is connected" : "Off (add ABUSEIPDB_API_KEY to enable)" },
              { label: "Threat feeds", value: data.threat_feeds.length > 0 ? data.threat_feeds.join(", ") : "None (add THREAT_FEED_URLS to enable)" },
              { label: "Event retention", value: `${data.retention_days} days` },
              { label: "Simulator", value: data.simulator_enabled ? "Enabled" : "Disabled" },
            ]}
          />
          {data.simulator_enabled ? <Notice tone="warn">The simulator is meant for testing. For a production deployment, set ENABLE_SIMULATOR=false.</Notice> : null}
        </div>
      </Panel>
    </div>
  );
}
