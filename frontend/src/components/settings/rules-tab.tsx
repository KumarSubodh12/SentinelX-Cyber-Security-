"use client";

import { useState } from "react";
import { SeverityBadge } from "@/components/badges";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, Select, Textarea } from "@/components/ui/form";
import { ErrorNote, Skeleton } from "@/components/ui/misc";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { titleCase } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { SEVERITIES, type Rule, type Severity } from "@/lib/types";

const PARAM_LABELS: Record<string, string> = {
  threshold: "Events needed to trigger",
  window_seconds: "Time window (seconds)",
  distinct_users: "Different usernames",
  min_attempts: "Minimum attempts",
  distinct_ips: "Different source IPs",
  failures: "Failures before the success",
  distinct_ports: "Different ports",
  start_hour: "Quiet hours start (0-23)",
  end_hour: "Quiet hours end (0-23)",
  tz_offset_minutes: "Time zone offset (minutes from UTC)",
  groups: "Privileged groups (one per line)",
};

type Draft = Record<string, string>;

function toDraft(params: Rule["params"]): Draft {
  const draft: Draft = {};
  for (const [key, value] of Object.entries(params)) {
    draft[key] = Array.isArray(value) ? value.join("\n") : String(value);
  }
  return draft;
}

function toParams(draft: Draft, original: Rule["params"]): Rule["params"] {
  const params: Rule["params"] = {};
  for (const [key, text] of Object.entries(draft)) {
    if (Array.isArray(original[key])) {
      params[key] = text
        .split("\n")
        .map((line) => line.trim().toLowerCase())
        .filter(Boolean);
    } else {
      params[key] = Number(text);
    }
  }
  return params;
}

function RuleRow({ rule, admin, onChanged }: { rule: Rule; admin: boolean; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const [severity, setSeverity] = useState<Severity>(rule.severity);
  const [draft, setDraft] = useState<Draft>(() => toDraft(rule.params));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const editable = Object.keys(rule.params).length > 0;

  async function patch(body: Record<string, unknown>) {
    setBusy(true);
    setError(null);
    try {
      await api(`/api/rules/${rule.key}`, { method: "PATCH", body });
      onChanged();
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the rule");
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    const params = toParams(draft, rule.params);
    if (Object.values(params).some((v) => typeof v === "number" && Number.isNaN(v))) {
      setError("Use whole numbers for the numeric settings.");
      return;
    }
    if (await patch({ severity, params })) setOpen(false);
  }

  async function reset() {
    if (!window.confirm(`Restore the default settings for "${rule.name}"?`)) return;
    setBusy(true);
    setError(null);
    try {
      const fresh = await api<Rule>(`/api/rules/${rule.key}/reset`, { method: "POST" });
      setSeverity(fresh.severity);
      setDraft(toDraft(fresh.params));
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reset the rule");
    } finally {
      setBusy(false);
    }
  }

  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm font-medium text-ink">{rule.name}</p>
            <SeverityBadge severity={rule.severity} />
            {rule.mitre ? <span className="rounded border border-line px-1.5 py-0.5 font-mono text-[11px] text-ink-3">{rule.mitre}</span> : null}
          </div>
          {rule.description ? <p className="mt-1 text-xs text-ink-3">{rule.description}</p> : null}
        </div>
        <div className="flex items-center gap-3">
          <Checkbox checked={rule.enabled} disabled={!admin || busy} label={rule.enabled ? "On" : "Off"} onChange={(value) => void patch({ enabled: value })} />
          {admin ? (
            <Button size="sm" variant="ghost" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
              {open ? "Close" : "Adjust"}
            </Button>
          ) : null}
        </div>
      </div>

      {open ? (
        <div className="mt-3 space-y-3 rounded border border-line bg-page p-3">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Severity">
              <Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {titleCase(s)}
                  </option>
                ))}
              </Select>
            </Field>
            {editable
              ? Object.keys(rule.params).map((key) =>
                  Array.isArray(rule.params[key]) ? (
                    <div key={key} className="sm:col-span-2 lg:col-span-3">
                      <Field label={PARAM_LABELS[key] ?? titleCase(key)}>
                        <Textarea value={draft[key] ?? ""} onChange={(e) => setDraft({ ...draft, [key]: e.target.value })} className="font-mono text-xs" />
                      </Field>
                    </div>
                  ) : (
                    <Field key={key} label={PARAM_LABELS[key] ?? titleCase(key)}>
                      <Input type="number" inputMode="numeric" value={draft[key] ?? ""} onChange={(e) => setDraft({ ...draft, [key]: e.target.value })} />
                    </Field>
                  ),
                )
              : null}
          </div>
          {!editable ? <p className="text-xs text-ink-3">This rule has no thresholds to adjust. You can change its severity or turn it off.</p> : null}
          {error ? <ErrorNote message={error} /> : null}
          <div className="flex gap-2">
            <Button size="sm" variant="primary" disabled={busy} onClick={save}>
              Save changes
            </Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={reset}>
              Restore defaults
            </Button>
          </div>
        </div>
      ) : error ? (
        <div className="mt-2">
          <ErrorNote message={error} />
        </div>
      ) : null}
    </li>
  );
}

export function RulesTab() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi<Rule[]>("/api/rules");

  return (
    <Panel>
      <PanelHeader
        title="Detection rules"
        hint={can("admin") ? "Changes apply to new events straight away. Lower thresholds catch more but raise more false alarms." : "Only admins can change rules."}
      />
      {error ? (
        <div className="p-3">
          <ErrorNote message={error} onRetry={reload} />
        </div>
      ) : null}
      {loading && !data ? (
        <div className="p-4">
          <Skeleton className="h-40 w-full" />
        </div>
      ) : (
        <ul className="divide-y divide-line">
          {data?.map((rule) => (
            <RuleRow key={rule.key} rule={rule} admin={can("admin")} onChanged={reload} />
          ))}
        </ul>
      )}
    </Panel>
  );
}
