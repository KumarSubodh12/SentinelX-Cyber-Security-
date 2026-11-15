"use client";

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { fmtNumber } from "@/lib/format";
import type { Severity } from "@/lib/types";

/**
 * Chart colours. These are the same values as the CSS tokens in globals.css (blue, orange, aqua),
 * validated for the dark panel surface. Recharts needs literal colour strings.
 */
export const CHART = {
  s1: "#3987e5",
  s2: "#d95926",
  s3: "#199e70",
  surface: "#131b24",
  grid: "#26323f",
  axis: "#7d8b99",
  ink: "#e8edf2",
} as const;

export const SEV_HEX: Record<Severity, string> = {
  critical: "#d03b3b",
  high: "#ec835a",
  medium: "#fab219",
  low: "#3987e5",
  info: "#898781",
};

interface TipPayload {
  name?: string;
  value?: number;
  color?: string;
  dataKey?: string;
}
interface TipProps {
  active?: boolean;
  label?: string | number;
  payload?: TipPayload[];
}

export function ChartTooltip({
  active,
  label,
  payload,
  formatLabel,
  names,
}: TipProps & { formatLabel?: (label: string) => string; names?: Record<string, string> }) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="min-w-[140px] rounded border border-line bg-raised px-3 py-2 text-xs shadow-none">
      <p className="mb-1.5 text-ink-2">{formatLabel ? formatLabel(String(label)) : String(label)}</p>
      {payload.map((item) => (
        <div key={item.dataKey ?? item.name} className="flex items-center justify-between gap-4">
          <span className="flex items-center gap-1.5 text-ink">
            <span className="h-2 w-2 rounded-full" style={{ background: item.color }} />
            {names?.[item.dataKey ?? ""] ?? item.name}
          </span>
          <span className="num font-medium text-ink">{fmtNumber(item.value ?? 0)}</span>
        </div>
      ))}
    </div>
  );
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-2">
      {items.map((item) => (
        <li key={item.label} className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full" style={{ background: item.color }} />
          {item.label}
        </li>
      ))}
    </ul>
  );
}

export function formatBucket(iso: string, bucketSeconds: number): string {
  const d = new Date(iso);
  if (bucketSeconds >= 86400) return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
  if (bucketSeconds >= 3600)
    return `${d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" })} ${String(d.getHours()).padStart(2, "0")}:00`;
  return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });
}

interface SeriesRowProps {
  label: string;
  color: string;
  data: { t: string; value: number }[];
  bucketSeconds: number;
  showAxis: boolean;
  total: number;
}

/** One single-series area chart. Several of these stacked share a hover position (small multiples). */
function SeriesRow({ label, color, data, bucketSeconds, showAxis, total }: SeriesRowProps) {
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <div className="grid grid-cols-[96px_1fr] items-center gap-3 sm:grid-cols-[132px_1fr]">
      <div>
        <p className="flex items-center gap-1.5 text-xs text-ink-2">
          <span className="h-2 w-2 rounded-full" style={{ background: color }} />
          {label}
        </p>
        <p className="num mt-0.5 text-lg font-semibold text-ink">{fmtNumber(total)}</p>
      </div>
      <div style={{ height: showAxis ? 118 : 84 }} aria-hidden={false}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} syncId="timeline" margin={{ top: 6, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid vertical={false} stroke={CHART.grid} strokeWidth={1} />
            <XAxis
              dataKey="t"
              hide={!showAxis}
              tickFormatter={(v: string) => formatBucket(v, bucketSeconds)}
              tick={{ fill: CHART.axis, fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: CHART.grid }}
              minTickGap={48}
            />
            <YAxis
              width={34}
              tick={{ fill: CHART.axis, fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              domain={[0, max]}
              ticks={[0, max]}
              allowDecimals={false}
            />
            <Tooltip
              cursor={{ stroke: CHART.axis, strokeWidth: 1 }}
              content={(props) => (
                <ChartTooltip
                  {...(props as unknown as TipProps)}
                  formatLabel={(l) => formatBucket(l, bucketSeconds)}
                  names={{ value: label }}
                />
              )}
            />
            <Area
              type="monotone"
              dataKey="value"
              name={label}
              stroke={color}
              strokeWidth={2}
              strokeLinecap="round"
              fill={color}
              fillOpacity={0.12}
              dot={false}
              activeDot={{ r: 4, stroke: CHART.surface, strokeWidth: 2, fill: color }}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export interface TimePoint {
  t: string;
  events: number;
  failed_logins: number;
  alerts: number;
}

/** Events, failed logins and alerts have very different scales, so each gets its own axis. */
export function ActivityChart({ data, bucketSeconds }: { data: TimePoint[]; bucketSeconds: number }) {
  const sum = (key: "events" | "failed_logins" | "alerts") => data.reduce((acc, d) => acc + d[key], 0);
  const rows = [
    { key: "events" as const, label: "Events", color: CHART.s1 },
    { key: "failed_logins" as const, label: "Failed logins", color: CHART.s2 },
    { key: "alerts" as const, label: "Alerts", color: CHART.s3 },
  ];
  return (
    <div className="space-y-2">
      {rows.map((row, index) => (
        <SeriesRow
          key={row.key}
          label={row.label}
          color={row.color}
          bucketSeconds={bucketSeconds}
          showAxis={index === rows.length - 1}
          total={sum(row.key)}
          data={data.map((d) => ({ t: d.t, value: d[row.key] }))}
        />
      ))}
    </div>
  );
}

interface StackedProps {
  data: Record<string, string | number>[];
  xKey: string;
  series: { key: string; label: string; color: string }[];
  formatX?: (value: string) => string;
  height?: number;
}

/** Stacked or single-series columns. A 2px surface-coloured stroke separates stacked segments. */
export function Columns({ data, xKey, series, formatX, height = 220 }: StackedProps) {
  const names = Object.fromEntries(series.map((s) => [s.key, s.label]));
  return (
    <div>
      {series.length > 1 ? (
        <div className="mb-2">
          <Legend items={series.map((s) => ({ label: s.label, color: s.color }))} />
        </div>
      ) : null}
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 6, right: 8, bottom: 0, left: 0 }} barCategoryGap="22%">
            <CartesianGrid vertical={false} stroke={CHART.grid} strokeWidth={1} />
            <XAxis
              dataKey={xKey}
              tick={{ fill: CHART.axis, fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: CHART.grid }}
              tickFormatter={formatX}
              minTickGap={24}
            />
            <YAxis width={34} tick={{ fill: CHART.axis, fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
            <Tooltip
              cursor={{ fill: "rgba(255,255,255,0.04)" }}
              content={(props) => <ChartTooltip {...(props as unknown as TipProps)} formatLabel={formatX} names={names} />}
            />
            {series.map((s, index) => (
              <Bar
                key={s.key}
                dataKey={s.key}
                name={s.label}
                stackId={series.length > 1 ? "stack" : undefined}
                fill={s.color}
                stroke={CHART.surface}
                strokeWidth={series.length > 1 ? 2 : 0}
                radius={index === series.length - 1 ? [3, 3, 0, 0] : [0, 0, 0, 0]}
                isAnimationActive={false}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
