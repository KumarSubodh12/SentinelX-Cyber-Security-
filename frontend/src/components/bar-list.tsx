import type { ReactNode } from "react";
import { fmtNumber } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface BarItem {
  key: string;
  label: ReactNode;
  value: number;
  /** Tailwind background class for the bar, e.g. "bg-sev-high". */
  barClass?: string;
  note?: ReactNode;
  onClick?: () => void;
}

/** Horizontal bars with the label and the value written out, so no hover is needed to read it. */
export function BarList({ items, empty }: { items: BarItem[]; empty?: string }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (items.length === 0) return <p className="px-4 py-6 text-sm text-ink-3">{empty ?? "Nothing to show yet."}</p>;
  return (
    <ul className="divide-y divide-line">
      {items.map((item) => {
        const body = (
          <>
            <div className="flex items-baseline justify-between gap-3">
              <span className="min-w-0 truncate text-sm text-ink">{item.label}</span>
              <span className="num shrink-0 text-sm font-medium text-ink">{fmtNumber(item.value)}</span>
            </div>
            <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-raised">
              <div
                className={cn("h-full rounded-full", item.barClass ?? "bg-series-1")}
                style={{ width: `${Math.max(2, (item.value / max) * 100)}%` }}
              />
            </div>
            {item.note ? <div className="mt-1 text-xs text-ink-3">{item.note}</div> : null}
          </>
        );
        return (
          <li key={item.key}>
            {item.onClick ? (
              <button type="button" onClick={item.onClick} className="block w-full px-4 py-2.5 text-left hover:bg-raised">
                {body}
              </button>
            ) : (
              <div className="px-4 py-2.5">{body}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
