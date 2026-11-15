"use client";

import { Button } from "@/components/ui/button";
import { EmptyState, ErrorNote, Skeleton, TableWrap } from "@/components/ui/misc";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useAuth } from "@/lib/auth";
import { fmtDateTime, titleCase } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { AuditEntry } from "@/lib/types";

export function AuditTab() {
  const { can } = useAuth();
  const admin = can("admin");
  const { data, error, loading, reload } = useApi<AuditEntry[]>("/api/audit", { limit: 200 }, { enabled: admin });

  if (!admin) {
    return (
      <Panel>
        <div className="p-4 text-sm text-ink-2">Only admins can read the audit log.</div>
      </Panel>
    );
  }

  return (
    <Panel>
      <PanelHeader
        title="Audit log"
        hint="Who changed what: sign-ins, alert triage, rule and user changes. The latest 200 entries."
        actions={
          <Button size="sm" variant="ghost" onClick={reload}>
            Refresh
          </Button>
        }
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
      ) : data && data.length === 0 ? (
        <EmptyState title="Nothing recorded yet" />
      ) : (
        <TableWrap>
          <table className="w-full min-w-[720px] text-sm">
            <thead>
              <tr className="border-b border-line">
                <th className="th">When</th>
                <th className="th">Who</th>
                <th className="th">Action</th>
                <th className="th">Detail</th>
                <th className="th">From</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {data?.map((entry) => (
                <tr key={entry.id}>
                  <td className="td num whitespace-nowrap text-ink-2">{fmtDateTime(entry.created_at)}</td>
                  <td className="td">{entry.actor ?? "system"}</td>
                  <td className="td whitespace-nowrap">{titleCase(entry.action)}</td>
                  <td className="td max-w-[320px] truncate text-ink-2" title={entry.detail ?? ""}>
                    {entry.detail ?? "-"}
                  </td>
                  <td className="td font-mono text-xs text-ink-3">{entry.ip_address ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Panel>
  );
}
