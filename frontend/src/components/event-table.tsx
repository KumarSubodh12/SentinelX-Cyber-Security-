"use client";

import { useDetail } from "@/lib/detail";
import { fmtDateTime, titleCase } from "@/lib/format";
import type { EventRow } from "@/lib/types";
import { Mono, OriginBadge } from "./badges";
import { TableWrap } from "./ui/misc";

/** Compact event list used inside the alert and IP panels. */
export function EventTable({ events, showIp = true }: { events: EventRow[]; showIp?: boolean }) {
  const { openIp } = useDetail();
  if (events.length === 0) return <p className="py-4 text-sm text-ink-3">No events recorded.</p>;
  return (
    <TableWrap>
      <table className="w-full min-w-[560px] text-sm">
        <thead>
          <tr className="border-b border-line">
            <th className="th">Time</th>
            <th className="th">Event</th>
            <th className="th">User</th>
            {showIp ? <th className="th">Source IP</th> : null}
            <th className="th">Detail</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {events.map((event) => (
            <tr key={event.id}>
              <td className="td num whitespace-nowrap text-ink-2">{fmtDateTime(event.timestamp)}</td>
              <td className="td whitespace-nowrap">
                <div className="flex items-center gap-2">
                  {titleCase(event.event_type)}
                  <OriginBadge origin={event.data_origin} />
                </div>
              </td>
              <td className="td">{event.username ?? "-"}</td>
              {showIp ? (
                <td className="td">
                  {event.source_ip ? (
                    <button type="button" className="underline decoration-line underline-offset-2 hover:decoration-ink" onClick={() => openIp(event.source_ip as string)}>
                      <Mono>{event.source_ip}</Mono>
                    </button>
                  ) : (
                    "-"
                  )}
                </td>
              ) : null}
              <td className="td max-w-[280px] truncate text-ink-2" title={event.message ?? event.http_path ?? ""}>
                {event.message ?? event.http_path ?? "-"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}
