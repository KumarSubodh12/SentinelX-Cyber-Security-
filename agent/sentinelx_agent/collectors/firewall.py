"""Firewall logs written by the Linux kernel (UFW, or iptables rules with a LOG prefix).

Example line:
  Nov 13 10:15:01 host kernel: [123.4] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.5 PROTO=TCP SPT=4444 DPT=22

Only inbound drops are reported (IN= is set) - outbound blocks would show our own
address as the "source" and produce misleading alerts.
"""

from __future__ import annotations

import re
from datetime import datetime, tzinfo
from typing import Any, Optional

from .base import FileTailer, OffsetState, PollingCollector, clean_ip, split_syslog_prefix

_FIELD = re.compile(r"\b(?P<k>IN|OUT|SRC|DST|PROTO|SPT|DPT)=(?P<v>\S*)")


def parse_firewall_line(
    line: str,
    markers: list[str],
    hostname: Optional[str] = None,
    tz: Optional[tzinfo] = None,
    now: Optional[datetime] = None,
) -> Optional[dict[str, Any]]:
    if not any(marker in line for marker in markers):
        return None
    split = split_syslog_prefix(line, now=now, tz=tz)
    if not split:
        return None
    ts, host, _ = split
    fields = {m["k"]: m["v"] for m in _FIELD.finditer(line)}
    if not fields.get("IN") or not fields.get("SRC"):
        return None  # outbound or incomplete
    proto = fields.get("PROTO", "")
    dport = fields.get("DPT")
    src = clean_ip(fields["SRC"])
    if not src:
        return None
    event: dict[str, Any] = {
        "timestamp": ts.isoformat(),
        "source": "firewall",
        "event_type": "connection_blocked",
        "hostname": host or hostname,
        "source_ip": src,
        "dest_ip": clean_ip(fields.get("DST")),
        "dest_port": int(dport) if dport and dport.isdigit() else None,
        "message": f"Firewall blocked {proto or 'traffic'} from {src}" + (f" to port {dport}" if dport else ""),
        "extra": {"proto": proto, "interface": fields["IN"]},
    }
    return {k: v for k, v in event.items() if v is not None}


class FirewallCollector(PollingCollector):
    interval = 1.0

    def __init__(self, path: str, state: OffsetState, hostname: str, markers: list[str], backfill_lines: int = 0) -> None:
        self.name = f"firewall:{path}"
        self.hostname = hostname
        self.markers = markers
        self.tailer = FileTailer(path, state, backfill_lines)

    def poll(self) -> list[dict[str, Any]]:
        events = []
        for line, ref in self.tailer.poll():
            event = parse_firewall_line(line, self.markers, self.hostname)
            if event:
                event["ref"] = ref
                events.append(event)
        return events
