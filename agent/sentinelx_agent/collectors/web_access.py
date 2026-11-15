"""nginx / Apache access logs in the common "combined" format.

Login endpoints (configurable) are turned into login_failed / login_success events:
  * POST + 401/403            -> login_failed
  * POST + 301/302/303        -> login_success (redirect after a successful login)
Anything else, including a plain 200 (ambiguous: many apps re-render the form on
failure), stays a normal http_request so we never report a guess as a fact.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from .base import MONTHS, FileTailer, OffsetState, PollingCollector, clean_ip, redact_query

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
_TS = re.compile(r"^(?P<d>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<y>\d{4}):(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2}) (?P<tz>[+-]\d{4})$")


def parse_access_time(text: str) -> Optional[datetime]:
    m = _TS.match(text)
    if not m or m["mon"].title() not in MONTHS:
        return None
    try:
        local = datetime.strptime(
            f"{m['y']}-{MONTHS[m['mon'].title()]:02d}-{int(m['d']):02d} {m['h']}:{m['mi']}:{m['s']} {m['tz']}",
            "%Y-%m-%d %H:%M:%S %z",
        )
    except ValueError:
        return None
    return local.astimezone(timezone.utc)


def parse_access_line(line: str, login_paths: list[str], hostname: Optional[str] = None) -> Optional[dict[str, Any]]:
    m = _COMBINED.match(line)
    if not m:
        return None
    ts = parse_access_time(m["ts"])
    if ts is None:
        return None

    req = m["req"]
    parts = req.split(" ")
    if len(parts) >= 2 and parts[0].isalpha() and parts[1].startswith("/"):
        method, path = parts[0].upper(), parts[1]
    else:
        method, path = None, req[:200]  # malformed / binary probe: keep what we can
    path = redact_query(path)
    status = int(m["status"])
    ua = m["ua"] if m["ua"] and m["ua"] != "-" else None
    user = m["user"] if m["user"] != "-" else None
    bare_path = path.split("?", 1)[0].rstrip("/") or "/"

    event_type = "http_request"
    if method == "POST" and bare_path in {p.rstrip("/") or "/" for p in login_paths}:
        if status in (401, 403):
            event_type = "login_failed"
        elif status in (301, 302, 303):
            event_type = "login_success"

    event: dict[str, Any] = {
        "timestamp": ts.isoformat(),
        "source": "web_access",
        "event_type": event_type,
        "hostname": hostname,
        "source_ip": clean_ip(m["ip"]),
        "username": user,
        "http_method": method,
        "http_path": path,
        "status_code": status,
        "user_agent": ua,
        "message": f"{method or '-'} {bare_path} {status}",
    }
    return {k: v for k, v in event.items() if v is not None}


class WebAccessCollector(PollingCollector):
    interval = 1.0

    def __init__(self, path: str, state: OffsetState, hostname: str, login_paths: list[str], backfill_lines: int = 0) -> None:
        self.name = f"web-access:{path}"
        self.hostname = hostname
        self.login_paths = login_paths
        self.tailer = FileTailer(path, state, backfill_lines)

    def poll(self) -> list[dict[str, Any]]:
        events = []
        for line, ref in self.tailer.poll():
            event = parse_access_line(line, self.login_paths, self.hostname)
            if event:
                event["ref"] = ref
                events.append(event)
        return events
