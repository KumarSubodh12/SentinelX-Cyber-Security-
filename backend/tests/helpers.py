from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from app.services.normalizer import normalize_event
from app.services.rules_catalog import default_rule_configs
from app.services.types import NormalizedEvent

T0 = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)


def ev(
    offset_s: float = 0,
    *,
    event_type: str = "login_failed",
    source: str = "linux_auth",
    ip: Optional[str] = "203.0.113.9",
    user: Optional[str] = "root",
    host: Optional[str] = "srv1",
    base: datetime = T0,
    **kw,
) -> NormalizedEvent:
    raw = {
        "timestamp": (base + timedelta(seconds=offset_s)).isoformat(),
        "source": source,
        "event_type": event_type,
        "source_ip": ip,
        "username": user,
        "hostname": host,
        "message": f"{event_type} test",
    }
    raw.update(kw)
    return normalize_event(raw, now=base + timedelta(days=1))


def rules():
    return default_rule_configs()
