"""Validate and normalise raw events coming from agents.

Defence in depth: agents already avoid sending secrets, but the server also
strips control characters (log injection), validates IPs and redacts the values
of sensitive query-string parameters before anything is stored.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.constants import EVENT_TYPES, SOURCES
from app.services.types import NormalizedEvent

MAX_MESSAGE = 2000
MAX_PATH = 2048
MAX_FUTURE_SKEW = timedelta(minutes=10)

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_NEWLINES = re.compile(r"[\r\n\t]+")
_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|pwd|token|secret|api[_-]?key|auth|session|cookie|credential|otp|ssn)", re.I
)


class NormalizationError(ValueError):
    """Raised when an event cannot be made safe/valid enough to store."""


def clean_text(value: Any, max_len: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    text = _NEWLINES.sub(" ", text)
    text = _CONTROL.sub("", text).strip()
    if not text:
        return None
    return text[:max_len]


def normalize_ip(value: Any) -> Optional[str]:
    """Return a canonical IP string or None when the value is not a valid IP."""
    text = clean_text(value, 64)
    if not text or text in {"-", "::", "0.0.0.0", "unknown", "localhost"}:
        return None
    text = text.split("%", 1)[0]  # IPv6 zone id
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def is_public_ip(value: Optional[str]) -> bool:
    """True only for globally routable addresses (never private/documentation/loopback)."""
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def redact_path(path: Optional[str]) -> Optional[str]:
    """Redact values of sensitive query parameters but keep attack payloads visible."""
    if path is None:
        return None
    if "?" not in path:
        return path
    base, query = path.split("?", 1)
    parts = []
    for chunk in query.split("&"):
        if "=" in chunk:
            key, _, _val = chunk.partition("=")
            if _SENSITIVE_KEY.search(key):
                parts.append(f"{key}=[redacted]")
                continue
        parts.append(chunk)
    return base + "?" + "&".join(parts)


def parse_timestamp(value: Any, now: Optional[datetime] = None) -> tuple[datetime, bool]:
    """Parse a timestamp to aware UTC. Returns (timestamp, was_clamped)."""
    now = now or datetime.now(timezone.utc)
    if value is None or value == "":
        return now, False
    ts: Optional[datetime] = None
    if isinstance(value, datetime):
        ts = value
    elif isinstance(value, (int, float)):
        # Accept seconds or milliseconds since epoch.
        seconds = float(value) / 1000.0 if float(value) > 1e11 else float(value)
        try:
            ts = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise NormalizationError("timestamp out of range") from exc
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z") or text.endswith("z"):
            text = text[:-1] + "+00:00"
        # Python <3.11 only accepts up to 6 fractional digits.
        text = re.sub(r"(\.\d{6})\d+", r"\1", text)
        try:
            ts = datetime.fromisoformat(text)
        except ValueError as exc:
            raise NormalizationError(f"invalid timestamp: {value!r}") from exc
    else:
        raise NormalizationError("invalid timestamp type")

    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    ts = ts.astimezone(timezone.utc)
    if ts.year < 2000:
        raise NormalizationError("timestamp before year 2000")
    if ts > now + MAX_FUTURE_SKEW:
        return now, True
    return ts, False


def _clean_extra(extra: Any) -> dict[str, Any]:
    if not isinstance(extra, dict):
        return {}
    out: dict[str, Any] = {}
    for key, val in list(extra.items())[:20]:
        k = clean_text(key, 64)
        if not k or _SENSITIVE_KEY.search(k):
            continue
        if isinstance(val, (int, float, bool)) or val is None:
            out[k] = val
        elif isinstance(val, (list, tuple)):
            out[k] = [clean_text(v, 128) for v in list(val)[:20]]
        else:
            out[k] = clean_text(val, 256)
    return out


def _clean_port(value: Any) -> Optional[int]:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def _clean_status(value: Any) -> Optional[int]:
    try:
        code = int(value)
    except (TypeError, ValueError):
        return None
    return code if 100 <= code <= 599 else None


def normalize_event(
    raw: dict[str, Any], *, origin: str = "real", now: Optional[datetime] = None
) -> NormalizedEvent:
    if not isinstance(raw, dict):
        raise NormalizationError("event must be an object")

    timestamp, clamped = parse_timestamp(raw.get("timestamp"), now)

    event_type = (clean_text(raw.get("event_type"), 64) or "other").lower()
    if event_type not in EVENT_TYPES:
        event_type = "other"
    source = (clean_text(raw.get("source"), 64) or "other").lower()
    if source not in SOURCES:
        source = "other"

    extra = _clean_extra(raw.get("extra"))
    if clamped:
        extra["timestamp_clamped"] = True

    raw_ip = raw.get("source_ip")
    source_ip = normalize_ip(raw_ip)
    if raw_ip and source_ip is None:
        extra["source_ip_raw"] = clean_text(raw_ip, 64)

    method = clean_text(raw.get("http_method"), 16)
    path = clean_text(raw.get("http_path"), MAX_PATH)

    event = NormalizedEvent(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        message=clean_text(raw.get("message"), MAX_MESSAGE) or "",
        hostname=clean_text(raw.get("hostname"), 255),
        username=clean_text(raw.get("username"), 128),
        source_ip=source_ip,
        dest_ip=normalize_ip(raw.get("dest_ip")),
        dest_port=_clean_port(raw.get("dest_port")),
        http_method=method.upper() if method else None,
        http_path=redact_path(path),
        status_code=_clean_status(raw.get("status_code")),
        user_agent=clean_text(raw.get("user_agent"), 512),
        extra=extra,
        data_origin=origin,
        ref=clean_text(raw.get("ref"), 255),
    )
    if event.message:
        event.message = redact_path(event.message) or ""
    return event


def make_fingerprint(event: NormalizedEvent, agent_id: Optional[int]) -> str:
    """Stable id used to drop duplicates when an agent re-sends a batch."""
    material = "|".join(
        [
            str(agent_id or 0),
            event.ref or "",
            event.timestamp.isoformat(),
            event.source,
            event.event_type,
            event.source_ip or "",
            event.username or "",
            (event.message or "")[:500],
        ]
    )
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:40]
