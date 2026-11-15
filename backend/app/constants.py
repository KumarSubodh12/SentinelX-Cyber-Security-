"""Shared constants and enums. Pure Python - no framework imports."""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def severity_rank(value: str | None) -> int:
    return SEVERITY_RANK.get((value or "info").lower(), 0)


def max_severity(a: str | None, b: str | None) -> str:
    return a if severity_rank(a) >= severity_rank(b) else (b or "info")  # type: ignore[return-value]


def at_least(severity: str | None, minimum: str | None) -> bool:
    return severity_rank(severity) >= severity_rank(minimum)


class AlertStatus(str, Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    false_positive = "false_positive"


OPEN_ALERT_STATUSES = ("open", "acknowledged")


class IncidentStatus(str, Enum):
    open = "open"
    investigating = "investigating"
    contained = "contained"
    resolved = "resolved"
    closed = "closed"


ACTIVE_INCIDENT_STATUSES = ("open", "investigating", "contained")


class EventType(str, Enum):
    login_failed = "login_failed"
    login_success = "login_success"
    account_lockout = "account_lockout"
    account_created = "account_created"
    privilege_group_change = "privilege_group_change"
    privilege_escalation = "privilege_escalation"
    privilege_escalation_failed = "privilege_escalation_failed"
    audit_log_cleared = "audit_log_cleared"
    http_request = "http_request"
    access_denied = "access_denied"
    connection_blocked = "connection_blocked"
    connection_allowed = "connection_allowed"
    service_event = "service_event"
    app_error = "app_error"
    other = "other"


EVENT_TYPES = {e.value for e in EventType}

SOURCES = {
    "linux_auth",
    "windows_security",
    "web_access",
    "firewall",
    "application",
    "server",
    "simulator",
    "other",
}


class DataOrigin:
    REAL = "real"
    SIMULATED = "simulated"


ORIGINS = (DataOrigin.REAL, DataOrigin.SIMULATED)
