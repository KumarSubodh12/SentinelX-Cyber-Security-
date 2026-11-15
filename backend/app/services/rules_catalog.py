"""Default detection rules. Admins can enable/disable and tune these from the UI."""

from __future__ import annotations

from typing import Any

from app.services.types import RuleConfig

DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "key": "brute_force",
        "name": "Brute-force login attempts",
        "description": "Repeated failed logins from one source within a time window.",
        "severity": "high",
        "category": "brute_force",
        "mitre": "T1110.001",
        "params": {"threshold": 5, "window_seconds": 300},
    },
    {
        "key": "password_spray",
        "name": "Password spraying",
        "description": "One source failing against many different usernames.",
        "severity": "high",
        "category": "brute_force",
        "mitre": "T1110.003",
        "params": {"distinct_users": 5, "min_attempts": 5, "window_seconds": 600},
    },
    {
        "key": "distributed_account_attack",
        "name": "Distributed attack on one account",
        "description": "One account failing logins from many different sources.",
        "severity": "high",
        "category": "brute_force",
        "mitre": "T1110",
        "params": {"threshold": 8, "distinct_ips": 3, "window_seconds": 900},
    },
    {
        "key": "success_after_failures",
        "name": "Successful login after repeated failures",
        "description": "A login succeeded right after many failures from the same source - possible account compromise.",
        "severity": "critical",
        "category": "account_compromise",
        "mitre": "T1078",
        "params": {"failures": 5, "window_seconds": 600},
    },
    {
        "key": "web_scanning",
        "name": "Web scanning / path enumeration",
        "description": "Many HTTP 4xx responses to one source (directory or vulnerability scanning).",
        "severity": "medium",
        "category": "reconnaissance",
        "mitre": "T1595",
        "params": {"threshold": 15, "window_seconds": 120},
    },
    {
        "key": "suspicious_http_request",
        "name": "Suspicious HTTP request",
        "description": "Requests matching SQL injection, traversal, XSS, command injection or scanner signatures.",
        "severity": "medium",
        "category": "web_attack",
        "mitre": "T1190",
        "params": {},
    },
    {
        "key": "high_request_rate",
        "name": "Unusual request frequency",
        "description": "Very high request rate from one source (possible flooding or scraping).",
        "severity": "medium",
        "category": "dos",
        "mitre": "T1499",
        "params": {"threshold": 200, "window_seconds": 60},
    },
    {
        "key": "port_scan",
        "name": "Port scan",
        "description": "One source hit many different ports (blocked by the firewall).",
        "severity": "high",
        "category": "reconnaissance",
        "mitre": "T1046",
        "params": {"distinct_ports": 15, "window_seconds": 120},
    },
    {
        "key": "blocked_traffic_burst",
        "name": "Blocked traffic burst",
        "description": "Large number of connections blocked by the firewall from one source.",
        "severity": "low",
        "category": "network",
        "mitre": "T1595",
        "params": {"threshold": 30, "window_seconds": 300},
    },
    {
        "key": "access_violation",
        "name": "Repeated access violations",
        "description": "Repeated access-denied or failed privilege-escalation events.",
        "severity": "medium",
        "category": "access_violation",
        "mitre": "T1548",
        "params": {"threshold": 5, "window_seconds": 600},
    },
    {
        "key": "off_hours_login",
        "name": "Off-hours login",
        "description": "Successful login outside normal hours (local time offset is configurable).",
        "severity": "low",
        "category": "anomalous_login",
        "mitre": "T1078",
        "params": {"start_hour": 0, "end_hour": 5, "tz_offset_minutes": 330},
    },
    {
        "key": "account_lockout",
        "name": "Account lockout",
        "description": "An account was locked out after failed logins.",
        "severity": "medium",
        "category": "brute_force",
        "mitre": "T1110",
        "params": {},
    },
    {
        "key": "privileged_group_change",
        "name": "Privileged group membership change",
        "description": "A user was added to a privileged group.",
        "severity": "high",
        "category": "privilege_escalation",
        "mitre": "T1098",
        "params": {
            "groups": [
                "administrators",
                "domain admins",
                "enterprise admins",
                "schema admins",
                "backup operators",
                "account operators",
                "server operators",
                "sudo",
                "wheel",
                "root",
                "admin",
            ]
        },
    },
    {
        "key": "audit_log_cleared",
        "name": "Audit log cleared",
        "description": "The security audit log was cleared - a common attacker cover-up step.",
        "severity": "critical",
        "category": "defense_evasion",
        "mitre": "T1070.001",
        "params": {},
    },
    {
        "key": "new_account_created",
        "name": "New account created",
        "description": "A new user account was created.",
        "severity": "low",
        "category": "persistence",
        "mitre": "T1136",
        "params": {},
    },
    {
        "key": "malicious_ip_reputation",
        "name": "Known malicious IP",
        "description": "Activity from an IP flagged by threat intelligence (AbuseIPDB score or a blocklist feed).",
        "severity": "high",
        "category": "threat_intel",
        "mitre": "T1583",
        "params": {"min_score": 75},
    },
]

# Rule keys produced by the ML engine (not editable as windowed rules).
ML_RULE_KEY = "ml_anomaly"


def default_rule_configs() -> dict[str, RuleConfig]:
    return {
        r["key"]: RuleConfig(
            key=r["key"],
            name=r["name"],
            enabled=True,
            severity=r["severity"],
            params=dict(r["params"]),
            category=r["category"],
            mitre=r["mitre"],
        )
        for r in DEFAULT_RULES
    }


def default_params(key: str) -> dict[str, Any]:
    for r in DEFAULT_RULES:
        if r["key"] == key:
            return dict(r["params"])
    return {}


_BOUNDS = {
    "start_hour": (0, 23),
    "end_hour": (0, 24),
    "tz_offset_minutes": (-840, 840),
}


def validate_params(key: str, params: dict[str, Any]) -> dict[str, Any]:
    """Return cleaned params or raise ValueError. Unknown keys are rejected."""
    defaults = default_params(key)
    cleaned: dict[str, Any] = {}
    for name, value in params.items():
        if name not in defaults:
            raise ValueError(f"Unknown parameter '{name}' for rule '{key}'")
        default = defaults[name]
        if isinstance(default, list):
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ValueError(f"'{name}' must be a list of strings")
            cleaned[name] = [v.strip().lower() for v in value if v.strip()][:100]
        else:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"'{name}' must be a whole number")
            low, high = _BOUNDS.get(name, (1, 1_000_000))
            if not low <= value <= high:
                raise ValueError(f"'{name}' must be between {low} and {high}")
            cleaned[name] = value
    return cleaned
