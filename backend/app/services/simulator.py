"""Controlled attack simulations.

Everything generated here:
  * is labelled `data_origin = "simulated"` (shown as SIM in the UI),
  * uses RFC 5737 documentation IP ranges (203.0.113.0/24, 198.51.100.0/24,
    192.0.2.0/24) that can never belong to a real host, and
  * is kept separate from real data by the pipeline, so a simulation can never
    create or merge into a real alert.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

SCENARIOS = {
    "brute_force": "SSH brute-force against one account",
    "password_spray": "Password spraying across many accounts",
    "success_after_failures": "Brute-force followed by a successful login",
    "web_scan": "Directory / vulnerability scan against a web server",
    "web_attacks": "SQL injection, path traversal and XSS requests",
    "port_scan": "Port scan blocked by the firewall",
    "audit_log_cleared": "Windows audit log cleared + new admin account",
    "mixed": "Several attacks at once",
}

_ATTACKERS = ["203.0.113.45", "203.0.113.77", "198.51.100.23", "198.51.100.200", "192.0.2.66"]
_USERS = ["root", "admin", "ubuntu", "postgres", "deploy", "test", "oracle", "guest", "support", "backup"]
_SCAN_PATHS = [
    "/admin", "/login.php", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.zip",
    "/config.php", "/server-status", "/api/v1/users", "/console", "/manager/html", "/xmlrpc.php",
    "/old/", "/test/", "/dev/", "/db.sql", "/robots.txt", "/sitemap.xml", "/cgi-bin/test.cgi",
]


def _evt(ts: datetime, **kw: Any) -> dict[str, Any]:
    base = {
        "timestamp": ts.isoformat(),
        "source": "simulator",
        "hostname": kw.pop("hostname", "sim-server-01"),
        "ref": f"sim-{uuid.uuid4().hex[:16]}",
    }
    base.update(kw)
    return base


def generate(
    scenario: str,
    *,
    intensity: int = 1,
    now: Optional[datetime] = None,
    rng: Optional[random.Random] = None,
) -> list[dict[str, Any]]:
    """Return raw events (agent format) for a scenario. `intensity` scales volume (1-5)."""
    now = now or datetime.now(timezone.utc)
    rng = rng or random.Random()
    intensity = max(1, min(5, intensity))
    if scenario == "mixed":
        events: list[dict[str, Any]] = []
        for name in ("brute_force", "web_scan", "port_scan", "web_attacks"):
            events.extend(generate(name, intensity=intensity, now=now, rng=rng))
        return events
    fn = _SCENARIOS.get(scenario)
    if fn is None:
        raise ValueError(f"Unknown scenario '{scenario}'")
    return fn(now, intensity, rng)


def _brute_force(now: datetime, k: int, rng: random.Random) -> list[dict[str, Any]]:
    ip = rng.choice(_ATTACKERS)
    n = 12 * k
    start = now - timedelta(seconds=n * 3)
    return [
        _evt(
            start + timedelta(seconds=i * 3),
            source="linux_auth", event_type="login_failed", username="root", source_ip=ip,
            message=f"Failed password for root from {ip} port {40000 + i} ssh2",
        )
        for i in range(n)
    ]


def _password_spray(now: datetime, k: int, rng: random.Random) -> list[dict[str, Any]]:
    ip = rng.choice(_ATTACKERS)
    users = _USERS[: min(len(_USERS), 5 + k)]
    start = now - timedelta(seconds=len(users) * 2 * 20)
    out = []
    for i, user in enumerate(users * 2):
        out.append(
            _evt(
                start + timedelta(seconds=i * 20),
                source="linux_auth", event_type="login_failed", username=user, source_ip=ip,
                message=f"Failed password for invalid user {user} from {ip} port {50000 + i} ssh2",
            )
        )
    return out


def _success_after_failures(now: datetime, k: int, rng: random.Random) -> list[dict[str, Any]]:
    ip = rng.choice(_ATTACKERS)
    n = 8 + 2 * k
    start = now - timedelta(seconds=n * 4 + 10)
    out = [
        _evt(
            start + timedelta(seconds=i * 4),
            source="linux_auth", event_type="login_failed", username="deploy", source_ip=ip,
            message=f"Failed password for deploy from {ip} port {41000 + i} ssh2",
        )
        for i in range(n)
    ]
    out.append(
        _evt(
            now - timedelta(seconds=2),
            source="linux_auth", event_type="login_success", username="deploy", source_ip=ip,
            message=f"Accepted password for deploy from {ip} port 41999 ssh2",
        )
    )
    return out


def _web_scan(now: datetime, k: int, rng: random.Random) -> list[dict[str, Any]]:
    ip = rng.choice(_ATTACKERS)
    n = 20 * k
    start = now - timedelta(seconds=n)
    return [
        _evt(
            start + timedelta(seconds=i),
            source="web_access", event_type="http_request", source_ip=ip, hostname="sim-web-01",
            http_method="GET", http_path=_SCAN_PATHS[i % len(_SCAN_PATHS)] + (f"?r={i}" if i >= len(_SCAN_PATHS) else ""),
            status_code=404, user_agent="Mozilla/5.0 (compatible; scanner)",
            message=f"GET {_SCAN_PATHS[i % len(_SCAN_PATHS)]} 404",
        )
        for i in range(n)
    ]


def _web_attacks(now: datetime, k: int, rng: random.Random) -> list[dict[str, Any]]:
    ip = rng.choice(_ATTACKERS)
    payloads = [
        "/products?id=1%27%20OR%20%271%27=%271",
        "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users",
        "/download?file=../../../../etc/passwd",
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "/cgi-bin/status?x=;cat%20/etc/passwd",
    ]
    out = []
    for i in range(len(payloads) * k):
        path = payloads[i % len(payloads)]
        out.append(
            _evt(
                now - timedelta(seconds=(len(payloads) * k - i) * 2),
                source="web_access", event_type="http_request", source_ip=ip, hostname="sim-web-01",
                http_method="GET", http_path=path, status_code=403 if i % 2 else 200,
                user_agent="sqlmap/1.7", message=f"GET {path}",
            )
        )
    return out


def _port_scan(now: datetime, k: int, rng: random.Random) -> list[dict[str, Any]]:
    ip = rng.choice(_ATTACKERS)
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
    ports = ports[: 14 + 2 * k] if 14 + 2 * k <= len(ports) else ports
    start = now - timedelta(seconds=len(ports))
    return [
        _evt(
            start + timedelta(seconds=i),
            source="firewall", event_type="connection_blocked", source_ip=ip, dest_ip="10.0.0.5",
            dest_port=p, hostname="sim-fw-01", message=f"[UFW BLOCK] SRC={ip} DST=10.0.0.5 PROTO=TCP DPT={p}",
            extra={"proto": "TCP"},
        )
        for i, p in enumerate(ports)
    ]


def _audit_log_cleared(now: datetime, k: int, rng: random.Random) -> list[dict[str, Any]]:
    return [
        _evt(
            now - timedelta(seconds=20),
            source="windows_security", event_type="account_created", username="svc_backup2", hostname="SIM-WIN-01",
            message="A user account was created.", extra={"subject_user": "intruder"},
        ),
        _evt(
            now - timedelta(seconds=10),
            source="windows_security", event_type="privilege_group_change", username="svc_backup2", hostname="SIM-WIN-01",
            message="A member was added to a security-enabled local group.",
            extra={"subject_user": "intruder", "group_name": "Administrators"},
        ),
        _evt(
            now - timedelta(seconds=2),
            source="windows_security", event_type="audit_log_cleared", username="intruder", hostname="SIM-WIN-01",
            message="The audit log was cleared.", extra={"subject_user": "intruder"},
        ),
    ]


_SCENARIOS = {
    "brute_force": _brute_force,
    "password_spray": _password_spray,
    "success_after_failures": _success_after_failures,
    "web_scan": _web_scan,
    "web_attacks": _web_attacks,
    "port_scan": _port_scan,
    "audit_log_cleared": _audit_log_cleared,
}


def generate_baseline(days: int = 7, *, now: Optional[datetime] = None, rng: Optional[random.Random] = None) -> list[dict[str, Any]]:
    """Normal business-hours activity (logins + web traffic) so the ML model has a baseline to learn."""
    now = now or datetime.now(timezone.utc)
    rng = rng or random.Random(7)
    days = max(1, min(14, days))
    employees = [("asha", "10.20.0.11"), ("ravi", "10.20.0.12"), ("meera", "10.20.0.13"), ("kabir", "10.20.0.14"), ("sana", "10.20.0.15"), ("dev", "10.20.0.16")]
    out: list[dict[str, Any]] = []
    for d in range(days, 0, -1):
        day = (now - timedelta(days=d)).replace(hour=0, minute=0, second=0, microsecond=0)
        for user, ip in employees:
            # Daytime logins (local 09:00-18:00 for an IST-like office; stored as UTC 03:30-12:30).
            for _ in range(rng.randint(2, 5)):
                ts = day + timedelta(hours=3, minutes=30 + rng.randint(0, 540), seconds=rng.randint(0, 59))
                out.append(_evt(ts, source="linux_auth", event_type="login_success", username=user, source_ip=ip,
                                message=f"Accepted publickey for {user} from {ip} port {rng.randint(30000, 60000)} ssh2"))
            if rng.random() < 0.35:  # the odd typo
                ts = day + timedelta(hours=3, minutes=30 + rng.randint(0, 540))
                out.append(_evt(ts, source="linux_auth", event_type="login_failed", username=user, source_ip=ip,
                                message=f"Failed password for {user} from {ip} port {rng.randint(30000, 60000)} ssh2"))
            for _ in range(rng.randint(15, 60)):
                ts = day + timedelta(hours=3, minutes=30 + rng.randint(0, 540), seconds=rng.randint(0, 59))
                status = rng.choices([200, 200, 200, 304, 404], [60, 20, 10, 6, 4])[0]
                out.append(_evt(ts, source="web_access", event_type="http_request", username=None, source_ip=ip,
                                hostname="sim-web-01", http_method="GET", http_path=rng.choice(["/", "/dashboard", "/api/items", "/static/app.js"]),
                                status_code=status, message="GET"))
    return out
