"""Rule-based detection engine.

`evaluate()` is a pure function: it takes the *new* events of a batch plus the
recent *history* for the involved IPs/users and returns detections. Using the
events' own timestamps (not wall-clock time) makes it deterministic, replayable
and easy to unit test.

Windowed rules use a sliding window over the merged, time-sorted event list and
only report windows that end on a *new* event, so old history alone never
re-triggers an alert.
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any, Callable, Iterator, Optional
from urllib.parse import unquote, unquote_plus

from app.constants import max_severity, severity_rank
from app.services.types import Detection, NormalizedEvent, ReputationInfo, RuleConfig

MAX_LINKED_EVENTS = 100

# --------------------------------------------------------------------------- #
# HTTP signatures
# --------------------------------------------------------------------------- #

_HTTP_SIGNATURES: list[tuple[str, str, str, "re.Pattern[str]"]] = [
    (
        "sql_injection",
        "SQL injection",
        "high",
        re.compile(
            r"(union(\s|\+|/\*.*?\*/)+(all(\s|\+)+)?select"
            r"|(\bor\b|\band\b)(\s|\+)+['\"]?\d+['\"]?(\s|\+)*=(\s|\+)*['\"]?\d+"
            r"|sleep\(\s*\d+\s*\)|benchmark\(|information_schema|'\s*(or|and)\s*'"
            r"|;\s*drop\s+table|xp_cmdshell)",
            re.I,
        ),
    ),
    (
        "path_traversal",
        "path traversal",
        "high",
        re.compile(
            r"(\.\./|\.\.\\|%2e%2e(%2f|/|%5c)|/etc/(passwd|shadow)|/proc/self/|boot\.ini|win\.ini)",
            re.I,
        ),
    ),
    (
        "command_injection",
        "command injection",
        "high",
        re.compile(
            r"((;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|bash|sh|nc|powershell)\b"
            r"|/bin/(ba)?sh|cmd\.exe|\$\{jndi:)",
            re.I,
        ),
    ),
    (
        "xss",
        "cross-site scripting",
        "medium",
        re.compile(r"(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|<img[^>]+src)", re.I),
    ),
    (
        "sensitive_file_probe",
        "sensitive file probe",
        "medium",
        re.compile(
            r"(/\.env\b|/\.git/|/\.aws/|/\.ssh/|id_rsa|/phpmyadmin|/wp-login\.php|/xmlrpc\.php"
            r"|/cgi-bin/|/actuator/(env|heapdump)|/server-status|/\.DS_Store"
            r"|/backup\.(sql|zip|tar))",
            re.I,
        ),
    ),
]

_SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|zgrab|nuclei|acunetix"
    r"|nessus|feroxbuster|wfuzz)",
    re.I,
)


def _decode(text: str) -> str:
    """URL-decode twice so double-encoded payloads are still matched."""
    return unquote_plus(unquote(text))


def classify_http(event: NormalizedEvent) -> list[tuple[str, str, str]]:
    """Return [(class_key, label, severity)] for every signature the request matches."""
    hits: list[tuple[str, str, str]] = []
    if event.http_path:
        decoded = _decode(event.http_path)
        for key, label, severity, pattern in _HTTP_SIGNATURES:
            if pattern.search(decoded) or pattern.search(event.http_path):
                hits.append((key, label, severity))
    if event.user_agent and _SCANNER_UA.search(event.user_agent):
        hits.append(("scanner_user_agent", "scanner user-agent", "medium"))
    return hits


# --------------------------------------------------------------------------- #
# Sliding window helpers
# --------------------------------------------------------------------------- #

Item = tuple[float, NormalizedEvent, bool]  # (timestamp, event, is_new)


class _Win:
    """Incremental statistics for the events currently inside the window."""

    def __init__(self) -> None:
        self.n = 0
        self.users: Counter[str] = Counter()
        self.ips: Counter[str] = Counter()
        self.ports: Counter[int] = Counter()

    def add(self, ev: NormalizedEvent) -> None:
        self.n += 1
        if ev.user_key:
            self.users[ev.user_key] += 1
        if ev.source_ip:
            self.ips[ev.source_ip] += 1
        if ev.dest_port is not None:
            self.ports[ev.dest_port] += 1

    def remove(self, ev: NormalizedEvent) -> None:
        self.n -= 1
        if ev.user_key:
            self.users[ev.user_key] -= 1
            if self.users[ev.user_key] <= 0:
                del self.users[ev.user_key]
        if ev.source_ip:
            self.ips[ev.source_ip] -= 1
            if self.ips[ev.source_ip] <= 0:
                del self.ips[ev.source_ip]
        if ev.dest_port is not None:
            self.ports[ev.dest_port] -= 1
            if self.ports[ev.dest_port] <= 0:
                del self.ports[ev.dest_port]


def _windows(items: list[Item], window: float) -> Iterator[tuple[int, int, _Win]]:
    """Yield (left, right, stats) for each window that ends on a new item."""
    win = _Win()
    left = 0
    for right, (ts, ev, is_new) in enumerate(items):
        win.add(ev)
        while ts - items[left][0] > window:
            win.remove(items[left][1])
            left += 1
        if is_new:
            yield left, right, win


def _best_window(
    items: list[Item],
    window: float,
    predicate: Callable[[_Win], bool],
    score: Callable[[_Win], float],
) -> Optional[tuple[int, int, dict[str, Any]]]:
    best: Optional[tuple[float, int, int, dict[str, Any]]] = None
    for left, right, win in _windows(items, window):
        if predicate(win):
            s = score(win)
            if best is None or s >= best[0]:
                snap = {
                    "n": win.n,
                    "distinct_users": len(win.users),
                    "distinct_ips": len(win.ips),
                    "distinct_ports": len(win.ports),
                    "users": [u for u, _ in win.users.most_common(10)],
                    "ips": [i for i, _ in win.ips.most_common(10)],
                    "ports": sorted(win.ports)[:30],
                }
                best = (s, left, right, snap)
    if best is None:
        return None
    return best[1], best[2], best[3]


def _fmt_window(seconds: int) -> str:
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{seconds // 3600} h"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds} s"


def _label(events: list[NormalizedEvent]) -> str:
    """Human label for the actor of a group of events."""
    first = events[-1]
    if first.source_ip:
        return first.source_ip
    user = first.username or "unknown user"
    host = first.hostname or "unknown host"
    return f"{user} on {host}"


class _Context:
    def __init__(self, new: list[NormalizedEvent], history: list[NormalizedEvent]) -> None:
        self.new = new
        items: list[Item] = [(e.ts, e, False) for e in history] + [(e.ts, e, True) for e in new]
        items.sort(key=lambda it: it[0])
        self.pool = items

    def group(
        self,
        predicate: Callable[[NormalizedEvent], bool],
        key: Callable[[NormalizedEvent], Optional[str]],
    ) -> dict[str, list[Item]]:
        groups: dict[str, list[Item]] = defaultdict(list)
        has_new: set[str] = set()
        for item in self.pool:
            ev = item[1]
            if not predicate(ev):
                continue
            k = key(ev)
            if k is None:
                continue
            groups[k].append(item)
            if item[2]:
                has_new.add(k)
        return {k: v for k, v in groups.items() if k in has_new}


def _detection(
    cfg: RuleConfig,
    *,
    title: str,
    description: str,
    events: list[NormalizedEvent],
    dedup_key: str,
    count: Optional[int] = None,
    threshold: int = 0,
    severity: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> Detection:
    last = events[-1]
    hosts = Counter(e.hostname for e in events if e.hostname)
    users = Counter(e.username for e in events if e.username)
    ips = Counter(e.source_ip for e in events if e.source_ip)
    return Detection(
        rule_key=cfg.key,
        title=title,
        description=description,
        severity=severity or cfg.severity,
        category=cfg.category,
        dedup_key=dedup_key,
        events=events[-MAX_LINKED_EVENTS:],
        count=count if count is not None else len(events),
        first_seen=min(e.timestamp for e in events),
        last_seen=max(e.timestamp for e in events),
        source_ip=ips.most_common(1)[0][0] if ips else None,
        username=users.most_common(1)[0][0] if users else None,
        hostname=hosts.most_common(1)[0][0] if hosts else None,
        mitre=cfg.mitre,
        threshold=threshold,
        data_origin=last.data_origin,
        details=details or {},
    )


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

Rule = Callable[[_Context, RuleConfig, dict[str, ReputationInfo]], list[Detection]]


def _rule_brute_force(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    threshold = int(cfg.params.get("threshold", 5))
    window = int(cfg.params.get("window_seconds", 300))
    out: list[Detection] = []
    groups = ctx.group(lambda e: e.event_type == "login_failed", lambda e: e.entity)
    for entity, items in groups.items():
        best = _best_window(items, window, lambda w: w.n >= threshold, lambda w: w.n)
        if not best:
            continue
        left, right, snap = best
        events = [it[1] for it in items[left : right + 1]]
        out.append(
            _detection(
                cfg,
                title=f"Brute-force attack: {snap['n']} failed logins from {_label(events)} in {_fmt_window(window)}",
                description=(
                    f"{snap['n']} failed login attempts against {snap['distinct_users']} account(s) "
                    f"within {_fmt_window(window)} (threshold {threshold})."
                ),
                events=events,
                dedup_key=f"brute_force:{entity}",
                count=snap["n"],
                threshold=threshold,
                details={"targeted_users": snap["users"], "window_seconds": window},
            )
        )
    return out


def _rule_password_spray(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    distinct = int(cfg.params.get("distinct_users", 5))
    min_attempts = int(cfg.params.get("min_attempts", 5))
    window = int(cfg.params.get("window_seconds", 600))
    out: list[Detection] = []
    groups = ctx.group(lambda e: e.event_type == "login_failed", lambda e: e.entity)
    for entity, items in groups.items():
        best = _best_window(
            items,
            window,
            lambda w: len(w.users) >= distinct and w.n >= min_attempts,
            lambda w: len(w.users) * 10_000 + w.n,
        )
        if not best:
            continue
        left, right, snap = best
        events = [it[1] for it in items[left : right + 1]]
        out.append(
            _detection(
                cfg,
                title=f"Password spraying from {_label(events)}: {snap['distinct_users']} accounts targeted",
                description=(
                    f"{snap['n']} failed logins across {snap['distinct_users']} different accounts "
                    f"within {_fmt_window(window)}."
                ),
                events=events,
                dedup_key=f"password_spray:{entity}",
                count=snap["n"],
                threshold=distinct,
                details={"targeted_users": snap["users"], "window_seconds": window},
            )
        )
    return out


def _rule_distributed(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    threshold = int(cfg.params.get("threshold", 8))
    distinct_ips = int(cfg.params.get("distinct_ips", 3))
    window = int(cfg.params.get("window_seconds", 900))
    out: list[Detection] = []
    groups = ctx.group(lambda e: e.event_type == "login_failed" and bool(e.source_ip), lambda e: e.user_key)
    for user, items in groups.items():
        best = _best_window(
            items,
            window,
            lambda w: w.n >= threshold and len(w.ips) >= distinct_ips,
            lambda w: w.n,
        )
        if not best:
            continue
        left, right, snap = best
        events = [it[1] for it in items[left : right + 1]]
        out.append(
            _detection(
                cfg,
                title=f"Distributed attack on account '{user}': {snap['n']} failures from {snap['distinct_ips']} IPs",
                description=(
                    f"Account '{user}' saw {snap['n']} failed logins from {snap['distinct_ips']} different "
                    f"sources within {_fmt_window(window)}."
                ),
                events=events,
                dedup_key=f"distributed_account_attack:{user}",
                count=snap["n"],
                threshold=threshold,
                details={"source_ips": snap["ips"], "window_seconds": window},
            )
        )
    return out


def _rule_success_after_failures(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    threshold = int(cfg.params.get("failures", 5))
    window = int(cfg.params.get("window_seconds", 600))
    fails: dict[str, list[Item]] = defaultdict(list)
    for item in ctx.pool:
        ev = item[1]
        if ev.event_type == "login_failed" and ev.entity:
            fails[ev.entity].append(item)
    times = {k: [it[0] for it in v] for k, v in fails.items()}

    out: list[Detection] = []
    seen: set[str] = set()
    for ts, ev, is_new in ctx.pool:
        if not is_new or ev.event_type != "login_success" or not ev.entity:
            continue
        entity_fails = fails.get(ev.entity)
        if not entity_fails:
            continue
        lo = bisect_left(times[ev.entity], ts - window)
        hi = bisect_right(times[ev.entity], ts)
        n = hi - lo
        if n < threshold:
            continue
        key = f"success_after_failures:{ev.entity}:{ev.user_key or '-'}"
        if key in seen:
            continue
        seen.add(key)
        related = [it[1] for it in entity_fails[lo:hi]] + [ev]
        who = ev.username or "an account"
        out.append(
            _detection(
                cfg,
                title=f"Possible account compromise: {who} logged in from {_label([ev])} after {n} failures",
                description=(
                    f"A successful login for '{who}' followed {n} failed attempts from the same source "
                    f"within {_fmt_window(window)}."
                ),
                events=related,
                dedup_key=key,
                count=n + 1,
                threshold=threshold,
                details={"failures_before_success": n, "window_seconds": window},
            )
        )
    return out


def _rule_web_scanning(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    threshold = int(cfg.params.get("threshold", 15))
    window = int(cfg.params.get("window_seconds", 120))
    out: list[Detection] = []
    groups = ctx.group(
        lambda e: e.is_http
        and e.event_type != "login_failed"
        and e.status_code is not None
        and 400 <= e.status_code < 500,
        lambda e: e.source_ip,
    )
    for ip, items in groups.items():
        best = _best_window(items, window, lambda w: w.n >= threshold, lambda w: w.n)
        if not best:
            continue
        left, right, snap = best
        events = [it[1] for it in items[left : right + 1]]
        out.append(
            _detection(
                cfg,
                title=f"Web scanning from {ip}: {snap['n']} client-error responses in {_fmt_window(window)}",
                description=f"{snap['n']} HTTP 4xx responses to {ip} within {_fmt_window(window)} (threshold {threshold}).",
                events=events,
                dedup_key=f"web_scanning:{ip}",
                count=snap["n"],
                threshold=threshold,
                details={"window_seconds": window},
            )
        )
    return out


def _rule_suspicious_http(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for ev in ctx.new:
        if not ev.is_http and not ev.user_agent:
            continue
        for cls_key, label, sev in classify_http(ev):
            actor = ev.entity or "unknown"
            slot = grouped.setdefault(
                (actor, cls_key), {"label": label, "severity": sev, "events": [], "actor": actor}
            )
            slot["events"].append(ev)
    out: list[Detection] = []
    for (actor, cls_key), slot in grouped.items():
        events = slot["events"]
        sample = next((e.http_path for e in events if e.http_path), None)
        out.append(
            _detection(
                cfg,
                title=f"Suspicious HTTP request ({slot['label']}) from {_label(events)}",
                description=(
                    f"{len(events)} request(s) matched the {slot['label']} signature."
                    + (f" Example: {sample[:160]}" if sample else "")
                ),
                events=events,
                dedup_key=f"suspicious_http_request:{actor}:{cls_key}",
                severity=max_severity(slot["severity"], cfg.severity),
                details={"signature": cls_key, "sample_path": sample},
            )
        )
    return out


def _rule_high_request_rate(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    threshold = int(cfg.params.get("threshold", 200))
    window = int(cfg.params.get("window_seconds", 60))
    out: list[Detection] = []
    groups = ctx.group(lambda e: e.is_http, lambda e: e.source_ip)
    for ip, items in groups.items():
        best = _best_window(items, window, lambda w: w.n >= threshold, lambda w: w.n)
        if not best:
            continue
        left, right, snap = best
        events = [it[1] for it in items[left : right + 1]]
        out.append(
            _detection(
                cfg,
                title=f"Unusual request rate from {ip}: {snap['n']} requests in {_fmt_window(window)}",
                description=f"{snap['n']} HTTP requests within {_fmt_window(window)} (threshold {threshold}).",
                events=events,
                dedup_key=f"high_request_rate:{ip}",
                count=snap["n"],
                threshold=threshold,
                details={"window_seconds": window},
            )
        )
    return out


def _rule_port_scan(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    distinct = int(cfg.params.get("distinct_ports", 15))
    window = int(cfg.params.get("window_seconds", 120))
    out: list[Detection] = []
    groups = ctx.group(lambda e: e.event_type == "connection_blocked", lambda e: e.source_ip)
    for ip, items in groups.items():
        best = _best_window(items, window, lambda w: len(w.ports) >= distinct, lambda w: len(w.ports))
        if not best:
            continue
        left, right, snap = best
        events = [it[1] for it in items[left : right + 1]]
        out.append(
            _detection(
                cfg,
                title=f"Port scan from {ip}: {snap['distinct_ports']} ports probed in {_fmt_window(window)}",
                description=(
                    f"{ip} sent {snap['n']} blocked connections to {snap['distinct_ports']} different ports "
                    f"within {_fmt_window(window)}."
                ),
                events=events,
                dedup_key=f"port_scan:{ip}",
                count=snap["n"],
                threshold=distinct,
                details={"ports": snap["ports"], "window_seconds": window},
            )
        )
    return out


def _rule_blocked_burst(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    threshold = int(cfg.params.get("threshold", 30))
    window = int(cfg.params.get("window_seconds", 300))
    out: list[Detection] = []
    groups = ctx.group(lambda e: e.event_type == "connection_blocked", lambda e: e.source_ip)
    for ip, items in groups.items():
        best = _best_window(items, window, lambda w: w.n >= threshold, lambda w: w.n)
        if not best:
            continue
        left, right, snap = best
        events = [it[1] for it in items[left : right + 1]]
        out.append(
            _detection(
                cfg,
                title=f"{snap['n']} connections from {ip} blocked by the firewall in {_fmt_window(window)}",
                description=f"{snap['n']} blocked connections within {_fmt_window(window)} (threshold {threshold}).",
                events=events,
                dedup_key=f"blocked_traffic_burst:{ip}",
                count=snap["n"],
                threshold=threshold,
                details={"window_seconds": window},
            )
        )
    return out


def _rule_access_violation(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    threshold = int(cfg.params.get("threshold", 5))
    window = int(cfg.params.get("window_seconds", 600))
    out: list[Detection] = []
    groups = ctx.group(
        lambda e: e.event_type in ("access_denied", "privilege_escalation_failed"),
        lambda e: e.entity if e.source_ip else (e.user_key and f"user:{e.user_key}:{e.hostname or '-'}"),
    )
    for entity, items in groups.items():
        best = _best_window(items, window, lambda w: w.n >= threshold, lambda w: w.n)
        if not best:
            continue
        left, right, snap = best
        events = [it[1] for it in items[left : right + 1]]
        out.append(
            _detection(
                cfg,
                title=f"Repeated access violations by {_label(events)}: {snap['n']} in {_fmt_window(window)}",
                description=f"{snap['n']} access-denied or failed privilege-escalation events (threshold {threshold}).",
                events=events,
                dedup_key=f"access_violation:{entity}",
                count=snap["n"],
                threshold=threshold,
                details={"window_seconds": window},
            )
        )
    return out


def _rule_off_hours(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
    start = int(cfg.params.get("start_hour", 0))
    end = int(cfg.params.get("end_hour", 5))
    offset = timedelta(minutes=int(cfg.params.get("tz_offset_minutes", 0)))
    out: list[Detection] = []
    seen: dict[str, list[NormalizedEvent]] = {}
    for ev in ctx.new:
        if ev.event_type != "login_success":
            continue
        local = ev.timestamp + offset
        hour = local.hour
        in_window = start <= hour < end if start <= end else (hour >= start or hour < end)
        if not in_window:
            continue
        key = f"off_hours_login:{ev.user_key or '-'}:{ev.source_ip or '-'}:{local.date().isoformat()}"
        seen.setdefault(key, []).append(ev)
    for key, events in seen.items():
        last = events[-1]
        local_time = (last.timestamp + offset).strftime("%H:%M")
        out.append(
            _detection(
                cfg,
                title=f"Off-hours login: {last.username or 'unknown'} at {local_time} from {_label([last])}",
                description=f"Successful login at {local_time} local time, outside the normal window {start:02d}:00-{end:02d}:00.",
                events=events,
                dedup_key=key,
                details={"local_hour": (last.timestamp + offset).hour},
            )
        )
    return out


_SINGLE_EVENT_RULES = {
    "account_lockout": "account_lockout",
    "privilege_group_change": "privileged_group_change",
    "audit_log_cleared": "audit_log_cleared",
    "account_created": "new_account_created",
}


def _rule_single_event(rule_key: str) -> Rule:
    def run(ctx: _Context, cfg: RuleConfig, _reps: dict[str, ReputationInfo]) -> list[Detection]:
        wanted = [e for e in ctx.new if _SINGLE_EVENT_RULES.get(e.event_type) == rule_key]
        groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for ev in wanted:
            if rule_key == "privileged_group_change":
                allowed = {str(g).lower() for g in cfg.params.get("groups", [])}
                group = str(ev.extra.get("group_name", "")).lower()
                if allowed and group and group not in allowed:
                    continue
            groups[f"{rule_key}:{ev.hostname or '-'}:{ev.user_key or '-'}:{ev.extra.get('group_name', '-')}"].append(ev)

        out: list[Detection] = []
        for key, events in groups.items():
            ev = events[-1]
            host = ev.hostname or "unknown host"
            actor = ev.extra.get("subject_user")
            by = f" by {actor}" if actor else ""
            if rule_key == "audit_log_cleared":
                title = f"Security audit log cleared on {host}{by}"
                desc = "The audit log was cleared. Attackers often do this to hide their tracks."
            elif rule_key == "account_lockout":
                title = f"Account '{ev.username or 'unknown'}' locked out on {host}"
                desc = "An account lockout usually follows repeated failed logins."
            elif rule_key == "privileged_group_change":
                group = ev.extra.get("group_name", "a privileged group")
                title = f"'{ev.username or 'unknown'}' added to {group} on {host}{by}"
                desc = "Membership of a privileged group changed. Verify this was an approved change."
            else:
                title = f"New account '{ev.username or 'unknown'}' created on {host}{by}"
                desc = "A new account was created. Verify this was an approved change."
            out.append(_detection(cfg, title=title, description=desc, events=events, dedup_key=key))
        return out

    return run


def _rule_malicious_ip(ctx: _Context, cfg: RuleConfig, reps: dict[str, ReputationInfo]) -> list[Detection]:
    min_score = int(cfg.params.get("min_score", 75))
    by_ip: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for ev in ctx.new:
        if ev.source_ip and ev.source_ip in reps:
            by_ip[ev.source_ip].append(ev)
    out: list[Detection] = []
    for ip, events in by_ip.items():
        rep = reps[ip]
        if not (rep.is_malicious or rep.score >= min_score):
            continue
        out.append(
            _detection(
                cfg,
                title=f"Activity from known malicious IP {ip} (reputation {rep.score}/100)",
                description=(
                    f"{ip} is flagged by {rep.source}"
                    + (f" with {rep.total_reports} abuse reports" if rep.total_reports else "")
                    + f". {len(events)} event(s) observed."
                ),
                events=events,
                dedup_key=f"malicious_ip_reputation:{ip}",
                details={"reputation_score": rep.score, "reputation_source": rep.source, "country": rep.country},
            )
        )
    return out


_RULES: dict[str, Rule] = {
    "brute_force": _rule_brute_force,
    "password_spray": _rule_password_spray,
    "distributed_account_attack": _rule_distributed,
    "success_after_failures": _rule_success_after_failures,
    "web_scanning": _rule_web_scanning,
    "suspicious_http_request": _rule_suspicious_http,
    "high_request_rate": _rule_high_request_rate,
    "port_scan": _rule_port_scan,
    "blocked_traffic_burst": _rule_blocked_burst,
    "access_violation": _rule_access_violation,
    "off_hours_login": _rule_off_hours,
    "account_lockout": _rule_single_event("account_lockout"),
    "privileged_group_change": _rule_single_event("privileged_group_change"),
    "audit_log_cleared": _rule_single_event("audit_log_cleared"),
    "new_account_created": _rule_single_event("new_account_created"),
    "malicious_ip_reputation": _rule_malicious_ip,
}

# A more specific detection replaces a generic one for the same actor.
_SUPPRESSED_BY = {"blocked_traffic_burst": "port_scan", "brute_force": "password_spray"}


def _suppress_overlaps(detections: list[Detection]) -> list[Detection]:
    specific = {(d.rule_key, d.dedup_key.split(":", 1)[1]) for d in detections}
    kept = []
    for d in detections:
        winner = _SUPPRESSED_BY.get(d.rule_key)
        if winner and (winner, d.dedup_key.split(":", 1)[1]) in specific:
            continue
        kept.append(d)
    return kept


def evaluate(
    new_events: list[NormalizedEvent],
    history: list[NormalizedEvent],
    rules: dict[str, RuleConfig],
    reputations: Optional[dict[str, ReputationInfo]] = None,
) -> list[Detection]:
    """Run every enabled rule and return the resulting detections."""
    if not new_events:
        return []
    ctx = _Context(sorted(new_events, key=lambda e: e.ts), history)
    reps = reputations or {}
    detections: list[Detection] = []
    for key, fn in _RULES.items():
        cfg = rules.get(key)
        if cfg is None or not cfg.enabled:
            continue
        detections.extend(fn(ctx, cfg, reps))
    detections = _suppress_overlaps(detections)
    detections.sort(key=lambda d: (-severity_rank(d.severity), d.rule_key))
    return detections


def max_window_seconds(rules: dict[str, RuleConfig], floor: int = 900) -> int:
    """Largest lookback needed so history covers every enabled windowed rule."""
    best = floor
    for cfg in rules.values():
        if cfg.enabled:
            best = max(best, int(cfg.params.get("window_seconds", 0) or 0))
    return best
