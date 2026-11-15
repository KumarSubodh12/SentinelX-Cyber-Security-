"""The agent's output must be accepted by the backend and trigger the intended detections.

Skipped automatically when the agent folder is not next to the backend (e.g. in the backend Docker image).
"""

import os
import sys
from datetime import datetime, timezone

import pytest

AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "agent"))
if not os.path.isdir(AGENT_DIR):
    pytest.skip("agent folder not available", allow_module_level=True)
sys.path.insert(0, AGENT_DIR)

from sentinelx_agent.collectors.firewall import parse_firewall_line  # noqa: E402
from sentinelx_agent.collectors.linux_auth import parse_auth_line  # noqa: E402
from sentinelx_agent.collectors.web_access import parse_access_line  # noqa: E402
from sentinelx_agent.collectors.windows_security import parse_events_output  # noqa: E402

from app.services.detection import evaluate  # noqa: E402
from app.services.normalizer import normalize_event  # noqa: E402
from app.services.rules_catalog import default_rule_configs  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)


def to_events(raw):
    return [normalize_event(r, now=NOW) for r in raw]


def fired(events):
    return {d.rule_key for d in evaluate(events, [], default_rule_configs())}


def test_ssh_brute_force_log_lines_become_a_brute_force_alert():
    lines = [
        f"Nov 13 10:15:{i:02d} web01 sshd[10{i}]: Failed password for root from 203.0.113.9 port {40000 + i} ssh2"
        for i in range(8)
    ]
    raw = [parse_auth_line(line, tz=UTC, now=NOW) for line in lines]
    for i, r in enumerate(raw):
        r["ref"] = f"1:{i}"
    events = to_events(raw)
    assert all(e.event_type == "login_failed" and e.source_ip == "203.0.113.9" for e in events)
    assert fired(events) == {"brute_force"}


def test_web_attack_lines_are_detected():
    lines = [
        '203.0.113.5 - - [13/Nov/2026:10:00:0%d +0000] "GET /item?id=1%%27%%20OR%%20%%271%%27=%%271 HTTP/1.1" 200 5 "-" "sqlmap/1.7"' % i
        for i in range(3)
    ]
    events = to_events([parse_access_line(line, ["/login"], "web01") for line in lines])
    assert "suspicious_http_request" in fired(events)


def test_ufw_port_scan_lines_are_detected():
    lines = [
        f"Nov 13 10:15:01 fw kernel: [1.0] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.5 PROTO=TCP SPT=4444 DPT={1000 + i}"
        for i in range(20)
    ]
    events = to_events([parse_firewall_line(line, ["UFW BLOCK"], tz=UTC, now=NOW) for line in lines])
    assert "port_scan" in fired(events)


def test_windows_audit_log_cleared_is_critical():
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1102</EventID>'
        '<TimeCreated SystemTime="2026-11-13T10:15:01.1234567Z"/><EventRecordID>9</EventRecordID><Computer>WIN01</Computer></System>'
        '<UserData><LogFileCleared><SubjectUserName>intruder</SubjectUserName></LogFileCleared></UserData></Event>'
    )
    raw, _ = parse_events_output(xml)
    dets = evaluate(to_events(raw), [], default_rule_configs())
    assert [(d.rule_key, d.severity) for d in dets] == [("audit_log_cleared", "critical")]
