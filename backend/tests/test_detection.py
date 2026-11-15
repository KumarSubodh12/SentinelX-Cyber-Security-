from app.services.detection import classify_http, evaluate, max_window_seconds
from app.services.types import ReputationInfo
from tests.helpers import ev, rules


def keys(dets):
    return {d.rule_key for d in dets}


def test_brute_force_triggers_at_threshold():
    new = [ev(i * 10) for i in range(5)]
    dets = evaluate(new, [], rules())
    assert keys(dets) == {"brute_force"}
    d = dets[0]
    assert d.count == 5 and d.source_ip == "203.0.113.9" and d.severity == "high"
    assert d.dedup_key == "brute_force:203.0.113.9"


def test_brute_force_not_triggered_below_threshold_or_outside_window():
    assert evaluate([ev(i * 10) for i in range(4)], [], rules()) == []
    spread = [ev(i * 120) for i in range(5)]  # 5 failures but 8 minutes apart: window is 5 min
    assert evaluate(spread, [], rules()) == []


def test_history_counts_towards_window_but_does_not_trigger_alone():
    history = [ev(i * 10) for i in range(4)]
    new = [ev(45)]
    dets = evaluate(new, history, rules())
    assert keys(dets) == {"brute_force"} and dets[0].count == 5
    # History alone (no new events in the batch) never produces a detection.
    other_new = [ev(1000, ip="198.51.100.1")]
    assert evaluate(other_new, history, rules()) == []


def test_different_sources_are_not_mixed():
    # Nine different sources, each hitting a different account once: nothing should fire.
    new = [ev(i, ip=f"203.0.113.{i}", user=f"user{i}") for i in range(1, 10)]
    assert evaluate(new, [], rules()) == []


def test_password_spray_suppresses_brute_force():
    users = ["a", "b", "c", "d", "e", "f"]
    new = [ev(i * 5, user=users[i % 6]) for i in range(12)]
    dets = evaluate(new, [], rules())
    assert "password_spray" in keys(dets)
    assert "brute_force" not in keys(dets)


def test_distributed_account_attack():
    new = [ev(i * 30, ip=f"198.51.100.{i + 1}", user="admin") for i in range(9)]
    dets = evaluate(new, [], rules())
    assert "distributed_account_attack" in keys(dets)
    d = next(x for x in dets if x.rule_key == "distributed_account_attack")
    assert d.details["source_ips"] and d.username == "admin"


def test_success_after_failures_is_critical():
    new = [ev(i * 5) for i in range(6)] + [ev(40, event_type="login_success")]
    dets = evaluate(new, [], rules())
    d = next(x for x in dets if x.rule_key == "success_after_failures")
    assert d.severity == "critical" and d.details["failures_before_success"] == 6


def test_success_without_enough_failures_is_quiet():
    new = [ev(0), ev(5), ev(10, event_type="login_success", user="root")]
    assert "success_after_failures" not in keys(evaluate(new, [], rules()))


def test_local_logins_without_ip_group_by_user_and_host():
    new = [ev(i * 5, ip=None, user="bob", host="ws1") for i in range(5)]
    dets = evaluate(new, [], rules())
    assert keys(dets) == {"brute_force"}
    assert dets[0].source_ip is None and dets[0].username == "bob"


def test_web_scanning_counts_only_client_errors():
    new = [ev(i, event_type="http_request", source="web_access", user=None, http_path=f"/p{i}", status_code=404) for i in range(15)]
    assert "web_scanning" in keys(evaluate(new, [], rules()))
    ok = [ev(i, event_type="http_request", source="web_access", user=None, http_path=f"/p{i}", status_code=200) for i in range(30)]
    assert "web_scanning" not in keys(evaluate(ok, [], rules()))


def test_suspicious_http_signatures():
    cases = {
        "/p?id=1%27%20OR%20%271%27=%271": "sql_injection",
        "/p?q=1 UNION SELECT user,pass FROM t": "sql_injection",
        "/dl?f=../../../etc/passwd": "path_traversal",
        "/dl?f=%2e%2e%2f%2e%2e%2fetc/passwd": "path_traversal",
        "/s?q=%3Cscript%3Ealert(1)%3C/script%3E": "xss",
        "/x?c=;cat%20/etc/passwd": "command_injection",
        "/.env": "sensitive_file_probe",
        "/q?x=${jndi:ldap://evil/a}": "command_injection",
    }
    for path, expected in cases.items():
        e = ev(0, event_type="http_request", source="web_access", user=None, http_path=path, status_code=200)
        found = {k for k, _, _ in classify_http(e)}
        assert expected in found, (path, found)


def test_benign_requests_do_not_match():
    for path in ["/", "/products?id=42&sort=asc", "/static/app.js", "/api/items?page=2&q=red+shoes", "/blog/order-and-chaos"]:
        e = ev(0, event_type="http_request", source="web_access", user=None, http_path=path, status_code=200)
        assert classify_http(e) == [], path


def test_scanner_user_agent_and_severity_floor():
    e = ev(0, event_type="http_request", source="web_access", user=None, http_path="/", status_code=200, user_agent="sqlmap/1.7#stable")
    dets = evaluate([e], [], rules())
    assert keys(dets) == {"suspicious_http_request"}
    sql = ev(0, event_type="http_request", source="web_access", user=None, http_path="/p?id=1 OR 1=1", status_code=200)
    assert evaluate([sql], [], rules())[0].severity == "high"


def test_port_scan_suppresses_blocked_burst():
    new = [ev(i, event_type="connection_blocked", source="firewall", user=None, dest_port=1000 + i) for i in range(35)]
    dets = evaluate(new, [], rules())
    assert "port_scan" in keys(dets) and "blocked_traffic_burst" not in keys(dets)


def test_blocked_burst_on_single_port():
    new = [ev(i, event_type="connection_blocked", source="firewall", user=None, dest_port=22) for i in range(30)]
    assert keys(evaluate(new, [], rules())) == {"blocked_traffic_burst"}


def test_high_request_rate():
    new = [ev(i * 0.1, event_type="http_request", source="web_access", user=None, http_path="/", status_code=200) for i in range(200)]
    assert "high_request_rate" in keys(evaluate(new, [], rules()))


def test_access_violation():
    new = [ev(i * 20, event_type="privilege_escalation_failed", ip=None, user="eve", host="srv1") for i in range(5)]
    assert "access_violation" in keys(evaluate(new, [], rules()))


def test_off_hours_login_uses_timezone_offset():
    # 20:00 UTC == 01:30 IST next day -> inside 00:00-05:00 local window
    from datetime import datetime, timezone

    night = datetime(2026, 11, 13, 20, 0, tzinfo=timezone.utc)
    e = ev(0, event_type="login_success", base=night)
    assert "off_hours_login" in keys(evaluate([e], [], rules()))
    day = datetime(2026, 11, 13, 7, 0, tzinfo=timezone.utc)  # 12:30 IST
    assert "off_hours_login" not in keys(evaluate([ev(0, event_type="login_success", base=day)], [], rules()))


def test_single_event_rules():
    cleared = ev(0, event_type="audit_log_cleared", source="windows_security", ip=None, user="intruder", host="WIN1")
    d = evaluate([cleared], [], rules())
    assert keys(d) == {"audit_log_cleared"} and d[0].severity == "critical"

    admin = ev(0, event_type="privilege_group_change", source="windows_security", ip=None, user="bob", host="WIN1", extra={"group_name": "Administrators", "subject_user": "alice"})
    assert keys(evaluate([admin], [], rules())) == {"privileged_group_change"}
    harmless = ev(0, event_type="privilege_group_change", source="windows_security", ip=None, user="bob", host="WIN1", extra={"group_name": "Printer Users"})
    assert evaluate([harmless], [], rules()) == []


def test_reputation_rule_uses_supplied_reputation():
    new = [ev(0, event_type="http_request", source="web_access", user=None, http_path="/", status_code=200, ip="8.8.4.4")]
    reps = {"8.8.4.4": ReputationInfo(ip="8.8.4.4", score=92, is_malicious=True, source="abuseipdb", total_reports=140)}
    dets = evaluate(new, [], rules(), reps)
    assert keys(dets) == {"malicious_ip_reputation"}
    assert evaluate(new, [], rules(), {"8.8.4.4": ReputationInfo(ip="8.8.4.4", score=10)}) == []


def test_disabled_rule_does_not_fire():
    cfg = rules()
    cfg["brute_force"].enabled = False
    assert evaluate([ev(i) for i in range(10)], [], cfg) == []


def test_custom_threshold_is_respected():
    cfg = rules()
    cfg["brute_force"].params["threshold"] = 3
    assert keys(evaluate([ev(i) for i in range(3)], [], cfg)) == {"brute_force"}


def test_max_window_seconds():
    assert max_window_seconds(rules()) >= 900
