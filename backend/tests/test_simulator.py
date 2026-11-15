"""End-to-end check: every simulated scenario normalises cleanly and trips the intended rule."""

import ipaddress
import random
from datetime import datetime, timezone

import pytest

from app.services.detection import evaluate
from app.services.normalizer import is_public_ip, normalize_event
from app.services.rules_catalog import default_rule_configs
from app.services.simulator import SCENARIOS, generate, generate_baseline

NOW = datetime(2026, 11, 13, 7, 0, tzinfo=timezone.utc)  # 12:30 IST, outside the off-hours window

EXPECTED = {
    "brute_force": {"brute_force"},
    "password_spray": {"password_spray"},
    "success_after_failures": {"success_after_failures"},
    "web_scan": {"web_scanning"},
    "web_attacks": {"suspicious_http_request"},
    "port_scan": {"port_scan"},
    "audit_log_cleared": {"audit_log_cleared", "privileged_group_change", "new_account_created"},
}


@pytest.mark.parametrize("scenario", sorted(EXPECTED))
@pytest.mark.parametrize("intensity", [1, 3])
def test_scenarios_trigger_expected_rules(scenario, intensity):
    raw = generate(scenario, intensity=intensity, now=NOW, rng=random.Random(3))
    events = [normalize_event(r, origin="simulated", now=NOW) for r in raw]
    fired = {d.rule_key for d in evaluate(events, [], default_rule_configs())}
    assert EXPECTED[scenario] <= fired, (scenario, fired)


def test_mixed_scenario_and_listing():
    raw = generate("mixed", intensity=2, now=NOW, rng=random.Random(1))
    events = [normalize_event(r, origin="simulated", now=NOW) for r in raw]
    fired = {d.rule_key for d in evaluate(events, [], default_rule_configs())}
    assert {"brute_force", "web_scanning", "port_scan", "suspicious_http_request"} <= fired
    assert set(EXPECTED) | {"mixed"} == set(SCENARIOS)


def test_unknown_scenario_rejected():
    with pytest.raises(ValueError):
        generate("nope")


def test_simulated_ips_are_never_public():
    for scenario in EXPECTED:
        for r in generate(scenario, now=NOW):
            ip = r.get("source_ip")
            if ip:
                assert not is_public_ip(ip), ip
                assert ipaddress.ip_address(ip)


def test_baseline_is_quiet_and_large_enough():
    raw = generate_baseline(days=3, now=NOW)
    assert len(raw) > 500
    events = [normalize_event(r, origin="simulated", now=NOW) for r in raw]
    dets = evaluate(events, [], default_rule_configs())
    assert not {d.rule_key for d in dets} & {"brute_force", "password_spray", "success_after_failures", "web_scanning", "port_scan"}
