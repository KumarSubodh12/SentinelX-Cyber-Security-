from datetime import datetime, timedelta, timezone

import pytest

from app.services.normalizer import (
    NormalizationError,
    is_public_ip,
    make_fingerprint,
    normalize_event,
    normalize_ip,
    parse_timestamp,
    redact_path,
)


def test_normalize_ip_variants():
    assert normalize_ip("203.0.113.5") == "203.0.113.5"
    assert normalize_ip("::ffff:203.0.113.5") == "203.0.113.5"
    assert normalize_ip("fe80::1%eth0") == "fe80::1"
    assert normalize_ip("[2001:db8::1]") == "2001:db8::1"
    assert normalize_ip("not-an-ip") is None
    assert normalize_ip("-") is None
    assert normalize_ip(None) is None


def test_is_public_ip():
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("10.0.0.5")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("203.0.113.5")  # documentation range
    assert not is_public_ip(None)


def test_timestamp_parsing_and_clamping():
    now = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
    ts, clamped = parse_timestamp("2026-11-13T10:00:00.1234567Z", now)
    assert ts == datetime(2026, 11, 13, 10, 0, 0, 123456, tzinfo=timezone.utc) and not clamped
    ts, clamped = parse_timestamp("2026-11-13T15:30:00+05:30", now)
    assert ts == datetime(2026, 11, 13, 10, 0, tzinfo=timezone.utc)
    ts, clamped = parse_timestamp(now + timedelta(days=3), now)
    assert clamped and ts == now
    ts, _ = parse_timestamp(1763028000, now)
    assert ts.year == 2025 or ts.year == 2026
    with pytest.raises(NormalizationError):
        parse_timestamp("yesterday-ish", now)


def test_naive_timestamp_assumed_utc():
    now = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
    ts, _ = parse_timestamp("2026-11-13T10:00:00", now)
    assert ts.tzinfo is not None and ts.hour == 10


def test_redact_sensitive_query_values_but_keep_payloads():
    out = redact_path("/login?user=a&password=hunter2&token=abc&id=1' OR 1=1--")
    assert "hunter2" not in out and "abc" not in out
    assert "password=[redacted]" in out
    assert "1' OR 1=1--" in out


def test_normalize_event_cleans_input():
    raw = {
        "timestamp": "2026-11-13T10:00:00Z",
        "source": "LINUX_AUTH",
        "event_type": "Login_Failed",
        "source_ip": "::ffff:203.0.113.5",
        "username": "root\nFAKE LOG LINE",
        "message": "bad\x00 line\r\ninjected",
        "dest_port": "99999",
        "status_code": "404",
        "extra": {"password": "x", "group_name": "Administrators", "nested": {"a": 1}},
    }
    e = normalize_event(raw, now=datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc))
    assert e.source == "linux_auth" and e.event_type == "login_failed"
    assert e.source_ip == "203.0.113.5"
    assert "\n" not in e.username and "\n" not in e.message and "\x00" not in e.message
    assert e.dest_port is None
    assert e.status_code == 404
    assert "password" not in e.extra and e.extra["group_name"] == "Administrators"


def test_unknown_type_and_source_fall_back_to_other():
    e = normalize_event({"event_type": "weird", "source": "nope"})
    assert e.event_type == "other" and e.source == "other"


def test_invalid_ip_is_kept_out_of_ip_field():
    e = normalize_event({"source_ip": "banana", "event_type": "login_failed"})
    assert e.source_ip is None and e.extra["source_ip_raw"] == "banana"


def test_fingerprint_stable_and_ref_sensitive():
    a = normalize_event({"timestamp": "2026-11-13T10:00:00Z", "event_type": "login_failed", "message": "x", "ref": "f:1"})
    b = normalize_event({"timestamp": "2026-11-13T10:00:00Z", "event_type": "login_failed", "message": "x", "ref": "f:1"})
    c = normalize_event({"timestamp": "2026-11-13T10:00:00Z", "event_type": "login_failed", "message": "x", "ref": "f:2"})
    assert make_fingerprint(a, 1) == make_fingerprint(b, 1)
    assert make_fingerprint(a, 1) != make_fingerprint(c, 1)
    assert make_fingerprint(a, 1) != make_fingerprint(a, 2)
