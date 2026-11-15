import random
from datetime import datetime, timedelta, timezone

from app.services.ml import AnomalyDetector, build_features, ml_detections
from tests.helpers import ev

BASE = datetime(2026, 11, 2, 4, 0, tzinfo=timezone.utc)  # 09:30 IST


def baseline_events(days=8, seed=1):
    """Office users: a handful of logins and web calls in daytime hours."""
    rng = random.Random(seed)
    out = []
    for d in range(days):
        day = BASE + timedelta(days=d)
        for i in range(8):
            ip = f"10.20.0.{10 + i}"
            for _ in range(rng.randint(1, 3)):
                t = rng.randint(0, 8 * 3600)
                out.append(ev(t, event_type="login_success", ip=ip, user=f"user{i}", base=day))
            if rng.random() < 0.2:
                out.append(ev(rng.randint(0, 8 * 3600), event_type="login_failed", ip=ip, user=f"user{i}", base=day))
            for _ in range(rng.randint(10, 40)):
                out.append(ev(rng.randint(0, 8 * 3600), event_type="http_request", source="web_access", ip=ip, user=None, http_path="/", status_code=200, base=day))
    return out


def trained(tmp_path):
    det = AnomalyDetector(str(tmp_path), min_train_samples=100)
    frame = build_features(baseline_events(), tz_offset_minutes=330)
    result = det.train(frame)
    assert result.trained, result.reason
    return det


def test_features_shape():
    frame = build_features([ev(0), ev(10), ev(20, event_type="login_success", user="x")], tz_offset_minutes=330)
    assert len(frame) == 1
    row = frame.iloc[0]
    assert row["failed_logins"] == 2 and row["success_logins"] == 1 and row["distinct_users"] == 2


def test_refuses_to_train_without_enough_data(tmp_path):
    det = AnomalyDetector(str(tmp_path), min_train_samples=200)
    result = det.train(build_features([ev(i) for i in range(5)]))
    assert not result.trained and not det.ready
    assert det.status()["trained"] is False


def test_flags_attack_burst_but_not_normal_traffic(tmp_path):
    det = trained(tmp_path)
    day = BASE + timedelta(days=20)

    attack = [ev(i * 2, event_type="login_failed", ip="203.0.113.50", user=u, base=day) for i, u in enumerate(["root", "admin", "test", "oracle"] * 15)]
    found = ml_detections(det, attack, [], tz_offset_minutes=330)
    assert found, "attack burst should be flagged"
    d = found[0]
    assert d.detection_type == "ml" and d.anomaly_score is not None and d.anomaly_score >= det.status()["threshold"]
    assert d.source_ip == "203.0.113.50"
    assert "failed logins" in d.description

    normal = [ev(100, event_type="login_success", ip="10.20.0.11", user="user1", base=day), ev(160, event_type="http_request", source="web_access", ip="10.20.0.11", user=None, http_path="/", status_code=200, base=day)]
    assert ml_detections(det, normal, [], tz_offset_minutes=330) == []


def test_few_events_never_flagged(tmp_path):
    det = trained(tmp_path)
    one = [ev(0, event_type="login_failed", ip="203.0.113.60", base=BASE + timedelta(days=20))]
    assert ml_detections(det, one, [], tz_offset_minutes=330) == []


def test_unusual_login_hour_is_flagged(tmp_path):
    det = trained(tmp_path)
    # 22:00 UTC == 03:30 IST: never seen in the baseline. Several events so the activity gate passes.
    night = datetime(2026, 11, 25, 22, 0, tzinfo=timezone.utc)
    events = [ev(i * 20, event_type="login_success", ip="203.0.113.70", user="user3", base=night) for i in range(3)]
    events += [ev(100 + i, event_type="http_request", source="web_access", ip="203.0.113.70", user=None, http_path="/", status_code=200, base=night) for i in range(4)]
    found = ml_detections(det, events, [], tz_offset_minutes=330)
    assert found and any("unusual hour" in r for r in found[0].details["reasons"])


def test_model_persists_to_disk(tmp_path):
    det = trained(tmp_path)
    again = AnomalyDetector(str(tmp_path), min_train_samples=100)
    assert again.ready and again.status()["samples"] == det.status()["samples"]
