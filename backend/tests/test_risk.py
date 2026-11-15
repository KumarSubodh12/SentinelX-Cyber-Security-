from app.services.risk import score_detection, score_event, severity_from_score


def test_severity_bands():
    assert severity_from_score(90) == "critical"
    assert severity_from_score(65) == "high"
    assert severity_from_score(45) == "medium"
    assert severity_from_score(25) == "low"
    assert severity_from_score(5) == "info"


def test_base_scores_stay_in_their_band():
    for sev in ("critical", "high", "medium", "low", "info"):
        assert score_detection(sev).severity == sev


def test_bonus_is_capped_and_can_lift_one_band():
    r = score_detection("medium", count=500, threshold=5, reputation_score=100, anomaly_score=1.0)
    assert r.factors["bonus_applied"] == 20.0
    assert r.score == 65 and r.severity == "high"


def test_frequency_grows_with_volume():
    low = score_detection("high", count=6, threshold=5).score
    high = score_detection("high", count=50, threshold=5).score
    assert high > low


def test_reputation_and_anomaly_contribute():
    base = score_detection("low").score
    assert score_detection("low", reputation_score=100).score > base
    assert score_detection("low", anomaly_score=0.9).score > base
    assert score_detection("low", anomaly_score=0.4).score == base


def test_score_event_ranges():
    assert score_event("audit_log_cleared") == 85
    assert score_event("login_failed") > score_event("login_success")
    assert score_event("http_request", 404) > score_event("http_request", 200)
    assert score_event("login_failed", reputation_score=100) <= 100
