"""Threat risk scoring (0-100) and severity classification.

The score is deliberately simple and explainable:

    risk = base(rule severity) + min(20, frequency + reputation + anomaly)

`base` puts a detection inside its own severity band, and the capped bonus can
push it up at most one band. Every contributing factor is returned so the UI can
show *why* an alert got its score.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

BASE_SCORE = {"critical": 85, "high": 65, "medium": 45, "low": 25, "info": 5}
MAX_BONUS = 20


@dataclass
class RiskResult:
    score: int
    severity: str
    factors: dict[str, float] = field(default_factory=dict)


def severity_from_score(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def score_detection(
    base_severity: str,
    *,
    count: int = 1,
    threshold: int = 0,
    reputation_score: Optional[int] = None,
    anomaly_score: Optional[float] = None,
) -> RiskResult:
    base = BASE_SCORE.get(base_severity, 5)

    frequency = 0.0
    if threshold > 0 and count > threshold:
        # Doubling the threshold adds ~5 points, capped at 10.
        frequency = min(10.0, 5.0 * math.log2(count / threshold))

    reputation = 0.0
    if reputation_score:
        reputation = max(0.0, min(100, reputation_score)) / 100.0 * 12.0

    anomaly = 0.0
    if anomaly_score is not None and anomaly_score > 0.5:
        anomaly = min(1.0, (anomaly_score - 0.5) * 2.0) * 10.0

    bonus = min(float(MAX_BONUS), frequency + reputation + anomaly)
    score = int(round(max(0.0, min(100.0, base + bonus))))
    return RiskResult(
        score=score,
        severity=severity_from_score(score),
        factors={
            "base": float(base),
            "frequency": round(frequency, 1),
            "reputation": round(reputation, 1),
            "anomaly": round(anomaly, 1),
            "bonus_applied": round(bonus, 1),
        },
    )


_EVENT_BASE = {
    "login_failed": 15,
    "account_lockout": 45,
    "privilege_escalation_failed": 30,
    "access_denied": 25,
    "connection_blocked": 12,
    "audit_log_cleared": 85,
    "privilege_group_change": 50,
    "account_created": 25,
    "app_error": 10,
    "http_request": 3,
    "login_success": 5,
}


def score_event(event_type: str, status_code: Optional[int] = None, reputation_score: Optional[int] = None) -> int:
    """Per-event risk used for the live feed (alerts carry the real, correlated score)."""
    score = _EVENT_BASE.get(event_type, 2)
    if status_code is not None and 400 <= status_code < 500 and event_type == "http_request":
        score = 8
    if status_code is not None and status_code >= 500:
        score = max(score, 10)
    if reputation_score:
        score += int(max(0, min(100, reputation_score)) / 100 * 25)
    return max(0, min(100, score))
