"""Isolation Forest anomaly detection over behaviour features.

Events are grouped into (entity, 5-minute bucket) rows, where *entity* is the
source IP (or the local user when there is no IP). Each row becomes a feature
vector (login failures, distinct users, HTTP errors, blocked connections, time
of day, ...). An Isolation Forest is trained on the historical baseline and
scores new buckets; scores are in 0..1 (higher = more unusual).

A bucket is only reported when ALL of the following hold, which keeps the
false-positive rate low:
  1. its anomaly score is above the learned threshold,
  2. it has a minimum amount of activity, and
  3. at least one count feature is clearly outside the baseline (z >= 2.5) OR a
     successful login happened in an hour that is rare in the baseline.

ML output is an *indicator to investigate*, never proof of an attack.
"""

from __future__ import annotations

import math
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.services.types import Detection, NormalizedEvent

BUCKET_SECONDS = 300
MODEL_VERSION = 1

COUNT_FEATURES = [
    "total_events",
    "failed_logins",
    "success_logins",
    "distinct_users",
    "distinct_hosts",
    "http_requests",
    "http_errors",
    "blocked_conns",
]
FEATURES = COUNT_FEATURES + ["fail_ratio", "hour_sin", "hour_cos"]

FEATURE_LABELS = {
    "total_events": "events",
    "failed_logins": "failed logins",
    "success_logins": "successful logins",
    "distinct_users": "distinct accounts",
    "distinct_hosts": "distinct hosts",
    "http_requests": "HTTP requests",
    "http_errors": "HTTP errors",
    "blocked_conns": "blocked connections",
}


# --------------------------------------------------------------------------- #
# Feature building
# --------------------------------------------------------------------------- #


def entity_of(ev: NormalizedEvent) -> Optional[str]:
    if ev.source_ip:
        return ev.source_ip
    if ev.username:
        return f"user:{ev.user_key}"
    return None


class FeatureAggregator:
    """Streaming aggregation so large baselines never need to sit in memory as objects."""

    def __init__(self, tz_offset_minutes: int = 0) -> None:
        self.tz_offset = tz_offset_minutes
        self._rows: dict[tuple[str, int], dict[str, Any]] = {}

    def add(self, ev: NormalizedEvent) -> None:
        entity = entity_of(ev)
        if entity is None:
            return
        bucket = int(ev.ts // BUCKET_SECONDS) * BUCKET_SECONDS
        row = self._rows.get((entity, bucket))
        if row is None:
            row = {"users": set(), "hosts": set(), "total": 0, "failed": 0, "success": 0, "http": 0, "http_err": 0, "blocked": 0}
            self._rows[(entity, bucket)] = row
        row["total"] += 1
        if ev.user_key:
            row["users"].add(ev.user_key)
        if ev.hostname:
            row["hosts"].add(ev.hostname)
        if ev.event_type == "login_failed":
            row["failed"] += 1
        elif ev.event_type == "login_success":
            row["success"] += 1
        elif ev.event_type == "connection_blocked":
            row["blocked"] += 1
        if ev.is_http:
            row["http"] += 1
            if ev.status_code is not None and ev.status_code >= 400:
                row["http_err"] += 1

    def add_many(self, events: Iterable[NormalizedEvent]) -> "FeatureAggregator":
        for ev in events:
            self.add(ev)
        return self

    def frame(self) -> pd.DataFrame:
        records = []
        for (entity, bucket), r in self._rows.items():
            local_hour = ((bucket + self.tz_offset * 60) / 3600.0) % 24.0
            angle = 2.0 * math.pi * local_hour / 24.0
            logins = r["failed"] + r["success"]
            records.append(
                {
                    "entity": entity,
                    "bucket": bucket,
                    "total_events": r["total"],
                    "failed_logins": r["failed"],
                    "success_logins": r["success"],
                    "distinct_users": len(r["users"]),
                    "distinct_hosts": len(r["hosts"]),
                    "http_requests": r["http"],
                    "http_errors": r["http_err"],
                    "blocked_conns": r["blocked"],
                    "fail_ratio": (r["failed"] / logins) if logins else 0.0,
                    "hour_sin": math.sin(angle),
                    "hour_cos": math.cos(angle),
                    "local_hour": int(local_hour),
                }
            )
        columns = ["entity", "bucket", *FEATURES, "local_hour"]
        return pd.DataFrame.from_records(records, columns=columns)


def build_features(events: Iterable[NormalizedEvent], tz_offset_minutes: int = 0) -> pd.DataFrame:
    return FeatureAggregator(tz_offset_minutes).add_many(events).frame()


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #


@dataclass
class TrainResult:
    trained: bool
    reason: str
    samples: int = 0
    threshold: float = 0.0
    trained_at: Optional[str] = None


class AnomalyDetector:
    """Thread-safe wrapper around an Isolation Forest with persistence."""

    def __init__(
        self,
        model_dir: str,
        *,
        min_train_samples: int = 200,
        min_score: float = 0.55,
        min_events_per_bucket: int = 5,
        z_gate: float = 2.5,
    ) -> None:
        self.model_dir = model_dir
        self.min_train_samples = min_train_samples
        self.min_score = min_score
        self.min_events = min_events_per_bucket
        self.z_gate = z_gate
        self._lock = threading.RLock()
        self._state: Optional[dict[str, Any]] = None
        self.load()

    # -- persistence ------------------------------------------------------- #
    @property
    def path(self) -> str:
        return os.path.join(self.model_dir, "isolation_forest.joblib")

    def load(self) -> bool:
        """Load a model that this application previously saved itself."""
        with self._lock:
            if not os.path.exists(self.path):
                return False
            try:
                state = joblib.load(self.path)  # trusted: written only by this process
                if state.get("version") != MODEL_VERSION:
                    return False
                self._state = state
                return True
            except Exception:  # corrupted file - fall back to untrained
                self._state = None
                return False

    def _save(self) -> None:
        os.makedirs(self.model_dir, exist_ok=True)
        tmp = self.path + ".tmp"
        joblib.dump(self._state, tmp)
        os.replace(tmp, self.path)

    # -- status ------------------------------------------------------------ #
    @property
    def ready(self) -> bool:
        return self._state is not None

    def status(self) -> dict[str, Any]:
        with self._lock:
            if not self._state:
                return {
                    "trained": False,
                    "algorithm": "IsolationForest",
                    "min_train_samples": self.min_train_samples,
                }
            s = self._state
            return {
                "trained": True,
                "algorithm": "IsolationForest",
                "trained_at": s["trained_at"],
                "samples": s["samples"],
                "threshold": round(s["threshold"], 4),
                "features": FEATURES,
                "min_train_samples": self.min_train_samples,
                "bucket_seconds": BUCKET_SECONDS,
                "baseline": {
                    name: {"mean": round(s["means"][name], 3), "std": round(s["stds"][name], 3)}
                    for name in COUNT_FEATURES
                },
            }

    # -- training ---------------------------------------------------------- #
    def train(self, frame: pd.DataFrame, *, random_state: int = 42) -> TrainResult:
        n = len(frame)
        if n < self.min_train_samples:
            return TrainResult(False, f"Need at least {self.min_train_samples} behaviour samples, have {n}.", n)

        X = frame[FEATURES].to_numpy(dtype=float)
        model = IsolationForest(
            n_estimators=200,
            max_samples=min(256, n),
            contamination="auto",
            random_state=random_state,
            n_jobs=1,
        )
        model.fit(X)
        train_scores = -model.score_samples(X)
        threshold = max(self.min_score, float(np.percentile(train_scores, 99)))

        means = {c: float(frame[c].mean()) for c in COUNT_FEATURES}
        stds = {c: float(frame[c].std(ddof=0)) for c in COUNT_FEATURES}

        # Hour-of-day distribution of buckets that contain successful logins.
        login_rows = frame[frame["success_logins"] > 0]
        hour_hist = np.zeros(24)
        for hour, weight in zip(login_rows["local_hour"], login_rows["success_logins"]):
            hour_hist[int(hour) % 24] += float(weight)

        trained_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._state = {
                "version": MODEL_VERSION,
                "model": model,
                "means": means,
                "stds": stds,
                "threshold": threshold,
                "hour_hist": hour_hist.tolist(),
                "samples": n,
                "trained_at": trained_at,
            }
            self._save()
        return TrainResult(True, "Model trained.", n, threshold, trained_at)

    # -- scoring ----------------------------------------------------------- #
    def score(self, frame: pd.DataFrame) -> np.ndarray:
        with self._lock:
            if not self._state or frame.empty:
                return np.zeros(len(frame))
            model = self._state["model"]
        return np.clip(-model.score_samples(frame[FEATURES].to_numpy(dtype=float)), 0.0, 1.0)

    def _z(self, name: str, value: float) -> float:
        assert self._state is not None
        std = max(self._state["stds"][name], 1.0)  # floor: one extra event is not an outlier
        return (value - self._state["means"][name]) / std

    def _rare_hour(self, local_hour: int) -> bool:
        assert self._state is not None
        hist = np.array(self._state["hour_hist"])
        total = hist.sum()
        if total < 50:  # not enough login history to judge
            return False
        return hist[local_hour % 24] / total < 0.02

    def analyse(self, frame: pd.DataFrame) -> list[dict[str, Any]]:
        """Return the anomalous rows with score and an explanation."""
        if not self.ready or frame.empty:
            return []
        scores = self.score(frame)
        with self._lock:
            assert self._state is not None
            threshold = self._state["threshold"]
        results: list[dict[str, Any]] = []
        for (_, row), score in zip(frame.iterrows(), scores):
            if score < threshold or row["total_events"] < self.min_events:
                continue
            deviations = []
            for name in COUNT_FEATURES:
                z = self._z(name, float(row[name]))
                if z > 0 and row[name] > 0:
                    deviations.append((name, float(row[name]), self._state["means"][name], z))  # type: ignore[index]
            deviations.sort(key=lambda d: d[3], reverse=True)
            count_gate = bool(deviations) and deviations[0][3] >= self.z_gate
            hour_gate = row["success_logins"] > 0 and self._rare_hour(int(row["local_hour"]))
            if not (count_gate or hour_gate):
                continue
            reasons = [
                f"{FEATURE_LABELS[n]}: {v:.0f} (baseline avg {m:.1f})"
                for n, v, m, z in deviations[:3]
                if z >= self.z_gate
            ]
            if hour_gate:
                reasons.append(f"successful login at an unusual hour ({int(row['local_hour']):02d}:00)")
            results.append(
                {
                    "entity": row["entity"],
                    "bucket": int(row["bucket"]),
                    "score": float(score),
                    "reasons": reasons,
                    "features": {name: float(row[name]) for name in COUNT_FEATURES},
                }
            )
        return results


def ml_detections(
    detector: AnomalyDetector,
    new_events: list[NormalizedEvent],
    history: list[NormalizedEvent],
    *,
    tz_offset_minutes: int = 0,
) -> list[Detection]:
    """Score every (entity, bucket) touched by new events and return detections."""
    if not detector.ready or not new_events:
        return []
    touched = {(entity_of(e), int(e.ts // BUCKET_SECONDS) * BUCKET_SECONDS) for e in new_events if entity_of(e)}
    # Aggregate history + new events, then keep only the buckets that contain new activity.
    frame = build_features([*history, *new_events], tz_offset_minutes)
    if frame.empty:
        return []
    mask = [(r.entity, int(r.bucket)) in touched for r in frame.itertuples()]
    frame = frame[mask]
    findings = detector.analyse(frame)

    detections: list[Detection] = []
    for f in findings:
        entity, bucket = f["entity"], f["bucket"]
        events = [e for e in [*history, *new_events] if entity_of(e) == entity and int(e.ts // BUCKET_SECONDS) * BUCKET_SECONDS == bucket]
        if not events:
            continue
        events.sort(key=lambda e: e.ts)
        is_ip = not entity.startswith("user:")
        score = f["score"]
        severity = "high" if score >= 0.75 else "medium"
        label = entity if is_ip else entity.split(":", 1)[1]
        detections.append(
            Detection(
                rule_key="ml_anomaly",
                title=f"Anomalous behaviour from {label} (anomaly score {score:.2f})",
                description="Behaviour deviates from the learned baseline: " + "; ".join(f["reasons"]) + ".",
                severity=severity,
                category="anomaly",
                dedup_key=f"ml_anomaly:{entity}:{bucket}",
                events=events[-100:],
                count=len(events),
                first_seen=events[0].timestamp,
                last_seen=events[-1].timestamp,
                source_ip=entity if is_ip else None,
                username=None if is_ip else label,
                hostname=events[-1].hostname,
                mitre="",
                detection_type="ml",
                anomaly_score=score,
                data_origin=events[-1].data_origin,
                details={"features": f["features"], "reasons": f["reasons"], "bucket_start": bucket},
            )
        )
    return detections
