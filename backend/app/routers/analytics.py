from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.constants import OPEN_ALERT_STATUSES, SEVERITIES
from app.database import get_db
from app.deps import agent_online, any_user
from app.models import Agent, Alert, Incident, SecurityEvent, User
from app.services.pipeline import get_detector
from app.services.runtime_settings import load_runtime_settings
from app.services.sqlutil import (
    apply_origin,
    bucket_expr,
    bucket_seconds_for,
    bucket_starts,
    count_if,
    to_iso,
)

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


def overview_data(db: Session, hours: int, origin: Optional[str]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    def ev(*cond: Any) -> Any:
        return apply_origin(select(func.count()).select_from(SecurityEvent).where(*cond), SecurityEvent.data_origin, origin)

    def al(*cond: Any) -> Any:
        return apply_origin(select(func.count()).select_from(Alert).where(*cond), Alert.data_origin, origin)

    def inc(*cond: Any) -> Any:
        return apply_origin(select(func.count()).select_from(Incident).where(*cond), Incident.data_origin, origin)

    agents = list(db.scalars(select(Agent)))
    suspicious_ips = db.scalar(
        apply_origin(
            select(func.count(func.distinct(Alert.source_ip))).where(Alert.source_ip.is_not(None), Alert.created_at >= since),
            Alert.data_origin,
            origin,
        )
    )
    totals = {
        "events_total": db.scalar(ev()) or 0,
        "events_window": db.scalar(ev(SecurityEvent.timestamp >= since)) or 0,
        "threats_total": db.scalar(al()) or 0,
        "threats_window": db.scalar(al(Alert.created_at >= since)) or 0,
        "active_alerts": db.scalar(al(Alert.status.in_(OPEN_ALERT_STATUSES))) or 0,
        "critical_alerts_active": db.scalar(al(Alert.status.in_(OPEN_ALERT_STATUSES), Alert.severity == "critical")) or 0,
        "open_incidents": db.scalar(inc(Incident.status.in_(["open", "investigating", "contained"]))) or 0,
        "critical_incidents": db.scalar(inc(Incident.status.in_(["open", "investigating", "contained"]), Incident.severity == "critical")) or 0,
        "agents_total": len(agents),
        "agents_online": sum(1 for a in agents if agent_online(a)),
        "failed_logins_window": db.scalar(ev(SecurityEvent.timestamp >= since, SecurityEvent.event_type == "login_failed")) or 0,
        "success_logins_window": db.scalar(ev(SecurityEvent.timestamp >= since, SecurityEvent.event_type == "login_success")) or 0,
        "suspicious_ips_window": suspicious_ips or 0,
    }

    sev_rows = db.execute(
        apply_origin(
            select(Alert.severity, func.count()).where(Alert.created_at >= since).group_by(Alert.severity),
            Alert.data_origin,
            origin,
        )
    ).all()
    sev = {s: 0 for s in SEVERITIES}
    sev.update({s: c for s, c in sev_rows})

    seconds = bucket_seconds_for(hours)
    b_ev = bucket_expr(db, SecurityEvent.timestamp, seconds)
    ev_rows = db.execute(
        apply_origin(
            select(b_ev.label("b"), func.count(), count_if(SecurityEvent.event_type == "login_failed"))
            .where(SecurityEvent.timestamp >= since)
            .group_by(b_ev),
            SecurityEvent.data_origin,
            origin,
        )
    ).all()
    b_al = bucket_expr(db, Alert.created_at, seconds)
    al_rows = db.execute(
        apply_origin(
            select(b_al.label("b"), func.count()).where(Alert.created_at >= since).group_by(b_al),
            Alert.data_origin,
            origin,
        )
    ).all()
    ev_map = {int(b): (c, f) for b, c, f in ev_rows}
    al_map = {int(b): c for b, c in al_rows}
    series = []
    for b in bucket_starts(since, now, seconds):
        events_n, failed_n = ev_map.get(b, (0, 0))
        series.append({"t": to_iso(b), "events": events_n, "failed_logins": int(failed_n), "alerts": al_map.get(b, 0)})

    top_rows = db.execute(
        apply_origin(
            select(SecurityEvent.source_ip, func.count().label("n"), count_if(SecurityEvent.event_type == "login_failed"))
            .where(SecurityEvent.timestamp >= since, SecurityEvent.source_ip.is_not(None))
            .group_by(SecurityEvent.source_ip)
            .order_by(func.count().desc())
            .limit(8),
            SecurityEvent.data_origin,
            origin,
        )
    ).all()
    by_source = db.execute(
        apply_origin(
            select(SecurityEvent.source, func.count()).where(SecurityEvent.timestamp >= since).group_by(SecurityEvent.source),
            SecurityEvent.data_origin,
            origin,
        )
    ).all()
    top_rules = db.execute(
        apply_origin(
            select(Alert.rule_key, func.count()).where(Alert.created_at >= since).group_by(Alert.rule_key).order_by(func.count().desc()).limit(8),
            Alert.data_origin,
            origin,
        )
    ).all()

    return {
        "window_hours": hours,
        "bucket_seconds": seconds,
        "totals": totals,
        "severity_distribution": sev,
        "timeseries": series,
        "top_ips": [{"ip": ip, "events": n, "failed_logins": int(f)} for ip, n, f in top_rows],
        "by_source": {s: c for s, c in by_source},
        "top_rules": [{"rule_key": k, "count": c} for k, c in top_rules],
    }


@router.get("/overview")
def overview(
    hours: int = Query(24, ge=1, le=720),
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    _: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return overview_data(db, hours, origin)


@router.get("/trends")
def trends(
    days: int = Query(30, ge=7, le=180),
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    _: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Daily trend plus weekly roll-up (weeks start on Monday, UTC)."""
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    b_ev = bucket_expr(db, SecurityEvent.timestamp, 86400)
    ev_rows = db.execute(
        apply_origin(
            select(b_ev.label("b"), func.count(), count_if(SecurityEvent.event_type == "login_failed"))
            .where(SecurityEvent.timestamp >= since)
            .group_by(b_ev),
            SecurityEvent.data_origin,
            origin,
        )
    ).all()
    b_al = bucket_expr(db, Alert.created_at, 86400)
    al_rows = db.execute(
        apply_origin(
            select(b_al.label("b"), func.count(), count_if(Alert.severity.in_(["critical", "high"])))
            .where(Alert.created_at >= since)
            .group_by(b_al),
            Alert.data_origin,
            origin,
        )
    ).all()
    ev_map = {int(b): (c, int(f)) for b, c, f in ev_rows}
    al_map = {int(b): (c, int(h)) for b, c, h in al_rows}

    daily = []
    weekly: dict[str, dict[str, Any]] = defaultdict(lambda: {"events": 0, "failed_logins": 0, "alerts": 0, "high_alerts": 0})
    for b in bucket_starts(since, now, 86400):
        events_n, failed_n = ev_map.get(b, (0, 0))
        alerts_n, high_n = al_map.get(b, (0, 0))
        day = datetime.fromtimestamp(b, tz=timezone.utc)
        daily.append({"date": day.date().isoformat(), "events": events_n, "failed_logins": failed_n, "alerts": alerts_n, "high_alerts": high_n})
        monday = (day - timedelta(days=day.weekday())).date().isoformat()
        w = weekly[monday]
        w["events"] += events_n
        w["failed_logins"] += failed_n
        w["alerts"] += alerts_n
        w["high_alerts"] += high_n
    return {"daily": daily, "weekly": [{"week_start": k, **v} for k, v in sorted(weekly.items())]}


@router.get("/ai")
def ai_analytics(
    days: int = Query(14, ge=1, le=90),
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    _: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    rt = load_runtime_settings(db)

    b_al = bucket_expr(db, Alert.created_at, 86400)
    rows = db.execute(
        apply_origin(
            select(b_al.label("b"), Alert.detection_type, func.count()).where(Alert.created_at >= since).group_by(b_al, Alert.detection_type),
            Alert.data_origin,
            origin,
        )
    ).all()
    per_day: dict[int, dict[str, int]] = defaultdict(lambda: {"rule": 0, "ml": 0, "intel": 0})
    for b, dtype, c in rows:
        per_day[int(b)][dtype] = c
    detections_by_day = [
        {"date": datetime.fromtimestamp(b, tz=timezone.utc).date().isoformat(), **per_day.get(b, {"rule": 0, "ml": 0, "intel": 0})}
        for b in bucket_starts(since, now, 86400)
    ]

    scores = [s for (s,) in db.execute(apply_origin(select(Alert.risk_score).where(Alert.created_at >= since), Alert.data_origin, origin))]
    edges = [(0, 19), (20, 39), (40, 59), (60, 79), (80, 100)]
    histogram = [{"range": f"{lo}-{hi}", "count": sum(1 for s in scores if lo <= s <= hi)} for lo, hi in edges]

    ml_alerts = db.scalars(
        apply_origin(
            select(Alert).where(Alert.detection_type == "ml", Alert.created_at >= since),
            Alert.data_origin,
            origin,
        )
        .order_by(Alert.anomaly_score.desc())
        .limit(15)
    ).all()
    ml_total = db.scalar(
        apply_origin(select(func.count()).select_from(Alert).where(Alert.detection_type == "ml", Alert.created_at >= since), Alert.data_origin, origin)
    )
    return {
        "model": get_detector().status(),
        "ml_enabled": rt.ml_enabled,
        "window_days": days,
        "ml_alerts_total": ml_total or 0,
        "average_risk": round(sum(scores) / len(scores), 1) if scores else 0,
        "detections_by_day": detections_by_day,
        "risk_histogram": histogram,
        "top_anomalies": [
            {
                "id": a.id,
                "entity": a.source_ip or a.username,
                "title": a.title,
                "anomaly_score": a.anomaly_score,
                "risk_score": a.risk_score,
                "severity": a.severity,
                "status": a.status,
                "reasons": (a.details or {}).get("reasons", []),
                "last_seen": a.last_seen,
                "data_origin": a.data_origin,
            }
            for a in ml_alerts
        ],
    }
