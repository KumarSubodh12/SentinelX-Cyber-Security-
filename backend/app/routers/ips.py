from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.constants import OPEN_ALERT_STATUSES
from app.database import get_db
from app.deps import analyst_or_admin, any_user, audit, client_ip
from app.models import Alert, Incident, SecurityEvent, User
from app.schemas import AlertOut, EventOut
from app.services import threat_intel
from app.services.normalizer import is_public_ip, normalize_ip
from app.services.sqlutil import apply_origin, count_if

router = APIRouter(prefix="/api/ips", tags=["ip-intelligence"])


def _rep_dict(info: Any) -> Optional[dict[str, Any]]:
    if info is None:
        return None
    return {
        "score": info.score,
        "is_malicious": info.is_malicious,
        "source": info.source,
        "country": info.country,
        "isp": info.isp,
        "total_reports": info.total_reports,
    }


@router.get("")
def list_ips(
    hours: int = Query(168, ge=1, le=2160),
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    q: Optional[str] = Query(None, max_length=64),
    suspicious_only: bool = False,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    _: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    stmt = (
        select(
            SecurityEvent.source_ip.label("ip"),
            func.count().label("events"),
            count_if(SecurityEvent.event_type == "login_failed").label("failed_logins"),
            func.max(SecurityEvent.timestamp).label("last_seen"),
            func.max(SecurityEvent.risk_score).label("max_risk"),
        )
        .where(SecurityEvent.source_ip.is_not(None), SecurityEvent.timestamp >= since)
        .group_by(SecurityEvent.source_ip)
    )
    stmt = apply_origin(stmt, SecurityEvent.data_origin, origin)
    if q:
        stmt = stmt.where(SecurityEvent.source_ip.startswith(q, autoescape=True))
    if suspicious_only:
        stmt = stmt.having(func.max(SecurityEvent.risk_score) >= 40)

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.execute(
        stmt.order_by(func.max(SecurityEvent.risk_score).desc(), func.count().desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    ips = [r.ip for r in rows]

    alert_counts: dict[str, tuple[int, int]] = {}
    if ips:
        for ip, total_alerts, active in db.execute(
            select(Alert.source_ip, func.count(), count_if(Alert.status.in_(OPEN_ALERT_STATUSES)))
            .where(Alert.source_ip.in_(ips))
            .group_by(Alert.source_ip)
        ):
            alert_counts[ip] = (total_alerts, int(active))
    reps = threat_intel.get_reputations(db, ips)

    items = []
    for r in rows:
        total_alerts, active_alerts = alert_counts.get(r.ip, (0, 0))
        items.append(
            {
                "ip": r.ip,
                "events": r.events,
                "failed_logins": int(r.failed_logins),
                "last_seen": r.last_seen,
                "max_risk": r.max_risk or 0,
                "alerts": total_alerts,
                "active_alerts": active_alerts,
                "is_public": is_public_ip(r.ip),
                "reputation": _rep_dict(reps.get(r.ip)),
            }
        )
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/{ip}")
def ip_detail(
    ip: str,
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    _: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    clean = normalize_ip(ip)
    if not clean:
        raise HTTPException(status_code=400, detail="Not a valid IP address")

    ev_filter = [SecurityEvent.source_ip == clean]
    base = apply_origin(select(func.count()).select_from(SecurityEvent).where(*ev_filter), SecurityEvent.data_origin, origin)
    total_events = db.scalar(base) or 0

    by_type = dict(
        db.execute(
            apply_origin(
                select(SecurityEvent.event_type, func.count()).where(*ev_filter).group_by(SecurityEvent.event_type),
                SecurityEvent.data_origin,
                origin,
            )
        ).all()
    )
    targeted = [
        {"username": u, "count": c}
        for u, c in db.execute(
            apply_origin(
                select(SecurityEvent.username, func.count())
                .where(*ev_filter, SecurityEvent.username.is_not(None))
                .group_by(SecurityEvent.username)
                .order_by(func.count().desc())
                .limit(10),
                SecurityEvent.data_origin,
                origin,
            )
        )
    ]
    first_last = db.execute(
        apply_origin(
            select(func.min(SecurityEvent.timestamp), func.max(SecurityEvent.timestamp)).where(*ev_filter),
            SecurityEvent.data_origin,
            origin,
        )
    ).one()
    events = db.scalars(
        apply_origin(select(SecurityEvent).where(*ev_filter), SecurityEvent.data_origin, origin)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(50)
    ).all()
    alerts = db.scalars(
        apply_origin(select(Alert).where(Alert.source_ip == clean), Alert.data_origin, origin).order_by(Alert.created_at.desc()).limit(25)
    ).all()
    incident_rows = db.scalars(
        apply_origin(select(Incident).where(Incident.source_ip == clean), Incident.data_origin, origin).order_by(Incident.created_at.desc()).limit(10)
    ).unique().all()
    reps = threat_intel.get_reputations(db, [clean])

    return {
        "ip": clean,
        "is_public": is_public_ip(clean),
        "reputation": _rep_dict(reps.get(clean)),
        "intel_configured": bool(threat_intel.settings.abuseipdb_api_key) or threat_intel.blocklist.size > 0,
        "total_events": total_events,
        "first_seen": first_last[0],
        "last_seen": first_last[1],
        "events_by_type": by_type,
        "targeted_users": targeted,
        "alerts": [AlertOut.model_validate(a) for a in alerts],
        "incidents": [
            {"id": i.id, "title": i.title, "severity": i.severity, "status": i.status, "created_at": i.created_at}
            for i in incident_rows
        ],
        "recent_events": [EventOut.model_validate(e) for e in events],
    }


@router.post("/{ip}/refresh")
def refresh_reputation(
    ip: str, request: Request, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)
) -> dict[str, Any]:
    clean = normalize_ip(ip)
    if not clean or not is_public_ip(clean):
        raise HTTPException(status_code=400, detail="Only public IP addresses can be checked")
    if not threat_intel.settings.abuseipdb_api_key:
        raise HTTPException(status_code=400, detail="Set ABUSEIPDB_API_KEY on the backend to enable reputation lookups")
    info = threat_intel.lookup_abuseipdb(clean)
    if info is None:
        raise HTTPException(status_code=502, detail="Reputation service unavailable or rate limited. Try again later.")
    threat_intel.save_reputation(db, info)
    audit(db, user.username, "ip_reputation_lookup", clean, client_ip(request))
    db.commit()
    return {"ip": clean, "reputation": _rep_dict(info)}
