from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import any_user
from app.models import Alert, AlertEvent, SecurityEvent, User
from app.schemas import AlertOut, EventOut, Page
from app.services.sqlutil import apply_origin

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=Page[EventOut])
def list_events(
    q: Optional[str] = Query(None, max_length=200),
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    agent_id: Optional[int] = None,
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> Page[EventOut]:
    stmt = select(SecurityEvent)
    stmt = apply_origin(stmt, SecurityEvent.data_origin, origin)
    if source:
        stmt = stmt.where(SecurityEvent.source == source)
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
    if source_ip:
        stmt = stmt.where(SecurityEvent.source_ip == source_ip)
    if username:
        stmt = stmt.where(SecurityEvent.username == username)
    if hostname:
        stmt = stmt.where(SecurityEvent.hostname == hostname)
    if agent_id:
        stmt = stmt.where(SecurityEvent.agent_id == agent_id)
    if since:
        stmt = stmt.where(SecurityEvent.timestamp >= since)
    if until:
        stmt = stmt.where(SecurityEvent.timestamp <= until)
    if q:
        needle = q.lower()
        stmt = stmt.where(
            or_(
                func.lower(SecurityEvent.message).contains(needle, autoescape=True),
                func.lower(SecurityEvent.username).contains(needle, autoescape=True),
                func.lower(SecurityEvent.hostname).contains(needle, autoescape=True),
                func.lower(SecurityEvent.http_path).contains(needle, autoescape=True),
                SecurityEvent.source_ip == q,
            )
        )
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return Page[EventOut](items=[EventOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size)


class TimelineItem(BaseModel):
    kind: str  # "event" | "alert"
    time: datetime
    event: Optional[EventOut] = None
    alert: Optional[AlertOut] = None


@router.get("/timeline", response_model=list[TimelineItem])
def timeline(
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    alert_id: Optional[int] = None,
    incident_id: Optional[int] = None,
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(300, ge=1, le=1000),
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    _: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> list[TimelineItem]:
    """Chronological events and alerts for one IP, user, alert or incident."""
    if not any([source_ip, username, alert_id, incident_id]):
        raise HTTPException(status_code=400, detail="Provide source_ip, username, alert_id or incident_id")

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    alerts: list[Alert] = []
    ev_stmt = select(SecurityEvent)

    if alert_id or incident_id:
        a_stmt = select(Alert)
        a_stmt = a_stmt.where(Alert.id == alert_id) if alert_id else a_stmt.where(Alert.incident_id == incident_id)
        alerts = list(db.scalars(a_stmt))
        ids = [a.id for a in alerts]
        if not ids:
            return []
        ev_stmt = ev_stmt.join(AlertEvent, AlertEvent.event_id == SecurityEvent.id).where(AlertEvent.alert_id.in_(ids)).distinct()
    else:
        a_stmt = select(Alert).where(Alert.last_seen >= since)
        ev_stmt = ev_stmt.where(SecurityEvent.timestamp >= since)
        if source_ip:
            a_stmt = a_stmt.where(Alert.source_ip == source_ip)
            ev_stmt = ev_stmt.where(SecurityEvent.source_ip == source_ip)
        if username:
            a_stmt = a_stmt.where(Alert.username == username)
            ev_stmt = ev_stmt.where(SecurityEvent.username == username)
        a_stmt = apply_origin(a_stmt, Alert.data_origin, origin)
        ev_stmt = apply_origin(ev_stmt, SecurityEvent.data_origin, origin)
        alerts = list(db.scalars(a_stmt.limit(200)))

    events = db.scalars(ev_stmt.order_by(SecurityEvent.timestamp.desc()).limit(limit)).all()
    items: list[TimelineItem] = [
        TimelineItem(kind="event", time=e.timestamp, event=EventOut.model_validate(e)) for e in events
    ]
    items += [TimelineItem(kind="alert", time=a.created_at, alert=AlertOut.model_validate(a)) for a in alerts]
    items.sort(key=lambda i: i.time)
    return items


@router.get("/facets")
def facets(_: User = Depends(any_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Distinct values for the filter drop-downs."""
    sources = [r for (r,) in db.execute(select(SecurityEvent.source).distinct())]
    types = [r for (r,) in db.execute(select(SecurityEvent.event_type).distinct())]
    hosts = [r for (r,) in db.execute(select(SecurityEvent.hostname).where(SecurityEvent.hostname.is_not(None)).distinct().limit(100))]
    return {"sources": sorted(sources), "event_types": sorted(types), "hostnames": sorted(hosts)}
