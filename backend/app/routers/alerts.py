from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.constants import OPEN_ALERT_STATUSES
from app.database import get_db
from app.deps import analyst_or_admin, any_user, audit, client_ip
from app.models import Alert, AlertEvent, SecurityEvent, User
from app.schemas import AlertDetail, AlertOut, AlertStatusUpdate, EventOut, Page
from app.services.sqlutil import apply_origin
from app.websocket import manager

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

SORTS = {
    "newest": (Alert.created_at.desc(), Alert.id.desc()),
    "risk": (Alert.risk_score.desc(), Alert.created_at.desc()),
    "last_seen": (Alert.last_seen.desc(),),
}


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    status: Optional[str] = Query(None, description="open, acknowledged, resolved, false_positive or 'active' (open+acknowledged)"),
    severity: Optional[str] = None,
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    rule_key: Optional[str] = None,
    source_ip: Optional[str] = None,
    incident_id: Optional[int] = None,
    detection_type: Optional[str] = Query(None, pattern="^(rule|ml|intel)$"),
    q: Optional[str] = Query(None, max_length=200),
    sort: str = Query("newest", pattern="^(newest|risk|last_seen)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    _: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> Page[AlertOut]:
    stmt = select(Alert)
    stmt = apply_origin(stmt, Alert.data_origin, origin)
    if status == "active":
        stmt = stmt.where(Alert.status.in_(OPEN_ALERT_STATUSES))
    elif status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity.in_([s.strip() for s in severity.split(",")]))
    if rule_key:
        stmt = stmt.where(Alert.rule_key == rule_key)
    if source_ip:
        stmt = stmt.where(Alert.source_ip == source_ip)
    if incident_id:
        stmt = stmt.where(Alert.incident_id == incident_id)
    if detection_type:
        stmt = stmt.where(Alert.detection_type == detection_type)
    if q:
        needle = q.lower()
        stmt = stmt.where(
            or_(
                func.lower(Alert.title).contains(needle, autoescape=True),
                func.lower(Alert.username).contains(needle, autoescape=True),
                func.lower(Alert.hostname).contains(needle, autoescape=True),
                Alert.source_ip == q,
            )
        )
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(*SORTS[sort]).offset((page - 1) * page_size).limit(page_size)).all()
    return Page[AlertOut](items=[AlertOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size)


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, _: User = Depends(any_user), db: Session = Depends(get_db)) -> AlertDetail:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    events = db.scalars(
        select(SecurityEvent)
        .join(AlertEvent, AlertEvent.event_id == SecurityEvent.id)
        .where(AlertEvent.alert_id == alert_id)
        .order_by(SecurityEvent.timestamp.asc())
        .limit(500)
    ).all()
    detail = AlertDetail.model_validate(alert)
    detail.events = [EventOut.model_validate(e) for e in events]
    return detail


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert_status(
    alert_id: int,
    body: AlertStatusUpdate,
    request: Request,
    user: User = Depends(analyst_or_admin),
    db: Session = Depends(get_db),
) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    now = datetime.now(timezone.utc)
    new = body.status.value
    if new in ("resolved", "false_positive") and not (body.note and body.note.strip()):
        raise HTTPException(status_code=400, detail="Add a short note explaining how this alert was handled")

    previous = alert.status
    alert.status = new
    if new == "acknowledged":
        alert.acknowledged_by, alert.acknowledged_at = user.username, now
    elif new in ("resolved", "false_positive"):
        alert.resolved_by, alert.resolved_at, alert.resolution_note = user.username, now, body.note
    elif new == "open":
        alert.resolved_by = alert.resolved_at = alert.resolution_note = None
    audit(db, user.username, "alert_status", f"alert #{alert.id}: {previous} -> {new}", client_ip(request))
    db.commit()
    out = AlertOut.model_validate(alert)
    manager.publish({"type": "alert_update", "data": out.model_dump(mode="json")})
    return out
