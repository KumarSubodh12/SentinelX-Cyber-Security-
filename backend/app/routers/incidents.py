from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import analyst_or_admin, any_user, audit, client_ip
from app.models import Alert, Incident, IncidentNote, User
from app.schemas import (
    AlertOut,
    IncidentCreate,
    IncidentDetail,
    IncidentOut,
    IncidentUpdate,
    NoteCreate,
    NoteOut,
    Page,
)
from app.services.sqlutil import apply_origin
from app.websocket import manager

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _counts(db: Session, ids: list[int]) -> dict[int, int]:
    if not ids:
        return {}
    rows = db.execute(select(Alert.incident_id, func.count()).where(Alert.incident_id.in_(ids)).group_by(Alert.incident_id)).all()
    return {i: c for i, c in rows}


def _to_out(incident: Incident, counts: dict[int, int]) -> IncidentOut:
    out = IncidentOut.model_validate(incident)
    if incident.assignee:
        out.assignee_name = incident.assignee.full_name or incident.assignee.username
    out.alert_count = counts.get(incident.id, 0)
    return out


def _note(db: Session, incident: Incident, author: str, kind: str, body: str) -> None:
    db.add(IncidentNote(incident_id=incident.id, author=author, kind=kind, body=body))
    incident.updated_at = datetime.now(timezone.utc)


@router.get("", response_model=Page[IncidentOut])
def list_incidents(
    status: Optional[str] = Query(None, description="a status, or 'active' for open/investigating/contained"),
    severity: Optional[str] = None,
    assigned_to_id: Optional[int] = None,
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    q: Optional[str] = Query(None, max_length=200),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    _: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> Page[IncidentOut]:
    stmt = select(Incident)
    stmt = apply_origin(stmt, Incident.data_origin, origin)
    if status == "active":
        stmt = stmt.where(Incident.status.in_(["open", "investigating", "contained"]))
    elif status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if assigned_to_id:
        stmt = stmt.where(Incident.assigned_to_id == assigned_to_id)
    if q:
        needle = q.lower()
        stmt = stmt.where(or_(func.lower(Incident.title).contains(needle, autoescape=True), Incident.source_ip == q))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Incident.created_at.desc()).offset((page - 1) * page_size).limit(page_size)).unique().all()
    counts = _counts(db, [r.id for r in rows])
    return Page[IncidentOut](items=[_to_out(r, counts) for r in rows], total=total, page=page, page_size=page_size)


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, _: User = Depends(any_user), db: Session = Depends(get_db)) -> IncidentDetail:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = db.scalars(select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.created_at.asc())).all()
    base = _to_out(incident, {incident_id: len(alerts)})
    return IncidentDetail(
        **base.model_dump(),
        notes=[NoteOut.model_validate(n) for n in incident.notes],
        alerts=[AlertOut.model_validate(a) for a in alerts],
    )


@router.post("", response_model=IncidentOut, status_code=201)
def create_incident(
    body: IncidentCreate, request: Request, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)
) -> IncidentOut:
    alerts = list(db.scalars(select(Alert).where(Alert.id.in_(body.alert_ids)))) if body.alert_ids else []
    if len(alerts) != len(set(body.alert_ids)):
        raise HTTPException(status_code=404, detail="One or more alerts were not found")
    if body.assigned_to_id and not db.get(User, body.assigned_to_id):
        raise HTTPException(status_code=404, detail="Assignee not found")
    origins = {a.data_origin for a in alerts}
    incident = Incident(
        title=body.title,
        description=body.description,
        severity=body.severity.value,
        status="open",
        source_ip=next((a.source_ip for a in alerts if a.source_ip), None),
        data_origin="simulated" if origins == {"simulated"} else "real",
        assigned_to_id=body.assigned_to_id,
        created_by=user.username,
    )
    db.add(incident)
    db.flush()
    for a in alerts:
        a.incident_id = incident.id
    _note(db, incident, user.username, "system", f"Incident created by {user.username}" + (f" from {len(alerts)} alert(s)" if alerts else ""))
    audit(db, user.username, "incident_created", f"#{incident.id} {incident.title}", client_ip(request))
    db.commit()
    db.refresh(incident)
    out = _to_out(incident, {incident.id: len(alerts)})
    manager.publish({"type": "incident", "data": {"id": incident.id, "title": incident.title, "severity": incident.severity, "status": incident.status, "data_origin": incident.data_origin}})
    return out


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: int,
    body: IncidentUpdate,
    request: Request,
    user: User = Depends(analyst_or_admin),
    db: Session = Depends(get_db),
) -> IncidentOut:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    now = datetime.now(timezone.utc)

    if body.title:
        incident.title = body.title
    if body.description is not None:
        incident.description = body.description
    if body.severity and body.severity.value != incident.severity:
        _note(db, incident, user.username, "system", f"Severity changed {incident.severity} -> {body.severity.value}")
        incident.severity = body.severity.value

    if body.unassign and incident.assigned_to_id:
        _note(db, incident, user.username, "assignment", "Unassigned")
        incident.assigned_to_id = None
    elif body.assigned_to_id and body.assigned_to_id != incident.assigned_to_id:
        assignee = db.get(User, body.assigned_to_id)
        if not assignee or not assignee.is_active:
            raise HTTPException(status_code=404, detail="Assignee not found")
        incident.assigned_to_id = assignee.id
        _note(db, incident, user.username, "assignment", f"Assigned to {assignee.full_name or assignee.username}")

    if body.resolution is not None:
        incident.resolution = body.resolution

    if body.status and body.status.value != incident.status:
        new = body.status.value
        if new in ("resolved", "closed") and not (incident.resolution and incident.resolution.strip()):
            raise HTTPException(status_code=400, detail="Record how the incident was resolved before closing it")
        _note(db, incident, user.username, "status", f"Status changed {incident.status} -> {new}")
        incident.status = new
        if new in ("resolved", "closed"):
            incident.resolved_at = now
            open_alerts = db.scalars(
                select(Alert).where(Alert.incident_id == incident.id, Alert.status.in_(["open", "acknowledged"]))
            ).all()
            for a in open_alerts:
                a.status, a.resolved_by, a.resolved_at = "resolved", user.username, now
                a.resolution_note = f"Resolved with incident #{incident.id}: {incident.resolution}"
        else:
            incident.resolved_at = None

    incident.updated_at = now
    audit(db, user.username, "incident_updated", f"#{incident.id}", client_ip(request))
    db.commit()
    counts = _counts(db, [incident.id])
    return _to_out(incident, counts)


@router.post("/{incident_id}/notes", response_model=NoteOut, status_code=201)
def add_note(
    incident_id: int, body: NoteCreate, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)
) -> IncidentNote:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    note = IncidentNote(incident_id=incident.id, author=user.username, kind="note", body=body.body)
    db.add(note)
    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    return note
