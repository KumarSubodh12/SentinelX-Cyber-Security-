from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.deps import admin_only, analyst_or_admin, audit, client_ip
from app.models import Alert, Incident, SecurityEvent, User
from app.schemas import BaselineRequest, IncomingEvent, SimulationRequest
from app.services import pipeline, simulator

router = APIRouter(prefix="/api/simulate", tags=["simulation"])


def _require_enabled() -> None:
    if not settings.enable_simulator:
        raise HTTPException(status_code=404, detail="The simulator is disabled on this server")


@router.get("/scenarios")
def scenarios(_: User = Depends(analyst_or_admin)) -> dict[str, Any]:
    _require_enabled()
    return {"scenarios": [{"key": k, "description": v} for k, v in simulator.SCENARIOS.items()]}


@router.post("")
def run_simulation(
    body: SimulationRequest, request: Request, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Generate labelled test events. They use documentation-only IP ranges and never mix with real data."""
    _require_enabled()
    try:
        raw = simulator.generate(body.scenario, intensity=body.intensity)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result = pipeline.ingest(db, [IncomingEvent(**r) for r in raw], origin="simulated")
    audit(db, user.username, "simulation_run", f"{body.scenario} x{body.intensity}", client_ip(request))
    db.commit()
    return {
        "scenario": body.scenario,
        "events_generated": len(raw),
        "accepted": result.accepted,
        "alerts_created": result.alerts_created,
        "alerts_updated": result.alerts_updated,
        "data_origin": "simulated",
    }


@router.post("/baseline")
def generate_baseline(
    body: BaselineRequest, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Create days of normal-looking activity so the anomaly model has something to learn from."""
    _require_enabled()
    raw = simulator.generate_baseline(days=body.days)
    accepted = 0
    for i in range(0, len(raw), 500):
        chunk = [IncomingEvent(**r) for r in raw[i : i + 500]]
        accepted += pipeline.ingest(db, chunk, origin="simulated", run_detection=False).accepted
    audit(db, user.username, "simulation_baseline", f"{body.days} days, {accepted} events", client_ip(request))
    db.commit()
    return {"events_generated": len(raw), "accepted": accepted, "data_origin": "simulated"}


@router.delete("/data")
def clear_simulated_data(request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Remove every simulated event, alert and incident. Real data is never touched."""
    _require_enabled()
    alerts = db.execute(delete(Alert).where(Alert.data_origin == "simulated")).rowcount or 0
    incidents = db.execute(delete(Incident).where(Incident.data_origin == "simulated")).rowcount or 0
    events = db.execute(delete(SecurityEvent).where(SecurityEvent.data_origin == "simulated")).rowcount or 0
    audit(db, admin.username, "simulation_cleared", f"{events} events, {alerts} alerts, {incidents} incidents", client_ip(request))
    db.commit()
    return {"events_deleted": events, "alerts_deleted": alerts, "incidents_deleted": incidents}


@router.get("/stats")
def simulated_counts(_: User = Depends(analyst_or_admin), db: Session = Depends(get_db)) -> dict[str, int]:
    _require_enabled()
    return {
        "events": db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.data_origin == "simulated")) or 0,
        "alerts": db.scalar(select(func.count()).select_from(Alert).where(Alert.data_origin == "simulated")) or 0,
        "incidents": db.scalar(select(func.count()).select_from(Incident).where(Incident.data_origin == "simulated")) or 0,
    }
