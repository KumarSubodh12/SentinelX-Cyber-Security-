from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import admin_only, any_user, audit, client_ip
from app.models import User
from app.schemas import TrainRequest
from app.services import pipeline
from app.services.runtime_settings import load_runtime_settings

router = APIRouter(prefix="/api/ml", tags=["machine-learning"])


@router.get("/status")
def status(_: User = Depends(any_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    rt = load_runtime_settings(db)
    return {"enabled": rt.ml_enabled, **pipeline.get_detector().status()}


@router.post("/train")
def train(
    body: TrainRequest, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Re-learn the behaviour baseline from stored events (runs in the request thread pool)."""
    result = pipeline.train_model(db, include_simulated=body.include_simulated)
    audit(db, admin.username, "ml_train", f"trained={result.trained} samples={result.samples} simulated={body.include_simulated}", client_ip(request))
    db.commit()
    return {
        "trained": result.trained,
        "message": result.reason,
        "samples": result.samples,
        "threshold": result.threshold,
        "status": pipeline.get_detector().status(),
    }
