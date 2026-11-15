"""Detection rules, runtime settings and the audit log (admin area)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.deps import admin_only, any_user, audit, client_ip
from app.models import AuditLog, DetectionRule, User
from app.schemas import AuditOut, RuleOut, RuleUpdate, SettingsOut, SettingsUpdate
from app.services.rules_catalog import DEFAULT_RULES, validate_params
from app.services.runtime_settings import load_runtime_settings, save_setting

router = APIRouter(prefix="/api", tags=["admin"])


# --- Detection rules ---------------------------------------------------------------


@router.get("/rules", response_model=list[RuleOut])
def list_rules(_: User = Depends(any_user), db: Session = Depends(get_db)) -> list[DetectionRule]:
    return list(db.scalars(select(DetectionRule).order_by(DetectionRule.name)))


@router.patch("/rules/{key}", response_model=RuleOut)
def update_rule(
    key: str, body: RuleUpdate, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)
) -> DetectionRule:
    rule = db.get(DetectionRule, key)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.severity is not None:
        rule.severity = body.severity.value
    if body.params is not None:
        try:
            rule.params = {**(rule.params or {}), **validate_params(key, body.params)}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    rule.updated_at = datetime.now(timezone.utc)
    audit(db, admin.username, "rule_updated", f"{key} enabled={rule.enabled} severity={rule.severity} params={rule.params}", client_ip(request))
    db.commit()
    return rule


@router.post("/rules/{key}/reset", response_model=RuleOut)
def reset_rule(key: str, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)) -> DetectionRule:
    rule = db.get(DetectionRule, key)
    default = next((r for r in DEFAULT_RULES if r["key"] == key), None)
    if not rule or not default:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.enabled, rule.severity, rule.params = True, default["severity"], dict(default["params"])
    audit(db, admin.username, "rule_reset", key, client_ip(request))
    db.commit()
    return rule


# --- Settings -----------------------------------------------------------------------


def _settings_out(db: Session) -> SettingsOut:
    rt = load_runtime_settings(db)
    return SettingsOut(
        alert_webhook_url=rt.alert_webhook_url,
        notify_min_severity=rt.notify_min_severity,
        auto_incident_min_severity=rt.auto_incident_min_severity,
        alert_cooldown_seconds=rt.alert_cooldown_seconds,
        ml_enabled=rt.ml_enabled,
        abuseipdb_configured=bool(settings.abuseipdb_api_key),
        threat_feeds=settings.feed_urls,
        retention_days=settings.retention_days,
        simulator_enabled=settings.enable_simulator,
    )


@router.get("/settings", response_model=SettingsOut)
def get_settings_endpoint(_: User = Depends(any_user), db: Session = Depends(get_db)) -> SettingsOut:
    return _settings_out(db)


@router.put("/settings", response_model=SettingsOut)
def update_settings(
    body: SettingsUpdate, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)
) -> SettingsOut:
    changed = []
    if body.alert_webhook_url is not None:
        save_setting(db, "alert_webhook_url", body.alert_webhook_url)
        changed.append("alert_webhook_url")
    if body.notify_min_severity is not None:
        save_setting(db, "notify_min_severity", body.notify_min_severity.value)
        changed.append("notify_min_severity")
    if body.auto_incident_min_severity is not None:
        save_setting(db, "auto_incident_min_severity", body.auto_incident_min_severity.value)
        changed.append("auto_incident_min_severity")
    if body.alert_cooldown_seconds is not None:
        save_setting(db, "alert_cooldown_seconds", str(body.alert_cooldown_seconds))
        changed.append("alert_cooldown_seconds")
    if body.ml_enabled is not None:
        save_setting(db, "ml_enabled", "true" if body.ml_enabled else "false")
        changed.append("ml_enabled")
    audit(db, admin.username, "settings_updated", ", ".join(changed), client_ip(request))
    db.commit()
    return _settings_out(db)


# --- Audit log -------------------------------------------------------------------------


@router.get("/audit", response_model=list[AuditOut])
def audit_log(
    limit: int = Query(100, ge=1, le=500), _: User = Depends(admin_only), db: Session = Depends(get_db)
) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)))
