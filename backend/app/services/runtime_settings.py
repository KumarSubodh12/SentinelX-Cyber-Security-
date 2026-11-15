"""Admin-editable settings (stored in the DB, defaults come from environment variables)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AppSetting, DetectionRule
from app.services.rules_catalog import DEFAULT_RULES
from app.services.types import RuleConfig


@dataclass
class RuntimeSettings:
    alert_webhook_url: str
    notify_min_severity: str
    auto_incident_min_severity: str
    alert_cooldown_seconds: int
    ml_enabled: bool


def _defaults() -> dict[str, str]:
    return {
        "alert_webhook_url": settings.alert_webhook_url,
        "notify_min_severity": settings.notify_min_severity,
        "auto_incident_min_severity": settings.auto_incident_min_severity,
        "alert_cooldown_seconds": str(settings.alert_cooldown_seconds),
        "ml_enabled": "true" if settings.ml_enabled else "false",
    }


def load_runtime_settings(db: Session) -> RuntimeSettings:
    values = _defaults()
    for row in db.scalars(select(AppSetting)):
        if row.key in values and row.value is not None:
            values[row.key] = row.value
    return RuntimeSettings(
        alert_webhook_url=values["alert_webhook_url"],
        notify_min_severity=values["notify_min_severity"],
        auto_incident_min_severity=values["auto_incident_min_severity"],
        alert_cooldown_seconds=int(values["alert_cooldown_seconds"]),
        ml_enabled=values["ml_enabled"].lower() == "true",
    )


def save_setting(db: Session, key: str, value: Optional[str]) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value


def load_rule_configs(db: Session) -> dict[str, RuleConfig]:
    rows = db.scalars(select(DetectionRule)).all()
    return {
        r.key: RuleConfig(
            key=r.key,
            name=r.name,
            enabled=r.enabled,
            severity=r.severity,
            params=dict(r.params or {}),
            category=r.category or "",
            mitre=r.mitre or "",
        )
        for r in rows
    }


def seed_rules(db: Session) -> None:
    """Insert any default rule that is missing (keeps admin edits to existing rules)."""
    existing = {r.key for r in db.scalars(select(DetectionRule))}
    for r in DEFAULT_RULES:
        if r["key"] not in existing:
            db.add(
                DetectionRule(
                    key=r["key"],
                    name=r["name"],
                    description=r["description"],
                    enabled=True,
                    severity=r["severity"],
                    category=r["category"],
                    mitre=r["mitre"],
                    params=dict(r["params"]),
                )
            )
