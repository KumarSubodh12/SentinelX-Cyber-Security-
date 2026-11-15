from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, UTCDateTime

JsonType = JSON().with_variant(JSONB(), "postgresql")
BigId = BigInteger().with_variant(Integer(), "sqlite")  # SQLite only autoincrements INTEGER PKs


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(128))
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    os_type: Mapped[Optional[str]] = mapped_column(String(64))
    version: Mapped[Optional[str]] = mapped_column(String(32))
    ip_address: Mapped[Optional[str]] = mapped_column(String(64))
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    api_key_prefix: Mapped[str] = mapped_column(String(12))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    events_received: Mapped[int] = mapped_column(BigInteger, default=0)


class SecurityEvent(Base):
    """Append-only: no API endpoint updates or deletes individual events."""

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_ts", "timestamp"),
        Index("ix_events_ip_ts", "source_ip", "timestamp"),
        Index("ix_events_user_ts", "username", "timestamp"),
        Index("ix_events_type_ts", "event_type", "timestamp"),
        Index("ix_events_origin_ts", "data_origin", "timestamp"),
    )

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    agent_id: Mapped[Optional[int]] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    source: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(48))
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    username: Mapped[Optional[str]] = mapped_column(String(128))
    source_ip: Mapped[Optional[str]] = mapped_column(String(64))
    dest_ip: Mapped[Optional[str]] = mapped_column(String(64))
    dest_port: Mapped[Optional[int]] = mapped_column(Integer)
    http_method: Mapped[Optional[str]] = mapped_column(String(16))
    http_path: Mapped[Optional[str]] = mapped_column(Text)
    status_code: Mapped[Optional[int]] = mapped_column(Integer)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512))
    message: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float)
    data_origin: Mapped[str] = mapped_column(String(16), default="real")
    extra: Mapped[Optional[dict[str, Any]]] = mapped_column(JsonType)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status_created", "status", "created_at"),
        Index("ix_alerts_dedup", "dedup_key", "status"),
        Index("ix_alerts_ip", "source_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_key: Mapped[str] = mapped_column(String(64), index=True)
    detection_type: Mapped[str] = mapped_column(String(16), default="rule")  # rule | ml | intel
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[Optional[str]] = mapped_column(Text)
    category: Mapped[Optional[str]] = mapped_column(String(48))
    mitre: Mapped[Optional[str]] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16), default="open")
    dedup_key: Mapped[str] = mapped_column(String(255))
    source_ip: Mapped[Optional[str]] = mapped_column(String(64))
    username: Mapped[Optional[str]] = mapped_column(String(128))
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    data_origin: Mapped[str] = mapped_column(String(16), default="real")
    details: Mapped[Optional[dict[str, Any]]] = mapped_column(JsonType)
    incident_id: Mapped[Optional[int]] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(64))
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(64))
    resolved_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    resolution_note: Mapped[Optional[str]] = mapped_column(Text)


class AlertEvent(Base):
    """Links alerts to the events that caused them (used for investigation and timelines)."""

    __tablename__ = "alert_events"
    __table_args__ = (Index("ix_alert_events_event", "event_id"),)

    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[int] = mapped_column(BigId, ForeignKey("security_events.id", ondelete="CASCADE"), primary_key=True)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_group", "group_key", "status"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    group_key: Mapped[Optional[str]] = mapped_column(String(255))
    source_ip: Mapped[Optional[str]] = mapped_column(String(64))
    data_origin: Mapped[str] = mapped_column(String(16), default="real")
    assigned_to_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_by: Mapped[Optional[str]] = mapped_column(String(64))
    resolution: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)

    assignee: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_to_id], lazy="joined")
    notes: Mapped[list["IncidentNote"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentNote.created_at"
    )


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(24), default="note")  # note | status | assignment | alert | system
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="notes")


class IPReputation(Base):
    __tablename__ = "ip_reputation"

    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(32), default="unknown")
    country: Mapped[Optional[str]] = mapped_column(String(8))
    isp: Mapped[Optional[str]] = mapped_column(String(255))
    total_reports: Mapped[int] = mapped_column(Integer, default=0)
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[Optional[str]] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    category: Mapped[Optional[str]] = mapped_column(String(48))
    mitre: Mapped[Optional[str]] = mapped_column(String(16))
    params: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Optional[str]] = mapped_column(Text)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor: Mapped[Optional[str]] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[Optional[str]] = mapped_column(Text)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64))
