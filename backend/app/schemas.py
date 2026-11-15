from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.constants import AlertStatus, IncidentStatus, Role, Severity

T = TypeVar("T")


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


# --- Auth / users --------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(ORM):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(min_length=3, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    full_name: Optional[str] = Field(default=None, max_length=128)
    password: str = Field(min_length=10, max_length=256)
    role: Role = Role.viewer


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(default=None, max_length=128)
    role: Optional[Role] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=10, max_length=256)


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=256)


# --- Ingest ----------------------------------------------------------------------


class IncomingEvent(BaseModel):
    timestamp: Optional[Any] = None
    source: Optional[str] = None
    event_type: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[Any] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    status_code: Optional[Any] = None
    user_agent: Optional[str] = None
    message: Optional[str] = None
    extra: Optional[dict[str, Any]] = None
    ref: Optional[str] = None


class AgentInfo(BaseModel):
    hostname: Optional[str] = Field(default=None, max_length=255)
    os: Optional[str] = Field(default=None, max_length=64)
    version: Optional[str] = Field(default=None, max_length=32)


class IngestRequest(BaseModel):
    agent: Optional[AgentInfo] = None
    events: list[IncomingEvent] = Field(max_length=1000)


class IngestResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: int
    alerts_created: int
    alerts_updated: int


class HeartbeatRequest(BaseModel):
    agent: Optional[AgentInfo] = None


# --- Events ----------------------------------------------------------------------


class EventOut(ORM):
    id: int
    timestamp: datetime
    received_at: datetime
    agent_id: Optional[int] = None
    source: str
    event_type: str
    hostname: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    message: Optional[str] = None
    severity: str
    risk_score: int
    anomaly_score: Optional[float] = None
    data_origin: str
    extra: Optional[dict[str, Any]] = None


# --- Alerts ----------------------------------------------------------------------


class AlertOut(ORM):
    id: int
    rule_key: str
    detection_type: str
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    mitre: Optional[str] = None
    severity: str
    risk_score: int
    anomaly_score: Optional[float] = None
    status: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    event_count: int
    data_origin: str
    details: Optional[dict[str, Any]] = None
    incident_id: Optional[int] = None
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_note: Optional[str] = None


class AlertDetail(AlertOut):
    events: list[EventOut] = []


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    note: Optional[str] = Field(default=None, max_length=2000)


# --- Incidents -------------------------------------------------------------------


class NoteOut(ORM):
    id: int
    author: str
    kind: str
    body: str
    created_at: datetime


class IncidentOut(ORM):
    id: int
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    source_ip: Optional[str] = None
    data_origin: str
    assigned_to_id: Optional[int] = None
    assignee_name: Optional[str] = None
    created_by: Optional[str] = None
    resolution: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    alert_count: int = 0


class IncidentDetail(IncidentOut):
    notes: list[NoteOut] = []
    alerts: list[AlertOut] = []


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: Optional[str] = Field(default=None, max_length=5000)
    severity: Severity = Severity.medium
    alert_ids: list[int] = []
    assigned_to_id: Optional[int] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=300)
    description: Optional[str] = Field(default=None, max_length=5000)
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    assigned_to_id: Optional[int] = None
    unassign: bool = False
    resolution: Optional[str] = Field(default=None, max_length=5000)


class NoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


# --- Agents / rules / settings -----------------------------------------------


class AgentOut(ORM):
    id: int
    name: str
    hostname: Optional[str] = None
    os_type: Optional[str] = None
    version: Optional[str] = None
    ip_address: Optional[str] = None
    api_key_prefix: str
    is_active: bool
    created_at: datetime
    last_seen: Optional[datetime] = None
    events_received: int
    online: bool = False


class AgentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128, pattern=r"^[A-Za-z0-9 _.-]+$")


class AgentCreated(AgentOut):
    api_key: str


class AgentUpdate(BaseModel):
    is_active: Optional[bool] = None
    name: Optional[str] = Field(default=None, min_length=2, max_length=128, pattern=r"^[A-Za-z0-9 _.-]+$")


class RuleOut(ORM):
    key: str
    name: str
    description: Optional[str] = None
    enabled: bool
    severity: str
    category: Optional[str] = None
    mitre: Optional[str] = None
    params: dict[str, Any]
    updated_at: datetime


class RuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    severity: Optional[Severity] = None
    params: Optional[dict[str, Any]] = None


class SettingsOut(BaseModel):
    alert_webhook_url: str
    notify_min_severity: str
    auto_incident_min_severity: str
    alert_cooldown_seconds: int
    ml_enabled: bool
    abuseipdb_configured: bool
    threat_feeds: list[str]
    retention_days: int
    simulator_enabled: bool


class SettingsUpdate(BaseModel):
    alert_webhook_url: Optional[str] = Field(default=None, max_length=500)
    notify_min_severity: Optional[Severity] = None
    auto_incident_min_severity: Optional[Severity] = None
    alert_cooldown_seconds: Optional[int] = Field(default=None, ge=60, le=86400)
    ml_enabled: Optional[bool] = None

    @field_validator("alert_webhook_url")
    @classmethod
    def _https_only(cls, v: Optional[str]) -> Optional[str]:
        if v and not v.lower().startswith("https://"):
            raise ValueError("Webhook URL must start with https://")
        return v


class SimulationRequest(BaseModel):
    scenario: str
    intensity: int = Field(default=1, ge=1, le=5)


class BaselineRequest(BaseModel):
    days: int = Field(default=7, ge=1, le=14)


class TrainRequest(BaseModel):
    include_simulated: bool = False


class AuditOut(ORM):
    id: int
    created_at: datetime
    actor: Optional[str] = None
    action: str
    detail: Optional[str] = None
    ip_address: Optional[str] = None
