"""Plain dataclasses shared by the detection pipeline. No framework imports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class NormalizedEvent:
    timestamp: datetime
    source: str
    event_type: str
    message: str = ""
    hostname: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)
    data_origin: str = "real"
    ref: Optional[str] = None
    fingerprint: str = ""
    id: Optional[int] = None
    agent_id: Optional[int] = None

    @property
    def ts(self) -> float:
        return self.timestamp.timestamp()

    @property
    def user_key(self) -> Optional[str]:
        return self.username.lower() if self.username else None

    @property
    def entity(self) -> Optional[str]:
        """Who the activity is attributed to: the source IP, else local user@host."""
        if self.source_ip:
            return self.source_ip
        if self.hostname or self.username:
            return f"local:{self.hostname or '-'}:{self.user_key or '-'}"
        return None

    @property
    def is_http(self) -> bool:
        return self.http_path is not None


@dataclass
class RuleConfig:
    key: str
    name: str
    enabled: bool
    severity: str
    params: dict[str, Any]
    category: str = ""
    mitre: str = ""


@dataclass
class ReputationInfo:
    ip: str
    score: int = 0
    is_malicious: bool = False
    source: str = "unknown"
    country: Optional[str] = None
    isp: Optional[str] = None
    total_reports: int = 0


@dataclass
class Detection:
    rule_key: str
    title: str
    description: str
    severity: str
    category: str
    dedup_key: str
    events: list[NormalizedEvent]
    count: int
    first_seen: datetime
    last_seen: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    mitre: str = ""
    threshold: int = 0
    detection_type: str = "rule"  # "rule" | "ml" | "intel"
    anomaly_score: Optional[float] = None
    data_origin: str = "real"
    details: dict[str, Any] = field(default_factory=dict)
