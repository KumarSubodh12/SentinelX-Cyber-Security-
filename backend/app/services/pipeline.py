"""Event ingestion pipeline: normalise -> store -> detect -> score -> alert -> correlate -> broadcast."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session

from app.config import settings
from app.constants import OPEN_ALERT_STATUSES, ACTIVE_INCIDENT_STATUSES, at_least, max_severity, severity_rank
from app.database import SessionLocal
from app.models import Alert, AlertEvent, Incident, IncidentNote, SecurityEvent, utcnow
from app.schemas import AlertOut, EventOut, IncomingEvent
from app.services import detection, risk, threat_intel
from app.services import ml as ml_service
from app.services.normalizer import NormalizationError, make_fingerprint, normalize_event
from app.services.notifier import notify_async
from app.services.runtime_settings import RuntimeSettings, load_rule_configs, load_runtime_settings
from app.services.types import Detection, NormalizedEvent, ReputationInfo
from app.websocket import manager

log = logging.getLogger("sentinelx.pipeline")

# --------------------------------------------------------------------------- #
# ML singleton
# --------------------------------------------------------------------------- #

_detector: Optional[ml_service.AnomalyDetector] = None


def get_detector() -> ml_service.AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = ml_service.AnomalyDetector(
            settings.model_dir,
            min_train_samples=settings.ml_min_train_samples,
            min_score=settings.ml_min_score,
        )
    return _detector


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def row_to_event(r: SecurityEvent) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=r.timestamp,
        source=r.source,
        event_type=r.event_type,
        message=r.message or "",
        hostname=r.hostname,
        username=r.username,
        source_ip=r.source_ip,
        dest_ip=r.dest_ip,
        dest_port=r.dest_port,
        http_method=r.http_method,
        http_path=r.http_path,
        status_code=r.status_code,
        user_agent=r.user_agent,
        extra=dict(r.extra or {}),
        data_origin=r.data_origin,
        fingerprint=r.fingerprint,
        id=r.id,
        agent_id=r.agent_id,
    )


def load_history(
    db: Session, origin: str, ips: set[str], users: set[str], since
) -> list[NormalizedEvent]:
    conds = []
    if ips:
        conds.append(SecurityEvent.source_ip.in_(sorted(ips)))
    if users:
        conds.append(SecurityEvent.username.in_(sorted(users)))
    if not conds:
        return []
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.data_origin == origin, SecurityEvent.timestamp >= since, or_(*conds))
        .order_by(SecurityEvent.timestamp.desc())
        .limit(settings.history_row_limit)
    )
    return [row_to_event(r) for r in db.scalars(stmt)]


def _link_events(db: Session, alert: Alert, events: list[NormalizedEvent]) -> None:
    ids = {e.id for e in events if e.id}
    if ids:
        already = set(
            db.scalars(select(AlertEvent.event_id).where(AlertEvent.alert_id == alert.id, AlertEvent.event_id.in_(sorted(ids))))
        )
        for event_id in ids - already:
            db.add(AlertEvent(alert_id=alert.id, event_id=event_id))
        db.flush()
    alert.event_count = db.scalar(select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == alert.id)) or 0


@dataclass
class ProcessOutcome:
    created: list[Alert] = field(default_factory=list)
    updated: list[Alert] = field(default_factory=list)
    escalated: list[Alert] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    linked_event_ids: dict[int, Alert] = field(default_factory=dict)


def _incident_title(alert: Alert) -> str:
    label = (alert.category or "security").replace("_", " ").title()
    entity = alert.source_ip or alert.username or alert.hostname or f"alert #{alert.id}"
    return f"{label}: {entity}"[:300]


def _correlate_incident(db: Session, alert: Alert, rt: RuntimeSettings, outcome: ProcessOutcome) -> None:
    if not at_least(alert.severity, rt.auto_incident_min_severity):
        return
    if alert.incident_id:
        incident = db.get(Incident, alert.incident_id)
        if incident and severity_rank(alert.severity) > severity_rank(incident.severity):
            incident.severity = alert.severity
            incident.updated_at = utcnow()
        return

    if alert.source_ip:
        group_key = alert.source_ip
    elif alert.username:
        group_key = f"user:{alert.username.lower()}:{alert.hostname or '-'}"
    else:
        group_key = f"alert:{alert.id}"

    incident = db.scalar(
        select(Incident)
        .where(
            Incident.group_key == group_key,
            Incident.data_origin == alert.data_origin,
            Incident.status.in_(ACTIVE_INCIDENT_STATUSES),
        )
        .order_by(Incident.id.desc())
        .limit(1)
    )
    if incident is None:
        incident = Incident(
            title=_incident_title(alert),
            description=alert.description,
            severity=alert.severity,
            status="open",
            group_key=group_key,
            source_ip=alert.source_ip,
            data_origin=alert.data_origin,
            created_by="system",
        )
        db.add(incident)
        db.flush()
        db.add(
            IncidentNote(
                incident_id=incident.id,
                author="system",
                kind="system",
                body=f"Incident opened automatically from alert #{alert.id}: {alert.title}",
            )
        )
        outcome.incidents.append(incident)
    else:
        incident.severity = max_severity(incident.severity, alert.severity)
        incident.updated_at = utcnow()
        db.add(
            IncidentNote(
                incident_id=incident.id,
                author="system",
                kind="alert",
                body=f"Alert #{alert.id} linked: {alert.title}",
            )
        )
    alert.incident_id = incident.id


def process_detections(
    db: Session,
    detections: list[Detection],
    origin: str,
    reputations: dict[str, ReputationInfo],
    rt: RuntimeSettings,
) -> ProcessOutcome:
    """Turn detections into alerts (create or merge), link events and correlate incidents."""
    outcome = ProcessOutcome()
    cooldown = timedelta(seconds=rt.alert_cooldown_seconds)

    for det in detections:
        rep = reputations.get(det.source_ip) if det.source_ip else None
        scored = risk.score_detection(
            det.severity,
            count=det.count,
            threshold=det.threshold,
            reputation_score=rep.score if rep else None,
            anomaly_score=det.anomaly_score,
        )
        details = {**det.details, "risk_factors": scored.factors, "window_event_count": det.count}
        if rep:
            details["reputation"] = {"score": rep.score, "source": rep.source, "country": rep.country}

        existing = db.scalar(
            select(Alert)
            .where(
                Alert.dedup_key == det.dedup_key,
                Alert.data_origin == origin,
                Alert.status.in_(OPEN_ALERT_STATUSES),
                Alert.last_seen >= det.last_seen - cooldown,
            )
            .order_by(Alert.id.desc())
            .limit(1)
        )

        if existing is None:
            alert = Alert(
                rule_key=det.rule_key,
                detection_type=det.detection_type,
                title=det.title[:300],
                description=det.description,
                category=det.category,
                mitre=det.mitre or None,
                severity=scored.severity,
                risk_score=scored.score,
                anomaly_score=det.anomaly_score,
                status="open",
                dedup_key=det.dedup_key,
                source_ip=det.source_ip,
                username=det.username,
                hostname=det.hostname,
                event_count=0,
                data_origin=origin,
                details=details,
                first_seen=det.first_seen,
                last_seen=det.last_seen,
            )
            db.add(alert)
            db.flush()
            _link_events(db, alert, det.events)
            outcome.created.append(alert)
        else:
            alert = existing
            previous = alert.severity
            alert.title = det.title[:300]
            alert.description = det.description
            alert.first_seen = min(alert.first_seen, det.first_seen)
            alert.last_seen = max(alert.last_seen, det.last_seen)
            alert.risk_score = max(alert.risk_score, scored.score)
            alert.severity = max_severity(alert.severity, scored.severity)
            if det.anomaly_score is not None:
                alert.anomaly_score = max(alert.anomaly_score or 0.0, det.anomaly_score)
            alert.details = {**(alert.details or {}), **details}
            _link_events(db, alert, det.events)
            if severity_rank(alert.severity) > severity_rank(previous):
                outcome.escalated.append(alert)
            outcome.updated.append(alert)

        _correlate_incident(db, alert, rt, outcome)
        for e in det.events:
            if e.id:
                outcome.linked_event_ids[e.id] = alert
    return outcome


def _publish_outcome(outcome: ProcessOutcome, rt: RuntimeSettings) -> None:
    for incident in outcome.incidents:
        manager.publish(
            {
                "type": "incident",
                "data": {
                    "id": incident.id,
                    "title": incident.title,
                    "severity": incident.severity,
                    "status": incident.status,
                    "data_origin": incident.data_origin,
                },
            }
        )
    for alert in outcome.created:
        payload = AlertOut.model_validate(alert).model_dump(mode="json")
        manager.publish({"type": "alert", "data": payload})
        if alert.data_origin == "real" and at_least(alert.severity, rt.notify_min_severity):
            notify_async(rt.alert_webhook_url, payload)
    created_ids = {a.id for a in outcome.created}
    for alert in outcome.updated:
        if alert.id in created_ids:
            continue
        payload = AlertOut.model_validate(alert).model_dump(mode="json")
        manager.publish({"type": "alert_update", "data": payload})
        if alert in outcome.escalated and alert.data_origin == "real" and at_least(alert.severity, rt.notify_min_severity):
            notify_async(rt.alert_webhook_url, payload)


# --------------------------------------------------------------------------- #
# Ingest
# --------------------------------------------------------------------------- #


@dataclass
class IngestResult:
    accepted: int = 0
    duplicates: int = 0
    rejected: int = 0
    alerts_created: int = 0
    alerts_updated: int = 0
    ips_to_enrich: list[str] = field(default_factory=list)


def ingest(
    db: Session,
    events: list[IncomingEvent],
    *,
    agent_id: Optional[int] = None,
    origin: str = "real",
    run_detection: bool = True,
) -> IngestResult:
    result = IngestResult()

    # 1. Normalise + de-duplicate within the batch.
    seen: set[str] = set()
    batch: list[NormalizedEvent] = []
    for raw in events:
        try:
            ev = normalize_event(raw.model_dump(), origin=origin)
        except NormalizationError:
            result.rejected += 1
            continue
        ev.agent_id = agent_id
        ev.fingerprint = make_fingerprint(ev, agent_id)
        if ev.fingerprint in seen:
            result.duplicates += 1
            continue
        seen.add(ev.fingerprint)
        batch.append(ev)
    if not batch:
        return result

    # 2. Drop events already stored (agent retries / restarts).
    existing = set(db.scalars(select(SecurityEvent.fingerprint).where(SecurityEvent.fingerprint.in_(sorted(seen)))))
    fresh = [e for e in batch if e.fingerprint not in existing]
    result.duplicates += len(batch) - len(fresh)
    if not fresh:
        return result
    fresh.sort(key=lambda e: e.ts)

    rules = load_rule_configs(db)
    rt = load_runtime_settings(db)
    ips = {e.source_ip for e in fresh if e.source_ip}
    users = {e.username for e in fresh if e.username}
    reputations = threat_intel.get_reputations(db, ips) if origin == "real" else {}

    # 3. History must be read BEFORE the new rows are inserted.
    history: list[NormalizedEvent] = []
    if run_detection:
        lookback = detection.max_window_seconds(rules) + ml_service.BUCKET_SECONDS
        history = load_history(db, origin, ips, users, fresh[0].timestamp - timedelta(seconds=lookback))

    # 4. Persist.
    rows: list[SecurityEvent] = []
    for e in fresh:
        rep = reputations.get(e.source_ip) if e.source_ip else None
        score = risk.score_event(e.event_type, e.status_code, rep.score if rep else None)
        rows.append(
            SecurityEvent(
                agent_id=e.agent_id,
                fingerprint=e.fingerprint,
                timestamp=e.timestamp,
                source=e.source,
                event_type=e.event_type,
                hostname=e.hostname,
                username=e.username,
                source_ip=e.source_ip,
                dest_ip=e.dest_ip,
                dest_port=e.dest_port,
                http_method=e.http_method,
                http_path=e.http_path,
                status_code=e.status_code,
                user_agent=e.user_agent,
                message=e.message,
                severity=risk.severity_from_score(score),
                risk_score=score,
                data_origin=origin,
                extra=e.extra or None,
            )
        )
    db.add_all(rows)
    db.flush()
    for e, row in zip(fresh, rows):
        e.id = row.id
    result.accepted = len(rows)
    by_id = {r.id: r for r in rows}

    # 5. Detect.
    outcome = ProcessOutcome()
    if run_detection:
        detections = detection.evaluate(fresh, history, rules, reputations)
        detector = get_detector()
        if rt.ml_enabled and detector.ready:
            try:
                detections += ml_service.ml_detections(
                    detector, fresh, history, tz_offset_minutes=settings.business_tz_offset_minutes
                )
            except Exception:  # ML must never block ingestion
                log.exception("ML scoring failed")
        outcome = process_detections(db, detections, origin, reputations, rt)

        for event_id, alert in outcome.linked_event_ids.items():
            target = by_id.get(event_id)
            if target is None:
                continue  # an older event from history; it keeps its original score
            target.severity = max_severity(target.severity, alert.severity)
            target.risk_score = max(target.risk_score, alert.risk_score)
            if alert.anomaly_score is not None:
                target.anomaly_score = alert.anomaly_score

    db.commit()

    # 6. Live updates (after commit, so the dashboard never shows rolled-back data).
    manager.publish(
        {
            "type": "events",
            "data": [EventOut.model_validate(r).model_dump(mode="json") for r in rows[-50:]],
            "count": len(rows),
        }
    )
    _publish_outcome(outcome, rt)

    result.alerts_created = len(outcome.created)
    result.alerts_updated = len(outcome.updated)
    if origin == "real":
        result.ips_to_enrich = threat_intel.ips_needing_lookup(db, ips)
    return result


def ingest_internal(
    db: Session,
    *,
    event_type: str,
    username: Optional[str],
    source_ip: Optional[str],
    message: str,
    http_path: Optional[str] = None,
    status_code: Optional[int] = None,
) -> None:
    """Feed SentinelX's own authentication events into the pipeline (never raises)."""
    try:
        ingest(
            db,
            [
                IncomingEvent(
                    source="application",
                    event_type=event_type,
                    hostname="sentinelx-api",
                    username=username,
                    source_ip=source_ip,
                    http_method="POST" if http_path else None,
                    http_path=http_path,
                    status_code=status_code,
                    message=message,
                    ref=uuid.uuid4().hex,
                )
            ],
        )
    except Exception:
        db.rollback()
        log.exception("could not record internal auth event")


# --------------------------------------------------------------------------- #
# Background jobs
# --------------------------------------------------------------------------- #


def enrich_ips(ips: list[str]) -> None:
    """Look up reputation for new public IPs, then raise alerts for malicious ones."""
    if not ips:
        return
    try:
        with SessionLocal() as db:
            infos: dict[str, ReputationInfo] = {}
            for ip in ips:
                info = threat_intel.lookup_abuseipdb(ip)
                if info is None:
                    continue
                threat_intel.save_reputation(db, info)
                infos[ip] = info
            db.commit()

            malicious = {ip: i for ip, i in infos.items() if i.is_malicious}
            if not malicious:
                return
            rules = load_rule_configs(db)
            cfg = rules.get("malicious_ip_reputation")
            if cfg is None or not cfg.enabled:
                return
            rt = load_runtime_settings(db)
            since = utcnow() - timedelta(hours=24)
            recent = [
                row_to_event(r)
                for r in db.scalars(
                    select(SecurityEvent)
                    .where(SecurityEvent.source_ip.in_(list(malicious)), SecurityEvent.timestamp >= since, SecurityEvent.data_origin == "real")
                    .order_by(SecurityEvent.timestamp.desc())
                    .limit(200)
                )
            ]
            detections = detection.evaluate(recent, [], {"malicious_ip_reputation": cfg}, malicious)
            outcome = process_detections(db, detections, "real", malicious, rt)
            db.commit()
            _publish_outcome(outcome, rt)
    except Exception:
        log.exception("IP enrichment failed")


def train_model(db: Session, include_simulated: bool = False) -> ml_service.TrainResult:
    """Train on historical behaviour. Events that caused alerts are excluded from the baseline."""
    since = utcnow() - timedelta(days=settings.ml_train_days)
    stmt = select(SecurityEvent).where(
        SecurityEvent.timestamp >= since,
        ~exists().where(AlertEvent.event_id == SecurityEvent.id),
    )
    if not include_simulated:
        stmt = stmt.where(SecurityEvent.data_origin == "real")
    agg = ml_service.FeatureAggregator(settings.business_tz_offset_minutes)
    for row in db.scalars(stmt.execution_options(yield_per=5000)):
        agg.add(row_to_event(row))
    return get_detector().train(agg.frame())


def purge_old_events(db: Session) -> int:
    """Retention: delete old events that are not evidence for any alert."""
    from sqlalchemy import delete

    cutoff = utcnow() - timedelta(days=settings.retention_days)
    res = db.execute(
        delete(SecurityEvent).where(
            SecurityEvent.timestamp < cutoff,
            ~exists().where(AlertEvent.event_id == SecurityEvent.id),
        )
    )
    db.commit()
    return res.rowcount or 0
