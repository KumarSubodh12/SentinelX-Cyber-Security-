from __future__ import annotations

import csv
import html
import io
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.constants import SEVERITIES
from app.database import SessionLocal, get_db
from app.deps import any_user, audit, client_ip
from app.models import Alert, Incident, SecurityEvent, User
from app.routers.analytics import overview_data
from app.services.sqlutil import apply_origin

router = APIRouter(prefix="/api/reports", tags=["reports"])

MAX_EXPORT_ROWS = 50_000

COLUMNS = {
    "alerts": ["id", "created_at", "severity", "risk_score", "status", "rule_key", "detection_type", "title", "source_ip", "username", "hostname", "event_count", "data_origin", "resolved_by", "resolution_note"],
    "events": ["id", "timestamp", "source", "event_type", "severity", "risk_score", "hostname", "username", "source_ip", "dest_ip", "dest_port", "http_method", "http_path", "status_code", "message", "data_origin"],
    "incidents": ["id", "created_at", "severity", "status", "title", "source_ip", "created_by", "resolved_at", "resolution", "data_origin"],
}


def _safe_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection (cells starting with = + - @)."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return "" if value is None else value


def _rows(db: Session, kind: str, since: datetime, origin: Optional[str]) -> Iterator[Any]:
    """Stream rows with a server-side cursor so large exports stay memory-friendly."""
    if kind == "alerts":
        stmt = apply_origin(select(Alert).where(Alert.created_at >= since), Alert.data_origin, origin).order_by(Alert.created_at.desc())
    elif kind == "events":
        stmt = apply_origin(select(SecurityEvent).where(SecurityEvent.timestamp >= since), SecurityEvent.data_origin, origin).order_by(SecurityEvent.timestamp.desc())
    else:
        stmt = apply_origin(select(Incident).where(Incident.created_at >= since), Incident.data_origin, origin).order_by(Incident.created_at.desc())
    return iter(db.scalars(stmt.limit(MAX_EXPORT_ROWS).execution_options(yield_per=2000)))


@router.get("/export")
def export_csv(
    request: Request,
    kind: str = Query(..., pattern="^(alerts|events|incidents)$"),
    days: int = Query(7, ge=1, le=365),
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    user: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    columns = COLUMNS[kind]
    audit(db, user.username, "report_export", f"{kind} csv, last {days} days", client_ip(request))
    db.commit()

    def generate() -> Iterator[str]:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(columns)
        yield buf.getvalue()
        # The request-scoped session may already be closed while streaming, so use our own.
        with SessionLocal() as stream_db:
            for row in _rows(stream_db, kind, since, origin):
                buf.seek(0)
                buf.truncate(0)
                writer.writerow([_safe_cell(getattr(row, c)) for c in columns])
                yield buf.getvalue()

    filename = f"sentinelx-{kind}-{datetime.now(timezone.utc):%Y%m%d}.csv"
    return StreamingResponse(
        generate(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


@router.get("/summary.html", response_class=HTMLResponse)
def summary_report(
    request: Request,
    days: int = Query(7, ge=1, le=90),
    origin: Optional[str] = Query(None, pattern="^(real|simulated)$"),
    user: User = Depends(any_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Printable report - open it and use the browser's 'Save as PDF'."""
    data = overview_data(db, days * 24, origin)
    t = data["totals"]
    since = datetime.now(timezone.utc) - timedelta(days=days)
    critical = db.scalars(
        apply_origin(
            select(Alert).where(Alert.created_at >= since, Alert.severity.in_(["critical", "high"])),
            Alert.data_origin,
            origin,
        )
        .order_by(Alert.risk_score.desc())
        .limit(25)
    ).all()
    open_inc = db.scalars(
        apply_origin(select(Incident).where(Incident.status.in_(["open", "investigating", "contained"])), Incident.data_origin, origin)
        .order_by(Incident.created_at.desc())
        .limit(25)
    ).unique().all()
    audit(db, user.username, "report_export", f"summary html, last {days} days", client_ip(request))
    db.commit()

    def table(headers: list[str], rows: list[list[Any]]) -> str:
        head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in r) + "</tr>" for r in rows)
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body or '<tr><td colspan=99>Nothing to report.</td></tr>'}</tbody></table>"

    scope = {"real": "Real data only", "simulated": "Simulated data only"}.get(origin or "", "Real and simulated data (simulated events are marked SIM)")
    sev_rows = [[s.title(), data["severity_distribution"].get(s, 0)] for s in SEVERITIES]
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SentinelX security report</title>
<style>
 body{{font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif;color:#111;margin:32px auto;max-width:960px;padding:0 16px}}
 h1{{margin:0 0 4px}} h2{{margin:28px 0 8px;font-size:16px}} .muted{{color:#555}}
 .grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}}
 .card{{border:1px solid #ccc;border-radius:6px;padding:10px 12px}} .card b{{display:block;font-size:22px}}
 table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{border:1px solid #ddd;padding:5px 8px;text-align:left;vertical-align:top}} th{{background:#f4f4f4}}
 @media print{{body{{margin:0}}}}
</style></head><body>
<h1>SentinelX security report</h1>
<p class="muted">Last {days} days &middot; generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC by {_esc(user.username)} &middot; {_esc(scope)}</p>
<div class="grid">
 <div class="card"><b>{t['events_window']}</b>events</div><div class="card"><b>{t['threats_window']}</b>threats detected</div>
 <div class="card"><b>{t['failed_logins_window']}</b>failed logins</div><div class="card"><b>{t['suspicious_ips_window']}</b>suspicious IPs</div>
 <div class="card"><b>{t['active_alerts']}</b>active alerts</div><div class="card"><b>{t['open_incidents']}</b>open incidents</div>
 <div class="card"><b>{t['critical_incidents']}</b>critical incidents</div><div class="card"><b>{t['agents_online']}/{t['agents_total']}</b>agents online</div>
</div>
<h2>Threats by severity</h2>{table(["Severity", "Alerts"], sev_rows)}
<h2>Most active source IPs</h2>{table(["IP", "Events", "Failed logins"], [[r["ip"], r["events"], r["failed_logins"]] for r in data["top_ips"]])}
<h2>Most frequent detections</h2>{table(["Rule", "Alerts"], [[r["rule_key"], r["count"]] for r in data["top_rules"]])}
<h2>High and critical alerts</h2>{table(["Time (UTC)", "Severity", "Risk", "Status", "Alert", "Source"], [[a.created_at.strftime("%Y-%m-%d %H:%M"), a.severity, a.risk_score, a.status, ("[SIM] " if a.data_origin == "simulated" else "") + a.title, a.source_ip or a.username or ""] for a in critical])}
<h2>Active incidents</h2>{table(["ID", "Severity", "Status", "Title", "Opened (UTC)"], [[i.id, i.severity, i.status, ("[SIM] " if i.data_origin == "simulated" else "") + i.title, i.created_at.strftime("%Y-%m-%d %H:%M")] for i in open_inc])}
<p class="muted">Machine-learning findings are indicators that need investigation, not proof of an attack.</p>
</body></html>"""
    return HTMLResponse(page)
