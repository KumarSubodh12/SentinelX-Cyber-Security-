from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app import __version__
from app.bootstrap import init_db
from app.config import settings
from app.database import SessionLocal, engine
from app.routers import admin, agents, alerts, analytics, auth, events, incidents, ips, ml, reports, simulate, users, ws
from app.services import pipeline, threat_intel
from app.services.runtime_settings import load_runtime_settings
from app.websocket import manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sentinelx")


def _train_job() -> None:
    with SessionLocal() as db:
        if not load_runtime_settings(db).ml_enabled:
            return
        result = pipeline.train_model(db, include_simulated=False)
        log.info("scheduled ML training: %s (%s samples)", result.reason, result.samples)


def _purge_job() -> None:
    with SessionLocal() as db:
        removed = pipeline.purge_old_events(db)
        if removed:
            log.info("retention: removed %s old events", removed)


async def maintenance_loop() -> None:
    """Feed refresh, ML retraining and retention. Runs in the background of the single API process."""
    await asyncio.sleep(5)
    last_feed = last_train = last_purge = 0.0
    while True:
        try:
            now = time.time()
            if settings.feed_urls and now - last_feed >= settings.threat_feed_refresh_hours * 3600:
                await asyncio.to_thread(threat_intel.refresh_blocklists)
                last_feed = now
            if now - last_train >= settings.ml_retrain_hours * 3600:
                await asyncio.to_thread(_train_job)
                last_train = now
            if now - last_purge >= 24 * 3600:
                await asyncio.to_thread(_purge_job)
                last_purge = now
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("maintenance task failed")
        await asyncio.sleep(300)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.is_production:
        settings.assert_production_safe()
    manager.bind_loop(asyncio.get_running_loop())
    await asyncio.to_thread(init_db)
    task = asyncio.create_task(maintenance_loop())
    log.info("SentinelX %s started (%s)", __version__, settings.environment)
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(
    title="SentinelX API",
    version=__version__,
    description="AI-powered SIEM and threat detection backend.",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.enable_docs else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,  # auth uses a Bearer header, not cookies
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Agent-Key"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/docs"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


for module in (auth, users, agents, events, alerts, incidents, ips, analytics, reports, admin, ml, simulate, ws):
    app.include_router(module.router)


@app.get("/api/health", tags=["system"])
def health() -> dict[str, Any]:
    db_ok = True
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "version": __version__,
        "database": db_ok,
        "websocket_clients": manager.client_count,
        "ml_model_ready": pipeline.get_detector().ready,
        "environment": settings.environment,
    }
