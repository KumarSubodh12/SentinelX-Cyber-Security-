from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.deps import admin_only, agent_online, any_user, audit, client_ip, get_agent
from app.models import Agent, User
from app.schemas import (
    AgentCreate,
    AgentCreated,
    AgentInfo,
    AgentOut,
    AgentUpdate,
    HeartbeatRequest,
    IngestRequest,
    IngestResponse,
)
from app.security import generate_api_key
from app.services import pipeline
from app.websocket import manager

router = APIRouter(tags=["agents"])


def _out(agent: Agent) -> AgentOut:
    out = AgentOut.model_validate(agent)
    out.online = agent_online(agent)
    return out


def _touch(agent: Agent, info: AgentInfo | None, ip: str | None) -> None:
    agent.last_seen = datetime.now(timezone.utc)
    if ip:
        agent.ip_address = ip
    if info:
        agent.hostname = info.hostname or agent.hostname
        agent.os_type = info.os or agent.os_type
        agent.version = info.version or agent.version


# --- Agent-facing endpoints (authenticated with X-Agent-Key) -----------------


@router.post("/api/ingest", response_model=IngestResponse)
def ingest(
    body: IngestRequest,
    request: Request,
    background: BackgroundTasks,
    agent: Agent = Depends(get_agent),
    db: Session = Depends(get_db),
) -> IngestResponse:
    if len(body.events) > settings.max_batch_size:
        raise HTTPException(status_code=413, detail=f"Batch too large (max {settings.max_batch_size})")
    was_online = agent_online(agent)
    _touch(agent, body.agent, client_ip(request))
    result = pipeline.ingest(db, body.events, agent_id=agent.id, origin="real")
    agent.events_received = (agent.events_received or 0) + result.accepted
    db.commit()
    if not was_online:
        manager.publish({"type": "agent_status", "data": {"id": agent.id, "name": agent.name, "online": True}})
    if result.ips_to_enrich:
        background.add_task(pipeline.enrich_ips, result.ips_to_enrich)
    return IngestResponse(
        accepted=result.accepted,
        duplicates=result.duplicates,
        rejected=result.rejected,
        alerts_created=result.alerts_created,
        alerts_updated=result.alerts_updated,
    )


@router.post("/api/agents/heartbeat", status_code=204, response_class=Response, response_model=None)
def heartbeat(
    body: HeartbeatRequest, request: Request, agent: Agent = Depends(get_agent), db: Session = Depends(get_db)
) -> None:
    was_online = agent_online(agent)
    _touch(agent, body.agent, client_ip(request))
    db.commit()
    if not was_online:
        manager.publish({"type": "agent_status", "data": {"id": agent.id, "name": agent.name, "online": True}})


# --- Admin endpoints -------------------------------------------------------------


@router.get("/api/agents", response_model=list[AgentOut])
def list_agents(_: User = Depends(any_user), db: Session = Depends(get_db)) -> list[AgentOut]:
    return [_out(a) for a in db.scalars(select(Agent).order_by(Agent.id))]


@router.post("/api/agents", response_model=AgentCreated, status_code=201)
def create_agent(body: AgentCreate, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)) -> AgentCreated:
    if db.scalar(select(Agent).where(Agent.name == body.name)):
        raise HTTPException(status_code=409, detail="An agent with this name already exists")
    key, key_hash, prefix = generate_api_key()
    agent = Agent(name=body.name, api_key_hash=key_hash, api_key_prefix=prefix)
    db.add(agent)
    audit(db, admin.username, "agent_created", body.name, client_ip(request))
    db.commit()
    out = _out(agent)
    return AgentCreated(**out.model_dump(), api_key=key)  # the plaintext key is only ever returned here


@router.post("/api/agents/{agent_id}/rotate-key", response_model=AgentCreated)
def rotate_key(agent_id: int, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)) -> AgentCreated:
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    key, key_hash, prefix = generate_api_key()
    agent.api_key_hash, agent.api_key_prefix = key_hash, prefix
    audit(db, admin.username, "agent_key_rotated", agent.name, client_ip(request))
    db.commit()
    return AgentCreated(**_out(agent).model_dump(), api_key=key)


@router.patch("/api/agents/{agent_id}", response_model=AgentOut)
def update_agent(
    agent_id: int, body: AgentUpdate, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)
) -> AgentOut:
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if body.is_active is not None:
        agent.is_active = body.is_active
    if body.name:
        agent.name = body.name
    audit(db, admin.username, "agent_updated", agent.name, client_ip(request))
    db.commit()
    return _out(agent)


@router.delete("/api/agents/{agent_id}", status_code=204, response_class=Response, response_model=None)
def delete_agent(agent_id: int, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)) -> None:
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    audit(db, admin.username, "agent_deleted", agent.name, client_ip(request))
    db.delete(agent)  # its events are kept (agent_id is set to NULL)
    db.commit()
