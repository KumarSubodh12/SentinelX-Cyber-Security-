from __future__ import annotations

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from app.database import SessionLocal
from app.models import User
from app.security import decode_access_token
from app.websocket import manager

router = APIRouter()


def _valid_user(token: str) -> bool:
    payload = decode_access_token(token)
    if not payload:
        return False
    with SessionLocal() as db:
        user = db.get(User, int(payload["sub"]))
        return bool(user and user.is_active)


@router.websocket("/ws")
async def live_feed(ws: WebSocket, token: str = Query(...)) -> None:
    """Live events/alerts. Authenticate with ?token=<JWT> (use wss:// in production)."""
    if not await run_in_threadpool(_valid_user, token):
        await ws.close(code=4401)
        return
    await manager.connect(ws)
    await ws.send_text('{"type":"hello"}')
    try:
        while True:
            message = await ws.receive_text()
            if message == "ping":
                await ws.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(ws)
