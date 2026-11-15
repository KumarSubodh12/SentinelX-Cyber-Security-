from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import Agent, AuditLog, User
from app.security import decode_access_token, hash_api_key

bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> Optional[str]:
    """Client IP. X-Forwarded-For is only trusted when explicitly enabled (behind a proxy)."""
    if settings.trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip() or None
        real = request.headers.get("x-real-ip")
        if real:
            return real.strip()
    return request.client.host if request.client else None


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if creds is None:
        raise unauthorized
    payload = decode_access_token(creds.credentials)
    if not payload:
        raise unauthorized
    try:
        user = db.get(User, int(payload["sub"]))
    except (ValueError, KeyError):
        raise unauthorized
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_roles(*roles: str):
    allowed = set(roles)

    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to do this")
        return user

    return checker


# Convenience dependencies
any_user = get_current_user
analyst_or_admin = require_roles("admin", "analyst")
admin_only = require_roles("admin")


def get_agent(
    x_agent_key: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> Agent:
    if not x_agent_key:
        raise HTTPException(status_code=401, detail="Missing X-Agent-Key header")
    agent = db.scalar(select(Agent).where(Agent.api_key_hash == hash_api_key(x_agent_key)))
    if agent is None or not agent.is_active:
        raise HTTPException(status_code=401, detail="Invalid or disabled agent key")
    return agent


def audit(db: Session, actor: Optional[str], action: str, detail: Optional[str] = None, ip: Optional[str] = None) -> None:
    db.add(AuditLog(actor=actor, action=action, detail=(detail or "")[:2000] or None, ip_address=ip))


class SlidingWindowLimiter:
    """Tiny in-memory limiter (per process). Good enough for login throttling on a single instance."""

    def __init__(self, attempts: int, window_seconds: int) -> None:
        self.attempts = attempts
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str) -> deque[float]:
        q = self._hits[key]
        cutoff = time.monotonic() - self.window
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        return len(self._prune(key)) >= self.attempts

    def hit(self, key: str) -> None:
        self._prune(key).append(time.monotonic())

    def reset(self, key: str) -> None:
        self._hits.pop(key, None)


login_limiter = SlidingWindowLimiter(settings.login_rate_limit_attempts, settings.login_rate_limit_window_seconds)

AGENT_ONLINE_WINDOW = timedelta(minutes=2)


def agent_online(agent: Agent) -> bool:
    return bool(agent.is_active and agent.last_seen and datetime.now(timezone.utc) - agent.last_seen <= AGENT_ONLINE_WINDOW)
