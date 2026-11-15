from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import any_user, audit, client_ip, login_limiter
from app.models import User
from app.schemas import LoginRequest, PasswordChange, TokenOut, UserOut
from app.security import (
    create_access_token,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.services.pipeline import ingest_internal

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Verifying against this hash for unknown users keeps response time similar (no user enumeration).
_DUMMY_HASH = hash_password("not-a-real-password-Aa1")


@router.post("/login", response_model=TokenOut)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    ip = client_ip(request)
    limiter_key = ip or "unknown"
    if login_limiter.blocked(limiter_key):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in a few minutes.")

    user = db.scalar(select(User).where(User.username == body.username))
    ok = verify_password(body.password, user.hashed_password if user else _DUMMY_HASH)
    if not user or not ok or not user.is_active:
        login_limiter.hit(limiter_key)
        audit(db, body.username[:64], "login_failed", ip=ip)
        db.commit()
        # SentinelX monitors itself: failed logins feed the same brute-force rules as any other source.
        ingest_internal(
            db,
            event_type="login_failed",
            username=body.username[:128],
            source_ip=ip,
            message="Failed SentinelX dashboard login",
            http_path="/api/auth/login",
            status_code=401,
        )
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    login_limiter.reset(limiter_key)
    user.last_login = datetime.now(timezone.utc)
    audit(db, user.username, "login", ip=ip)
    db.commit()
    ingest_internal(
        db,
        event_type="login_success",
        username=user.username,
        source_ip=ip,
        message="SentinelX dashboard login",
        http_path="/api/auth/login",
        status_code=200,
    )
    token, expires = create_access_token(user.id, user.role)
    return TokenOut(access_token=token, expires_in=expires)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(any_user)) -> User:
    return user


@router.post("/change-password", status_code=204, response_class=Response, response_model=None)
def change_password(
    body: PasswordChange, request: Request, user: User = Depends(any_user), db: Session = Depends(get_db)
) -> None:
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    problem = validate_password_strength(body.new_password)
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    user.hashed_password = hash_password(body.new_password)
    audit(db, user.username, "password_changed", ip=client_ip(request))
    db.commit()
