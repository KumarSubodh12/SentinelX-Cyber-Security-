from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import admin_only, analyst_or_admin, audit, client_ip
from app.models import User
from app.schemas import UserCreate, UserOut, UserUpdate
from app.security import hash_password, validate_password_strength

router = APIRouter(prefix="/api/users", tags=["users"])


def _active_admin_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.is_active.is_(True))) or 0


@router.get("", response_model=list[UserOut])
def list_users(_: User = Depends(admin_only), db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)))


@router.get("/assignable")
def assignable_users(_: User = Depends(analyst_or_admin), db: Session = Depends(get_db)) -> list[dict]:
    """Minimal user list for the incident 'assign to' picker (analysts cannot see the full user admin list)."""
    users = db.scalars(select(User).where(User.is_active.is_(True), User.role.in_(["admin", "analyst"])).order_by(User.username))
    return [{"id": u.id, "username": u.username, "full_name": u.full_name, "role": u.role} for u in users]


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)) -> User:
    problem = validate_password_strength(body.password)
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    if db.scalar(select(User).where(func.lower(User.username) == body.username.lower())):
        raise HTTPException(status_code=409, detail="Username already exists")
    if db.scalar(select(User).where(func.lower(User.email) == body.email.lower())):
        raise HTTPException(status_code=409, detail="Email already exists")
    user = User(
        username=body.username,
        email=body.email,
        full_name=body.full_name,
        hashed_password=hash_password(body.password),
        role=body.role.value,
    )
    db.add(user)
    audit(db, admin.username, "user_created", f"{body.username} ({body.role.value})", client_ip(request))
    db.commit()
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int, body: UserUpdate, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)
) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    demoting = (body.role is not None and body.role.value != "admin") or body.is_active is False
    if user.role == "admin" and user.is_active and demoting and _active_admin_count(db) <= 1:
        raise HTTPException(status_code=400, detail="At least one active administrator is required")

    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        user.role = body.role.value
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password:
        problem = validate_password_strength(body.password)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        user.hashed_password = hash_password(body.password)
    audit(db, admin.username, "user_updated", f"{user.username}", client_ip(request))
    db.commit()
    return user


@router.delete("/{user_id}", status_code=204, response_class=Response, response_model=None)
def delete_user(user_id: int, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)) -> None:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    if user.role == "admin" and user.is_active and _active_admin_count(db) <= 1:
        raise HTTPException(status_code=400, detail="At least one active administrator is required")
    audit(db, admin.username, "user_deleted", user.username, client_ip(request))
    db.delete(user)
    db.commit()
