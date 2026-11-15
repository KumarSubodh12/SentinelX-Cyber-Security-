"""Small portable SQL helpers (PostgreSQL in production, SQLite for quick local runs)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import BigInteger, case, cast, func
from sqlalchemy.orm import Session


def bucket_expr(db: Session, column: Any, seconds: int) -> Any:
    """SQL expression: the column's timestamp floored to `seconds`, as epoch seconds."""
    if db.get_bind().dialect.name == "sqlite":
        epoch = cast(func.strftime("%s", column), BigInteger)
    else:
        epoch = cast(func.floor(func.extract("epoch", column)), BigInteger)
    return epoch - (epoch % seconds)


def bucket_starts(since: datetime, until: datetime, seconds: int) -> list[int]:
    start = int(since.timestamp()) // seconds * seconds
    end = int(until.timestamp()) // seconds * seconds
    return list(range(start, end + 1, seconds))


def to_iso(epoch: int) -> str:
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()


def count_if(condition: Any) -> Any:
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


def apply_origin(stmt: Any, column: Any, origin: Optional[str]) -> Any:
    return stmt.where(column == origin) if origin in ("real", "simulated") else stmt


def bucket_seconds_for(hours: int) -> int:
    if hours <= 6:
        return 300
    if hours <= 48:
        return 3600
    return 86400


def window_start(hours: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)
