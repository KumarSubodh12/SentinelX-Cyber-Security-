"""Database initialisation and first-run seeding."""

from __future__ import annotations

import logging
import time

from sqlalchemy import func, select, text
from sqlalchemy.exc import OperationalError

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.models import User
from app.security import hash_password
from app.services.runtime_settings import seed_rules

log = logging.getLogger("sentinelx.bootstrap")


def wait_for_database(attempts: int = 30, delay: float = 2.0) -> None:
    for attempt in range(1, attempts + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError as exc:
            log.warning("database not ready (%s/%s): %s", attempt, attempts, str(exc).splitlines()[0])
            time.sleep(delay)
    raise RuntimeError("Could not connect to the database. Check DATABASE_URL.")


def init_db() -> None:
    wait_for_database()
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        seed_rules(db)
        if (db.scalar(select(func.count()).select_from(User)) or 0) == 0:
            db.add(
                User(
                    username=settings.first_admin_username,
                    email=settings.first_admin_email,
                    full_name="Administrator",
                    hashed_password=hash_password(settings.first_admin_password),
                    role="admin",
                )
            )
            log.warning("Created first administrator '%s'. Change the password after logging in.", settings.first_admin_username)
        db.commit()
