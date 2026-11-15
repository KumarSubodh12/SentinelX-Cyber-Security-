from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
import jwt

from app.config import settings

ALGORITHM = "HS256"


def _prehash(password: str) -> bytes:
    # bcrypt only reads the first 72 bytes (and newer versions reject longer input),
    # so hash first. Base64 keeps the digest free of NUL bytes.
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def validate_password_strength(password: str) -> Optional[str]:
    """Return an error message, or None when the password is acceptable."""
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    if password.lower() == password or password.upper() == password:
        return "Password must mix upper and lower case letters."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit."
    return None


def create_access_token(user_id: int, role: str, expires_minutes: Optional[int] = None) -> tuple[str, int]:
    minutes = expires_minutes or settings.access_token_expire_minutes
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM), minutes * 60


def decode_access_token(token: str) -> Optional[dict[str, Any]]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        return None


# --- Agent API keys ---------------------------------------------------------


def generate_api_key() -> tuple[str, str, str]:
    """Return (plaintext key, sha256 hash, display prefix). The plaintext is shown once."""
    key = "sx_" + secrets.token_urlsafe(32)
    return key, hash_api_key(key), key[:10]


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
