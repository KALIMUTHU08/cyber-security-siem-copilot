"""
app/core/security.py — Password hashing and JWT utilities.

Security rules (enforced here):
- Passwords are NEVER logged, stored plaintext, or embedded in tokens.
- Tokens contain only user_id (sub) and exp — never email, role, or hash.
- The user record is always reloaded from DB on each request (not trusted from token).
"""
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings


def hash_password(plain: str) -> str:
    """Hash a password with bcrypt. Truncate to 72 bytes per bcrypt spec."""
    pwd_bytes = plain.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Securely compare plain password against stored bcrypt hash."""
    try:
        pwd_bytes = plain.encode("utf-8")[:72]
        hashed_bytes = hashed.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hashed_bytes)
    except Exception:
        return False


def create_access_token(user_id: str, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT with minimal claims: sub (user id) and exp only."""
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta
    payload = {"sub": user_id, "exp": expire}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> str:
    """Decode and verify a JWT; return the user_id (sub claim).

    Raises ValueError on any failure (expired, invalid, tampered).
    Callers must convert this to an HTTP 401 — see app.core.deps.
    """
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        user_id: Optional[str] = payload.get("sub")
        if not user_id:
            raise ValueError("Token has no sub claim")
        return user_id
    except JWTError as exc:
        raise ValueError(f"Invalid or expired token: {exc}") from exc
