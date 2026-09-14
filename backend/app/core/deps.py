"""
app/core/deps.py — FastAPI dependency: authenticated user extraction.

The real security boundary is HERE — every protected route Depends() on
get_current_user (or require_permission which wraps it).

Frontend role/permission gating is UX convenience only.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.database.session import get_db
from app.models.user import UserModel

# Points to our login endpoint (used only for OpenAPI "Authorize" UI)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> UserModel:
    """
    Extract and validate the JWT bearer token; return the active UserModel.

    Returns HTTP 401 for: missing token, invalid token, expired token, unknown user.
    Returns HTTP 403 for: inactive/deactivated user (user exists but is_active=False).
    """
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user_id = decode_token(token)
    except ValueError:
        raise credentials_exc

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if user is None:
        raise credentials_exc
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )
    return user
