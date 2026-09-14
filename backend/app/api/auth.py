"""
app/api/auth.py — Authentication and user management endpoints.

Protected routes:
  POST /api/auth/login    — public (unauthenticated)
  GET  /api/auth/me       — any valid authenticated user
  POST /api/auth/logout   — any valid authenticated user (client-side token discard)
  GET  /api/auth/users    — ADMIN only (users.view)
  POST /api/auth/users    — ADMIN only (users.manage)
  PATCH /api/auth/users/{id} — ADMIN only (users.manage)

Brute-force protection:
  In-memory counter per (email, remote_ip) — no external infrastructure.
  After LOGIN_MAX_FAILURES failed attempts in LOGIN_LOCKOUT_SECONDS, the account
  is temporarily locked from the login attempt.  This is application-level only
  (not stored in DB) and resets on server restart, which is acceptable for a
  college-project demo with no Redis.
"""
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.audit import log_audit
from app.core.config import settings
from app.core.deps import get_current_user
from app.core.permissions import Permission, get_permissions_for_role, require_permission
from app.core.security import create_access_token, hash_password, verify_password
from app.database.session import get_db
from app.models.user import UserModel
from app.schemas.user import (
    MeResponse,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserOut,
    UserUpdate,
    VALID_ROLES,
)

router = APIRouter(prefix="/auth", tags=["Auth"])

# ---------------------------------------------------------------------------
# In-memory brute-force protection
# Stores: {key: (failure_count, window_start_utc)}
# Resets on server restart (acceptable for college demo; upgrade to DB/Redis for prod)
# ---------------------------------------------------------------------------
_failure_tracker: dict[str, tuple[int, datetime]] = defaultdict(lambda: (0, datetime.utcnow()))


def _brute_force_key(email: str, ip: str) -> str:
    return f"{email.lower()}|{ip}"


def _check_brute_force(email: str, ip: str) -> None:
    key = _brute_force_key(email, ip)
    count, window_start = _failure_tracker[key]
    elapsed = (datetime.utcnow() - window_start).total_seconds()
    if elapsed > settings.LOGIN_LOCKOUT_SECONDS:
        # Window expired — reset counter
        _failure_tracker[key] = (0, datetime.utcnow())
        return
    if count >= settings.LOGIN_MAX_FAILURES:
        remaining = int(settings.LOGIN_LOCKOUT_SECONDS - elapsed)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in {remaining} seconds.",
        )


def _record_failure(email: str, ip: str) -> None:
    key = _brute_force_key(email, ip)
    count, window_start = _failure_tracker[key]
    elapsed = (datetime.utcnow() - window_start).total_seconds()
    if elapsed > settings.LOGIN_LOCKOUT_SECONDS:
        _failure_tracker[key] = (1, datetime.utcnow())
    else:
        _failure_tracker[key] = (count + 1, window_start)


def _reset_failures(email: str, ip: str) -> None:
    key = _brute_force_key(email, ip)
    _failure_tracker[key] = (0, datetime.utcnow())


def _user_to_out(user: UserModel) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        last_login=user.last_login,
        created_at=user.created_at,
    )


def _user_permissions(user: UserModel) -> List[str]:
    return [p.value for p in get_permissions_for_role(user.role)]


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse)
def login(request: Request, body: UserLogin, db: Session = Depends(get_db)):
    """Authenticate and return a JWT access token.

    HTTP responses:
      200  — success
      401  — wrong credentials (user not found or password mismatch)
      403  — user is deactivated
      429  — too many failed attempts (brute-force protection)
    """
    client_ip = request.client.host if request.client else "unknown"

    # Brute-force check BEFORE we touch the DB (avoids leaking timing info about account existence)
    _check_brute_force(body.email, client_ip)

    user = db.query(UserModel).filter(UserModel.email == body.email).first()

    if not user or not verify_password(body.password, user.hashed_password):
        _record_failure(body.email, client_ip)
        log_audit(
            db,
            action="login.failure",
            result="failure",
            user_email=body.email,
            source_ip=client_ip,
            details={"reason": "invalid credentials"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    if not user.is_active:
        log_audit(
            db,
            action="login.failure",
            result="failure",
            user_id=user.id,
            user_email=user.email,
            source_ip=client_ip,
            details={"reason": "account deactivated"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact your administrator.",
        )

    _reset_failures(body.email, client_ip)

    token = create_access_token(user.id)
    user.last_login = datetime.utcnow()

    log_audit(
        db,
        action="login.success",
        result="success",
        user_id=user.id,
        user_email=user.email,
        source_ip=client_ip,
    )
    db.commit()

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=_user_to_out(user),
        permissions=_user_permissions(user),
    )


# ---------------------------------------------------------------------------
# Authenticated endpoints
# ---------------------------------------------------------------------------

@router.get("/me", response_model=MeResponse)
def get_me(current_user: UserModel = Depends(get_current_user)):
    """Return the current user's profile and permission set."""
    return MeResponse(
        user=_user_to_out(current_user),
        permissions=_user_permissions(current_user),
    )


@router.post("/logout")
def logout(current_user: UserModel = Depends(get_current_user)):
    """Signal logout intent.  Token invalidation is client-side (localStorage removal).
    This endpoint exists so the frontend has a clean logout call and we can audit it."""
    # No server-side token blacklist in this project (acceptable for college demo).
    # The frontend discards the token from localStorage.
    return {"detail": "Logged out successfully."}


# ---------------------------------------------------------------------------
# ADMIN-only: user management
# ---------------------------------------------------------------------------

@router.get("/users", response_model=List[UserOut])
def list_users(
    _: UserModel = Depends(require_permission(Permission.USERS_VIEW)),
    db: Session = Depends(get_db),
):
    users = db.query(UserModel).order_by(UserModel.created_at.asc()).all()
    return [_user_to_out(u) for u in users]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    current_user: UserModel = Depends(require_permission(Permission.USERS_MANAGE)),
    db: Session = Depends(get_db),
):
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role '{body.role}'. Must be one of {sorted(VALID_ROLES)}.")

    existing = db.query(UserModel).filter(UserModel.email == body.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="A user with this email already exists.")

    if len(body.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")

    new_user = UserModel(
        id=str(uuid.uuid4()),
        email=body.email,
        full_name=body.full_name,
        hashed_password=hash_password(body.password),
        role=body.role,
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db.add(new_user)

    log_audit(
        db,
        action="user.created",
        result="success",
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="user",
        resource_id=new_user.id,
        details={"new_user_email": body.email, "role": body.role},
    )
    db.commit()
    db.refresh(new_user)
    return _user_to_out(new_user)


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    body: UserUpdate,
    current_user: UserModel = Depends(require_permission(Permission.USERS_MANAGE)),
    db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Prevent self-role-escalation
    if body.role is not None and user_id == current_user.id:
        raise HTTPException(status_code=403, detail="You cannot change your own role.")

    if body.role is not None and body.role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role '{body.role}'.")

    # Prevent deactivating the last active ADMIN
    if body.is_active is False and user.role == "ADMIN":
        active_admins = db.query(UserModel).filter(
            UserModel.role == "ADMIN", UserModel.is_active == True
        ).count()
        if active_admins <= 1:
            raise HTTPException(
                status_code=409,
                detail="Cannot deactivate the last active ADMIN account.",
            )

    # Prevent demoting the last ADMIN
    if body.role is not None and body.role != "ADMIN" and user.role == "ADMIN":
        active_admins = db.query(UserModel).filter(
            UserModel.role == "ADMIN", UserModel.is_active == True
        ).count()
        if active_admins <= 1:
            raise HTTPException(
                status_code=409,
                detail="Cannot demote the last active ADMIN account.",
            )

    audit_details: dict = {}
    if body.full_name is not None:
        user.full_name = body.full_name
        audit_details["full_name"] = body.full_name
    if body.role is not None:
        old_role = user.role
        user.role = body.role
        audit_details["role_change"] = {"from": old_role, "to": body.role}
    if body.is_active is not None:
        user.is_active = body.is_active
        audit_details["is_active"] = body.is_active
    if body.new_password is not None:
        if len(body.new_password) < 8:
            raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")
        user.hashed_password = hash_password(body.new_password)
        audit_details["password_reset"] = True

    log_audit(
        db,
        action="user.updated",
        result="success",
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="user",
        resource_id=user_id,
        details=audit_details,
    )
    db.commit()
    db.refresh(user)
    return _user_to_out(user)
