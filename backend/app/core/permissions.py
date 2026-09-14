"""
app/core/permissions.py — Centralized RBAC permission model.

USAGE (in route handlers):
    from app.core.deps import get_current_user
    from app.core.permissions import require_permission

    @router.get("/protected")
    def my_endpoint(user = Depends(require_permission("logs.view"))):
        ...

DESIGN:
- Role-to-permission mapping lives here and only here.
- Route handlers NEVER check `user.role == "ADMIN"` — they call require_permission().
- Frontend gets `userPermissions` from /api/auth/me and uses hasPermission() for UX-only gating.
"""
from __future__ import annotations

from enum import Enum
from fastapi import Depends, HTTPException, status
from typing import Set

from app.models.user import UserModel


class Permission(str, Enum):
    # Dashboard & Analytics
    DASHBOARD_VIEW = "dashboard.view"
    ANALYTICS_VIEW = "analytics.view"

    # Logs
    LOGS_VIEW = "logs.view"
    LOGS_INGEST = "logs.ingest"

    # Alerts
    ALERTS_VIEW = "alerts.view"
    ALERTS_UPDATE = "alerts.update"

    # Incidents
    INCIDENTS_VIEW = "incidents.view"
    INCIDENTS_INVESTIGATE = "incidents.investigate"

    # Threat Hunting
    HUNTING_EXECUTE = "hunting.execute"

    # Copilot
    COPILOT_USE = "copilot.use"

    # Detection Rules
    RULES_VIEW = "rules.view"
    RULES_MANAGE = "rules.manage"

    # Response Actions
    RESPONSE_VIEW = "response.view"
    RESPONSE_RECOMMEND = "response.recommend"
    RESPONSE_APPROVE = "response.approve"
    RESPONSE_EXECUTE = "response.execute"

    # User Management
    USERS_VIEW = "users.view"
    USERS_MANAGE = "users.manage"

    # Audit Logs
    AUDIT_VIEW = "audit.view"

    # System Settings
    SETTINGS_MANAGE = "settings.manage"

    # Blocklist
    BLOCKLIST_VIEW = "blocklist.view"


# ---------------------------------------------------------------------------
# Role → Permission mapping (the single authoritative source)
# ---------------------------------------------------------------------------
_ROLE_PERMISSIONS: dict[str, Set[Permission]] = {
    "ADMIN": {
        Permission.DASHBOARD_VIEW,
        Permission.ANALYTICS_VIEW,
        Permission.LOGS_VIEW,
        Permission.LOGS_INGEST,
        Permission.ALERTS_VIEW,
        Permission.ALERTS_UPDATE,
        Permission.INCIDENTS_VIEW,
        Permission.INCIDENTS_INVESTIGATE,
        Permission.HUNTING_EXECUTE,
        Permission.COPILOT_USE,
        Permission.RULES_VIEW,
        Permission.RULES_MANAGE,
        Permission.RESPONSE_VIEW,
        Permission.RESPONSE_RECOMMEND,
        Permission.RESPONSE_APPROVE,
        Permission.RESPONSE_EXECUTE,
        Permission.USERS_VIEW,
        Permission.USERS_MANAGE,
        Permission.AUDIT_VIEW,
        Permission.SETTINGS_MANAGE,
        Permission.BLOCKLIST_VIEW,
    },
    "SECURITY_ANALYST": {
        Permission.DASHBOARD_VIEW,
        Permission.ANALYTICS_VIEW,
        Permission.LOGS_VIEW,
        Permission.LOGS_INGEST,
        Permission.ALERTS_VIEW,
        Permission.ALERTS_UPDATE,
        Permission.INCIDENTS_VIEW,
        Permission.INCIDENTS_INVESTIGATE,
        Permission.HUNTING_EXECUTE,
        Permission.COPILOT_USE,
        Permission.RULES_VIEW,
        Permission.RESPONSE_VIEW,
        Permission.RESPONSE_RECOMMEND,
        Permission.RESPONSE_APPROVE,    # Analyst approves; does NOT execute
        Permission.BLOCKLIST_VIEW,
    },
    "SOC_OPERATOR": {
        Permission.DASHBOARD_VIEW,
        Permission.ANALYTICS_VIEW,
        Permission.LOGS_VIEW,
        Permission.ALERTS_VIEW,
        Permission.INCIDENTS_VIEW,
        Permission.RESPONSE_VIEW,
        Permission.RESPONSE_EXECUTE,    # Operator executes; does NOT approve
        Permission.BLOCKLIST_VIEW,
    },
    "VIEWER": {
        Permission.DASHBOARD_VIEW,
        Permission.ANALYTICS_VIEW,
        Permission.LOGS_VIEW,
        Permission.ALERTS_VIEW,
        Permission.INCIDENTS_VIEW,
    },
}


def get_permissions_for_role(role: str) -> Set[Permission]:
    """Return the permission set for a given role string."""
    return _ROLE_PERMISSIONS.get(role, set())


def role_has_permission(role: str, permission: Permission) -> bool:
    return permission in _ROLE_PERMISSIONS.get(role, set())


def require_permission(permission: Permission):
    """
    FastAPI dependency factory.  Apply to any route that requires a specific permission.

    Example:
        @router.post("/upload")
        async def upload(
            file: UploadFile,
            user: UserModel = Depends(require_permission(Permission.LOGS_INGEST)),
            db: Session = Depends(get_db),
        ):
    """
    # Import here to avoid circular imports (deps imports from this module)
    from app.core.deps import get_current_user

    def _check(user: UserModel = Depends(get_current_user)) -> UserModel:
        if not role_has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission.value}' required.",
            )
        return user

    return _check
