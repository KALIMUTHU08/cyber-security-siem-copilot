"""
app/api/audit.py — Audit log read endpoint (ADMIN / audit.view only).

No update or delete endpoint is ever provided. Audit logs are append-only.
"""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.permissions import Permission, require_permission
from app.database.session import get_db
from app.models.audit_log import AuditLogModel
from app.models.user import UserModel
from app.schemas.common import CamelModel

router = APIRouter(prefix="/audit-logs", tags=["Audit"])


class AuditLogOut(CamelModel):
    id: str
    timestamp: datetime
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    result: str
    source_ip: Optional[str] = None
    details: dict = {}


@router.get("", response_model=List[AuditLogOut])
def list_audit_logs(
    action: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None, alias="userId"),
    result: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200, alias="pageSize"),
    _: UserModel = Depends(require_permission(Permission.AUDIT_VIEW)),
    db: Session = Depends(get_db),
):
    query = db.query(AuditLogModel)
    if action:
        query = query.filter(AuditLogModel.action.ilike(f"%{action}%"))
    if user_id:
        query = query.filter(AuditLogModel.user_id == user_id)
    if result:
        query = query.filter(AuditLogModel.result == result)

    entries = (
        query.order_by(desc(AuditLogModel.timestamp))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return [
        AuditLogOut(
            id=e.id,
            timestamp=e.timestamp,
            user_id=e.user_id,
            user_email=e.user_email,
            action=e.action,
            resource_type=e.resource_type,
            resource_id=e.resource_id,
            result=e.result,
            source_ip=e.source_ip,
            details=e.details or {},
        )
        for e in entries
    ]
