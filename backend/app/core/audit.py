"""
app/core/audit.py — Centralized audit logging helper.

Call log_audit() from any endpoint or service that performs a security-relevant action.
Audit records are append-only — no update/delete API is ever exposed.
"""
import uuid
from datetime import datetime
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLogModel


def log_audit(
    db: Session,
    action: str,
    result: str,
    *,
    user_id: Optional[str] = None,
    user_email: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLogModel:
    """
    Write one immutable audit record.

    action  — dot-separated verb: "login.success", "response_action.approved", etc.
    result  — "success" or "failure"
    details — arbitrary JSON-serialisable dict; never include passwords or tokens.
    """
    entry = AuditLogModel(
        id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        user_id=user_id,
        user_email=user_email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        source_ip=source_ip,
        details=details or {},
    )
    db.add(entry)
    db.flush()   # write within the caller's transaction; commit is caller's responsibility
    return entry
