"""
app/api/blocklist.py — Simulated IP blocklist read endpoint.

Supports reading the current blocklist and auto-expiring stale entries.
No real firewall interaction — DB records only.
"""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.audit import log_audit
from app.core.deps import get_current_user
from app.core.permissions import Permission, require_permission
from app.database.session import get_db
from app.models.blocklist import BlocklistEntryModel
from app.models.user import UserModel
from app.schemas.common import CamelModel

router = APIRouter(prefix="/blocklist", tags=["Blocklist"])


class BlocklistEntryOut(CamelModel):
    id: str
    ip: str
    status: str
    reason: str
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    response_action_id: str


@router.get("", response_model=List[BlocklistEntryOut])
def list_blocklist(
    _: UserModel = Depends(require_permission(Permission.BLOCKLIST_VIEW)),
    db: Session = Depends(get_db),
):
    """List all blocklist entries. Auto-expires stale BLOCKED entries."""
    now = datetime.utcnow()

    # Auto-expire: mark BLOCKED entries whose expires_at has passed
    expired = (
        db.query(BlocklistEntryModel)
        .filter(
            BlocklistEntryModel.status == "BLOCKED",
            BlocklistEntryModel.expires_at != None,
            BlocklistEntryModel.expires_at <= now,
        )
        .all()
    )
    for entry in expired:
        entry.status = "EXPIRED"
        log_audit(
            db,
            action="blocklist.expired",
            result="success",
            resource_type="blocklist_entry",
            resource_id=entry.id,
            details={"ip": entry.ip},
        )
    if expired:
        db.commit()

    entries = (
        db.query(BlocklistEntryModel)
        .order_by(BlocklistEntryModel.created_at.desc())
        .all()
    )
    return [
        BlocklistEntryOut(
            id=e.id,
            ip=e.ip,
            status=e.status,
            reason=e.reason,
            created_by=e.created_by,
            created_at=e.created_at,
            expires_at=e.expires_at,
            response_action_id=e.response_action_id,
        )
        for e in entries
    ]
