from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.permissions import Permission, require_permission
from app.database.session import get_db
from app.models.user import UserModel
from app.schemas.threat_hunting import ThreatHuntRequest, ThreatHuntQuery
from app.services.threat_hunting import execute_threat_hunt

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])


@router.post("/query", response_model=ThreatHuntQuery)
def run_threat_hunt_endpoint(
    request: ThreatHuntRequest,
    _: UserModel = Depends(require_permission(Permission.HUNTING_EXECUTE)),
    db: Session = Depends(get_db),
):
    return execute_threat_hunt(db, request.query_text)
