from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.threat_hunting import ThreatHuntRequest, ThreatHuntQuery
from app.services.threat_hunting import execute_threat_hunt

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])


@router.post("/query", response_model=ThreatHuntQuery)
def run_threat_hunt_endpoint(request: ThreatHuntRequest, db: Session = Depends(get_db)):
    return execute_threat_hunt(db, request.query_text)
