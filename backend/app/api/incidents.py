from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.incident import IncidentModel
from app.schemas.incident import Incident, TimelineEvent
from app.schemas.common import PaginatedResult, RiskScore

router = APIRouter(prefix="/incidents", tags=["Incidents"])


def to_incident_schema(i: IncidentModel) -> Incident:
    timeline_events = [
        TimelineEvent(
            id=t.id,
            timestamp=t.timestamp,
            title=t.title,
            description=t.description,
            event_type=t.event_type,
            severity=t.severity,
            related_log_ids=t.related_log_ids or [],
            related_alert_ids=t.related_alert_ids or [],
            metadata=t.event_metadata or {},
        )
        for t in sorted(i.timeline_events, key=lambda evt: evt.timestamp)
    ]

    return Incident(
        id=i.id,
        title=i.title,
        severity=i.severity,
        status=i.status,
        risk_score=RiskScore(score=i.risk_score, level=i.risk_level, factors=i.risk_factors or []),
        source_ip=i.source_ip,
        destination_ip=i.destination_ip,
        target_user=i.target_user,
        affected_device=i.affected_device,
        first_seen=i.first_seen,
        last_seen=i.last_seen,
        summary=i.summary,
        attack_vector=i.attack_vector,
        timeline=timeline_events,
        related_alert_ids=i.related_alert_ids or [],
        related_log_ids=i.related_log_ids or [],
        observed_evidence=i.observed_evidence or [],
        ai_assessment=i.ai_assessment or "",
        recommended_next_steps=i.recommended_next_steps or [],
        tags=i.tags or [],
    )


@router.get("", response_model=PaginatedResult[Incident])
def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100, alias="pageSize"),
    db: Session = Depends(get_db),
):
    query = db.query(IncidentModel)
    total = query.count()
    items = (
        query.order_by(IncidentModel.last_seen.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedResult[Incident](
        items=[to_incident_schema(inc) for inc in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{incident_id}", response_model=Incident)
def get_incident_by_id(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return to_incident_schema(incident)
