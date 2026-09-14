from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.core.permissions import Permission, require_permission
from app.database.session import get_db
from app.models.alert import AlertModel
from app.models.user import UserModel
from app.schemas.alert import SecurityAlert, AlertStatusUpdate
from app.schemas.log import BatchIdsRequest
from app.schemas.common import PaginatedResult, RiskScore

router = APIRouter(prefix="/alerts", tags=["Alerts"])


def to_security_alert_schema(a: AlertModel) -> SecurityAlert:
    return SecurityAlert(
        id=a.id,
        title=a.title,
        severity=a.severity,
        status=a.status,
        risk_score=RiskScore(score=a.risk_score, level=a.risk_level, factors=a.risk_factors or []),
        detection_rule_id=a.detection_rule_id,
        detection_rule_name=a.detection_rule_name,
        detection_condition=a.detection_condition,
        source_ip=a.source_ip,
        destination_ip=a.destination_ip,
        username=a.username,
        device=a.device,
        first_seen=a.first_seen,
        last_seen=a.last_seen,
        match_count=a.match_count,
        matching_summary=a.matching_summary,
        matching_log_ids=a.matching_log_ids or [],
        related_incident_id=a.related_incident_id,
        tags=a.tags or [],
    )


@router.get("", response_model=PaginatedResult[SecurityAlert])
def list_alerts(
    search: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None, alias="sourceIp"),
    username: Optional[str] = Query(None),
    detection_type: Optional[str] = Query(None, alias="detectionType"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100, alias="pageSize"),
    _: UserModel = Depends(require_permission(Permission.ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    query = db.query(AlertModel)

    if search:
        s = f"%{search.lower()}%"
        query = query.filter(
            or_(
                AlertModel.title.ilike(s),
                AlertModel.source_ip.ilike(s),
                AlertModel.username.ilike(s),
                AlertModel.device.ilike(s),
                AlertModel.detection_rule_name.ilike(s),
            )
        )

    if severity:
        query = query.filter(AlertModel.severity == severity)
    if status:
        query = query.filter(AlertModel.status == status)
    if source_ip:
        query = query.filter(AlertModel.source_ip.ilike(f"%{source_ip}%"))
    if username:
        query = query.filter(AlertModel.username.ilike(f"%{username}%"))
    if detection_type:
        query = query.filter(AlertModel.detection_rule_name.ilike(f"%{detection_type}%"))

    total = query.count()
    items = (
        query.order_by(AlertModel.last_seen.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedResult[SecurityAlert](
        items=[to_security_alert_schema(a) for a in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/batch", response_model=List[SecurityAlert])
def get_alerts_by_ids_post(
    request: BatchIdsRequest,
    _: UserModel = Depends(require_permission(Permission.ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    if not request.ids:
        return []
    alerts = db.query(AlertModel).filter(AlertModel.id.in_(request.ids)).all()
    return [to_security_alert_schema(a) for a in alerts]


@router.get("/batch", response_model=List[SecurityAlert])
def get_alerts_by_ids_get(
    ids: str = Query(""),
    _: UserModel = Depends(require_permission(Permission.ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    if not id_list:
        return []
    alerts = db.query(AlertModel).filter(AlertModel.id.in_(id_list)).all()
    return [to_security_alert_schema(a) for a in alerts]


@router.get("/{alert_id}", response_model=SecurityAlert)
def get_alert_by_id(
    alert_id: str,
    _: UserModel = Depends(require_permission(Permission.ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return to_security_alert_schema(alert)


@router.patch("/{alert_id}", response_model=SecurityAlert)
def update_alert_status(
    alert_id: str,
    update: AlertStatusUpdate,
    _: UserModel = Depends(require_permission(Permission.ALERTS_UPDATE)),
    db: Session = Depends(get_db),
):
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    alert.status = update.status
    db.commit()
    db.refresh(alert)
    return to_security_alert_schema(alert)
